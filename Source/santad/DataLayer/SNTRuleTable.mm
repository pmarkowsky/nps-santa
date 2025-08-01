/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#import "Source/santad/DataLayer/SNTRuleTable.h"

#import <EndpointSecurity/EndpointSecurity.h>

#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/Platform.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTError.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTXxhash.h"
#import "Source/common/SigningIDHelpers.h"
#include "Source/common/String.h"
#include "Source/common/cel/Evaluator.h"

static const uint32_t kRuleTableCurrentVersion = 9;

// How many rules must be in database before we start trying to remove transitive rules.
static const int64_t kTransitiveRuleCullingThreshold = 500000;
// Consider transitive rules out of date if they haven't been used in six months.
static const NSUInteger kTransitiveRuleExpirationSeconds = 6 * 30 * 24 * 3600;

static void addPathsFromDefaultMuteSet(NSMutableSet *criticalPaths) {
  // Create a temporary ES client in order to grab the default set of muted paths.
  // TODO(mlw): Reorganize this code so that a temporary ES client doesn't need to be created
  es_client_t *client = NULL;
  es_new_client_result_t ret = es_new_client(&client, ^(es_client_t *c, const es_message_t *m){
                                                 // noop
                                             });
  if (ret != ES_NEW_CLIENT_RESULT_SUCCESS) {
    // Creating the client failed, so we cannot grab the current default mute set.
    LOGE(@"Failed to create client to grab default muted paths");
    return;
  }

  es_muted_paths_t *mps = NULL;
  if (es_muted_paths_events(client, &mps) != ES_RETURN_SUCCESS) {
    LOGE(@"Failed to obtain list of default muted paths.");
    es_delete_client(client);
    return;
  }

  for (size_t i = 0; i < mps->count; i++) {
    // Only add literal paths, prefix paths would require recursive directory search
    if (mps->paths[i].type == ES_MUTE_PATH_TYPE_LITERAL) {
      [criticalPaths addObject:@(mps->paths[i].path.data)];
    }
  }

  es_release_muted_paths(mps);
  es_delete_client(client);
}

@interface SNTRuleTable () {
  std::unique_ptr<santa::cel::Evaluator> _celEvaluator;
}
@property MOLCodesignChecker *santadCSInfo;
@property MOLCodesignChecker *launchdCSInfo;
@property NSDate *lastTransitiveRuleCulling;
@property NSDictionary *criticalSystemBinaries;
@property(readonly) NSArray *criticalSystemBinaryPaths;
@property(readwrite) NSDictionary<NSString *, SNTRule *> *cachedStaticRules;
@property(atomic) NSString *rulesHash;
@end

@implementation SNTRuleTable

//  ES on Monterey now has a “default mute set” of paths that are automatically applied to each ES
//  client. This mute set contains most (not all) AUTH event types for some paths that were deemed
//  “system critical”.
+ (NSArray *)criticalSystemBinaryPaths {
  static dispatch_once_t onceToken;
  static NSArray *criticalPaths = nil;
  dispatch_once(&onceToken, ^{
    // These paths have previously existed in the ES default mute set. They are hardcoded
    // here in case grabbing the current default mute set fails, or if Santa is running on
    // an OS that did not yet support this feature.
    NSSet *fallbackDefaultMuteSet = [[NSSet alloc] initWithArray:@[
      @"/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer",
      @"/System/Library/PrivateFrameworks/TCC.framework/Support/tccd",
      @"/System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/tccd",
      @"/usr/sbin/cfprefsd",
      @"/usr/sbin/securityd",
      @"/usr/libexec/opendirectoryd",
      @"/usr/libexec/sandboxd",
      @"/usr/libexec/syspolicyd",
      @"/usr/libexec/runningboardd",
      @"/usr/libexec/amfid",
      @"/usr/libexec/watchdogd",
    ]];

    // This is a Santa-curated list of paths to check on startup. This list will be merged
    // with the set of default muted paths from ES.

    NSSet *santaDefinedCriticalPaths = [NSSet setWithArray:@[
      @"/usr/libexec/trustd",
      @"/usr/lib/dyld",
      @"/usr/libexec/xpcproxy",
      @"/usr/sbin/ocspd",
      @"/Applications/Santa.app/Contents/MacOS/Santa",
      @"/Applications/Santa.app/Contents/MacOS/santactl",
      @"/Applications/Santa.app/Contents/MacOS/santabundleservice",
      @"/Applications/Santa.app/Contents/MacOS/santametricservice",
      @"/Applications/Santa.app/Contents/MacOS/santasyncservice",
    ]];

    // Combine the fallback default mute set and Santa-curated set
    NSMutableSet *superSet = [NSMutableSet setWithSet:fallbackDefaultMuteSet];
    [superSet unionSet:santaDefinedCriticalPaths];

    // Attempt to add the real default mute set
    addPathsFromDefaultMuteSet(superSet);

    criticalPaths = [superSet allObjects];
  });

  return criticalPaths;
}

- (void)setupSystemCriticalBinaries {
  NSMutableDictionary *bins = [NSMutableDictionary dictionary];
  for (NSString *path in [SNTRuleTable criticalSystemBinaryPaths]) {
    SNTFileInfo *binInfo = [[SNTFileInfo alloc] initWithPath:path];
    if (!binInfo.SHA256) {
      // If there isn't a hash, no need to compute the other info here.
      // Just continue on to the next binary.
      LOGD(@"Unable to compute hash for critical system binary %@.", path);
      continue;
    }
    MOLCodesignChecker *csInfo = [binInfo codesignCheckerWithError:NULL];

    // Make sure the critical system binary is signed by the same chain as launchd/self
    BOOL systemBin = NO;
    if ([csInfo signingInformationMatches:self.launchdCSInfo]) {
      systemBin = YES;
    } else if (![csInfo.teamID isEqualToString:self.santadCSInfo.teamID]) {
      LOGW(@"Unable to validate critical system binary %@. "
           @"Not signed by same cert as pid 1: %@ vs %@, and does not match santad TeamID: %@ vs "
           @"%@.",
           path, self.launchdCSInfo.leafCertificate, csInfo.leafCertificate,
           self.santadCSInfo.teamID, csInfo.teamID);
      continue;
    }

    SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];

    cd.decision = SNTEventStateAllowSigningID;
    cd.decisionExtra = systemBin ? @"critical system binary" : @"santa binary";
    cd.sha256 = binInfo.SHA256;
    cd.signingID = FormatSigningID(csInfo);
    cd.cdhash = csInfo.cdhash;
    cd.secureSigningTime = csInfo.secureSigningTime;
    cd.signingTime = csInfo.signingTime;
    cd.signingStatus = IsProductionSigningCert(csInfo.leafCertificate)
                           ? SNTSigningStatusProduction
                           : SNTSigningStatusDevelopment;

    // Normalized by the FormatSigningID function so this will always have a
    // prefix.
    cd.teamID = [cd.signingID componentsSeparatedByString:@":"].firstObject;

    // Not needed, but nice for logging and events.
    cd.certChain = csInfo.certificates;
    cd.certSHA256 = csInfo.leafCertificate.SHA256;
    cd.certCommonName = csInfo.leafCertificate.commonName;

    bins[cd.signingID] = cd;
  }

  self.criticalSystemBinaries = bins;
}

- (uint32_t)currentSupportedVersion {
  return kRuleTableCurrentVersion;
}

- (uint32_t)initializeDatabase:(FMDatabase *)db fromVersion:(uint32_t)version {
  // Lock this database from other processes
  [[db executeQuery:@"PRAGMA locking_mode = EXCLUSIVE;"] close];

  uint32_t newVersion = 0;

  if (version < 1) {
    [db executeUpdate:@"CREATE TABLE 'rules' ("
                      @"'shasum' TEXT NOT NULL, "
                      @"'state' INTEGER NOT NULL, "
                      @"'type' INTEGER NOT NULL, "
                      @"'custommsg' TEXT"
                      @")"];
    [db executeUpdate:@"CREATE UNIQUE INDEX rulesunique ON rules (shasum, type)"];

    [[SNTConfigurator configurator] setSyncTypeRequired:SNTSyncTypeCleanAll];

    newVersion = 1;
  }

  if (version < 2) {
    [db executeUpdate:@"DROP VIEW IF EXISTS binrules"];
    [db executeUpdate:@"DROP VIEW IF EXISTS certrules"];
    newVersion = 2;
  }

  if (version < 3) {
    // Add timestamp column for tracking age of transitive rules.
    [db executeUpdate:@"ALTER TABLE 'rules' ADD 'timestamp' INTEGER"];
    newVersion = 3;
  }

  if (version < 4) {
    // Rename `shasum` column to `identifier`.
    [db executeUpdate:@"ALTER TABLE 'rules' RENAME COLUMN 'shasum' TO 'identifier'"];
    newVersion = 4;
  }

  if (version < 5) {
    // Migrate SNTRuleType enum values
    // Note: The reordering is intentional so that the type values are in order
    // of precedence.
    [db executeUpdate:@"UPDATE rules SET type = 1000 WHERE type = 1"];
    [db executeUpdate:@"UPDATE rules SET type = 3000 WHERE type = 2"];
    [db executeUpdate:@"UPDATE rules SET type = 4000 WHERE type = 3"];
    [db executeUpdate:@"UPDATE rules SET type = 2000 WHERE type = 4"];

    newVersion = 5;
  }

  if (version < 6) {
    // Force hash identifiers for Binary and Certificate rules to always be lowercase
    [db executeUpdate:@"UPDATE rules SET identifier = LOWER(identifier) WHERE type = ? OR type = ?",
                      @(SNTRuleTypeBinary), @(SNTRuleTypeCertificate)];

    // Force team ID identifiers for TeamID rules to always be uppercase
    [db executeUpdate:@"UPDATE rules SET identifier = UPPER(identifier) WHERE type = ?",
                      @(SNTRuleTypeTeamID)];

    // Note: Intentionally not attempting to migrate exsting SigningID rules to enforce
    // the TeamID component to be uppercase. Since this is a newer rule type, it is
    // assumed to be unnecessary and we'd rather not maintain the SQL to perform this
    // migration automatically.

    newVersion = 6;
  }

  if (version < 7) {
    [db executeUpdate:@"ALTER TABLE 'rules' ADD 'customurl' TEXT"];
    newVersion = 7;
  }

  if (version < 8) {
    [db executeUpdate:@"ALTER TABLE 'rules' ADD 'comment' TEXT"];
    newVersion = 8;
  }

  if (version < 9) {
    [db executeUpdate:@"ALTER TABLE 'rules' ADD 'cel_expr' TEXT"];
    newVersion = 9;
  }

  // Save signing info for launchd and santad. Used to ensure they are always allowed.
  self.santadCSInfo = [[MOLCodesignChecker alloc] initWithSelf];
  self.launchdCSInfo = [[MOLCodesignChecker alloc] initWithPID:1];

  auto celEval = santa::cel::Evaluator::Create();
  if (celEval.ok()) {
    _celEvaluator = std::move(celEval.value());
  } else {
    LOGE(@"Failed to create CEL evaluator: %s", std::string(celEval.status().message()).c_str());
  }

  // Setup critical system binaries
  [self setupSystemCriticalBinaries];

  // Prime the cached static rules.
  [self updateStaticRules:[[SNTConfigurator configurator] staticRules]];

  return newVersion;
}

#pragma mark Entry Counts

- (int64_t)ruleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules"];
  }];
  return count;
}

- (int64_t)ruleCountForRuleType:(SNTRuleType)ruleType {
  __block int64_t count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE type=?", @(ruleType)];
  }];
  return count;
}

- (int64_t)binaryRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeBinary];
}

- (int64_t)certificateRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeCertificate];
}

- (int64_t)compilerRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count =
        [db longForQuery:@"SELECT COUNT(*) FROM rules WHERE state=?", @(SNTRuleStateAllowCompiler)];
  }];
  return count;
}

- (int64_t)transitiveRuleCount {
  __block NSUInteger count = 0;
  [self inDatabase:^(FMDatabase *db) {
    count = [db
        longForQuery:@"SELECT COUNT(*) FROM rules WHERE state=?", @(SNTRuleStateAllowTransitive)];
  }];
  return count;
}

- (int64_t)teamIDRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeTeamID];
}

- (int64_t)signingIDRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeSigningID];
}

- (int64_t)cdhashRuleCount {
  return [self ruleCountForRuleType:SNTRuleTypeCDHash];
}

- (SNTRule *)ruleFromResultSet:(FMResultSet *)rs {
  return [[SNTRule alloc] initWithIdentifier:[rs stringForColumn:@"identifier"]
                                       state:static_cast<SNTRuleState>([rs intForColumn:@"state"])
                                        type:static_cast<SNTRuleType>([rs intForColumn:@"type"])
                                   customMsg:[rs stringForColumn:@"custommsg"]
                                   customURL:[rs stringForColumn:@"customurl"]
                                   timestamp:[rs intForColumn:@"timestamp"]
                                     comment:[rs stringForColumn:@"comment"]
                                     celExpr:[rs stringForColumn:@"cel_expr"]
                                       error:nil];
}

- (SNTRule *)ruleForIdentifiers:(struct RuleIdentifiers)identifiers {
  __block SNTRule *rule;

  // Look for a static rule that matches.
  NSDictionary *staticRules = self.cachedStaticRules;
  if (staticRules.count) {
    // IMPORTANT: The order static rules are checked here should be the same
    // order as given by the SQL query for the rules database.
    rule = staticRules[identifiers.cdhash];
    if (rule.type == SNTRuleTypeCDHash) {
      return rule;
    }

    rule = staticRules[identifiers.binarySHA256];
    if (rule.type == SNTRuleTypeBinary) {
      return rule;
    }

    rule = staticRules[identifiers.signingID];
    if (rule.type == SNTRuleTypeSigningID) {
      return rule;
    }

    rule = staticRules[identifiers.certificateSHA256];
    if (rule.type == SNTRuleTypeCertificate) {
      return rule;
    }

    rule = staticRules[identifiers.teamID];
    if (rule.type == SNTRuleTypeTeamID) {
      return rule;
    }
  }

  // Now query the database.
  //
  // NOTE: This code is written with the intention that the binary rule is searched for first
  // as Santa is designed to go with the most-specific rule possible.
  //
  // The intended order of precedence is CDHash > Binaries > Signing IDs > Certificates > Team IDs.
  //
  // As such the query should have "ORDER BY type ASC" before the LIMIT, to ensure that is the
  // case. However, in all tested versions of SQLite that ORDER BY clause is unnecessary: the query
  // is performed 'as written' by doing separate lookups in the index and the later lookups are if
  // the first returns a result. That behavior can be checked here: http://sqlfiddle.com/#!5/cdc42/1
  //
  // Adding the ORDER BY clause slows down this query, particularly in a database where
  // the number of binary rules outweighs the number of certificate rules because:
  //       a) now it can't avoid the certificate rule lookup when a binary rule is found
  //       b) after fetching the results it now has to sort even if there's just 1 row
  //
  // There is a test for this in SNTRuleTableTests in case SQLite behavior changes in the future.
  //
  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs =
        [db executeQuery:@"SELECT * FROM rules WHERE "
                         @"   (identifier=? AND type=500) "
                         @"OR (identifier=? AND type=1000) "
                         @"OR (identifier=? AND type=2000) "
                         @"OR (identifier=? AND type=3000) "
                         @"OR (identifier=? AND type=4000) LIMIT 1",
                         identifiers.cdhash, identifiers.binarySHA256, identifiers.signingID,
                         identifiers.certificateSHA256, identifiers.teamID];
    if ([rs next]) {
      rule = [self ruleFromResultSet:rs];
    }
    [rs close];
  }];

  // Allow binaries signed by the "Software Signing" cert used to sign launchd
  // if no existing rule has matched.
  if (!rule && [identifiers.certificateSHA256 isEqual:self.launchdCSInfo.leafCertificate.SHA256]) {
    rule = [[SNTRule alloc] initWithIdentifier:identifiers.certificateSHA256
                                         state:SNTRuleStateAllow
                                          type:SNTRuleTypeCertificate];
  }

  return rule;
}

#pragma mark Adding

- (BOOL)addRules:(NSArray *)rules ruleCleanup:(SNTRuleCleanup)cleanupType error:(NSError **)error {
  // Only accept an empty rules array if the cleanup-type is not none.
  if ((!rules || rules.count < 1) && cleanupType == SNTRuleCleanupNone) {
    [SNTError populateError:error withCode:SNTErrorCodeEmptyRuleArray format:@"Empty rule array"];
    return NO;
  }

  __block BOOL failed = NO;
  __block NSError *blockErr;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    if (cleanupType == SNTRuleCleanupAll) {
      [db executeUpdate:@"DELETE FROM rules"];
    } else if (cleanupType == SNTRuleCleanupNonTransitive) {
      [db executeUpdate:@"DELETE FROM rules WHERE state != ?", @(SNTRuleStateAllowTransitive)];
    }

    for (SNTRule *rule in rules) {
      if (![rule isKindOfClass:[SNTRule class]] || rule.identifier.length == 0 ||
          rule.state == SNTRuleStateUnknown || rule.type == SNTRuleTypeUnknown) {
        [SNTError populateError:&blockErr
                       withCode:SNTErrorCodeRuleInvalid
                        message:@"Rule array contained invalid entry"
                         detail:rule.description];
        *rollback = failed = YES;
        return;
      }

      if (rule.state == SNTRuleStateCEL && _celEvaluator) {
        auto celExpr = _celEvaluator->Compile(santa::NSStringToUTF8StringView(rule.celExpr));
        if (!celExpr.ok()) {
          [SNTError populateError:&blockErr
                         withCode:SNTErrorCodeRuleInvalidCELExpression
                          message:@"Rule array contained rule with invalid CEL expression"
                           detail:santa::StringToNSString(celExpr.status().message())];
          continue;
        }
      }

      if (rule.state == SNTRuleStateRemove) {
        if (![db executeUpdate:@"DELETE FROM rules WHERE identifier=? AND type=?", rule.identifier,
                               @(rule.type)]) {
          [SNTError populateError:&blockErr
                         withCode:SNTErrorCodeRemoveRuleFailed
                          message:@"A database error occurred while deleting a rule"
                           detail:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      } else {
        if (![db executeUpdate:@"INSERT OR REPLACE INTO rules "
                               @"(identifier, state, type, custommsg, customurl, timestamp, "
                               @"comment, cel_expr) "
                               @"VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                               rule.identifier, @(rule.state), @(rule.type), rule.customMsg,
                               rule.customURL, @(rule.timestamp), rule.comment, rule.celExpr]) {
          [SNTError populateError:&blockErr
                         withCode:SNTErrorCodeInsertOrReplaceRuleFailed
                          message:@"A database error occurred while inserting/replacing a rule"
                           detail:[db lastErrorMessage]];
          *rollback = failed = YES;
          return;
        }
      }
    }

    // Clear the rules hash
    self.rulesHash = nil;
  }];

  if (blockErr && error) {
    *error = blockErr;
  }

  return !failed;
}

- (BOOL)addedRulesShouldFlushDecisionCache:(NSArray *)rules {
  uint64_t nonAllowRuleCount = 0;

  for (SNTRule *rule in rules) {
    // If the rule is a remove rule, act conservatively and flush the cache.
    // This is to make sure cached rules of different precedence rules do not
    // impact final decision.
    if (rule.state == SNTRuleStateRemove) {
      return YES;
    }
    if (rule.state != SNTRuleStateAllow) {
      nonAllowRuleCount++;

      // Just flush if we more than 1000 block rules.
      if (nonAllowRuleCount >= 1000) return YES;
    }
  }

  // Check newly synced rules for any blocking rules. If any are found, check
  // in the db to see if they already exist. If they're not found or were
  // previously allow rules flush the cache.
  //
  // If all rules in the array are allowlist rules,  look for allowlist rules
  // where there is a previously existing allowlist compiler rule for the same
  // identifier.  If so we find such a rule, then cache should be flushed.
  __block BOOL flushDecisionCache = NO;

  [self inTransaction:^(FMDatabase *db, BOOL *rollback) {
    for (SNTRule *rule in rules) {
      if (rule.state != SNTRuleStateAllow) {
        // If the rule is a CEL rule, block rule, silent block rule, or a compiler rule check if it
        // already exists in the database. If it is a CEL rule also check the expression is the
        // same.
        //
        // If it does not then flush the cache. To ensure that the new rule is honored.
        if ([db longForQuery:@"SELECT COUNT(*) FROM rules WHERE identifier=? AND type=? AND "
                             @"state=? AND (cel_expr IS NULL OR cel_expr=?) LIMIT 1",
                             rule.identifier, @(rule.type), @(rule.state), rule.celExpr] == 0) {
          flushDecisionCache = YES;
          return;
        }
      } else {
        // At this point we know the rule is an allowlist rule. Check if it's
        // overriding a compiler rule.

        // Skip certificate and TeamID rules as they cannot be compiler rules.
        if (rule.type == SNTRuleTypeCertificate || rule.type == SNTRuleTypeTeamID) continue;

        if ([db longForQuery:@"SELECT COUNT(*) FROM rules WHERE identifier=? AND type IN (?, ?, ?)"
                             @" AND state=? LIMIT 1",
                             rule.identifier, @(SNTRuleTypeCDHash), @(SNTRuleTypeBinary),
                             @(SNTRuleTypeSigningID), @(SNTRuleStateAllowCompiler)] > 0) {
          flushDecisionCache = YES;
          return;
        }
      }
    }
  }];

  return flushDecisionCache;
}

// Updates the timestamp to current time for the given rule.
- (void)resetTimestampForRule:(SNTRule *)rule {
  if (!rule) return;
  [rule resetTimestamp];
  [self inDatabase:^(FMDatabase *db) {
    if (![db executeUpdate:@"UPDATE rules SET timestamp=? WHERE identifier=? AND type=?",
                           @(rule.timestamp), rule.identifier, @(rule.type)]) {
      LOGE(@"Could not update timestamp for rule with sha256=%@", rule.identifier);
    }
  }];
}

- (void)removeOutdatedTransitiveRules {
  // Don't attempt to remove transitive rules unless it's been at least an hour since the
  // last time we tried to remove them.
  if (self.lastTransitiveRuleCulling &&
      -[self.lastTransitiveRuleCulling timeIntervalSinceNow] < 3600)
    return;

  // Don't bother removing rules unless rule database is large.
  if ([self ruleCount] < kTransitiveRuleCullingThreshold) return;
  // Determine what timestamp qualifies as outdated.
  NSUInteger outdatedTimestamp =
      [[NSDate date] timeIntervalSinceReferenceDate] - kTransitiveRuleExpirationSeconds;

  [self inDatabase:^(FMDatabase *db) {
    if (![db executeUpdate:@"DELETE FROM rules WHERE state=? AND timestamp < ?",
                           @(SNTRuleStateAllowTransitive), @(outdatedTimestamp)]) {
      LOGE(@"Could not remove outdated transitive rules");
    }
  }];

  self.lastTransitiveRuleCulling = [NSDate date];
}

#pragma mark Querying

// Retrieve all rules from the Database
- (NSArray<SNTRule *> *)retrieveAllRules {
  NSMutableArray<SNTRule *> *rules = [NSMutableArray array];
  [self inDatabase:^(FMDatabase *db) {
    FMResultSet *rs = [db executeQuery:@"SELECT * FROM rules"];
    while ([rs next]) {
      [rules addObject:[self ruleFromResultSet:rs]];
    }
    [rs close];
  }];
  return rules;
}

#pragma mark Caching Static Rules

- (void)updateStaticRules:(NSArray<NSDictionary *> *)staticRules {
  if (![staticRules isKindOfClass:[NSArray class]]) {
    self.cachedStaticRules = nil;
    return;
  }

  NSMutableDictionary<NSString *, SNTRule *> *rules =
      [NSMutableDictionary dictionaryWithCapacity:staticRules.count];
  for (id rule in staticRules) {
    if (![rule isKindOfClass:[NSDictionary class]]) continue;
    NSError *error;
    SNTRule *r = [[SNTRule alloc] initStaticRuleWithDictionary:rule error:&error];
    if (error) {
      LOGE(@"Failed to initialize static rule %@: %@", rule, error);
    }
    if (!r) continue;

    if (r.state == SNTRuleStateCEL && _celEvaluator) {
      auto celExpr = _celEvaluator->Compile(santa::NSStringToUTF8StringView(r.celExpr));
      if (!celExpr.ok()) {
        LOGE(@"Failed to compile CEL expression for static rule %@: %s", r.identifier,
             std::string(celExpr.status().message()).c_str());
        continue;
      }
    }

    rules[r.identifier] = r;
  }
  self.cachedStaticRules = [rules copy];
}

- (NSString *)hashOfHashes {
  __block NSString *digest;
  [self inDatabase:^(FMDatabase *db) {
    // If santad has previously computed the hash and stored it in memory, return it.
    // When a rule is added or removed the hash will be cleared so that the next
    // request for the hash will recompute it.
    if (self.rulesHash.length) {
      digest = self.rulesHash;
      return;
    }

    santa::Xxhash hash;

    FMResultSet *rs =
        [db executeQuery:@"SELECT identifier, state, type, cel_expr FROM rules WHERE state != ?",
                         @(SNTRuleStateAllowTransitive)];
    while ([rs next]) {
      NSString *identifier = [rs stringForColumn:@"identifier"];
      NSString *cel = [rs stringForColumn:@"cel_expr"];
      int state = [rs intForColumn:@"state"];
      int type = [rs intForColumn:@"type"];

      hash.Update(identifier.UTF8String,
                  [identifier lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
      hash.Update(cel.UTF8String, [cel lengthOfBytesUsingEncoding:NSUTF8StringEncoding]);
      hash.Update(static_cast<void *>(&state), sizeof(state));
      hash.Update(static_cast<void *>(&type), sizeof(type));
    }
    [rs close];

    digest = santa::StringToNSString(hash.Digest());
    self.rulesHash = digest;
  }];
  return digest;
}

@end
