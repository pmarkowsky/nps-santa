/// Copyright 2015 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santasyncservice/SNTSyncRuleDownload.h"
#include "Source/santasyncservice/SNTPushNotificationsTracker.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTSyncConstants.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/String.h"
#import "Source/santasyncservice/SNTPushNotificationsTracker.h"
#import "Source/santasyncservice/SNTSyncConfigBundle.h"
#import "Source/santasyncservice/SNTSyncLogging.h"
#import "Source/santasyncservice/SNTSyncState.h"

#include <google/protobuf/arena.h>
#include "sync/v1.pb.h"
namespace pbv1 = ::santa::sync::v1;

using santa::NSStringToUTF8String;
using santa::StringToNSString;

SNTRuleCleanup SyncTypeToRuleCleanup(SNTSyncType syncType) {
  switch (syncType) {
    case SNTSyncTypeNormal: return SNTRuleCleanupNone;
    case SNTSyncTypeClean: return SNTRuleCleanupNonTransitive;
    case SNTSyncTypeCleanAll: return SNTRuleCleanupAll;
    default: return SNTRuleCleanupNone;
  }
}

@implementation SNTSyncRuleDownload

- (NSURL *)stageURL {
  NSString *stageName = [@"ruledownload" stringByAppendingFormat:@"/%@", self.syncState.machineID];
  return [NSURL URLWithString:stageName relativeToURL:self.syncState.syncBaseURL];
}

- (BOOL)sync {
  // Grab the new rules from server
  NSArray<SNTRule *> *newRules = [self downloadNewRulesFromServer];
  if (!newRules) return NO;         // encountered a problem with the download
  if (!newRules.count) return YES;  // successfully completed request, but no new rules

  // Tell santad to add the new rules to the database.
  // Wait until finished or until 5 minutes pass.
  dispatch_semaphore_t sema = dispatch_semaphore_create(0);
  __block NSError *error;
  [[self.daemonConn remoteObjectProxy]
      databaseRuleAddRules:newRules
               ruleCleanup:SyncTypeToRuleCleanup(self.syncState.syncType)
                    source:SNTRuleAddSourceSyncService
                     reply:^(NSError *e) {
                       error = e;
                       dispatch_semaphore_signal(sema);
                     }];
  if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 300 * NSEC_PER_SEC))) {
    SLOGE(@"Failed to add rule(s) to database: timeout sending rules to daemon");
    return NO;
  }

  if (error) {
    SLOGE(@"Failed to add rule(s) to database: %@", error.localizedDescription);
    SLOGD(@"Failure reason: %@", error.localizedFailureReason);
    return NO;
  }

  // Tell santad to record a successful rules sync and wait for it to finish.
  sema = dispatch_semaphore_create(0);
  [[self.daemonConn remoteObjectProxy] updateSyncSettings:RuleSyncConfigBundle()
                                                    reply:^{
                                                      dispatch_semaphore_signal(sema);
                                                    }];
  dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));

  SLOGI(@"Processed %lu rules", newRules.count);

  // Send out push notifications about any newly allowed binaries
  // that had been previously blocked by santad.
  [self announceUnblockingRules:newRules];
  return YES;
}

// Downloads new rules from server and converts them into SNTRule.
// Returns an array of all converted rules, or nil if there was a server problem.
// Note that rules from the server are filtered.
- (NSArray<SNTRule *> *)downloadNewRulesFromServer {
  google::protobuf::Arena arena;

  self.syncState.rulesReceived = 0;
  NSMutableArray<SNTRule *> *newRules = [NSMutableArray array];
  std::string cursor;

  do {
    @autoreleasepool {
      auto req = google::protobuf::Arena::Create<::pbv1::RuleDownloadRequest>(&arena);
      req->set_machine_id(NSStringToUTF8String(self.syncState.machineID));

      if (!cursor.empty()) {
        req->set_cursor(cursor);
      }
      ::pbv1::RuleDownloadResponse response;
      NSError *err = [self performRequest:[self requestWithMessage:req]
                              intoMessage:&response
                                  timeout:30];

      if (err) {
        SLOGE(@"Error downloading rules: %@", err);
        return nil;
      }

      for (const ::pbv1::Rule &rule : response.rules()) {
        SNTRule *r = [self ruleFromProtoRule:rule];
        if (!r) {
          SLOGD(@"Ignoring bad rule: %s", rule.Utf8DebugString().c_str());
          continue;
        }
        [self processBundleNotificationsForRule:r fromProtoRule:&rule];
        [newRules addObject:r];
      }

      cursor = response.cursor();
      SLOGI(@"Received %lu rules", (unsigned long)response.rules_size());
      self.syncState.rulesReceived += response.rules_size();
    }
  } while (!cursor.empty());

  self.syncState.rulesProcessed = newRules.count;

  return newRules;
}

- (SNTRule *)ruleFromProtoRule:(::pbv1::Rule)rule {
  NSString *identifier = StringToNSString(rule.identifier());
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  if (!identifier.length) identifier = StringToNSString(rule.deprecated_sha256());
#pragma clang diagnostic pop
  if (!identifier.length) {
    LOGE(@"Failed to process rule with no identifier");
    return nil;
  }

  SNTRuleState state;
  switch (rule.policy()) {
    case ::pbv1::ALLOWLIST: state = SNTRuleStateAllow; break;
    case ::pbv1::ALLOWLIST_COMPILER: state = SNTRuleStateAllowCompiler; break;
    case ::pbv1::BLOCKLIST: state = SNTRuleStateBlock; break;
    case ::pbv1::SILENT_BLOCKLIST: state = SNTRuleStateSilentBlock; break;
    case ::pbv1::REMOVE: state = SNTRuleStateRemove; break;
    case ::pbv1::CEL: state = SNTRuleStateCEL; break;
    default: LOGE(@"Failed to process rule with unknown policy: %d", rule.policy()); return nil;
  }

  SNTRuleType type;
  switch (rule.rule_type()) {
    case ::pbv1::BINARY: type = SNTRuleTypeBinary; break;
    case ::pbv1::CERTIFICATE: type = SNTRuleTypeCertificate; break;
    case ::pbv1::TEAMID: type = SNTRuleTypeTeamID; break;
    case ::pbv1::SIGNINGID: type = SNTRuleTypeSigningID; break;
    case ::pbv1::CDHASH: type = SNTRuleTypeCDHash; break;
    default: LOGE(@"Failed to process rule with unknown type: %d", rule.rule_type()); return nil;
  }

  const std::string &custom_msg = rule.custom_msg();
  NSString *customMsg = (!custom_msg.empty()) ? StringToNSString(custom_msg) : nil;

  const std::string &custom_url = rule.custom_url();
  NSString *customURL = (!custom_url.empty()) ? StringToNSString(custom_url) : nil;

  const std::string &cel_expr = rule.cel_expr();
  NSString *celExpr = (!cel_expr.empty()) ? StringToNSString(cel_expr) : nil;

  return [[SNTRule alloc] initWithIdentifier:identifier
                                       state:state
                                        type:type
                                   customMsg:customMsg
                                   customURL:customURL
                                     celExpr:celExpr];
}

// Send out push notifications for allowed bundles/binaries whose rule download was preceded by
// an associated announcing FCM message.
- (void)announceUnblockingRules:(NSArray<SNTRule *> *)newRules {
  NSMutableArray *processed = [NSMutableArray array];
  SNTPushNotificationsTracker *tracker = [SNTPushNotificationsTracker tracker];
  [[tracker all]
      enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSDictionary *notifier, BOOL *stop) {
        // Each notifier object is a dictionary with name and count keys. If the count has been
        // decremented to zero, then this means that we have downloaded all of the rules associated
        // with this SHA256 hash (which might be a bundle hash or a binary hash), in which case we
        // are OK to show a notification that the named bundle/binary can be run.
        NSNumber *remaining = notifier[kFileBundleBinaryCount];
        if (remaining && [remaining intValue] == 0) {
          [processed addObject:key];
          NSString *app = notifier[kFileName];
          [[self.daemonConn remoteObjectProxy] postRuleSyncNotificationForApplication:app
                                                                                reply:^{
                                                                                }];
        }
      }];

  [tracker removeNotificationsForHashes:processed];
}

- (void)processBundleNotificationsForRule:(SNTRule *)rule
                            fromProtoRule:(const ::pbv1::Rule *)protoRule {
  // Display a system notification if notification_app_name is set and this is not a clean sync.
  NSString *appName = StringToNSString(protoRule->notification_app_name());
  if (appName.length) {
    // If notification_app_name is set but this is a clean sync, return early. We don't want to
    // spam users with notifications for many apps that might be included in a clean sync, and
    // we don't want to fallback to the deprecated behavior. Also ignore app name if the rule state
    // is remove.
    if (self.syncState.syncType != SNTSyncTypeNormal || rule.state == SNTRuleStateRemove) return;
    [[SNTPushNotificationsTracker tracker]
        addNotification:[@{kFileName : appName, kFileBundleBinaryCount : @(0)} mutableCopy]
                forHash:rule.identifier];
    return;
  }

  // If notification_app_name is not set, continue processing with deprecated behavior.
  [self processDeprecatedBundleNotificationsForRule:rule fromProtoRule:protoRule];
}

- (void)processDeprecatedBundleNotificationsForRule:(SNTRule *)rule
                                      fromProtoRule:(const ::pbv1::Rule *)protoRule {
  // Check rule for extra notification related info.
  if (rule.state == SNTRuleStateAllow || rule.state == SNTRuleStateAllowCompiler) {
    // primaryHash is the bundle hash if there was a bundle hash included in the rule, otherwise
    // it is simply the binary hash.
    NSString *primaryHash = StringToNSString(protoRule->file_bundle_hash());
    if (primaryHash.length != 64) {
      primaryHash = rule.identifier;
    }

    // As we read in rules, we update the "remaining count" information. This count represents the
    // number of rules associated with the primary hash that still need to be downloaded and added.
    [[SNTPushNotificationsTracker tracker]
        decrementPendingRulesForHash:primaryHash
                      totalRuleCount:@(protoRule->file_bundle_binary_count())];
  }
}

@end
