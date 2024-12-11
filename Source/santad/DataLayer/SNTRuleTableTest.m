/// Copyright 2015 Google Inc. All rights reserved.
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

#import <MOLCertificate/MOLCertificate.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <OCMock/OCMock.h>
#import <XCTest/XCTest.h>
#include <stdint.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SigningIDHelpers.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"

/// This test case actually tests SNTRuleTable and SNTRule
@interface SNTRuleTableTest : XCTestCase
@property SNTRuleTable *sut;
@property FMDatabaseQueue *dbq;
@property id mockConfigurator;
@end

@implementation SNTRuleTableTest

- (void)setUp {
  [super setUp];

  self.dbq = [[FMDatabaseQueue alloc] init];
  self.sut = [[SNTRuleTable alloc] initWithDatabaseQueue:self.dbq];

  self.mockConfigurator = OCMClassMock([SNTConfigurator class]);
  OCMStub([self.mockConfigurator configurator]).andReturn(self.mockConfigurator);
}

- (void)tearDown {
  [self.mockConfigurator stopMocking];
}

- (SNTRule *)_exampleTeamIDRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"ABCDEFGHIJ";
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeTeamID;
  r.customMsg = @"A teamID rule";
  return r;
}

- (SNTRule *)_exampleSigningIDRuleIsPlatform:(BOOL)isPlatformBinary {
  SNTRule *r = [[SNTRule alloc] init];
  if (isPlatformBinary) {
    r.identifier = @"platform:signingID";
  } else {
    r.identifier = @"ABCDEFGHIJ:signingID";
  }
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeSigningID;
  r.customMsg = @"A signingID rule";
  return r;
}

- (SNTRule *)_exampleCDHashRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a";
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeCDHash;
  r.customMsg = @"A cdhash rule";
  return r;
}

- (SNTRule *)_exampleBinaryRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670";
  r.state = SNTRuleStateBlock;
  r.type = SNTRuleTypeBinary;
  r.customMsg = @"A rule";
  return r;
}

- (SNTRule *)_exampleTransitiveRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"1111e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b111";
  r.state = SNTRuleStateAllowTransitive;
  r.type = SNTRuleTypeBinary;
  r.customMsg = @"Transitive rule";
  return r;
}

- (SNTRule *)_exampleCertRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258";
  r.state = SNTRuleStateAllow;
  r.type = SNTRuleTypeCertificate;
  return r;
}

- (void)testAddRulesNotClean {
  NSUInteger ruleCount = self.sut.ruleCount;
  NSUInteger binaryRuleCount = self.sut.binaryRuleCount;

  NSError *error;
  [self.sut addRules:@[ [self _exampleBinaryRule] ] ruleCleanup:SNTRuleCleanupNone error:&error];

  XCTAssertEqual(self.sut.ruleCount, ruleCount + 1);
  XCTAssertEqual(self.sut.binaryRuleCount, binaryRuleCount + 1);
  XCTAssertNil(error);
}

- (void)testAddRulesClean {
  // Add a binary rule without clean slate
  NSError *error = nil;
  XCTAssertTrue([self.sut addRules:@[ [self _exampleBinaryRule] ]
                       ruleCleanup:SNTRuleCleanupNone
                             error:&error]);
  XCTAssertNil(error);

  // Now add a cert rule with a clean slate, assert that the binary rule was removed
  error = nil;
  XCTAssertTrue(([self.sut addRules:@[ [self _exampleCertRule] ]
                        ruleCleanup:SNTRuleCleanupAll
                              error:&error]));
  XCTAssertEqual([self.sut binaryRuleCount], 0);
  XCTAssertNil(error);
}

- (void)testAddRulesCleanNonTransitive {
  // Add a multiple binary rules, including a transitive rule
  NSError *error = nil;
  XCTAssertTrue(([self.sut addRules:@[
    [self _exampleBinaryRule], [self _exampleCertRule], [self _exampleTransitiveRule]
  ]
                        ruleCleanup:SNTRuleCleanupNone
                              error:&error]));
  XCTAssertEqual([self.sut binaryRuleCount], 2);
  XCTAssertNil(error);

  // Now add a cert rule while cleaning non-transitive rules. Ensure the transitive rule remains
  error = nil;
  XCTAssertTrue(([self.sut addRules:@[ [self _exampleCertRule] ]
                        ruleCleanup:SNTRuleCleanupNonTransitive
                              error:&error]));
  XCTAssertEqual([self.sut binaryRuleCount], 1);
  XCTAssertEqual([self.sut certificateRuleCount], 1);
  XCTAssertNil(error);
}

- (void)testAddMultipleRules {
  NSUInteger ruleCount = self.sut.ruleCount;

  NSError *error;
  [self.sut
         addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule], [self _exampleBinaryRule] ]
      ruleCleanup:SNTRuleCleanupNone
            error:&error];

  XCTAssertEqual(self.sut.ruleCount, ruleCount + 2);
  XCTAssertNil(error);
}

- (void)testAddRulesEmptyArray {
  NSError *error;
  XCTAssertFalse([self.sut addRules:@[] ruleCleanup:SNTRuleCleanupAll error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorEmptyRuleArray);
}

- (void)testAddRulesNilArray {
  NSError *error;
  XCTAssertFalse([self.sut addRules:nil ruleCleanup:SNTRuleCleanupAll error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorEmptyRuleArray);
}

- (void)testAddInvalidRule {
  SNTRule *r = [[SNTRule alloc] init];
  r.identifier = @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258";
  r.type = SNTRuleTypeCertificate;

  NSError *error;
  XCTAssertFalse([self.sut addRules:@[ r ] ruleCleanup:SNTRuleCleanupNone error:&error]);
  XCTAssertEqual(error.code, SNTRuleTableErrorInvalidRule);
}

- (void)testFetchBinaryRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ]
         ruleCleanup:SNTRuleCleanupNone
               error:nil];

  SNTRule *r = [self.sut
      ruleForIdentifiers:
          (struct RuleIdentifiers){
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
          }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(r.type, SNTRuleTypeBinary);

  r = [self.sut
      ruleForIdentifiers:
          (struct RuleIdentifiers){
              .binarySHA256 = @"b6ee1c3c5a715c049d14a8457faa6b6701b8507efe908300e238e0768bd759c2",
          }];
  XCTAssertNil(r);
}

- (void)testFetchCertificateRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleCertRule] ]
         ruleCleanup:SNTRuleCleanupNone
               error:nil];

  SNTRule *r =
      [self.sut ruleForIdentifiers:
                    (struct RuleIdentifiers){
                        .certificateSHA256 =
                            @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
                    }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258");
  XCTAssertEqual(r.type, SNTRuleTypeCertificate);

  r = [self.sut ruleForIdentifiers:
                    (struct RuleIdentifiers){
                        .certificateSHA256 =
                            @"5bdab1288fc16892fef50c658db54f1e2e19cf8f71cc55f77de2b95e051e2562",
                    }];
  XCTAssertNil(r);
}

- (void)testFetchTeamIDRule {
  [self.sut addRules:@[ [self _exampleBinaryRule], [self _exampleTeamIDRule] ]
         ruleCleanup:SNTRuleCleanupNone
               error:nil];

  SNTRule *r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                                .teamID = @"ABCDEFGHIJ",
                                            }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(r.type, SNTRuleTypeTeamID);
  XCTAssertEqual([self.sut teamIDRuleCount], 1);

  r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .teamID = @"nonexistentTeamID",
                                   }];
  XCTAssertNil(r);
}

- (void)testFetchSigningIDRule {
  [self.sut addRules:@[
    [self _exampleBinaryRule], [self _exampleSigningIDRuleIsPlatform:YES],
    [self _exampleSigningIDRuleIsPlatform:NO]
  ]
         ruleCleanup:SNTRuleCleanupNone
               error:nil];

  XCTAssertEqual([self.sut signingIDRuleCount], 2);

  SNTRule *r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                                .signingID = @"ABCDEFGHIJ:signingID",
                                            }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ:signingID");
  XCTAssertEqual(r.type, SNTRuleTypeSigningID);

  r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .signingID = @"platform:signingID",
                                   }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"platform:signingID");
  XCTAssertEqual(r.type, SNTRuleTypeSigningID);

  r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .signingID = @"nonexistent",
                                   }];
  XCTAssertNil(r);
}

- (void)testFetchCDHashRule {
  [self.sut addRules:@[
    [self _exampleBinaryRule], [self _exampleTeamIDRule], [self _exampleCDHashRule]
  ]
         ruleCleanup:SNTRuleCleanupNone
               error:nil];

  XCTAssertEqual([self.sut cdhashRuleCount], 1);

  SNTRule *r =
      [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .cdhash = @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a",
                                   }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a");
  XCTAssertEqual(r.type, SNTRuleTypeCDHash);

  r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .cdhash = @"nonexistent",
                                   }];
  XCTAssertNil(r);
}

- (void)testFetchRuleOrdering {
  NSError *err;
  [self.sut addRules:@[
    [self _exampleCertRule],
    [self _exampleBinaryRule],
    [self _exampleTeamIDRule],
    [self _exampleSigningIDRuleIsPlatform:NO],
    [self _exampleCDHashRule],
  ]
         ruleCleanup:SNTRuleCleanupNone
               error:&err];
  XCTAssertNil(err);

  // This test verifies that the implicit rule ordering we've been abusing is still working.
  // See the comment in SNTRuleTable#ruleForIdentifiers:
  SNTRule *r = [self.sut
      ruleForIdentifiers:
          (struct RuleIdentifiers){
              .cdhash = @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a",
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
              .signingID = @"ABCDEFGHIJ:signingID",
              .certificateSHA256 =
                  @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
              .teamID = @"ABCDEFGHIJ",
          }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"dbe8c39801f93e05fc7bc53a02af5b4d3cfc670a");
  XCTAssertEqual(r.type, SNTRuleTypeCDHash, @"Implicit rule ordering failed");

  r = [self.sut
      ruleForIdentifiers:
          (struct RuleIdentifiers){
              .cdhash = @"unknown",
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
              .signingID = @"ABCDEFGHIJ:signingID",
              .certificateSHA256 =
                  @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
              .teamID = @"ABCDEFGHIJ",
          }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(r.type, SNTRuleTypeBinary, @"Implicit rule ordering failed");

  r = [self.sut
      ruleForIdentifiers:
          (struct RuleIdentifiers){
              .cdhash = @"unknown",
              .binarySHA256 = @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670",
              .signingID = @"ABCDEFGHIJ:signingID",
              .certificateSHA256 = @"unknown",
              .teamID = @"ABCDEFGHIJ",
          }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"b7c1e3fd640c5f211c89b02c2c6122f78ce322aa5c56eb0bb54bc422a8f8b670");
  XCTAssertEqual(r.type, SNTRuleTypeBinary, @"Implicit rule ordering failed");

  r = [self.sut ruleForIdentifiers:
                    (struct RuleIdentifiers){
                        .cdhash = @"unknown",
                        .binarySHA256 = @"unknown",
                        .signingID = @"unknown",
                        .certificateSHA256 =
                            @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258",
                        .teamID = @"ABCDEFGHIJ",
                    }];

  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier,
                        @"7ae80b9ab38af0c63a9a81765f434d9a7cd8f720eb6037ef303de39d779bc258");
  XCTAssertEqual(r.type, SNTRuleTypeCertificate, @"Implicit rule ordering failed");

  r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .cdhash = @"unknown",
                                       .binarySHA256 = @"unknown",
                                       .signingID = @"ABCDEFGHIJ:signingID",
                                       .certificateSHA256 = @"unknown",
                                       .teamID = @"ABCDEFGHIJ",
                                   }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ:signingID");
  XCTAssertEqual(r.type, SNTRuleTypeSigningID, @"Implicit rule ordering failed (SigningID)");

  r = [self.sut ruleForIdentifiers:(struct RuleIdentifiers){
                                       .cdhash = @"unknown",
                                       .binarySHA256 = @"unknown",
                                       .signingID = @"unknown",
                                       .certificateSHA256 = @"unknown",
                                       .teamID = @"ABCDEFGHIJ",
                                   }];
  XCTAssertNotNil(r);
  XCTAssertEqualObjects(r.identifier, @"ABCDEFGHIJ");
  XCTAssertEqual(r.type, SNTRuleTypeTeamID, @"Implicit rule ordering failed (TeamID)");
}

- (void)testBadDatabase {
  NSString *dbPath = [NSTemporaryDirectory() stringByAppendingString:@"sntruletabletest_baddb.db"];
  [@"some text" writeToFile:dbPath atomically:YES encoding:NSUTF8StringEncoding error:NULL];

  FMDatabaseQueue *dbq = [[FMDatabaseQueue alloc] initWithPath:dbPath];
  SNTRuleTable *sut = [[SNTRuleTable alloc] initWithDatabaseQueue:dbq];

  [sut addRules:@[ [self _exampleBinaryRule] ] ruleCleanup:SNTRuleCleanupNone error:nil];
  XCTAssertGreaterThan(sut.ruleCount, 0);

  [[NSFileManager defaultManager] removeItemAtPath:dbPath error:NULL];
}

- (void)testRetrieveAllRulesWithEmptyDatabase {
  NSArray<SNTRule *> *rules = [self.sut retrieveAllRules];
  XCTAssertEqual(rules.count, 0);
}

- (void)testRetrieveAllRulesWithMultipleRules {
  [self.sut addRules:@[
    [self _exampleCertRule],
    [self _exampleBinaryRule],
    [self _exampleTeamIDRule],
    [self _exampleSigningIDRuleIsPlatform:NO],
    [self _exampleCDHashRule],
  ]
         ruleCleanup:SNTRuleCleanupNone
               error:nil];

  NSArray<SNTRule *> *rules = [self.sut retrieveAllRules];
  XCTAssertEqual(rules.count, 5);
  XCTAssertEqualObjects(rules[0], [self _exampleCertRule]);
  XCTAssertEqualObjects(rules[1], [self _exampleBinaryRule]);
  XCTAssertEqualObjects(rules[2], [self _exampleTeamIDRule]);
  XCTAssertEqualObjects(rules[3], [self _exampleSigningIDRuleIsPlatform:NO]);
  XCTAssertEqualObjects(rules[4], [self _exampleCDHashRule]);
}

- (void)testAddedRulesShouldFlushDecisionCacheWithNewBlockRule {
  // Ensure that a brand new block rule flushes the decision cache.
  NSError *error;
  SNTRule *r = [self _exampleBinaryRule];
  [self.sut addRules:@[ r ] ruleCleanup:SNTRuleCleanupNone error:&error];
  XCTAssertNil(error);
  XCTAssertEqual(self.sut.ruleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);

  // Change the identifer so that the hash of a block rule is not found in the
  // db.
  r.identifier = @"bfff7d3f6c389ebf7a76a666c484d42ea447834901bc29141439ae7c7b96ff09";
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

// Ensure that a brand new block rule flushes the decision cache.
- (void)testAddedRulesShouldFlushDecisionCacheWithOldBlockRule {
  NSError *error;
  SNTRule *r = [self _exampleBinaryRule];
  [self.sut addRules:@[ r ] ruleCleanup:SNTRuleCleanupNone error:&error];
  XCTAssertNil(error);
  XCTAssertEqual(self.sut.ruleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
  XCTAssertEqual(NO, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

// Ensure that a larger number of blocks flushes the decision cache.
- (void)testAddedRulesShouldFlushDecisionCacheWithLargeNumberOfBlocks {
  NSError *error;
  SNTRule *r = [self _exampleBinaryRule];
  [self.sut addRules:@[ r ] ruleCleanup:SNTRuleCleanupNone error:&error];
  XCTAssertNil(error);
  XCTAssertEqual(self.sut.ruleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
  NSMutableArray<SNTRule *> *newRules = [NSMutableArray array];
  for (int i = 0; i < 1000; i++) {
    newRules[i] = r;
  }

  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:newRules]);
}

// Ensure that an allow rule that overrides a compiler rule flushes the
// decision cache.
- (void)testAddedRulesShouldFlushDecisionCacheWithCompilerRule {
  NSError *error;
  SNTRule *r = [self _exampleBinaryRule];
  r.type = SNTRuleTypeBinary;
  r.state = SNTRuleStateAllowCompiler;
  [self.sut addRules:@[ r ] ruleCleanup:SNTRuleCleanupNone error:&error];
  XCTAssertNil(error);
  XCTAssertEqual(self.sut.ruleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);
  // make the rule an allow rule
  r.state = SNTRuleStateAllow;
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

// Ensure that an Remove rule targeting an allow rule causes a flush of the cache.
- (void)testAddedRulesShouldFlushDecisionCacheWithRemoveRule {
  NSError *error;
  SNTRule *r = [self _exampleBinaryRule];
  r.type = SNTRuleTypeBinary;
  r.state = SNTRuleStateAllow;
  [self.sut addRules:@[ r ] ruleCleanup:SNTRuleCleanupNone error:&error];
  XCTAssertNil(error);
  XCTAssertEqual(self.sut.ruleCount, 1);
  XCTAssertEqual(self.sut.binaryRuleCount, 1);

  r.state = SNTRuleStateRemove;
  XCTAssertEqual(YES, [self.sut addedRulesShouldFlushDecisionCache:@[ r ]]);
}

- (void)testCriticalBinariesProduceFullSigningInformation {
  // Get the hash of the critical binary
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/usr/libexec/trustd"];
  MOLCodesignChecker *csInfo = [fi codesignCheckerWithError:nil];

  SNTCachedDecision *cd = self.sut.criticalSystemBinaries[fi.SHA256];

  XCTAssertEqualObjects(fi.SHA256, cd.sha256, @"hashes should match");
  XCTAssertEqualObjects(csInfo.leafCertificate.SHA256, cd.certSHA256, @"cert hashes should match");
  XCTAssertEqualObjects(csInfo.cdhash, cd.cdhash, @"cdhashes should match");
  XCTAssertEqualObjects(csInfo.certificates, cd.certChain, @"cert chains should match");
  NSString *signingID = FormatSigningID(csInfo);
  NSString *teamID = [signingID componentsSeparatedByString:@":"][0];
  XCTAssertEqualObjects(signingID, cd.signingID, @"signing IDs should match");
  XCTAssertEqualObjects(teamID, cd.teamID, @"team IDs should match");
}

- (void)testCriticalBinariesHaveBothSHAandSigningIDRules {
  SNTFileInfo *fi = [[SNTFileInfo alloc] initWithPath:@"/usr/libexec/trustd"];
  MOLCodesignChecker *csInfo = [fi codesignCheckerWithError:nil];

  SNTCachedDecision *cd = self.sut.criticalSystemBinaries[fi.SHA256];

  XCTAssertEqualObjects(fi.SHA256, cd.sha256, @"hashes should match");
  XCTAssertEqual(SNTEventStateAllowBinary, cd.decision, @"decision should be allow by binary");
  XCTAssertEqualObjects(csInfo.leafCertificate.SHA256, cd.certSHA256, @"cert hashes should match");
  XCTAssertEqualObjects(csInfo.cdhash, cd.cdhash, @"cdhashes should match");
  XCTAssertEqualObjects(csInfo.certificates, cd.certChain, @"cert chains should match");
  NSString *signingID = FormatSigningID(csInfo);
  NSString *teamID = [signingID componentsSeparatedByString:@":"][0];
  XCTAssertEqualObjects(signingID, cd.signingID, @"signing IDs should match");
  XCTAssertEqualObjects(teamID, cd.teamID, @"team IDs should match");

  SNTCachedDecision *cd2 = self.sut.criticalSystemBinaries[signingID];
  XCTAssertEqual(SNTEventStateAllowSigningID, cd2.decision,
                 @"decision should be allow by signing ID");
  XCTAssertEqualObjects(cd.sha256, cd2.sha256, @"hashes should match");
  XCTAssertEqualObjects(cd.certSHA256, cd2.certSHA256, @"cert hashes should match");
  XCTAssertEqualObjects(cd.cdhash, cd2.cdhash, @"cdhashes should match");
  XCTAssertEqualObjects(cd.certChain, cd2.certChain, @"cert chains should match");
  XCTAssertEqualObjects(cd.signingID, cd2.signingID, @"signing IDs should match");
  XCTAssertEqualObjects(cd.teamID, cd2.teamID, @"team IDs should match");
}

// This test ensures that we bump the constant on updates to the rule table
// schema.
- (void)testConstantVersionIsUpdated {
  XCTAssertEqual([self.sut currentSupportedVersion], [self.sut currentVersion],
                 @"initialized database should update to the maximum supported version");
}

@end
