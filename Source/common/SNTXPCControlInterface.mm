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

#import "Source/common/SNTXPCControlInterface.h"

#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"

NSString *const kBundleID = @"com.northpolesec.santa.daemon";

@implementation SNTXPCControlInterface

+ (NSString *)serviceID {
#ifdef SANTAADHOC
  // The mach service for an adhoc signed ES sysx uses the "endpoint-security" prefix instead of
  // the teamid. In Santa's case it will be endpoint-security.com.northpolesec.santa.daemon.xpc.
  return [NSString stringWithFormat:@"endpoint-security.%@.xpc", kBundleID];
#else
  MOLCodesignChecker *cs = [[MOLCodesignChecker alloc] initWithSelf];
  // "teamid.com.northpolesec.santa.daemon.xpc"
  return [NSString stringWithFormat:@"%@.%@.xpc", cs.teamID, kBundleID];
#endif
}

+ (NSString *)systemExtensionID {
  return kBundleID;
}

+ (void)initializeControlInterface:(NSXPCInterface *)r {
  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class],
                                      [SNTStoredExecutionEvent class], nil]
        forSelector:@selector(databaseEventsPending:)
      argumentIndex:0
            ofReply:YES];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTRule class], nil]
        forSelector:@selector(databaseRuleAddRules:ruleCleanup:source:reply:)
      argumentIndex:0
            ofReply:NO];

  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTRule class], nil]
        forSelector:@selector(retrieveAllRules:)
      argumentIndex:0
            ofReply:YES];
}

+ (NSXPCInterface *)controlInterface {
  NSXPCInterface *r = [NSXPCInterface interfaceWithProtocol:@protocol(SNTDaemonControlXPC)];
  [self initializeControlInterface:r];

  return r;
}

+ (MOLXPCConnection *)configuredConnection {
  MOLXPCConnection *c = [[MOLXPCConnection alloc] initClientWithName:[self serviceID]
                                                          privileged:YES];
  c.remoteInterface = [self controlInterface];
  return c;
}

@end
