/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import <Foundation/Foundation.h>

#import "Source/common/MOLCertificate.h"
#import "Source/common/SNTCommonEnums.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SantaVnode.h"

@class SNTRule;
@class SNTStoredExecutionEvent;
@class MOLXPCConnection;

struct RuleCounts {
  int64_t binary;
  int64_t certificate;
  int64_t compiler;
  int64_t transitive;
  int64_t teamID;
  int64_t signingID;
  int64_t cdhash;
};

///
///  Protocol implemented by santad and utilized by santactl (unprivileged operations)
///
@protocol SNTUnprivilegedDaemonControlXPC

///
///  Cache Ops
///
- (void)cacheCounts:(void (^)(uint64_t rootCache, uint64_t nonRootCache))reply;
- (void)checkCacheForVnodeID:(SantaVnode)vnodeID withReply:(void (^)(SNTAction))reply;

///
///  Database ops
///
- (void)databaseRuleCounts:(void (^)(struct RuleCounts ruleCounts))reply;
- (void)databaseEventCount:(void (^)(int64_t count))reply;
- (void)staticRuleCount:(void (^)(int64_t count))reply;
- (void)databaseRulesHash:(void (^)(NSString *hash))reply;
- (void)databaseRuleForIdentifiers:(SNTRuleIdentifiers *)identifiers
                             reply:(void (^)(SNTRule *))reply;

///
///  Config ops
///
- (void)watchdogInfo:(void (^)(uint64_t, uint64_t, double, double))reply;
- (void)watchItemsState:(void (^)(BOOL, uint64_t, NSString *, NSString *, NSTimeInterval))reply;
- (void)clientMode:(void (^)(SNTClientMode))reply;
- (void)fullSyncLastSuccess:(void (^)(NSDate *))reply;
- (void)ruleSyncLastSuccess:(void (^)(NSDate *))reply;
- (void)syncTypeRequired:(void (^)(SNTSyncType))reply;
- (void)enableBundles:(void (^)(BOOL))reply;
- (void)enableTransitiveRules:(void (^)(BOOL))reply;
- (void)blockUSBMount:(void (^)(BOOL))reply;
- (void)remountUSBMode:(void (^)(NSArray<NSString *> *))reply;

///
/// Metrics ops
///
- (void)metrics:(void (^)(NSDictionary *))reply;

///
///  GUI Ops
///
- (void)setNotificationListener:(NSXPCListenerEndpoint *)listener;

///
///  Syncd Ops
///
- (void)pushNotificationStatus:(void (^)(SNTPushNotificationStatus))reply;

///
///  Bundle Ops
///
- (void)syncBundleEvent:(SNTStoredExecutionEvent *)event
          relatedEvents:(NSArray<SNTStoredExecutionEvent *> *)events;

///
///  Telemetry Ops
///
- (void)exportTelemetryWithReply:(void (^)(BOOL))reply;

@end

@interface SNTXPCUnprivilegedControlInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTUnprivilegedDaemonControlXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning
///
+ (NSXPCInterface *)controlInterface;

///
///  Internal method used to initialize the control interface
///
+ (void)initializeControlInterface:(NSXPCInterface *)r;

@end
