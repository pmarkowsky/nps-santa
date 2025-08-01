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

#import "Source/common/SNTXPCUnprivilegedControlInterface.h"

#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTStoredEvent.h"
#import "Source/common/SNTStoredExecutionEvent.h"

@implementation SNTXPCUnprivilegedControlInterface

+ (void)initializeControlInterface:(NSXPCInterface *)r {
  [r setClasses:[NSSet setWithObjects:[NSArray class], [SNTStoredEvent class],
                                      [SNTStoredExecutionEvent class], nil]
        forSelector:@selector(syncBundleEvent:relatedEvents:)
      argumentIndex:1
            ofReply:NO];
}

+ (NSXPCInterface *)controlInterface {
  NSXPCInterface *r =
      [NSXPCInterface interfaceWithProtocol:@protocol(SNTUnprivilegedDaemonControlXPC)];
  [self initializeControlInterface:r];

  return r;
}

@end
