/// Copyright 2017 Google Inc. All rights reserved.
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

#import "Source/common/MOLXPCConnection.h"

@class SNTStoredExecutionEvent;

///  A block that takes the calculated bundle hash, associated events and hashing time in ms.
typedef void (^SNTBundleHashBlock)(NSString *, NSArray<SNTStoredExecutionEvent *> *, NSNumber *);

///
///  Protocol implemented by the client of of SNTBundleServiceXPC. A listener of this type is passed
///  to `-[SNTBundleServiceXPC hashBundleBinariesForEvent:listener:reply:]`. SNTBundleServiceXPC
///  will then message the listener with hashing progress.
///
@protocol SNTBundleServiceProgressXPC
- (void)updateCountsForEvent:(SNTStoredExecutionEvent *)event
                 binaryCount:(uint64_t)binaryCount
                   fileCount:(uint64_t)fileCount
                 hashedCount:(uint64_t)hashedCount;
@end

///  Protocol implemented by santabundleservice and utilized by SantaGUI for bundle hashing
@protocol SNTBundleServiceXPC

///
///  Hash a bundle for an event. The SNTBundleHashBlock will be called with nil parameters if a
///  failure or cancellation occurs.
///
///  @param event The event that includes the fileBundlePath to be hashed. This method will
///      attempt to to find and use the ancestor bundle as a starting point.
///  @param listener A listener to connect back to the caller.
///  @param reply A SNTBundleHashBlock to be executed upon completion or cancellation.
///
///  @note If there is a current NSProgress when called this method will report back its progress.
///
- (void)hashBundleBinariesForEvent:(SNTStoredExecutionEvent *)event
                          listener:(NSXPCListenerEndpoint *)listener
                             reply:(SNTBundleHashBlock)reply;

@end

@interface SNTXPCBundleServiceInterface : NSObject

///
///  Returns an initialized NSXPCInterface for the SNTBundleServiceXPC protocol.
///  Ensures any methods that accept custom classes as arguments are set-up before returning.
///
+ (NSXPCInterface *)bundleServiceInterface;

///
///  Returns the MachService ID for this service.
///
+ (NSString *)serviceID;

///
///  Retrieve a pre-configured MOLXPCConnection for communicating with santabundleservice.
///  Connections just needs any handlers set and then can be resumed and used.
///
+ (MOLXPCConnection *)configuredConnection;

@end
