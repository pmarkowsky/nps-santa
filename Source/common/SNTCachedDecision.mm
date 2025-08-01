
/// Copyright 2015-2022 Google Inc. All rights reserved.
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

#import "Source/common/SNTCachedDecision.h"

@implementation SNTCachedDecision

- (instancetype)init {
  return [self initWithVnode:(SantaVnode){}];
}

- (instancetype)initWithEndpointSecurityFile:(const es_file_t *)esFile {
  return [self initWithVnode:SantaVnode::VnodeForFile(esFile)];
}

- (instancetype)initWithVnode:(SantaVnode)vnode {
  self = [super init];
  if (self) {
    _vnodeId = vnode;
    _cacheable = YES;
  }
  return self;
}

@end
