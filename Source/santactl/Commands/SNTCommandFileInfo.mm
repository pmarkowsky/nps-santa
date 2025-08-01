/// Copyright 2015-2022 Google Inc. All rights reserved.
/// Copyright 2025 North Pole Security, Inc.
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

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>

#import "Source/common/CertificateHelpers.h"
#import "Source/common/MOLCertificate.h"
#import "Source/common/MOLCodesignChecker.h"
#import "Source/common/MOLXPCConnection.h"
#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/SNTRuleIdentifiers.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#import "Source/common/SNTXPCBundleServiceInterface.h"
#import "Source/common/SNTXPCControlInterface.h"
#import "Source/common/SigningIDHelpers.h"
#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

// file info keys
static NSString *const kPath = @"Path";
static NSString *const kBundleName = @"Bundle Name";
static NSString *const kBundleVersion = @"Bundle Version";
static NSString *const kBundleVersionStr = @"Bundle Version Str";
static NSString *const kDownloadReferrerURL = @"Download Referrer URL";
static NSString *const kDownloadURL = @"Download URL";
static NSString *const kDownloadTimestamp = @"Download Timestamp";
static NSString *const kDownloadAgent = @"Download Agent";
static NSString *const kType = @"Type";
static NSString *const kPageZero = @"Page Zero";
static NSString *const kCodeSigned = @"Code-signed";
static NSString *const kRule = @"Rule";
static NSString *const kSigningChain = @"Signing Chain";
static NSString *const kUniversalSigningChain = @"Universal Signing Chain";
static NSString *const kTeamID = @"Team ID";
static NSString *const kSigningID = @"Signing ID";
static NSString *const kCDHash = @"CDHash";
static NSString *const kEntitlements = @"Entitlements";
static NSString *const kSecureSigningTime = @"Secure Signing Time";
static NSString *const kSigningTime = @"Signing Time";

// signing chain keys
static NSString *const kCommonName = @"Common Name";
static NSString *const kOrganization = @"Organization";
static NSString *const kOrganizationalUnit = @"Organizational Unit";
static NSString *const kValidFrom = @"Valid From";
static NSString *const kValidUntil = @"Valid Until";

// shared file info & signing chain keys
static NSString *const kSHA256 = @"SHA-256";
static NSString *const kSHA1 = @"SHA-1";

// bundle info keys
static NSString *const kBundleInfo = @"Bundle Info";
static NSString *const kBundlePath = @"Main Bundle Path";
static NSString *const kBundleID = @"Main Bundle ID";
static NSString *const kBundleHash = @"Bundle Hash";
static NSString *const kBundleHashes = @"Bundle Hashes";

// Message displayed when daemon communication fails
static NSString *const kCommunicationErrorMsg = @"Could not communicate with daemon";

// Used by longHelpText to display a list of valid keys passed in as an array.
NSString *formattedStringForKeyArray(NSArray<NSString *> *array) {
  NSMutableString *result = [[NSMutableString alloc] init];
  for (NSString *key in array) {
    [result appendString:[NSString stringWithFormat:@"                       \"%@\"\n", key]];
  }
  return result;
}

@interface SNTCommandFileInfo : SNTCommand <SNTCommandProtocol>

// Properties set from commandline flags
@property(nonatomic) BOOL recursive;
@property(nonatomic) BOOL jsonOutput;
@property(nonatomic) BOOL bundleInfo;
@property(nonatomic) BOOL enableEntitlements;
@property(nonatomic) BOOL filterInclusive;
@property(nonatomic) NSNumber *certIndex;
@property(nonatomic, copy) NSArray<NSString *> *outputKeyList;
@property(nonatomic, copy) NSDictionary<NSString *, NSRegularExpression *> *outputFilters;

// Flag indicating when to use TTY colors
@property(readonly, nonatomic) BOOL prettyOutput;

// Flag needed when printing JSON for multiple files to get commas right
@property(nonatomic) BOOL jsonPreviousEntry;

// Flag used to avoid multiple attempts to connect to daemon
@property(nonatomic) BOOL daemonUnavailable;

// Common date formatter
@property(nonatomic) NSDateFormatter *dateFormatter;

// Maximum length of output key name, used for formatting
@property(nonatomic) NSUInteger maxKeyWidth;

// Valid key lists
@property(readonly, nonatomic) NSArray<NSString *> *fileInfoKeys;
@property(readonly, nonatomic) NSArray<NSString *> *signingChainKeys;

// Block type to be used with propertyMap values.  The first SNTCommandFileInfo parameter
// is really required only for the the rule property getter which needs access to the daemon
// connection, but downloadTimestamp & signingChain also use it for a shared date formatter.
typedef id (^SNTAttributeBlock)(SNTCommandFileInfo *, SNTFileInfo *);

// on read generated properties
@property(readonly, copy, nonatomic) SNTAttributeBlock path;
@property(readonly, copy, nonatomic) SNTAttributeBlock sha256;
@property(readonly, copy, nonatomic) SNTAttributeBlock sha1;
@property(readonly, copy, nonatomic) SNTAttributeBlock bundleName;
@property(readonly, copy, nonatomic) SNTAttributeBlock bundleVersion;
@property(readonly, copy, nonatomic) SNTAttributeBlock bundleShortVersionString;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadReferrerURL;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadURL;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadTimestamp;
@property(readonly, copy, nonatomic) SNTAttributeBlock downloadAgent;
@property(readonly, copy, nonatomic) SNTAttributeBlock teamID;
@property(readonly, copy, nonatomic) SNTAttributeBlock signingID;
@property(readonly, copy, nonatomic) SNTAttributeBlock cdhash;
@property(readonly, copy, nonatomic) SNTAttributeBlock type;
@property(readonly, copy, nonatomic) SNTAttributeBlock pageZero;
@property(readonly, copy, nonatomic) SNTAttributeBlock codeSigned;
@property(readonly, copy, nonatomic) SNTAttributeBlock rule;
@property(readonly, copy, nonatomic) SNTAttributeBlock signingChain;
@property(readonly, copy, nonatomic) SNTAttributeBlock universalSigningChain;
@property(readonly, copy, nonatomic) SNTAttributeBlock entitlements;
@property(readonly, copy, nonatomic) SNTAttributeBlock secureSigningTime;
@property(readonly, copy, nonatomic) SNTAttributeBlock signingTime;

// Mapping between property string keys and SNTAttributeBlocks
@property(nonatomic) NSDictionary<NSString *, SNTAttributeBlock> *propertyMap;

// Serial queue and dispatch group used for printing output
@property(nonatomic) dispatch_queue_t printQueue;
@property(nonatomic) dispatch_group_t printGroup;

@end

@implementation SNTCommandFileInfo

REGISTER_COMMAND_NAME(@"fileinfo")

#pragma mark SNTCommand protocol methods

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Prints information about a file.";
}

+ (NSString *)longHelpText {
  return [NSString
      stringWithFormat:
          @"The details provided will be the same ones Santa uses to make a decision\n"
          @"about executables. This includes SHA-256, SHA-1, code signing information and\n"
          @"the type of file."
          @"\n"
          @"Usage: santactl fileinfo [options] [file-paths]\n"
          @"    --recursive (-r): Search directories recursively.\n"
          @"                      Incompatible with --bundleinfo.\n"
          @"    --json: Output in JSON format.\n"
          @"    --key: Search and return this one piece of information.\n"
          @"           You may specify multiple keys by repeating this flag.\n"
          @"           Valid Keys:\n"
          @"%@\n"
          @"           Valid keys when using --cert-index:\n"
          @"%@\n"
          @"    --cert-index: Supply an integer corresponding to a certificate of the\n"
          @"                  signing chain to show info only for that certificate.\n"
          @"                     0 up to n for the leaf certificate up to the root\n"
          @"                    -1 down to -n-1 for the root certificate down to the leaf\n"
          @"                  Incompatible with --bundleinfo."
          @"\n"
          @"    --localtz: Use timestamps in the local timezone for all dates, instead of UTC.\n"
          @"    --filter: Use predicates of the form 'key=regex' to filter out which files\n"
          @"              are displayed. Valid keys are the same as for --key. Value is a\n"
          @"              case-insensitive regular expression which must match anywhere in\n"
          @"              the keyed property value for the file's info to be displayed.\n"
          @"              You may specify multiple filters by repeating this flag.\n"
          @"              If multiple filters are specified, any match will display the\n"
          @"              file.\n"
          @"    --filter-inclusive: If multiple filters are specified, they must all match\n"
          @"                        for the file to be displayed.\n"
          @"    --entitlements: If the file has entitlements, will also display them\n"
          @"    --bundleinfo: If the file is part of a bundle, will also display bundle\n"
          @"                  hash information and hashes of all bundle executables.\n"
          @"                  Incompatible with --recursive and --cert-index.\n"
          @"\n"
          @"Examples: santactl fileinfo --cert-index 1 --key SHA-256 --json /usr/bin/yes\n"
          @"          santactl fileinfo --key SHA-256 --json /usr/bin/yes\n"
          @"          santactl fileinfo /usr/bin/yes /bin/*\n"
          @"          santactl fileinfo /usr/bin -r --key Path --key SHA-256 --key Rule\n"
          @"          santactl fileinfo /usr/bin/* --filter Type=Script --filter Path=zip",
          formattedStringForKeyArray(self.fileInfoKeys),
          formattedStringForKeyArray(self.signingChainKeys)];
}

+ (NSArray<NSString *> *)fileInfoKeys {
  return @[
    kPath,
    kSHA256,
    kSHA1,
    kBundleName,
    kBundleVersion,
    kBundleVersionStr,
    kDownloadReferrerURL,
    kDownloadURL,
    kDownloadTimestamp,
    kDownloadAgent,
    kTeamID,
    kSigningID,
    kCDHash,
    kType,
    kPageZero,
    kCodeSigned,
    kSecureSigningTime,
    kSigningTime,
    kRule,
    kEntitlements,
    kSigningChain,
    kUniversalSigningChain,
  ];
}

+ (NSArray<NSString *> *)signingChainKeys {
  return
      @[ kSHA256, kSHA1, kCommonName, kOrganization, kOrganizationalUnit, kValidFrom, kValidUntil ];
}

- (instancetype)initWithDaemonConnection:(MOLXPCConnection *)daemonConn {
  self = [super initWithDaemonConnection:daemonConn];
  if (self) {
    _dateFormatter = [[NSDateFormatter alloc] init];
    _dateFormatter.dateFormat = @"yyyy/MM/dd HH:mm:ss Z";
    _dateFormatter.timeZone = [NSTimeZone timeZoneForSecondsFromGMT:0];

    _propertyMap = @{
      kPath : self.path,
      kSHA256 : self.sha256,
      kSHA1 : self.sha1,
      kBundleName : self.bundleName,
      kBundleVersion : self.bundleVersion,
      kBundleVersionStr : self.bundleVersionStr,
      kDownloadReferrerURL : self.downloadReferrerURL,
      kDownloadURL : self.downloadURL,
      kDownloadTimestamp : self.downloadTimestamp,
      kDownloadAgent : self.downloadAgent,
      kType : self.type,
      kPageZero : self.pageZero,
      kCodeSigned : self.codeSigned,
      kRule : self.rule,
      kSigningChain : self.signingChain,
      kUniversalSigningChain : self.universalSigningChain,
      kTeamID : self.teamID,
      kSigningID : self.signingID,
      kCDHash : self.cdhash,
      kEntitlements : self.entitlements,
      kSecureSigningTime : self.secureSigningTime,
      kSigningTime : self.signingTime,
    };

    _printQueue =
        dispatch_queue_create("com.northpolesec.santactl.print_queue", DISPATCH_QUEUE_SERIAL);
  }
  return self;
}

#pragma mark property getters

- (SNTAttributeBlock)path {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.path;
  };
}

- (SNTAttributeBlock)sha256 {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.SHA256;
  };
}

- (SNTAttributeBlock)sha1 {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.SHA1;
  };
}

- (SNTAttributeBlock)bundleName {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.bundleName;
  };
}

- (SNTAttributeBlock)bundleVersion {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.bundleVersion;
  };
}

- (SNTAttributeBlock)bundleVersionStr {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.bundleShortVersionString;
  };
}

- (SNTAttributeBlock)downloadReferrerURL {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.quarantineRefererURL;
  };
}

- (SNTAttributeBlock)downloadURL {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.quarantineDataURL;
  };
}

- (SNTAttributeBlock)downloadTimestamp {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return [cmd.dateFormatter stringFromDate:fileInfo.quarantineTimestamp];
  };
}

- (SNTAttributeBlock)downloadAgent {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return fileInfo.quarantineAgentBundleID;
  };
}

- (SNTAttributeBlock)type {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    NSArray *archs = [fileInfo architectures];
    if (archs.count == 0) {
      return [fileInfo humanReadableFileType];
    }
    return [NSString stringWithFormat:@"%@ (%@)", [fileInfo humanReadableFileType],
                                      [archs componentsJoinedByString:@", "]];
  };
}

- (SNTAttributeBlock)pageZero {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    if ([fileInfo isMissingPageZero]) {
      return @"__PAGEZERO segment missing/bad!";
    }
    return nil;
  };
}

- (SNTAttributeBlock)codeSigned {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    return [fileInfo codesignStatus];
  };
}

- (SNTAttributeBlock)rule {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    // If we previously were unable to connect, don't try again.
    if (cmd.daemonUnavailable) return kCommunicationErrorMsg;
    static dispatch_once_t token;
    dispatch_once(&token, ^{
      [cmd.daemonConn resume];
    });
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    NSError *err;
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:&err];
    SNTSigningStatus signingStatus = SigningStatus(csc, err);

    struct RuleIdentifiers identifiers = {
        .cdhash = csc.cdhash,
        .binarySHA256 = fileInfo.SHA256,
        .signingID = FormatSigningID(csc),
        .certificateSHA256 = err ? nil : csc.leafCertificate.SHA256,
        .teamID = csc.teamID,
    };

    __block NSString *output = @"None";
    id<SNTDaemonControlXPC> rop = [cmd.daemonConn remoteObjectProxy];
    [rop databaseRuleForIdentifiers:[[SNTRuleIdentifiers alloc]
                                        initWithRuleIdentifiers:identifiers
                                               andSigningStatus:signingStatus]
                              reply:^(SNTRule *r) {
                                if (r) output = [r stringifyWithColor:(isatty(STDOUT_FILENO) == 1)];
                                dispatch_semaphore_signal(sema);
                              }];

    if (dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
      cmd.daemonUnavailable = YES;
      return kCommunicationErrorMsg;
    }
    return output;
  };
}

- (SNTAttributeBlock)signingChain {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    if (!csc.certificates.count) return nil;
    NSMutableArray *certs = [[NSMutableArray alloc] initWithCapacity:csc.certificates.count];
    for (MOLCertificate *c in csc.certificates) {
      [certs addObject:@{
        kSHA256 : c.SHA256 ?: @"null",
        kSHA1 : c.SHA1 ?: @"null",
        kCommonName : c.commonName ?: @"null",
        kOrganization : c.orgName ?: @"null",
        kOrganizationalUnit : c.orgUnit ?: @"null",
        kValidFrom : [cmd.dateFormatter stringFromDate:c.validFrom] ?: @"null",
        kValidUntil : [cmd.dateFormatter stringFromDate:c.validUntil] ?: @"null"
      }];
    }
    return certs;
  };
}

- (SNTAttributeBlock)universalSigningChain {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    if (csc.certificates.count) return nil;
    if (!csc.universalSigningInformation) return nil;
    NSMutableArray *universal = [NSMutableArray array];
    for (NSDictionary *arch in csc.universalSigningInformation) {
      [universal addObject:@{@"arch" : arch.allKeys.firstObject}];
      int flags = [arch.allValues.firstObject[(__bridge id)kSecCodeInfoFlags] intValue];
      if (flags & kSecCodeSignatureAdhoc) {
        [universal addObject:@{@"ad-hoc" : @YES}];
        continue;
      }
      NSArray *certs = arch.allValues.firstObject[(__bridge id)kSecCodeInfoCertificates];
      NSArray *chain = [MOLCertificate certificatesFromArray:certs];
      if (!chain.count) {
        [universal addObject:@{@"unsigned" : @YES}];
        continue;
      }
      for (MOLCertificate *c in chain) {
        [universal addObject:@{
          kSHA256 : c.SHA256 ?: @"null",
          kSHA1 : c.SHA1 ?: @"null",
          kCommonName : c.commonName ?: @"null",
          kOrganization : c.orgName ?: @"null",
          kOrganizationalUnit : c.orgUnit ?: @"null",
          kValidFrom : [cmd.dateFormatter stringFromDate:c.validFrom] ?: @"null",
          kValidUntil : [cmd.dateFormatter stringFromDate:c.validUntil] ?: @"null"
        }];
      }
    }
    NSMutableSet *set = [NSMutableSet set];
    for (NSDictionary *cert in universal) {
      if (cert[@"arch"]) continue;
      [set addObject:cert];
    }
    return (set.count > 1) ? universal : nil;
  };
}

- (SNTAttributeBlock)teamID {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    return csc.teamID;
  };
}

- (SNTAttributeBlock)signingID {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];

    return FormatSigningID(csc);
  };
}

- (SNTAttributeBlock)cdhash {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    return csc.cdhash;
  };
}

- (SNTAttributeBlock)entitlements {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    return csc.entitlements ?: @{};
  };
}

- (SNTAttributeBlock)secureSigningTime {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    return [cmd.dateFormatter stringFromDate:csc.secureSigningTime] ?: @"None";
  };
}

- (SNTAttributeBlock)signingTime {
  return ^id(SNTCommandFileInfo *cmd, SNTFileInfo *fileInfo) {
    MOLCodesignChecker *csc = [fileInfo codesignCheckerWithError:NULL];
    return [cmd.dateFormatter stringFromDate:csc.signingTime] ?: @"None";
  };
}

#pragma mark -

// Entry point for the command.
- (void)runWithArguments:(NSArray *)arguments {
  if (!arguments.count) [self printErrorUsageAndExit:@"No arguments"];

  NSArray *filePaths = [self parseArguments:arguments];

  if (!self.outputKeyList || !self.outputKeyList.count) {
    if (self.certIndex) {
      self.outputKeyList = [[self class] signingChainKeys];
    } else {
      self.outputKeyList = [[self class] fileInfoKeys];
    }
  }
  // Figure out max field width from list of keys
  self.maxKeyWidth = 0;
  for (NSString *key in self.outputKeyList) {
    if (key.length > self.maxKeyWidth) self.maxKeyWidth = key.length;
  }

  // For consistency, JSON output is always returned as an array of file info objects, regardless of
  // how many file info objects are being outputted.  So both empty and singleton result sets are
  // still enclosed in brackets.
  if (self.jsonOutput) printf("[\n");

  NSFileManager *fm = [NSFileManager defaultManager];
  NSString *cwd = [fm currentDirectoryPath];

  // Dispatch group for tasks printing to stdout.
  self.printGroup = dispatch_group_create();

  [filePaths enumerateObjectsWithOptions:NSEnumerationConcurrent
                              usingBlock:^(NSString *path, NSUInteger idx, BOOL *stop) {
                                NSString *fullPath = [path stringByStandardizingPath];
                                if (path.length && [path characterAtIndex:0] != '/') {
                                  fullPath = [cwd stringByAppendingPathComponent:fullPath];
                                }
                                [self recurseAtPath:fullPath];
                              }];

  // Wait for all tasks in print queue to complete.
  dispatch_group_wait(self.printGroup, DISPATCH_TIME_FOREVER);

  if (self.jsonOutput) printf("\n]\n");  // print closing bracket of JSON output array

  exit(0);
}

// Returns YES if we should output colored text.
- (BOOL)prettyOutput {
  return isatty(STDOUT_FILENO) && !self.jsonOutput;
}

// Print out file info for the object at the given path or, if path is a directory and the
// --recursive flag is set, print out file info for all objects in directory tree.
- (void)recurseAtPath:(NSString *)path {
  NSFileManager *fm = [NSFileManager defaultManager];
  BOOL isDir = NO, isBundle = NO;
  if (![fm fileExistsAtPath:path isDirectory:&isDir]) {
    dispatch_group_async(self.printGroup, self.printQueue, ^{
      TEE_LOGE(@"File does not exist: %@", path);
    });
    return;
  }

  if (isDir) {
    NSBundle *bundle = [NSBundle bundleWithPath:path];
    isBundle = bundle && [bundle bundleIdentifier];
  }

  NSOperationQueue *operationQueue = [[NSOperationQueue alloc] init];
  operationQueue.qualityOfService = NSQualityOfServiceUserInitiated;

  // Limit the number of concurrent operations to 2. By default it is unlimited. Querying for the
  // `Rule` results in an XPC message to the santa daemon. On an M1 Max we are
  // seeing issues with dropped XPC messages when there are 64 or more in-flight messages. The
  // number of in-flight requests to the santa daemon to will be capped to
  // `maxConcurrentOperationCount`.
  //
  // Why 2? We are seeing diminishing wall-time improvements for anything over 2 Qs.
  //
  // 1 Q
  // bazel run //Source/santactl -- fileinfo --recursive --key Path --key Rule /usr/libexec/
  // 1.16s user 0.92s system 35% cpu 5.775 total

  // 2 Qs
  // bazel run //Source/santactl -- fileinfo --recursive --key Path --key Rule /usr/libexec/
  // 1.22s user 1.07s system 62% cpu 3.675 total

  // 4 Qs
  // bazel run //Source/santactl -- fileinfo --recursive --key Path --key Rule /usr/libexec/
  // 1.22s user 1.16s system 72% cpu 3.275 total

  // 8 Qs
  // bazel run //Source/santactl -- fileinfo --recursive --key Path --key Rule /usr/libexec/
  // 1.25s user 1.26s system 75% cpu 3.304 total
  operationQueue.maxConcurrentOperationCount = 2;

  if (isDir && self.recursive) {
    NSDirectoryEnumerator *dirEnum = [fm enumeratorAtPath:path];
    NSString *file = [dirEnum nextObject];
    while (file) {
      @autoreleasepool {
        NSString *filepath = [path stringByAppendingPathComponent:file];
        BOOL exists = [fm fileExistsAtPath:filepath isDirectory:&isDir];
        if (!(exists && isDir)) {  // don't display anything for a directory path
          [operationQueue addOperationWithBlock:^{
            [self printInfoForFile:filepath];
          }];
        }
        file = [dirEnum nextObject];
      }
    }
  } else if (isDir && !isBundle) {
    dispatch_group_async(self.printGroup, self.printQueue, ^{
      TEE_LOGE(@"%@ is a directory.  Use the -r flag to search recursively.", path);
    });
  } else {
    [operationQueue addOperationWithBlock:^{
      [self printInfoForFile:path];
    }];
  }

  [operationQueue waitUntilAllOperationsAreFinished];
}

- (BOOL)shouldOutputValueToDictionary:(NSMutableDictionary *)outputDict
                          valueForKey:(NSString * (^)(NSString *key))valueForKey {
  if (self.outputFilters.count == 0) return YES;

  int matches = 0;
  for (NSString *key in self.outputFilters) {
    NSString *value = valueForKey(key);
    NSRegularExpression *regex = self.outputFilters[key];
    if (![regex firstMatchInString:value options:0 range:NSMakeRange(0, value.length)]) continue;
    // If this is a value we want to show, store it in the output dictionary.
    // This does a linear search on an array, but it's a small array.
    if (outputDict && value.length && [self.outputKeyList containsObject:key]) {
      outputDict[key] = value;
    }
    ++matches;
  }

  return self.filterInclusive ? matches == self.outputFilters.count : matches > 0;
}

// Prints out the info for a single (non-directory) file.  Which info is printed is controlled
// by the keys in self.outputKeyList.
// TODO: Refactor so this method is testable.
- (void)printInfoForFile:(NSString *)path {
  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:path];
  if (!fileInfo) {
    dispatch_group_async(self.printGroup, self.printQueue, ^{
      TEE_LOGE(@"Invalid or empty file: %@", path);
    });
    return;
  }

  // First build up a dictionary containing all the information we want to print out
  NSMutableDictionary *outputDict = [NSMutableDictionary dictionary];
  if (self.certIndex) {
    int index = [self.certIndex intValue];

    // --cert-index flag implicitly means that we want only the signing chain.  So we find the
    // specified certificate in the signing chain, then print out values for all keys in cert.
    NSArray *signingChain = self.propertyMap[kSigningChain](self, fileInfo);
    if (!signingChain || !signingChain.count) return;  // check signing chain isn't empty
    if (index < 0) {
      index = (int)signingChain.count - -(index);
      if (index < 0) {
        TEE_LOGE(@"Invalid --cert-index: %d\n", index);
        return;
      }
    } else {
      if (index >= (int)signingChain.count) {
        TEE_LOGE(@"Invalid --cert-index: %d", index);
        return;
      }
    }
    NSDictionary *cert = signingChain[index];

    // Check if we should skip over this item based on outputFilters.
    BOOL shouldOutput = [self shouldOutputValueToDictionary:nil
                                                valueForKey:^NSString *(NSString *key) {
                                                  return cert[key] ?: @"";
                                                }];
    if (!shouldOutput) {
      return;
    }

    // Filter out the info we want now, in case JSON output
    for (NSString *key in self.outputKeyList) {
      outputDict[key] = cert[key];
    }
  } else {
    // Check if we should skip over this item based on outputFilters. We do this before collecting
    // output info because there's a chance that we can bail out early if a filter doesn't match.
    // However we also don't want to recompute info, so we save any values that we plan to show.
    BOOL shouldOutput =
        [self shouldOutputValueToDictionary:outputDict
                                valueForKey:^NSString *(NSString *key) {
                                  return self.propertyMap[key](self, fileInfo) ?: @"";
                                }];
    if (!shouldOutput) {
      return;
    }

    // Then fill the outputDict with the rest of the missing values.
    for (NSString *key in self.outputKeyList) {
      if (outputDict[key]) continue;  // ignore keys that we've already set due to a filter
      outputDict[key] = self.propertyMap[key](self, fileInfo);
    }

    if (self.bundleInfo) {
      SNTStoredExecutionEvent *se = [[SNTStoredExecutionEvent alloc] init];
      se.fileBundlePath = fileInfo.bundlePath;

      MOLXPCConnection *bc = [SNTXPCBundleServiceInterface configuredConnection];
      [bc resume];

      __block NSMutableDictionary *bundleInfo = [[NSMutableDictionary alloc] init];

      bundleInfo[kBundlePath] = fileInfo.bundle.bundlePath;
      bundleInfo[kBundleID] = fileInfo.bundle.bundleIdentifier;

      dispatch_semaphore_t sema = dispatch_semaphore_create(0);

      [[bc remoteObjectProxy]
          hashBundleBinariesForEvent:se
                            listener:nil
                               reply:^(NSString *hash, NSArray<SNTStoredExecutionEvent *> *events,
                                       NSNumber *time) {
                                 bundleInfo[kBundleHash] = hash;

                                 NSMutableArray *bundleHashes = [[NSMutableArray alloc] init];

                                 for (SNTStoredExecutionEvent *event in events) {
                                   [bundleHashes addObject:@{
                                     kSHA256 : event.fileSHA256,
                                     kPath : event.filePath
                                   }];
                                 }

                                 bundleInfo[kBundleHashes] = bundleHashes;
                                 dispatch_semaphore_signal(sema);
                               }];

      int secondsToWait = 30;
      if (dispatch_semaphore_wait(sema,
                                  dispatch_time(DISPATCH_TIME_NOW, secondsToWait * NSEC_PER_SEC))) {
        TEE_LOGE(@"The bundle service did not finish collecting hashes within %d seconds\n",
                 secondsToWait);
      }

      outputDict[kBundleInfo] = bundleInfo;
    }
  }

  if (!self.enableEntitlements) {
    [outputDict removeObjectForKey:kEntitlements];
  }

  // If there's nothing in the outputDict, then don't need to print anything.
  if (!outputDict.count) return;

  // Then display the information in the dictionary.  How we display it depends on
  // a) do we want JSON output?
  // b) is there only one key?
  // c) are we displaying a cert?
  BOOL singleKey =
      (self.outputKeyList.count == 1 && ![self.outputKeyList.firstObject isEqual:kSigningChain]);
  NSMutableString *output = [NSMutableString string];
  if (self.jsonOutput) {
    [output appendString:[self jsonStringForDictionary:outputDict]];
  } else {
    for (NSString *key in self.outputKeyList) {
      if (![outputDict objectForKey:key]) continue;
      if ([key isEqual:kSigningChain] || [key isEqual:kUniversalSigningChain]) {
        [output appendString:[self stringForSigningChain:outputDict[key] key:key]];
      } else if ([key isEqual:kEntitlements]) {
        [output appendString:[self stringForEntitlements:outputDict[key] key:key]];
      } else {
        if (singleKey) {
          [output appendFormat:@"%@\n", outputDict[key]];
        } else {
          [output
              appendFormat:@"%-*s: %@\n", (int)self.maxKeyWidth, key.UTF8String, outputDict[key]];
        }
      }
    }

    if (self.bundleInfo) {
      [output appendString:[self stringForBundleInfo:outputDict[kBundleInfo] key:kBundleInfo]];
    }

    if (!singleKey) [output appendString:@"\n"];
  }

  dispatch_group_async(self.printGroup, self.printQueue, ^{
    if (self.jsonOutput) {  // print commas between JSON entries
      if (self.jsonPreviousEntry) printf(",\n");
      self.jsonPreviousEntry = YES;
    }
    printf("%s", output.UTF8String);
  });
}

// Parses the arguments in order to set the property variables:
//   self.recursive from --recursive or -r
//   self.json from --json
//   self.certIndex from --cert-index argument
//   self.outputKeyList from multiple possible --key arguments
//   self.outputFilters from multiple possible --filter arguments
// and returns any non-flag args as path names in an NSArray.
- (NSArray *)parseArguments:(NSArray<NSString *> *)arguments {
  NSMutableArray *paths = [NSMutableArray array];
  NSMutableOrderedSet *keys = [NSMutableOrderedSet orderedSet];
  NSMutableDictionary *filters = [NSMutableDictionary dictionary];
  NSUInteger nargs = [arguments count];
  for (NSUInteger i = 0; i < nargs; i++) {
    NSString *arg = [arguments objectAtIndex:i];
    if ([arg caseInsensitiveCompare:@"--json"] == NSOrderedSame) {
      self.jsonOutput = YES;
    } else if ([arg caseInsensitiveCompare:@"--cert-index"] == NSOrderedSame) {
      if (self.bundleInfo) {
        [self printErrorUsageAndExit:@"\n--cert-index is incompatible with --bundleinfo"];
      }
      i += 1;  // advance to next argument and grab index
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--cert-index requires an argument"];
      }
      int index = 0;
      NSScanner *scanner = [NSScanner scannerWithString:arguments[i]];
      if (![scanner scanInt:&index] || !scanner.atEnd) {
        [self printErrorUsageAndExit:
                  [NSString stringWithFormat:@"\n\"%@\" is an invalid argument for --cert-index\n",
                                             arguments[i]]];
      }
      self.certIndex = @(index);
    } else if ([arg caseInsensitiveCompare:@"--key"] == NSOrderedSame) {
      i += 1;  // advance to next argument and grab the key
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--key requires an argument"];
      }
      [keys addObject:arguments[i]];
    } else if ([arg caseInsensitiveCompare:@"--filter"] == NSOrderedSame) {
      i += 1;  // advance to next argument and grab the filter predicate
      if (i >= nargs || [arguments[i] hasPrefix:@"--"]) {
        [self printErrorUsageAndExit:@"\n--filter requires an argument"];
      }
      // Check that filter predicate has the format "key=regex".
      NSRange range = [arguments[i] rangeOfString:@"="];
      if (range.location == NSNotFound || range.location == 0 ||
          range.location == arguments[i].length - 1) {
        [self printErrorUsageAndExit:
                  [NSString stringWithFormat:@"\n\"%@\" is an invalid filter predicate.\n"
                                             @"Filter predicates must be of the form key=regex"
                                             @" (with no spaces around \"=\")",
                                             arguments[i]]];
      }
      NSString *key = [arguments[i] substringToIndex:range.location];
      NSString *rhs = [arguments[i] substringFromIndex:range.location + 1];
      // Convert right-hand side of '=' into a regular expression object.
      NSError *error;
      NSRegularExpression *regex =
          [NSRegularExpression regularExpressionWithPattern:rhs
                                                    options:NSRegularExpressionCaseInsensitive
                                                      error:&error];
      if (error) {
        [self printErrorUsageAndExit:[NSString stringWithFormat:@"\n\"%@\" is an invalid regular "
                                                                @"expression in filter argument.\n",
                                                                rhs]];
      }
      filters[key] = regex;
    } else if ([arg caseInsensitiveCompare:@"--recursive"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"-r"] == NSOrderedSame) {
      if (self.bundleInfo) {
        [self printErrorUsageAndExit:@"\n--recursive is incompatible with --bundleinfo"];
      }
      self.recursive = YES;
    } else if ([arg caseInsensitiveCompare:@"--bundleinfo"] == NSOrderedSame ||
               [arg caseInsensitiveCompare:@"-b"] == NSOrderedSame) {
      if (self.recursive || self.certIndex) {
        [self printErrorUsageAndExit:
                  @"\n--bundleinfo is incompatible with --recursive and --cert-index"];
      }
      self.bundleInfo = YES;
    } else if ([arg caseInsensitiveCompare:@"--entitlements"] == NSOrderedSame) {
      self.enableEntitlements = YES;
    } else if ([arg caseInsensitiveCompare:@"--filter-inclusive"] == NSOrderedSame) {
      self.filterInclusive = YES;
    } else if ([arg caseInsensitiveCompare:@"--localtz"] == NSOrderedSame) {
      self.dateFormatter.timeZone = [NSTimeZone localTimeZone];
    } else {
      [paths addObject:arg];
    }
  }

  // Do some error checking before returning to make sure that specified keys are valid.
  if (self.certIndex) {
    NSArray *validKeys = [[self class] signingChainKeys];
    for (NSString *key in keys) {
      if (![validKeys containsObject:key]) {
        [self printErrorUsageAndExit:
                  [NSString
                      stringWithFormat:@"\n\"%@\" is an invalid key when using --cert-index", key]];
      }
    }
    for (NSString *key in filters) {
      if (![validKeys containsObject:key]) {
        [self printErrorUsageAndExit:
                  [NSString
                      stringWithFormat:@"\n\"%@\" is an invalid filter key when using --cert-index",
                                       key]];
      }
    }
  } else {
    NSArray *validKeys = [[self class] fileInfoKeys];
    for (NSString *key in keys) {
      if (![validKeys containsObject:key]) {
        [self
            printErrorUsageAndExit:[NSString stringWithFormat:@"\n\"%@\" is an invalid key", key]];
      }
      // If user specifically asked for entitlements, make sure collection is enabled or they'll
      // get no output even if there are entitlements.
      if ([key isEqualToString:kEntitlements]) {
        self.enableEntitlements = YES;
      }
    }
    for (NSString *key in filters) {
      if (![validKeys containsObject:key] || [key isEqualToString:kSigningChain]) {
        [self
            printErrorUsageAndExit:[NSString
                                       stringWithFormat:@"\n\"%@\" is an invalid filter key", key]];
      }
    }
  }

  if (!paths.count) [self printErrorUsageAndExit:@"\nat least one file-path is needed"];

  self.outputKeyList = [keys array];
  self.outputFilters = [filters copy];
  return paths.copy;
}

- (NSString *)jsonStringForDictionary:(NSDictionary *)dict {
  NSData *jsonData = [NSJSONSerialization dataWithJSONObject:dict
                                                     options:NSJSONWritingPrettyPrinted
                                                       error:NULL];
  return [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
}

- (NSString *)stringForSigningChain:(NSArray *)signingChain key:(NSString *)key {
  if (!signingChain) return @"";
  NSMutableString *result = [NSMutableString string];
  [result appendFormat:@"%@:\n", key];
  int i = 1;
  NSArray<NSString *> *certKeys = [[self class] signingChainKeys];
  for (NSDictionary *cert in signingChain) {
    if ([cert isEqual:[NSNull null]]) continue;
    if (cert[@"arch"]) {
      [result appendFormat:@"  %2@\n", [@"Architecture: " stringByAppendingString:cert[@"arch"]]];
      i = 1;
      continue;
    } else if (cert[@"ad-hoc"]) {
      [result appendFormat:@"    %2d. %-20@\n", i, @"ad-hoc"];
      continue;
    } else if (cert[@"unsigned"]) {
      [result appendFormat:@"    %2d. %-20@\n", i, @"unsigned"];
      continue;
    }
    if (i > 1) [result appendFormat:@"\n"];
    [result appendString:[self stringForCertificate:cert withKeys:certKeys index:i]];
    i += 1;
  }
  return result.copy;
}

- (NSString *)stringForCertificate:(NSDictionary *)cert withKeys:(NSArray *)keys index:(int)index {
  if (!cert) return @"";
  NSMutableString *result = [NSMutableString string];
  BOOL firstKey = YES;
  for (NSString *key in keys) {
    if (firstKey) {
      [result appendFormat:@"   %2d. %-20s: %@\n", index, key.UTF8String, cert[key]];
      firstKey = NO;
    } else {
      [result appendFormat:@"       %-20s: %@\n", key.UTF8String, cert[key]];
    }
  }
  return result.copy;
}

- (NSString *)stringForBundleInfo:(NSDictionary *)bundleInfo key:(NSString *)key {
  NSMutableString *result = [NSMutableString string];

  [result appendFormat:@"%@:\n", key];

  [result appendFormat:@"       %-20s: %@\n", kBundlePath.UTF8String, bundleInfo[kBundlePath]];
  [result appendFormat:@"       %-20s: %@\n", kBundleID.UTF8String, bundleInfo[kBundleID]];
  [result appendFormat:@"       %-20s: %@\n", kBundleHash.UTF8String, bundleInfo[kBundleHash]];

  int i = 0;
  for (NSDictionary *hashPath in bundleInfo[kBundleHashes]) {
    [result appendFormat:@"          %3d. %@  %@\n", ++i, hashPath[kSHA256], hashPath[kPath]];
  }

  return [result copy];
}

- (NSString *)stringForEntitlements:(NSDictionary *)entitlements key:(NSString *)key {
  if (!entitlements.count) {
    return [NSString stringWithFormat:@"%-*s: None\n", (int)self.maxKeyWidth, key.UTF8String];
  }

  NSMutableString *result = [NSMutableString string];
  [result appendFormat:@"%@:\n", key];
  __block int i = 0;
  [entitlements enumerateKeysAndObjectsUsingBlock:^(NSString *key, id obj, BOOL *stop) {
    if ([obj isKindOfClass:[NSNumber class]]) {
      NSNumber *objNumber = (NSNumber *)obj;
      BOOL val = [objNumber boolValue];
      // If the value of the entitlement is false the app is not claiming it,
      // so don't print it.
      if (!val) return;

      // If the value of the entitlement is true, don't bother printing the
      // 'value', just print the entitlement name.
      [result appendFormat:@"   %2d. %@\n", ++i, key];
      return;
    }

    // This entitlement has a more complex value, so print it as-is.
    [result appendFormat:@"   %2d. %@: %@\n", ++i, key, obj];
  }];
  return result.copy;
}

@end
