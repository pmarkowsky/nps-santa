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

#import "Source/common/SNTSyncConstants.h"

NSString *const kDefaultXSRFTokenHeader = @"X-XSRF-TOKEN";
NSString *const kXSRFTokenHeader = @"X-XSRF-TOKEN-HEADER";

NSString *const kSerialNumber = @"serial_num";
NSString *const kHostname = @"hostname";
NSString *const kSantaVer = @"santa_version";
NSString *const kOSVer = @"os_version";
NSString *const kOSBuild = @"os_build";
NSString *const kModelIdentifier = @"model_identifier";
NSString *const kPrimaryUser = @"primary_user";
NSString *const kRequestCleanSync = @"request_clean_sync";
NSString *const kBatchSize = @"batch_size";
NSString *const kUploadLogsURL = @"upload_logs_url";
NSString *const kClientMode = @"client_mode";
NSString *const kBlockUSBMount = @"block_usb_mount";
NSString *const kRemountUSBMode = @"remount_usb_mode";
NSString *const kClientModeMonitor = @"MONITOR";
NSString *const kClientModeLockdown = @"LOCKDOWN";
NSString *const kCleanSyncDeprecated = @"clean_sync";
NSString *const kSyncType = @"sync_type";
NSString *const kAllowedPathRegex = @"allowed_path_regex";
NSString *const kAllowedPathRegexDeprecated = @"whitelist_regex";
NSString *const kBlockedPathRegex = @"blocked_path_regex";
NSString *const kBlockedPathRegexDeprecated = @"blacklist_regex";
NSString *const kBinaryRuleCount = @"binary_rule_count";
NSString *const kCertificateRuleCount = @"certificate_rule_count";
NSString *const kCompilerRuleCount = @"compiler_rule_count";
NSString *const kTransitiveRuleCount = @"transitive_rule_count";
NSString *const kTeamIDRuleCount = @"teamid_rule_count";
NSString *const kSigningIDRuleCount = @"signingid_rule_count";
NSString *const kCDHashRuleCount = @"cdhash_rule_count";
NSString *const kFullSyncInterval = @"full_sync_interval";
NSString *const kFCMToken = @"fcm_token";
NSString *const kFCMFullSyncInterval = @"fcm_full_sync_interval";
NSString *const kFCMGlobalRuleSyncDeadline = @"fcm_global_rule_sync_deadline";
NSString *const kOverrideFileAccessAction = @"override_file_access_action";

NSString *const kEnableBundles = @"enable_bundles";
NSString *const kEnableBundlesDeprecated = @"bundles_enabled";
NSString *const kEnableTransitiveRules = @"enable_transitive_rules";
NSString *const kEnableTransitiveRulesDeprecated = @"enabled_transitive_whitelisting";
NSString *const kEnableTransitiveRulesSuperDeprecated = @"transitive_whitelisting_enabled";
NSString *const kEnableAllEventUpload = @"enable_all_event_upload";
NSString *const kDisableUnknownEventUpload = @"disable_unknown_event_upload";

NSString *const kEvents = @"events";
NSString *const kFileSHA256 = @"file_sha256";
NSString *const kFilePath = @"file_path";
NSString *const kFileName = @"file_name";
NSString *const kExecutingUser = @"executing_user";
NSString *const kExecutionTime = @"execution_time";
NSString *const kDecision = @"decision";
NSString *const kDecisionAllowUnknown = @"ALLOW_UNKNOWN";
NSString *const kDecisionAllowBinary = @"ALLOW_BINARY";
NSString *const kDecisionAllowCertificate = @"ALLOW_CERTIFICATE";
NSString *const kDecisionAllowScope = @"ALLOW_SCOPE";
NSString *const kDecisionAllowTeamID = @"ALLOW_TEAMID";
NSString *const kDecisionAllowSigningID = @"ALLOW_SIGNINGID";
NSString *const kDecisionAllowCDHash = @"ALLOW_CDHASH";
NSString *const kDecisionBlockUnknown = @"BLOCK_UNKNOWN";
NSString *const kDecisionBlockBinary = @"BLOCK_BINARY";
NSString *const kDecisionBlockCertificate = @"BLOCK_CERTIFICATE";
NSString *const kDecisionBlockScope = @"BLOCK_SCOPE";
NSString *const kDecisionBlockTeamID = @"BLOCK_TEAMID";
NSString *const kDecisionBlockSigningID = @"BLOCK_SIGNINGID";
NSString *const kDecisionBlockCDHash = @"BLOCK_CDHASH";
NSString *const kDecisionUnknown = @"UNKNOWN";
NSString *const kDecisionBundleBinary = @"BUNDLE_BINARY";
NSString *const kLoggedInUsers = @"logged_in_users";
NSString *const kCurrentSessions = @"current_sessions";
NSString *const kFileBundleID = @"file_bundle_id";
NSString *const kFileBundlePath = @"file_bundle_path";
NSString *const kFileBundleExecutableRelPath = @"file_bundle_executable_rel_path";
NSString *const kFileBundleName = @"file_bundle_name";
NSString *const kFileBundleVersion = @"file_bundle_version";
NSString *const kFileBundleShortVersionString = @"file_bundle_version_string";
NSString *const kFileBundleHash = @"file_bundle_hash";
NSString *const kFileBundleHashMilliseconds = @"file_bundle_hash_millis";
NSString *const kFileBundleBinaryCount = @"file_bundle_binary_count";
NSString *const kPID = @"pid";
NSString *const kPPID = @"ppid";
NSString *const kParentName = @"parent_name";
NSString *const kSigningChain = @"signing_chain";
NSString *const kCertSHA256 = @"sha256";
NSString *const kCertCN = @"cn";
NSString *const kCertOrg = @"org";
NSString *const kCertOU = @"ou";
NSString *const kCertValidFrom = @"valid_from";
NSString *const kCertValidUntil = @"valid_until";
NSString *const kTeamID = @"team_id";
NSString *const kSigningID = @"signing_id";
NSString *const kCDHash = @"cdhash";
NSString *const kQuarantineDataURL = @"quarantine_data_url";
NSString *const kQuarantineRefererURL = @"quarantine_referer_url";
NSString *const kQuarantineTimestamp = @"quarantine_timestamp";
NSString *const kQuarantineAgentBundleID = @"quarantine_agent_bundle_id";
NSString *const kEventUploadBundleBinaries = @"event_upload_bundle_binaries";

NSString *const kRules = @"rules";
NSString *const kRuleSHA256 = @"sha256";
NSString *const kRuleIdentifier = @"identifier";
NSString *const kRulePolicy = @"policy";
NSString *const kRulePolicyAllowlist = @"ALLOWLIST";
NSString *const kRulePolicyAllowlistLocalBinary = @"ALLOWLIST_LOCAL_BINARY";
NSString *const kRulePolicyAllowlistLocalSigningID = @"ALLOWLIST_LOCAL_SIGNINGID";
NSString *const kRulePolicyAllowlistDeprecated = @"WHITELIST";
NSString *const kRulePolicyAllowlistCompiler = @"ALLOWLIST_COMPILER";
NSString *const kRulePolicyAllowlistCompilerDeprecated = @"WHITELIST_COMPILER";
NSString *const kRulePolicyBlocklist = @"BLOCKLIST";
NSString *const kRulePolicyBlocklistDeprecated = @"BLACKLIST";
NSString *const kRulePolicySilentBlocklist = @"SILENT_BLOCKLIST";
NSString *const kRulePolicySilentBlocklistDeprecated = @"SILENT_BLACKLIST";
NSString *const kRulePolicyRemove = @"REMOVE";
NSString *const kRulePolicyCEL = @"CEL";
NSString *const kRuleType = @"rule_type";
NSString *const kRuleTypeBinary = @"BINARY";
NSString *const kRuleTypeCertificate = @"CERTIFICATE";
NSString *const kRuleTypeTeamID = @"TEAMID";
NSString *const kRuleTypeSigningID = @"SIGNINGID";
NSString *const kRuleTypeCDHash = @"CDHASH";
NSString *const kRuleCustomMsg = @"custom_msg";
NSString *const kRuleCustomURL = @"custom_url";
NSString *const kRuleComment = @"comment";
NSString *const kRuleCELExpr = @"cel_expr";
NSString *const kCursor = @"cursor";

NSString *const kBackoffInterval = @"backoff";

NSString *const kFullSync = @"full_sync";
NSString *const kRuleSync = @"rule_sync";
NSString *const kConfigSync = @"config_sync";
NSString *const kLogSync = @"log_sync";

NSString *const kPostflightRulesReceived = @"rules_received";
NSString *const kPostflightRulesProcessed = @"rules_processed";

const NSUInteger kDefaultEventBatchSize = 50;
const NSUInteger kDefaultFullSyncInterval = 600;
const NSUInteger kDefaultPushNotificationsFullSyncInterval = 14400;
const NSUInteger kDefaultPushNotificationsGlobalRuleSyncDeadline = 600;
