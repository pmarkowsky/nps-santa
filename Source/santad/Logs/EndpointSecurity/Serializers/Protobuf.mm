/// Copyright 2022 Google LLC
/// Copyright 2024 North Pole Security, Inc.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///     https://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.

#include "Source/santad/Logs/EndpointSecurity/Serializers/Protobuf.h"

#include <EndpointSecurity/EndpointSecurity.h>
#include <Kernel/kern/cs_blobs.h>
#include <bsm/libbsm.h>
#include <google/protobuf/json/json.h>
#include <mach/message.h>
#include <math.h>
#include <sys/proc_info.h>
#include <sys/wait.h>
#include <time.h>

#include <functional>
#include <optional>
#include <string_view>

#include "Source/common/AuditUtilities.h"
#include "Source/common/EncodeEntitlements.h"
#import "Source/common/SNTCachedDecision.h"
#include "Source/common/SNTCommonEnums.h"
#include "Source/common/SNTLogging.h"
#import "Source/common/SNTStoredExecutionEvent.h"
#include "Source/common/SNTSystemInfo.h"
#import "Source/common/String.h"
#include "Source/santad/EventProviders/EndpointSecurity/EndpointSecurityAPI.h"
#include "Source/santad/Logs/EndpointSecurity/Serializers/Utilities.h"
#import "Source/santad/SNTDecisionCache.h"
#include "absl/status/status.h"
#include "google/protobuf/timestamp.pb.h"

using google::protobuf::Arena;
using google::protobuf::Timestamp;
using JsonPrintOptions = google::protobuf::json::PrintOptions;
using google::protobuf::json::MessageToJsonString;

namespace pbv1 = ::santa::pb::v1;

namespace santa {

std::shared_ptr<Protobuf> Protobuf::Create(std::shared_ptr<EndpointSecurityAPI> esapi,
                                           SNTDecisionCache *decision_cache, bool json) {
  return std::make_shared<Protobuf>(esapi, std::move(decision_cache), json);
}

Protobuf::Protobuf(std::shared_ptr<EndpointSecurityAPI> esapi, SNTDecisionCache *decision_cache,
                   bool json)
    : Serializer(std::move(decision_cache)), esapi_(esapi), json_(json) {}

static inline void EncodeTimestamp(Timestamp *timestamp, struct timespec ts) {
  timestamp->set_seconds(ts.tv_sec);
  timestamp->set_nanos((int32_t)ts.tv_nsec);
}

static inline void EncodeTimestamp(Timestamp *timestamp, struct timeval tv) {
  EncodeTimestamp(timestamp, (struct timespec){tv.tv_sec, tv.tv_usec * 1000});
}

static inline void EncodeProcessID(pbv1::ProcessID *proc_id, const audit_token_t &tok) {
  proc_id->set_pid(Pid(tok));
  proc_id->set_pidversion(Pidversion(tok));
}

static inline void EncodePath(std::string *buf, const es_file_t *dir,
                              const es_string_token_t file) {
  buf->append(std::string_view(dir->path.data, dir->path.length));
  buf->append("/");
  buf->append(std::string_view(file.data, file.length));
}

static inline void EncodePath(std::string *buf, const es_file_t *es_file) {
  buf->append(std::string_view(es_file->path.data, es_file->path.length));
}

static inline void EncodeString(std::function<std::string *()> lazy_f, NSString *value) {
  if (value) {
    lazy_f()->append(NSStringToUTF8StringView(value));
  }
}

static inline void EncodeString(std::function<std::string *()> lazy_f, std::string_view value) {
  if (value.length() > 0) {
    lazy_f()->append(value);
  }
}

static inline void EncodeStringToken(std::function<std::string *()> lazy_f, es_string_token_t tok) {
  if (tok.length > 0) {
    lazy_f()->append(StringTokenToStringView(tok));
  }
}

static inline void EncodeUserInfo(::pbv1::UserInfo *pb_user_info, uid_t uid,
                                  const std::optional<std::shared_ptr<std::string>> &name) {
  pb_user_info->set_uid(uid);
  if (name.has_value()) {
    pb_user_info->set_name(*name->get());
  }
}

static inline void EncodeUserInfo(std::function<::pbv1::UserInfo *()> lazy_f,
                                  std::optional<uid_t> uid, const std::string_view &name) {
  if (uid.has_value()) {
    lazy_f()->set_uid(uid.value());
  }
  if (name.length() > 0) {
    lazy_f()->set_name(name.data(), name.length());
  }
}

static inline void EncodeUserInfo(std::function<::pbv1::UserInfo *()> lazy_f,
                                  std::optional<uid_t> uid, const es_string_token_t &name) {
  EncodeUserInfo(std::move(lazy_f), std::move(uid), StringTokenToStringView(name));
}

static inline void EncodeGroupInfo(::pbv1::GroupInfo *pb_group_info, gid_t gid,
                                   const std::optional<std::shared_ptr<std::string>> &name) {
  pb_group_info->set_gid(gid);
  if (name.has_value()) {
    pb_group_info->set_name(*name->get());
  }
}

static inline void EncodeHash(::pbv1::Hash *pb_hash, NSString *sha256) {
  if (sha256) {
    pb_hash->set_type(::pbv1::Hash::HASH_ALGO_SHA256);
    EncodeString([pb_hash] { return pb_hash->mutable_hash(); }, sha256);
  }
}

static inline void EncodeStat(::pbv1::Stat *pb_stat, const struct stat &sb,
                              const std::optional<std::shared_ptr<std::string>> &username,
                              const std::optional<std::shared_ptr<std::string>> &groupname) {
  pb_stat->set_dev(sb.st_dev);
  pb_stat->set_mode(sb.st_mode);
  pb_stat->set_nlink(sb.st_nlink);
  pb_stat->set_ino(sb.st_ino);
  EncodeUserInfo(pb_stat->mutable_user(), sb.st_uid, username);
  EncodeGroupInfo(pb_stat->mutable_group(), sb.st_gid, groupname);
  pb_stat->set_rdev(sb.st_rdev);
  EncodeTimestamp(pb_stat->mutable_access_time(), sb.st_atimespec);
  EncodeTimestamp(pb_stat->mutable_modification_time(), sb.st_mtimespec);
  EncodeTimestamp(pb_stat->mutable_change_time(), sb.st_ctimespec);
  EncodeTimestamp(pb_stat->mutable_birth_time(), sb.st_birthtimespec);
  pb_stat->set_size(sb.st_size);
  pb_stat->set_blocks(sb.st_blocks);
  pb_stat->set_blksize(sb.st_blksize);
  pb_stat->set_flags(sb.st_flags);
  pb_stat->set_gen(sb.st_gen);
}

static inline void EncodeFileInfo(::pbv1::FileInfo *pb_file, const es_file_t *es_file,
                                  const EnrichedFile &enriched_file, NSString *sha256 = nil) {
  EncodePath(pb_file->mutable_path(), es_file);
  pb_file->set_truncated(es_file->path_truncated);
  EncodeStat(pb_file->mutable_stat(), es_file->stat, enriched_file.user(), enriched_file.group());
  if (sha256) {
    EncodeHash(pb_file->mutable_hash(), sha256);
  }
}

static inline void EncodeFileInfoLight(::pbv1::FileInfoLight *pb_file, std::string_view path,
                                       bool truncated) {
  EncodeString([pb_file] { return pb_file->mutable_path(); }, path);
  pb_file->set_truncated(truncated);
}

static inline void EncodeFileInfoLight(::pbv1::FileInfoLight *pb_file, const es_file_t *es_file) {
  EncodePath(pb_file->mutable_path(), es_file);
  pb_file->set_truncated(es_file->path_truncated);
}

static inline void EncodeAnnotations(std::function<::pbv1::process_tree::Annotations *()> lazy_f,
                                     const EnrichedProcess &enriched_proc) {
  if (std::optional<pbv1::process_tree::Annotations> proc_annotations = enriched_proc.annotations();
      proc_annotations) {
    *lazy_f() = *proc_annotations;
  }
}

#if !HAVE_MACOS_15
// Note: This type alias did not exist until the macOS 15 SDK.
typedef uint8_t es_cdhash_t[20];
#endif

static inline void EncodeCodeSignature(::pbv1::CodeSignature *pb_code_sig, const es_cdhash_t cdhash,
                                       es_string_token_t sid, es_string_token_t tid) {
  pb_code_sig->set_cdhash(cdhash, sizeof(es_cdhash_t));
  EncodeStringToken([pb_code_sig] { return pb_code_sig->mutable_signing_id(); }, sid);
  EncodeStringToken([pb_code_sig] { return pb_code_sig->mutable_team_id(); }, tid);
}

static inline void EncodeProcessInfoLight(::pbv1::ProcessInfoLight *pb_proc_info,
                                          const es_process_t *es_proc,
                                          const EnrichedProcess &enriched_proc) {
  EncodeProcessID(pb_proc_info->mutable_id(), es_proc->audit_token);
  EncodeProcessID(pb_proc_info->mutable_parent_id(), es_proc->parent_audit_token);

  pb_proc_info->set_original_parent_pid(es_proc->original_ppid);
  pb_proc_info->set_group_id(es_proc->group_id);
  pb_proc_info->set_session_id(es_proc->session_id);

  EncodeUserInfo(pb_proc_info->mutable_effective_user(), EffectiveUser(es_proc->audit_token),
                 enriched_proc.effective_user());
  EncodeUserInfo(pb_proc_info->mutable_real_user(), RealUser(es_proc->audit_token),
                 enriched_proc.real_user());
  EncodeGroupInfo(pb_proc_info->mutable_effective_group(), EffectiveGroup(es_proc->audit_token),
                  enriched_proc.effective_group());
  EncodeGroupInfo(pb_proc_info->mutable_real_group(), RealGroup(es_proc->audit_token),
                  enriched_proc.real_group());

  EncodeFileInfoLight(pb_proc_info->mutable_executable(), es_proc->executable);

  EncodeAnnotations([pb_proc_info] { return pb_proc_info->mutable_annotations(); }, enriched_proc);
}

static inline void EncodeProcessInfoLight(::pbv1::ProcessInfoLight *pb_proc_info,
                                          const EnrichedEventType &msg) {
  return EncodeProcessInfoLight(pb_proc_info, msg->process, msg.instigator());
}

static inline void EncodeProcessInfo(::pbv1::ProcessInfo *pb_proc_info, uint32_t message_version,
                                     const es_process_t *es_proc,
                                     const EnrichedProcess &enriched_proc,
                                     SNTCachedDecision *cd = nil) {
  EncodeProcessID(pb_proc_info->mutable_id(), es_proc->audit_token);
  EncodeProcessID(pb_proc_info->mutable_parent_id(), es_proc->parent_audit_token);
  if (message_version >= 4) {
    EncodeProcessID(pb_proc_info->mutable_responsible_id(), es_proc->responsible_audit_token);
  }

  pb_proc_info->set_original_parent_pid(es_proc->original_ppid);
  pb_proc_info->set_group_id(es_proc->group_id);
  pb_proc_info->set_session_id(es_proc->session_id);

  EncodeUserInfo(pb_proc_info->mutable_effective_user(), EffectiveUser(es_proc->audit_token),
                 enriched_proc.effective_user());
  EncodeUserInfo(pb_proc_info->mutable_real_user(), RealUser(es_proc->audit_token),
                 enriched_proc.real_user());
  EncodeGroupInfo(pb_proc_info->mutable_effective_group(), EffectiveGroup(es_proc->audit_token),
                  enriched_proc.effective_group());
  EncodeGroupInfo(pb_proc_info->mutable_real_group(), RealGroup(es_proc->audit_token),
                  enriched_proc.real_group());

  pb_proc_info->set_is_platform_binary(es_proc->is_platform_binary);
  pb_proc_info->set_is_es_client(es_proc->is_es_client);

  if (es_proc->codesigning_flags & CS_SIGNED) {
    EncodeCodeSignature(pb_proc_info->mutable_code_signature(), es_proc->cdhash,
                        es_proc->signing_id, es_proc->team_id);
  }

  pb_proc_info->set_cs_flags(es_proc->codesigning_flags);

  EncodeFileInfo(pb_proc_info->mutable_executable(), es_proc->executable,
                 enriched_proc.executable(), cd.sha256);
  if (message_version >= 2 && es_proc->tty) {
    EncodeFileInfoLight(pb_proc_info->mutable_tty(), es_proc->tty);
  }

  if (message_version >= 3) {
    EncodeTimestamp(pb_proc_info->mutable_start_time(), es_proc->start_time);
  }

  EncodeAnnotations([pb_proc_info] { return pb_proc_info->mutable_annotations(); }, enriched_proc);
}

void EncodeExitStatus(::pbv1::Exit *pb_exit, int exitStatus) {
  if (WIFEXITED(exitStatus)) {
    pb_exit->mutable_exited()->set_exit_status(WEXITSTATUS(exitStatus));
  } else if (WIFSIGNALED(exitStatus)) {
    pb_exit->mutable_signaled()->set_signal(WTERMSIG(exitStatus));
  } else if (WIFSTOPPED(exitStatus)) {
    pb_exit->mutable_stopped()->set_signal(WSTOPSIG(exitStatus));
  } else {
    LOGE(@"Unknown exit status encountered: %d", exitStatus);
  }
}

static inline void EncodeCertificateInfo(::pbv1::CertificateInfo *pb_cert_info, NSString *cert_hash,
                                         NSString *common_name) {
  if (cert_hash) {
    EncodeHash(pb_cert_info->mutable_hash(), cert_hash);
  }

  EncodeString([pb_cert_info] { return pb_cert_info->mutable_common_name(); }, common_name);
}

::pbv1::Execution::Decision GetDecisionEnum(SNTEventState event_state) {
  if (event_state & SNTEventStateAllowCompilerBinary ||
      event_state & SNTEventStateAllowCompilerCDHash ||
      event_state & SNTEventStateAllowCompilerSigningID) {
    return ::pbv1::Execution::DECISION_ALLOW_COMPILER;
  } else if (event_state & SNTEventStateAllow) {
    return ::pbv1::Execution::DECISION_ALLOW;
  } else if (event_state & SNTEventStateBlock) {
    return ::pbv1::Execution::DECISION_DENY;
  } else {
    return ::pbv1::Execution::DECISION_UNKNOWN;
  }
}

::pbv1::Execution::Reason GetReasonEnum(SNTEventState event_state) {
  switch (event_state) {
    case SNTEventStateAllowBinary: return ::pbv1::Execution::REASON_BINARY;
    case SNTEventStateAllowLocalBinary: return ::pbv1::Execution::REASON_BINARY;
    case SNTEventStateAllowCompilerBinary: return ::pbv1::Execution::REASON_BINARY;
    case SNTEventStateAllowTransitive: return ::pbv1::Execution::REASON_TRANSITIVE;
    case SNTEventStateAllowPendingTransitive: return ::pbv1::Execution::REASON_PENDING_TRANSITIVE;
    case SNTEventStateAllowCertificate: return ::pbv1::Execution::REASON_CERT;
    case SNTEventStateAllowScope: return ::pbv1::Execution::REASON_SCOPE;
    case SNTEventStateAllowTeamID: return ::pbv1::Execution::REASON_TEAM_ID;
    case SNTEventStateAllowLocalSigningID: return ::pbv1::Execution::REASON_SIGNING_ID;
    case SNTEventStateAllowSigningID: return ::pbv1::Execution::REASON_SIGNING_ID;
    case SNTEventStateAllowCompilerSigningID: return ::pbv1::Execution::REASON_SIGNING_ID;
    case SNTEventStateAllowCDHash: return ::pbv1::Execution::REASON_CDHASH;
    case SNTEventStateAllowCompilerCDHash: return ::pbv1::Execution::REASON_CDHASH;
    case SNTEventStateAllowUnknown: return ::pbv1::Execution::REASON_UNKNOWN;
    case SNTEventStateBlockBinary: return ::pbv1::Execution::REASON_BINARY;
    case SNTEventStateBlockCertificate: return ::pbv1::Execution::REASON_CERT;
    case SNTEventStateBlockScope: return ::pbv1::Execution::REASON_SCOPE;
    case SNTEventStateBlockTeamID: return ::pbv1::Execution::REASON_TEAM_ID;
    case SNTEventStateBlockSigningID: return ::pbv1::Execution::REASON_SIGNING_ID;
    case SNTEventStateBlockCDHash: return ::pbv1::Execution::REASON_CDHASH;
    case SNTEventStateBlockLongPath: return ::pbv1::Execution::REASON_LONG_PATH;
    case SNTEventStateBlockUnknown: return ::pbv1::Execution::REASON_UNKNOWN;
    case SNTEventStateUnknown: return ::pbv1::Execution::REASON_UNKNOWN;
    case SNTEventStateAllow: return ::pbv1::Execution::REASON_UNKNOWN;
    case SNTEventStateBlock: return ::pbv1::Execution::REASON_UNKNOWN;
    case SNTEventStateBundleBinary: return ::pbv1::Execution::REASON_UNKNOWN;
  }

  return ::pbv1::Execution::REASON_UNKNOWN;
}

::pbv1::Execution::Mode GetModeEnum(SNTClientMode mode) {
  switch (mode) {
    case SNTClientModeMonitor: return ::pbv1::Execution::MODE_MONITOR;
    case SNTClientModeLockdown: return ::pbv1::Execution::MODE_LOCKDOWN;
    case SNTClientModeStandalone: return ::pbv1::Execution::MODE_STANDALONE;
    case SNTClientModeUnknown: return ::pbv1::Execution::MODE_UNKNOWN;
    default: return ::pbv1::Execution::MODE_UNKNOWN;
  }
}

::pbv1::FileDescriptor::FDType GetFileDescriptorType(uint32_t fdtype) {
  switch (fdtype) {
    case PROX_FDTYPE_ATALK: return ::pbv1::FileDescriptor::FD_TYPE_ATALK;
    case PROX_FDTYPE_VNODE: return ::pbv1::FileDescriptor::FD_TYPE_VNODE;
    case PROX_FDTYPE_SOCKET: return ::pbv1::FileDescriptor::FD_TYPE_SOCKET;
    case PROX_FDTYPE_PSHM: return ::pbv1::FileDescriptor::FD_TYPE_PSHM;
    case PROX_FDTYPE_PSEM: return ::pbv1::FileDescriptor::FD_TYPE_PSEM;
    case PROX_FDTYPE_KQUEUE: return ::pbv1::FileDescriptor::FD_TYPE_KQUEUE;
    case PROX_FDTYPE_PIPE: return ::pbv1::FileDescriptor::FD_TYPE_PIPE;
    case PROX_FDTYPE_FSEVENTS: return ::pbv1::FileDescriptor::FD_TYPE_FSEVENTS;
    case PROX_FDTYPE_NETPOLICY: return ::pbv1::FileDescriptor::FD_TYPE_NETPOLICY;
    // Note: CHANNEL and NEXUS types weren't exposed until Xcode v13 SDK.
    // Not using the macros to be able to build on older SDK versions.
    case 10 /* PROX_FDTYPE_CHANNEL */: return ::pbv1::FileDescriptor::FD_TYPE_CHANNEL;
    case 11 /* PROX_FDTYPE_NEXUS */: return ::pbv1::FileDescriptor::FD_TYPE_NEXUS;
    default: return ::pbv1::FileDescriptor::FD_TYPE_UNKNOWN;
  }
}

::pbv1::FileAccess::AccessType GetAccessType(es_event_type_t event_type) {
  switch (event_type) {
    case ES_EVENT_TYPE_AUTH_CLONE: return ::pbv1::FileAccess::ACCESS_TYPE_CLONE;
    case ES_EVENT_TYPE_AUTH_CREATE: return ::pbv1::FileAccess::ACCESS_TYPE_CREATE;
    case ES_EVENT_TYPE_AUTH_COPYFILE: return ::pbv1::FileAccess::ACCESS_TYPE_COPYFILE;
    case ES_EVENT_TYPE_AUTH_EXCHANGEDATA: return ::pbv1::FileAccess::ACCESS_TYPE_EXCHANGEDATA;
    case ES_EVENT_TYPE_AUTH_LINK: return ::pbv1::FileAccess::ACCESS_TYPE_LINK;
    case ES_EVENT_TYPE_AUTH_OPEN: return ::pbv1::FileAccess::ACCESS_TYPE_OPEN;
    case ES_EVENT_TYPE_AUTH_RENAME: return ::pbv1::FileAccess::ACCESS_TYPE_RENAME;
    case ES_EVENT_TYPE_AUTH_TRUNCATE: return ::pbv1::FileAccess::ACCESS_TYPE_TRUNCATE;
    case ES_EVENT_TYPE_AUTH_UNLINK: return ::pbv1::FileAccess::ACCESS_TYPE_UNLINK;
    default: return ::pbv1::FileAccess::ACCESS_TYPE_UNKNOWN;
  }
}

::pbv1::FileAccess::PolicyDecision GetPolicyDecision(FileAccessPolicyDecision decision) {
  switch (decision) {
    case FileAccessPolicyDecision::kDenied: return ::pbv1::FileAccess::POLICY_DECISION_DENIED;
    case FileAccessPolicyDecision::kDeniedInvalidSignature:
      return ::pbv1::FileAccess::POLICY_DECISION_DENIED_INVALID_SIGNATURE;
    case FileAccessPolicyDecision::kAllowedAuditOnly:
      return ::pbv1::FileAccess::POLICY_DECISION_ALLOWED_AUDIT_ONLY;
    default: return ::pbv1::FileAccess::POLICY_DECISION_UNKNOWN;
  }
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena, struct timespec event_time,
                                                   struct timespec processed_time) {
  ::pbv1::SantaMessage *santa_msg = Arena::Create<::pbv1::SantaMessage>(arena);

  if (EnableMachineIDDecoration()) {
    EncodeString([santa_msg] { return santa_msg->mutable_machine_id(); }, *MachineID());
  }
  EncodeTimestamp(santa_msg->mutable_event_time(), event_time);
  EncodeTimestamp(santa_msg->mutable_processed_time(), processed_time);
  EncodeString([santa_msg] { return santa_msg->mutable_boot_session_uuid(); },
               [SNTSystemInfo bootSessionUUID]);

  return santa_msg;
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena, const EnrichedEventType &msg) {
  return CreateDefaultProto(arena, msg->time, msg.enrichment_time());
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena, const Message &msg) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  return CreateDefaultProto(arena, msg->time, ts);
}

::pbv1::SantaMessage *Protobuf::CreateDefaultProto(Arena *arena) {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  return CreateDefaultProto(arena, ts, ts);
}

std::vector<uint8_t> Protobuf::FinalizeProto(::pbv1::SantaMessage *santa_msg) {
  if (this->json_) {
    // TODO: Profile this. It's probably not the most efficient way to do this.
    JsonPrintOptions options;
    options.always_print_enums_as_ints = false;
    options.always_print_fields_with_no_presence = true;
    options.preserve_proto_field_names = true;
    std::string json;

    absl::Status status = MessageToJsonString(*santa_msg, &json, options);

    if (!status.ok()) {
      LOGE(@"Failed to convert protobuf to JSON: %s", status.ToString().c_str());
    }

    std::vector<uint8_t> vec(json.begin(), json.end());
    // Add a newline to the end of the JSON row.
    vec.push_back('\n');
    return vec;
  }

  std::vector<uint8_t> vec(santa_msg->ByteSizeLong());
  santa_msg->SerializeWithCachedSizesToArray(vec.data());
  return vec;
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedClose &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Close *pb_close = santa_msg->mutable_close();

  EncodeProcessInfoLight(pb_close->mutable_instigator(), msg);
  EncodeFileInfo(pb_close->mutable_target(), msg->event.close.target, msg.target());
  pb_close->set_modified(msg->event.close.modified);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExchange &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Exchangedata *pb_exchangedata = santa_msg->mutable_exchangedata();

  EncodeProcessInfoLight(pb_exchangedata->mutable_instigator(), msg);
  EncodeFileInfo(pb_exchangedata->mutable_file1(), msg->event.exchangedata.file1, msg.file1());
  EncodeFileInfo(pb_exchangedata->mutable_file2(), msg->event.exchangedata.file2, msg.file2());

  return FinalizeProto(santa_msg);
}

void EncodeEntitlements(::pbv1::Execution *pb_exec, SNTCachedDecision *cd) {
  ::pbv1::EntitlementInfo *pb_entitlement_info = pb_exec->mutable_entitlement_info();

  EncodeEntitlementsCommon(
      cd.entitlements, cd.entitlementsFiltered,
      ^(NSUInteger count, bool is_filtered) {
        pb_entitlement_info->set_entitlements_filtered(is_filtered);
        pb_entitlement_info->mutable_entitlements()->Reserve((int)count);
      },
      ^(NSString *entitlement, NSString *value) {
        ::pbv1::Entitlement *pb_entitlement = pb_entitlement_info->add_entitlements();
        EncodeString([pb_entitlement] { return pb_entitlement->mutable_key(); }, entitlement);
        EncodeString([pb_entitlement] { return pb_entitlement->mutable_value(); }, value);
      });
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExec &msg, SNTCachedDecision *cd) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  GetDecisionEnum(cd.decision);

  ::pbv1::Execution *pb_exec = santa_msg->mutable_execution();

  EncodeProcessInfoLight(pb_exec->mutable_instigator(), msg);
  EncodeProcessInfo(pb_exec->mutable_target(), msg->version, msg->event.exec.target, msg.target(),
                    cd);

  if (msg->version >= 2 && msg.script().has_value()) {
    EncodeFileInfo(pb_exec->mutable_script(), msg->event.exec.script, msg.script().value());
  }

  if (msg->version >= 3 && msg.working_dir().has_value()) {
    EncodeFileInfo(pb_exec->mutable_working_directory(), msg->event.exec.cwd,
                   msg.working_dir().value());
  }

  uint32_t arg_count = esapi_->ExecArgCount(&msg->event.exec);
  if (arg_count > 0) {
    pb_exec->mutable_args()->Reserve(arg_count);
    for (uint32_t i = 0; i < arg_count; i++) {
      es_string_token_t tok = esapi_->ExecArg(&msg->event.exec, i);
      pb_exec->add_args(tok.data, tok.length);
    }
  }

  uint32_t env_count = esapi_->ExecEnvCount(&msg->event.exec);
  if (env_count > 0) {
    pb_exec->mutable_envs()->Reserve(env_count);
    for (uint32_t i = 0; i < env_count; i++) {
      es_string_token_t tok = esapi_->ExecEnv(&msg->event.exec, i);
      pb_exec->add_envs(tok.data, tok.length);
    }
  }

  if (msg->version >= 4) {
    int32_t max_fd = -1;
    uint32_t fd_count = esapi_->ExecFDCount(&msg->event.exec);
    if (fd_count > 0) {
      pb_exec->mutable_fds()->Reserve(fd_count);
      for (uint32_t i = 0; i < fd_count; i++) {
        const es_fd_t *fd = esapi_->ExecFD(&msg->event.exec, i);
        max_fd = std::max(max_fd, fd->fd);
        ::pbv1::FileDescriptor *pb_fd = pb_exec->add_fds();
        pb_fd->set_fd(fd->fd);
        pb_fd->set_fd_type(GetFileDescriptorType(fd->fdtype));
        if (fd->fdtype == PROX_FDTYPE_PIPE) {
          pb_fd->set_pipe_id(fd->pipe.pipe_id);
        }
      }
    }

    // If the `max_fd` seen is less than `last_fd`, we know that ES truncated
    // the set of returned file descriptors
    pb_exec->set_fd_list_truncated(max_fd < msg->event.exec.last_fd);
  }

  pb_exec->set_decision(GetDecisionEnum(cd.decision));
  pb_exec->set_reason(GetReasonEnum(cd.decision));
  pb_exec->set_mode(GetModeEnum(cd.decisionClientMode));

  if (cd.certSHA256 || cd.certCommonName) {
    EncodeCertificateInfo(pb_exec->mutable_certificate_info(), cd.certSHA256, cd.certCommonName);
  }

  EncodeString([pb_exec] { return pb_exec->mutable_explain(); }, cd.decisionExtra);
  EncodeString([pb_exec] { return pb_exec->mutable_quarantine_url(); }, cd.quarantineURL);

  NSString *orig_path = santa::OriginalPathForTranslocation(msg->event.exec.target);
  EncodeString([pb_exec] { return pb_exec->mutable_original_path(); }, orig_path);

  EncodeEntitlements(pb_exec, cd);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedExit &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Exit *pb_exit = santa_msg->mutable_exit();

  EncodeProcessInfoLight(pb_exit->mutable_instigator(), msg);
  EncodeExitStatus(pb_exit, msg->event.exit.stat);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedFork &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Fork *pb_fork = santa_msg->mutable_fork();

  EncodeProcessInfoLight(pb_fork->mutable_instigator(), msg);
  EncodeProcessInfoLight(pb_fork->mutable_child(), msg->event.fork.child, msg.child());

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLink &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Link *pb_link = santa_msg->mutable_link();
  EncodeProcessInfoLight(pb_link->mutable_instigator(), msg);
  EncodeFileInfo(pb_link->mutable_source(), msg->event.link.source, msg.source());
  EncodePath(pb_link->mutable_target(), msg->event.link.target_dir,
             msg->event.link.target_filename);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedRename &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Rename *pb_rename = santa_msg->mutable_rename();
  EncodeProcessInfoLight(pb_rename->mutable_instigator(), msg);
  EncodeFileInfo(pb_rename->mutable_source(), msg->event.rename.source, msg.source());
  if (msg->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
    EncodePath(pb_rename->mutable_target(), msg->event.rename.destination.existing_file);
    pb_rename->set_target_existed(true);
  } else {
    EncodePath(pb_rename->mutable_target(), msg->event.rename.destination.new_path.dir,
               msg->event.rename.destination.new_path.filename);
    pb_rename->set_target_existed(false);
  }

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedUnlink &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Unlink *pb_unlink = santa_msg->mutable_unlink();
  EncodeProcessInfoLight(pb_unlink->mutable_instigator(), msg);
  EncodeFileInfo(pb_unlink->mutable_target(), msg->event.unlink.target, msg.target());

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedCSInvalidated &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::CodesigningInvalidated *pb_cs_invalidated = santa_msg->mutable_codesigning_invalidated();
  EncodeProcessInfoLight(pb_cs_invalidated->mutable_instigator(), msg);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedClone &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Clone *pb_clone = santa_msg->mutable_clone();
  EncodeProcessInfoLight(pb_clone->mutable_instigator(), msg);
  EncodeFileInfo(pb_clone->mutable_source(), msg->event.clone.source, msg.source());
  EncodePath(pb_clone->mutable_target(), msg->event.clone.target_dir, msg->event.clone.target_name);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedCopyfile &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Copyfile *pb_copyfile = santa_msg->mutable_copyfile();
  EncodeProcessInfoLight(pb_copyfile->mutable_instigator(), msg);
  EncodeFileInfo(pb_copyfile->mutable_source(), msg->event.copyfile.source, msg.source());
  EncodePath(pb_copyfile->mutable_target(), msg->event.copyfile.target_dir,
             msg->event.copyfile.target_name);

  // If `target_file` is set, it is an existing file that will be overwritten
  pb_copyfile->set_target_existed(msg->event.copyfile.target_file != NULL);
  pb_copyfile->set_mode(msg->event.copyfile.mode);
  pb_copyfile->set_flags(msg->event.copyfile.flags);

  return FinalizeProto(santa_msg);
}

::pbv1::SocketAddress::Type GetSocketAddressType(es_address_type_t type) {
  switch (type) {
    case ES_ADDRESS_TYPE_NONE: return ::pbv1::SocketAddress::TYPE_NONE;
    case ES_ADDRESS_TYPE_IPV4: return ::pbv1::SocketAddress::TYPE_IPV4;
    case ES_ADDRESS_TYPE_IPV6: return ::pbv1::SocketAddress::TYPE_IPV6;
    case ES_ADDRESS_TYPE_NAMED_SOCKET: return ::pbv1::SocketAddress::TYPE_NAMED_SOCKET;
    default: return ::pbv1::SocketAddress::TYPE_UNKNOWN;
  }
}

::pbv1::OpenSSHLogin::Result GetOpenSSHLoginResultType(es_openssh_login_result_type_t type) {
  switch (type) {
    case ES_OPENSSH_LOGIN_EXCEED_MAXTRIES:
      return ::pbv1::OpenSSHLogin::RESULT_LOGIN_EXCEED_MAXTRIES;
    case ES_OPENSSH_LOGIN_ROOT_DENIED: return ::pbv1::OpenSSHLogin::RESULT_LOGIN_ROOT_DENIED;
    case ES_OPENSSH_AUTH_SUCCESS: return ::pbv1::OpenSSHLogin::RESULT_AUTH_SUCCESS;
    case ES_OPENSSH_AUTH_FAIL_NONE: return ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_NONE;
    case ES_OPENSSH_AUTH_FAIL_PASSWD: return ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_PASSWD;
    case ES_OPENSSH_AUTH_FAIL_KBDINT: return ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_KBDINT;
    case ES_OPENSSH_AUTH_FAIL_PUBKEY: return ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_PUBKEY;
    case ES_OPENSSH_AUTH_FAIL_HOSTBASED: return ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_HOSTBASED;
    case ES_OPENSSH_AUTH_FAIL_GSSAPI: return ::pbv1::OpenSSHLogin::RESULT_AUTH_FAIL_GSSAPI;
    case ES_OPENSSH_INVALID_USER: return ::pbv1::OpenSSHLogin::RESULT_INVALID_USER;
    default: return ::pbv1::OpenSSHLogin::RESULT_UNKNOWN;
  }
}

static inline void EncodeSocketAddress(::pbv1::SocketAddress *pb_socket_addr, std::string_view addr,
                                       es_address_type_t type) {
  EncodeString([pb_socket_addr] { return pb_socket_addr->mutable_address(); }, addr);
  pb_socket_addr->set_type(GetSocketAddressType(type));
}

static inline void EncodeUserInfo(std::function<::pbv1::UserInfo *()> lazy_f,
                                  const es_string_token_t &name) {
  EncodeUserInfo(lazy_f, std::nullopt, name);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLoginWindowSessionLogin &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::LoginWindowSessionLogin *pb_lw_login =
      santa_msg->mutable_login_window_session()->mutable_login();

  EncodeProcessInfoLight(pb_lw_login->mutable_instigator(), msg);
  EncodeUserInfo([pb_lw_login] { return pb_lw_login->mutable_user(); }, msg.UID(),
                 msg->event.lw_session_login->username);

  pb_lw_login->mutable_graphical_session()->set_id(
      msg->event.lw_session_login->graphical_session_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLoginWindowSessionLogout &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::LoginWindowSessionLogout *pb_lw_logout =
      santa_msg->mutable_login_window_session()->mutable_logout();

  EncodeProcessInfoLight(pb_lw_logout->mutable_instigator(), msg);
  EncodeUserInfo([pb_lw_logout] { return pb_lw_logout->mutable_user(); }, msg.UID(),
                 msg->event.lw_session_logout->username);

  pb_lw_logout->mutable_graphical_session()->set_id(
      msg->event.lw_session_logout->graphical_session_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLoginWindowSessionLock &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::LoginWindowSessionLock *pb_lw_lock =
      santa_msg->mutable_login_window_session()->mutable_lock();

  EncodeProcessInfoLight(pb_lw_lock->mutable_instigator(), msg);
  EncodeUserInfo([pb_lw_lock] { return pb_lw_lock->mutable_user(); }, msg.UID(),
                 msg->event.lw_session_lock->username);

  pb_lw_lock->mutable_graphical_session()->set_id(msg->event.lw_session_lock->graphical_session_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLoginWindowSessionUnlock &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::LoginWindowSessionUnlock *pb_lw_unlock =
      santa_msg->mutable_login_window_session()->mutable_unlock();

  EncodeProcessInfoLight(pb_lw_unlock->mutable_instigator(), msg);
  EncodeUserInfo([pb_lw_unlock] { return pb_lw_unlock->mutable_user(); }, msg.UID(),
                 msg->event.lw_session_unlock->username);

  pb_lw_unlock->mutable_graphical_session()->set_id(
      msg->event.lw_session_unlock->graphical_session_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedScreenSharingAttach &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::ScreenSharingAttach *pb_attach = santa_msg->mutable_screen_sharing()->mutable_attach();

  EncodeProcessInfoLight(pb_attach->mutable_instigator(), msg);

  pb_attach->set_success(msg->event.screensharing_attach->success);

  EncodeSocketAddress(pb_attach->mutable_source(),
                      StringTokenToStringView(msg->event.screensharing_attach->source_address),
                      msg->event.screensharing_attach->source_address_type);
  EncodeString([pb_attach] { return pb_attach->mutable_viewer(); },
               StringTokenToStringView(msg->event.screensharing_attach->viewer_appleid));
  EncodeString([pb_attach] { return pb_attach->mutable_authentication_type(); },
               StringTokenToStringView(msg->event.screensharing_attach->authentication_type));
  EncodeUserInfo([pb_attach] { return pb_attach->mutable_authentication_user(); },
                 msg->event.screensharing_attach->authentication_username);
  EncodeUserInfo([pb_attach] { return pb_attach->mutable_session_user(); },
                 msg->event.screensharing_attach->session_username);

  pb_attach->set_existing_session(msg->event.screensharing_attach->existing_session);
  pb_attach->mutable_graphical_session()->set_id(
      msg->event.screensharing_attach->graphical_session_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedScreenSharingDetach &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::ScreenSharingDetach *pb_detach = santa_msg->mutable_screen_sharing()->mutable_detach();

  EncodeProcessInfoLight(pb_detach->mutable_instigator(), msg);
  EncodeSocketAddress(pb_detach->mutable_source(),
                      StringTokenToStringView(msg->event.screensharing_detach->source_address),
                      msg->event.screensharing_detach->source_address_type);
  EncodeString([pb_detach] { return pb_detach->mutable_viewer(); },
               StringTokenToStringView(msg->event.screensharing_detach->viewer_appleid));

  pb_detach->mutable_graphical_session()->set_id(
      msg->event.screensharing_detach->graphical_session_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedOpenSSHLogin &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::OpenSSHLogin *pb_ssh_login = santa_msg->mutable_open_ssh()->mutable_login();

  EncodeProcessInfoLight(pb_ssh_login->mutable_instigator(), msg);

  pb_ssh_login->set_result(GetOpenSSHLoginResultType(msg->event.openssh_login->result_type));

  EncodeSocketAddress(pb_ssh_login->mutable_source(),
                      StringTokenToStringView(msg->event.openssh_login->source_address),
                      msg->event.openssh_login->source_address_type);
  EncodeUserInfo([pb_ssh_login] { return pb_ssh_login->mutable_user(); },
                 msg->event.openssh_login->has_uid
                     ? std::make_optional<uid_t>(msg->event.openssh_login->uid.uid)
                     : std::nullopt,
                 msg->event.openssh_login->username);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedOpenSSHLogout &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::OpenSSHLogout *pb_ssh_logout = santa_msg->mutable_open_ssh()->mutable_logout();

  EncodeProcessInfoLight(pb_ssh_logout->mutable_instigator(), msg);

  EncodeSocketAddress(pb_ssh_logout->mutable_source(),
                      StringTokenToStringView(msg->event.openssh_logout->source_address),
                      msg->event.openssh_logout->source_address_type);
  EncodeUserInfo([pb_ssh_logout] { return pb_ssh_logout->mutable_user(); },
                 msg->event.openssh_logout->uid, msg->event.openssh_logout->username);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLoginLogin &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::Login *pb_login = santa_msg->mutable_login_logout()->mutable_login();

  EncodeProcessInfoLight(pb_login->mutable_instigator(), msg);
  pb_login->set_success(msg->event.login_login->success);

  EncodeString([pb_login] { return pb_login->mutable_failure_message(); },
               StringTokenToStringView(msg->event.login_login->failure_message));
  EncodeUserInfo([pb_login] { return pb_login->mutable_user(); },
                 msg->event.login_login->has_uid
                     ? std::make_optional<uid_t>(msg->event.login_login->uid.uid)
                     : std::nullopt,
                 msg->event.login_login->username);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLoginLogout &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::Logout *pb_logout = santa_msg->mutable_login_logout()->mutable_logout();

  EncodeProcessInfoLight(pb_logout->mutable_instigator(), msg);
  EncodeUserInfo([pb_logout] { return pb_logout->mutable_user(); }, msg->event.login_logout->uid,
                 msg->event.login_logout->username);

  return FinalizeProto(santa_msg);
}

void EncodeEventProcessOrFallback(
    const EnrichedEventType &event, const es_process_t *eventProcess,
    std::optional<audit_token_t> eventProcessToken,
    const std::optional<EnrichedProcess> &enrichedEventProcess,
    std::function<::pbv1::ProcessInfoLight *()> lazy_auth_instigator_f,
    std::function<::pbv1::ProcessID *()> lazy_auth_instigator_fallback_f) {
  if (eventProcess && enrichedEventProcess.has_value()) {
    EncodeProcessInfoLight(lazy_auth_instigator_f(), eventProcess, *enrichedEventProcess);
  } else if (eventProcessToken.has_value()) {
    ::pbv1::ProcessID *pb_proc_id = lazy_auth_instigator_fallback_f();
    EncodeProcessID(pb_proc_id, *eventProcessToken);
  }
}

void EncodeEventInstigatorOrFallback(
    const EnrichedEventWithInstigator &event,
    std::function<::pbv1::ProcessInfoLight *()> lazy_auth_instigator_f,
    std::function<::pbv1::ProcessID *()> lazy_auth_instigator_fallback_f) {
  return EncodeEventProcessOrFallback(event, event.EventInstigator(), event.EventInstigatorToken(),
                                      event.EnrichedEventInstigator(), lazy_auth_instigator_f,
                                      lazy_auth_instigator_fallback_f);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedAuthenticationOD &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Authentication *pb_auth = santa_msg->mutable_authentication();
  pb_auth->set_success(msg->event.authentication->success);

  ::pbv1::AuthenticationOD *pb_od = pb_auth->mutable_authentication_od();
  es_event_authentication_od_t *es_od_event = msg->event.authentication->data.od;

  EncodeProcessInfoLight(pb_od->mutable_instigator(), msg);
  EncodeEventInstigatorOrFallback(
      msg, [pb_od] { return pb_od->mutable_trigger_process(); },
      [pb_od] { return pb_od->mutable_trigger_id(); });

  EncodeStringToken([pb_od] { return pb_od->mutable_record_type(); }, es_od_event->record_type);
  EncodeStringToken([pb_od] { return pb_od->mutable_record_name(); }, es_od_event->record_name);
  EncodeStringToken([pb_od] { return pb_od->mutable_node_name(); }, es_od_event->node_name);
  EncodeStringToken([pb_od] { return pb_od->mutable_db_path(); }, es_od_event->db_path);

  return FinalizeProto(santa_msg);
}

::pbv1::AuthenticationTouchID::Mode GetAuthenticationTouchIDMode(es_touchid_mode_t mode) {
  switch (mode) {
    case ES_TOUCHID_MODE_VERIFICATION: return ::pbv1::AuthenticationTouchID::MODE_VERIFICATION;
    case ES_TOUCHID_MODE_IDENTIFICATION: return ::pbv1::AuthenticationTouchID::MODE_IDENTIFICATION;
    default: return ::pbv1::AuthenticationTouchID::MODE_UNKNOWN;
  }
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedAuthenticationTouchID &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Authentication *pb_auth = santa_msg->mutable_authentication();
  pb_auth->set_success(msg->event.authentication->success);

  ::pbv1::AuthenticationTouchID *pb_touchid = pb_auth->mutable_authentication_touch_id();
  es_event_authentication_touchid_t *es_touchid_event = msg->event.authentication->data.touchid;

  EncodeProcessInfoLight(pb_touchid->mutable_instigator(), msg);
  EncodeEventInstigatorOrFallback(
      msg, [pb_touchid] { return pb_touchid->mutable_trigger_process(); },
      [pb_touchid] { return pb_touchid->mutable_trigger_id(); });

  pb_touchid->set_mode(GetAuthenticationTouchIDMode(es_touchid_event->touchid_mode));
  if (es_touchid_event->has_uid) {
    EncodeUserInfo(pb_touchid->mutable_user(), es_touchid_event->uid.uid, msg.Username());
  }

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedAuthenticationToken &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Authentication *pb_auth = santa_msg->mutable_authentication();
  pb_auth->set_success(msg->event.authentication->success);

  ::pbv1::AuthenticationToken *pb_token = pb_auth->mutable_authentication_token();
  es_event_authentication_token_t *es_token_event = msg->event.authentication->data.token;

  EncodeProcessInfoLight(pb_token->mutable_instigator(), msg);
  EncodeEventInstigatorOrFallback(
      msg, [pb_token] { return pb_token->mutable_trigger_process(); },
      [pb_token] { return pb_token->mutable_trigger_id(); });

  EncodeStringToken([pb_token] { return pb_token->mutable_pubkey_hash(); },
                    es_token_event->pubkey_hash);
  EncodeStringToken([pb_token] { return pb_token->mutable_token_id(); }, es_token_event->token_id);
  EncodeStringToken([pb_token] { return pb_token->mutable_kerberos_principal(); },
                    es_token_event->kerberos_principal);

  return FinalizeProto(santa_msg);
}

::pbv1::AuthenticationAutoUnlock::Type GetAuthenticationAutoUnlockType(es_auto_unlock_type_t type) {
  switch (type) {
    case ES_AUTO_UNLOCK_MACHINE_UNLOCK:
      return ::pbv1::AuthenticationAutoUnlock::TYPE_MACHINE_UNLOCK;
    case ES_AUTO_UNLOCK_AUTH_PROMPT: return ::pbv1::AuthenticationAutoUnlock::TYPE_AUTH_PROMPT;
    default: return ::pbv1::AuthenticationAutoUnlock::TYPE_UNKNOWN;
  }
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedAuthenticationAutoUnlock &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::Authentication *pb_auth = santa_msg->mutable_authentication();
  pb_auth->set_success(msg->event.authentication->success);

  ::pbv1::AuthenticationAutoUnlock *pb_auto_unlock = pb_auth->mutable_authentication_auto_unlock();
  es_event_authentication_auto_unlock_t *es_auto_unlock_event =
      msg->event.authentication->data.auto_unlock;

  EncodeProcessInfoLight(pb_auto_unlock->mutable_instigator(), msg);

  EncodeUserInfo([pb_auto_unlock] { return pb_auto_unlock->mutable_user_info(); }, msg.UID(),
                 es_auto_unlock_event->username);

  pb_auto_unlock->set_type(GetAuthenticationAutoUnlockType(es_auto_unlock_event->type));

  return FinalizeProto(santa_msg);
}

::pbv1::LaunchItem::ItemType GetBTMLaunchItemType(es_btm_item_type_t item_type) {
  switch (item_type) {
    case ES_BTM_ITEM_TYPE_USER_ITEM: return ::pbv1::LaunchItem::ITEM_TYPE_USER_ITEM;
    case ES_BTM_ITEM_TYPE_APP: return ::pbv1::LaunchItem::ITEM_TYPE_APP;
    case ES_BTM_ITEM_TYPE_LOGIN_ITEM: return ::pbv1::LaunchItem::ITEM_TYPE_LOGIN_ITEM;
    case ES_BTM_ITEM_TYPE_AGENT: return ::pbv1::LaunchItem::ITEM_TYPE_AGENT;
    case ES_BTM_ITEM_TYPE_DAEMON: return ::pbv1::LaunchItem::ITEM_TYPE_DAEMON;
    default: return ::pbv1::LaunchItem::ITEM_TYPE_UNKNOWN;
  }
}

std::vector<uint8_t> Protobuf::SerializeMessageLaunchItemAdd(const EnrichedLaunchItem &msg) {
  assert(msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD);
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  const es_event_btm_launch_item_add_t *btm = msg->event.btm_launch_item_add;

  ::pbv1::LaunchItem *pb_launch_item = santa_msg->mutable_launch_item();

  EncodeProcessInfoLight(pb_launch_item->mutable_instigator(), msg);

  pb_launch_item->set_action(::pbv1::LaunchItem::ACTION_ADD);

  EncodeEventInstigatorOrFallback(
      msg, [pb_launch_item] { return pb_launch_item->mutable_trigger_process(); },
      [pb_launch_item] { return pb_launch_item->mutable_trigger_id(); });
  EncodeEventProcessOrFallback(
      msg, msg.AppRegistrant(), msg.AppRegistrantToken(), msg.EnrichedAppRegistrant(),
      [pb_launch_item] { return pb_launch_item->mutable_registrant_process(); },
      [pb_launch_item] { return pb_launch_item->mutable_registrant_id(); });

  pb_launch_item->set_item_type(GetBTMLaunchItemType(btm->item->item_type));
  pb_launch_item->set_legacy(btm->item->legacy);
  pb_launch_item->set_managed(btm->item->managed);

  EncodeUserInfo(pb_launch_item->mutable_item_user(), btm->item->uid, msg.Username());

  pb_launch_item->set_item_path(NSStringToUTF8StringView(
      ConcatPrefixIfRelativePath(btm->item->item_url, btm->item->app_url)));
  pb_launch_item->set_executable_path(NSStringToUTF8StringView(
      ConcatPrefixIfRelativePath(btm->executable_path, btm->item->app_url)));
  if (btm->item->app_url.length > 0) {
    pb_launch_item->set_app_path(NSStringToUTF8StringView(NormalizePath(btm->item->app_url)));
  }

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessageLaunchItemRemove(const EnrichedLaunchItem &msg) {
  assert(msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE);
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  const es_event_btm_launch_item_remove_t *btm = msg->event.btm_launch_item_remove;

  ::pbv1::LaunchItem *pb_launch_item = santa_msg->mutable_launch_item();

  EncodeProcessInfoLight(pb_launch_item->mutable_instigator(), msg);

  pb_launch_item->set_action(::pbv1::LaunchItem::ACTION_REMOVE);

  EncodeEventInstigatorOrFallback(
      msg, [pb_launch_item] { return pb_launch_item->mutable_trigger_process(); },
      [pb_launch_item] { return pb_launch_item->mutable_trigger_id(); });
  EncodeEventProcessOrFallback(
      msg, msg.AppRegistrant(), msg.AppRegistrantToken(), msg.EnrichedAppRegistrant(),
      [pb_launch_item] { return pb_launch_item->mutable_registrant_process(); },
      [pb_launch_item] { return pb_launch_item->mutable_registrant_id(); });

  pb_launch_item->set_item_type(GetBTMLaunchItemType(btm->item->item_type));
  pb_launch_item->set_legacy(btm->item->legacy);
  pb_launch_item->set_managed(btm->item->managed);

  EncodeUserInfo(pb_launch_item->mutable_item_user(), btm->item->uid, msg.Username());

  pb_launch_item->set_item_path(NSStringToUTF8StringView(
      ConcatPrefixIfRelativePath(btm->item->item_url, btm->item->app_url)));
  if (btm->item->app_url.length > 0) {
    pb_launch_item->set_app_path(NSStringToUTF8StringView(NormalizePath(btm->item->app_url)));
  }

  pb_launch_item->set_item_type(GetBTMLaunchItemType(btm->item->item_type));

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedLaunchItem &msg) {
  if (msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD) {
    return SerializeMessageLaunchItemAdd(msg);
  } else if (msg->event_type == ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE) {
    return SerializeMessageLaunchItemRemove(msg);
  } else {
    LOGE(@"Unexpected event type for EnrichedLaunchItem: %d", msg->event_type);
    std::abort();
  }
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedXProtectDetected &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::XProtect *pb_xp = santa_msg->mutable_xprotect();
  ::pbv1::XProtectDetected *pb_xp_detected = pb_xp->mutable_detected();

  EncodeProcessInfoLight(pb_xp_detected->mutable_instigator(), msg);

  const es_event_xp_malware_detected_t *xp = msg->event.xp_malware_detected;
  EncodeStringToken([pb_xp_detected] { return pb_xp_detected->mutable_signature_version(); },
                    xp->signature_version);
  EncodeStringToken([pb_xp_detected] { return pb_xp_detected->mutable_malware_identifier(); },
                    xp->malware_identifier);
  EncodeStringToken([pb_xp_detected] { return pb_xp_detected->mutable_incident_identifier(); },
                    xp->incident_identifier);
  EncodeStringToken([pb_xp_detected] { return pb_xp_detected->mutable_detected_path(); },
                    xp->detected_path);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedXProtectRemediated &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::XProtect *pb_xp = santa_msg->mutable_xprotect();
  ::pbv1::XProtectRemediated *pb_xp_remediated = pb_xp->mutable_remediated();

  EncodeProcessInfoLight(pb_xp_remediated->mutable_instigator(), msg);

  const es_event_xp_malware_remediated_t *xp = msg->event.xp_malware_remediated;
  EncodeStringToken([pb_xp_remediated] { return pb_xp_remediated->mutable_signature_version(); },
                    xp->signature_version);
  EncodeStringToken([pb_xp_remediated] { return pb_xp_remediated->mutable_malware_identifier(); },
                    xp->malware_identifier);
  EncodeStringToken([pb_xp_remediated] { return pb_xp_remediated->mutable_incident_identifier(); },
                    xp->incident_identifier);
  EncodeStringToken([pb_xp_remediated] { return pb_xp_remediated->mutable_action_type(); },
                    xp->action_type);
  pb_xp_remediated->set_success(xp->success);
  EncodeStringToken([pb_xp_remediated] { return pb_xp_remediated->mutable_result_description(); },
                    xp->result_description);
  EncodeStringToken([pb_xp_remediated] { return pb_xp_remediated->mutable_remediated_path(); },
                    xp->remediated_path);
  if (xp->remediated_process_audit_token) {
    EncodeProcessID(pb_xp_remediated->mutable_remediated_process_id(),
                    *xp->remediated_process_audit_token);
  }

  return FinalizeProto(santa_msg);
}

#if HAVE_MACOS_15

static inline void EncodeFileInfo(::pbv1::FileInfo *pb_file, const es_file_t *es_file,
                                  const std::optional<EnrichedFile> &enriched_file,
                                  NSString *sha256 = nil) {
  EncodePath(pb_file->mutable_path(), es_file);
  pb_file->set_truncated(es_file->path_truncated);
  if (enriched_file.has_value()) {
    EncodeStat(pb_file->mutable_stat(), es_file->stat, enriched_file.value().user(),
               enriched_file.value().group());
  }
  if (sha256) {
    EncodeHash(pb_file->mutable_hash(), sha256);
  }
}

static inline void EncodeFileInfo(::pbv1::FileInfo *pb_file, es_string_token_t path,
                                  bool truncated) {
  EncodeStringToken([pb_file] { return pb_file->mutable_path(); }, path);
  pb_file->set_truncated(truncated);
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedGatekeeperOverride &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);
  ::pbv1::GatekeeperOverride *pb_gk = santa_msg->mutable_gatekeeper_override();
  es_event_gatekeeper_user_override_t *gk = msg->event.gatekeeper_user_override;

  EncodeProcessInfoLight(pb_gk->mutable_instigator(), msg);

  switch (gk->file_type) {
    case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_FILE: {
      NSString *hashHexStr =
          gk->sha256 ? @(BufToHexString(*gk->sha256, sizeof(*gk->sha256)).c_str()) : nil;
      EncodeFileInfo(pb_gk->mutable_target(), gk->file.file, msg.Target(), hashHexStr);
      break;
    }

    case ES_GATEKEEPER_USER_OVERRIDE_FILE_TYPE_PATH: {
      EncodeFileInfo(pb_gk->mutable_target(), gk->file.file_path, false);
      break;
    }
  }

  if (gk->signing_info) {
    EncodeCodeSignature(pb_gk->mutable_code_signature(), gk->signing_info->cdhash,
                        gk->signing_info->signing_id, gk->signing_info->team_id);
  }

  return FinalizeProto(santa_msg);
}

#endif  // HAVE_MACOS_15

#if HAVE_MACOS_15_4

::pbv1::TCCModification::IdentityType GetTCCIdentityType(es_tcc_identity_type_t id_type) {
  switch (id_type) {
    case ES_TCC_IDENTITY_TYPE_BUNDLE_ID: return ::pbv1::TCCModification::IDENTITY_TYPE_BUNDLE_ID;
    case ES_TCC_IDENTITY_TYPE_EXECUTABLE_PATH:
      return ::pbv1::TCCModification::IDENTITY_TYPE_EXECUTABLE_PATH;
    case ES_TCC_IDENTITY_TYPE_POLICY_ID: return ::pbv1::TCCModification::IDENTITY_TYPE_POLICY_ID;
    case ES_TCC_IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID:
      return ::pbv1::TCCModification::IDENTITY_TYPE_FILE_PROVIDER_DOMAIN_ID;
    default: return ::pbv1::TCCModification::IDENTITY_TYPE_UNKNOWN;
  }
}

::pbv1::TCCModification::EventType GetTCCEventType(es_tcc_event_type_t event_type) {
  switch (event_type) {
    case ES_TCC_EVENT_TYPE_CREATE: return ::pbv1::TCCModification::EVENT_TYPE_CREATE;
    case ES_TCC_EVENT_TYPE_MODIFY: return ::pbv1::TCCModification::EVENT_TYPE_MODIFY;
    case ES_TCC_EVENT_TYPE_DELETE: return ::pbv1::TCCModification::EVENT_TYPE_DELETE;
    default: return ::pbv1::TCCModification::EVENT_TYPE_UNKNOWN;
  }
}

::pbv1::TCCModification::AuthorizationRight GetTCCAuthorizationRight(
    es_tcc_authorization_right_t auth_right) {
  switch (auth_right) {
    case ES_TCC_AUTHORIZATION_RIGHT_DENIED:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_DENIED;
    case ES_TCC_AUTHORIZATION_RIGHT_UNKNOWN:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_UNKNOWN;
    case ES_TCC_AUTHORIZATION_RIGHT_ALLOWED:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_ALLOWED;
    case ES_TCC_AUTHORIZATION_RIGHT_LIMITED:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_LIMITED;
    case ES_TCC_AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_ADD_MODIFY_ADDED;
    case ES_TCC_AUTHORIZATION_RIGHT_SESSION_PID:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_SESSION_PID;
    case ES_TCC_AUTHORIZATION_RIGHT_LEARN_MORE:
      return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_LEARN_MORE;
    default: return ::pbv1::TCCModification::AUTHORIZATION_RIGHT_UNKNOWN;
  }
}

::pbv1::TCCModification::AuthorizationReason GetTCCAuthorizationReason(
    es_tcc_authorization_reason_t auth_reason) {
  switch (auth_reason) {
    case ES_TCC_AUTHORIZATION_REASON_NONE:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_NONE;
    case ES_TCC_AUTHORIZATION_REASON_ERROR:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_ERROR;
    case ES_TCC_AUTHORIZATION_REASON_USER_CONSENT:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_USER_CONSENT;
    case ES_TCC_AUTHORIZATION_REASON_USER_SET:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_USER_SET;
    case ES_TCC_AUTHORIZATION_REASON_SYSTEM_SET:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_SYSTEM_SET;
    case ES_TCC_AUTHORIZATION_REASON_SERVICE_POLICY:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_SERVICE_POLICY;
    case ES_TCC_AUTHORIZATION_REASON_MDM_POLICY:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_MDM_POLICY;
    case ES_TCC_AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_SERVICE_OVERRIDE_POLICY;
    case ES_TCC_AUTHORIZATION_REASON_MISSING_USAGE_STRING:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_MISSING_USAGE_STRING;
    case ES_TCC_AUTHORIZATION_REASON_PROMPT_TIMEOUT:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_PROMPT_TIMEOUT;
    case ES_TCC_AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_PREFLIGHT_UNKNOWN;
    case ES_TCC_AUTHORIZATION_REASON_ENTITLED:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_ENTITLED;
    case ES_TCC_AUTHORIZATION_REASON_APP_TYPE_POLICY:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_APP_TYPE_POLICY;
    case ES_TCC_AUTHORIZATION_REASON_PROMPT_CANCEL:
      return ::pbv1::TCCModification::AUTHORIZATION_REASON_PROMPT_CANCEL;
    default: return ::pbv1::TCCModification::AUTHORIZATION_REASON_UNKNOWN;
  }
}

std::vector<uint8_t> Protobuf::SerializeMessage(const EnrichedTCCModification &msg) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  const es_event_tcc_modify_t *tcc = msg->event.tcc_modify;

  ::pbv1::TCCModification *pb_tcc = santa_msg->mutable_tcc_modification();

  EncodeProcessInfoLight(pb_tcc->mutable_instigator(), msg);
  EncodeEventInstigatorOrFallback(
      msg, [pb_tcc] { return pb_tcc->mutable_trigger_process(); },
      [pb_tcc] { return pb_tcc->mutable_trigger_id(); });
  EncodeEventProcessOrFallback(
      msg, msg.ResponsibleProcess(), msg.ResponsibleProcessToken(),
      msg.EnrichedResponsibleProcess(), [pb_tcc] { return pb_tcc->mutable_responsible_process(); },
      [pb_tcc] { return pb_tcc->mutable_responsible_id(); });

  EncodeStringToken([pb_tcc] { return pb_tcc->mutable_service(); }, tcc->service);
  EncodeStringToken([pb_tcc] { return pb_tcc->mutable_identity(); }, tcc->identity);

  pb_tcc->set_event_type(GetTCCEventType(tcc->update_type));
  pb_tcc->set_identity_type(GetTCCIdentityType(tcc->identity_type));
  pb_tcc->set_authorization_right(GetTCCAuthorizationRight(tcc->right));
  pb_tcc->set_authorization_reason(GetTCCAuthorizationReason(tcc->reason));

  return FinalizeProto(santa_msg);
}

#endif  // HAVE_MACOS_15_4

std::vector<uint8_t> Protobuf::SerializeFileAccess(
    const std::string &policy_version, const std::string &policy_name, const Message &msg,
    const EnrichedProcess &enriched_process, const std::string &target,
    FileAccessPolicyDecision decision, std::string_view operation_id) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena, msg);

  ::pbv1::FileAccess *file_access = santa_msg->mutable_file_access();

  EncodeProcessInfo(file_access->mutable_instigator(), msg->version, msg->process,
                    enriched_process);
  EncodeFileInfoLight(file_access->mutable_target(), target, false);
  EncodeString([file_access] { return file_access->mutable_policy_version(); }, policy_version);
  EncodeString([file_access] { return file_access->mutable_policy_name(); }, policy_name);

  file_access->set_access_type(GetAccessType(msg->event_type));
  file_access->set_policy_decision(GetPolicyDecision(decision));
  file_access->set_operation_id(operation_id);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeAllowlist(const Message &msg, const std::string_view hash) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  const es_file_t *es_file = santa::GetAllowListTargetFile(msg);

  EnrichedFile enriched_file(std::nullopt, std::nullopt, std::nullopt);
  EnrichedProcess enriched_process;

  ::pbv1::Allowlist *pb_allowlist = santa_msg->mutable_allowlist();
  EncodeProcessInfoLight(pb_allowlist->mutable_instigator(), msg->process, enriched_process);

  EncodeFileInfo(pb_allowlist->mutable_target(), es_file, enriched_file,
                 [NSString stringWithFormat:@"%s", hash.data()]);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeBundleHashingEvent(SNTStoredExecutionEvent *event) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  ::pbv1::Bundle *pb_bundle = santa_msg->mutable_bundle();

  EncodeHash(pb_bundle->mutable_file_hash(), event.fileSHA256);
  EncodeHash(pb_bundle->mutable_bundle_hash(), event.fileBundleHash);
  EncodeString([pb_bundle] { return pb_bundle->mutable_bundle_name(); },
               NonNull(event.fileBundleName));
  EncodeString([pb_bundle] { return pb_bundle->mutable_bundle_id(); }, NonNull(event.fileBundleID));
  EncodeString([pb_bundle] { return pb_bundle->mutable_bundle_path(); },
               NonNull(event.fileBundlePath));
  EncodeString([pb_bundle] { return pb_bundle->mutable_path(); }, NonNull(event.filePath));

  return FinalizeProto(santa_msg);
}

static void EncodeDisk(::pbv1::Disk *pb_disk, ::pbv1::Disk_Action action, NSDictionary *props) {
  pb_disk->set_action(action);

  NSString *dmg_path = nil;
  NSString *serial = nil;
  if ([props[@"DADeviceModel"] isEqual:@"Disk Image"]) {
    dmg_path = santa::DiskImageForDevice(props[@"DADevicePath"]);
  } else {
    serial = santa::SerialForDevice(props[@"DADevicePath"]);
  }

  NSString *model = [NSString stringWithFormat:@"%@ %@", NonNull(props[@"DADeviceVendor"]),
                                               NonNull(props[@"DADeviceModel"])];
  model = [model stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];

  EncodeString([pb_disk] { return pb_disk->mutable_mount(); }, [props[@"DAVolumePath"] path]);
  EncodeString([pb_disk] { return pb_disk->mutable_volume(); }, props[@"DAVolumeName"]);
  EncodeString([pb_disk] { return pb_disk->mutable_bsd_name(); }, props[@"DAMediaBSDName"]);
  EncodeString([pb_disk] { return pb_disk->mutable_fs(); }, props[@"DAVolumeKind"]);
  EncodeString([pb_disk] { return pb_disk->mutable_model(); }, model);
  EncodeString([pb_disk] { return pb_disk->mutable_serial(); }, serial);
  EncodeString([pb_disk] { return pb_disk->mutable_bus(); }, props[@"DADeviceProtocol"]);
  EncodeString([pb_disk] { return pb_disk->mutable_dmg_path(); }, dmg_path);
  EncodeString([pb_disk] { return pb_disk->mutable_mount_from(); },
               MountFromName([props[@"DAVolumePath"] path]));

  if (props[@"DAAppearanceTime"]) {
    // Note: `DAAppearanceTime` is set via `CFAbsoluteTimeGetCurrent`, which uses the defined
    // reference date of `Jan 1 2001 00:00:00 GMT` (not the typical `00:00:00 UTC on 1 January
    // 1970`).
    NSDate *appearance =
        [NSDate dateWithTimeIntervalSinceReferenceDate:[props[@"DAAppearanceTime"] doubleValue]];
    NSTimeInterval interval = [appearance timeIntervalSince1970];
    double seconds;
    double fractional = modf(interval, &seconds);
    struct timespec ts = {
        .tv_sec = (long)seconds,
        .tv_nsec = (long)(fractional * NSEC_PER_SEC),
    };
    EncodeTimestamp(pb_disk->mutable_appearance(), ts);
    Timestamp timestamp = pb_disk->appearance();
  }
}

std::vector<uint8_t> Protobuf::SerializeDiskAppeared(NSDictionary *props) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  EncodeDisk(santa_msg->mutable_disk(), ::pbv1::Disk::ACTION_APPEARED, props);

  return FinalizeProto(santa_msg);
}

std::vector<uint8_t> Protobuf::SerializeDiskDisappeared(NSDictionary *props) {
  Arena arena;
  ::pbv1::SantaMessage *santa_msg = CreateDefaultProto(&arena);

  EncodeDisk(santa_msg->mutable_disk(), ::pbv1::Disk::ACTION_DISAPPEARED, props);

  return FinalizeProto(santa_msg);
}

}  // namespace santa
