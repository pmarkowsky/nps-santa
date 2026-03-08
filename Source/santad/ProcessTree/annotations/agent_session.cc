/// Copyright 2026 North Pole Security, Inc.
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
#include "Source/santad/ProcessTree/annotations/agent_session.h"

#include <cstddef>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "absl/strings/str_cat.h"

namespace ptpb = ::santa::pb::v1::process_tree;

namespace santa::santad::process_tree {

namespace {

std::string GenerateUUID() {
  // Generate a v4 UUID using random bytes.
  uint8_t bytes[16];
  arc4random_buf(bytes, sizeof(bytes));
  // Set version (4) and variant (RFC 4122).
  bytes[6] = (bytes[6] & 0x0F) | 0x40;
  bytes[8] = (bytes[8] & 0x3F) | 0x80;
  return absl::StrCat(absl::Hex(bytes[0], absl::kZeroPad2),
                      absl::Hex(bytes[1], absl::kZeroPad2),
                      absl::Hex(bytes[2], absl::kZeroPad2),
                      absl::Hex(bytes[3], absl::kZeroPad2), "-",
                      absl::Hex(bytes[4], absl::kZeroPad2),
                      absl::Hex(bytes[5], absl::kZeroPad2), "-",
                      absl::Hex(bytes[6], absl::kZeroPad2),
                      absl::Hex(bytes[7], absl::kZeroPad2), "-",
                      absl::Hex(bytes[8], absl::kZeroPad2),
                      absl::Hex(bytes[9], absl::kZeroPad2), "-",
                      absl::Hex(bytes[10], absl::kZeroPad2),
                      absl::Hex(bytes[11], absl::kZeroPad2),
                      absl::Hex(bytes[12], absl::kZeroPad2),
                      absl::Hex(bytes[13], absl::kZeroPad2),
                      absl::Hex(bytes[14], absl::kZeroPad2),
                      absl::Hex(bytes[15], absl::kZeroPad2));
}

}  // namespace

bool AgentSessionAnnotator::IsSantactlAgentExec(const Process &process) {
  if (!process.program_ || !process.program_->code_signing) {
    return false;
  }
  if (process.program_->code_signing->signing_id != kSantactlSigningID) {
    return false;
  }

  // Look for "agent" followed by "exec" in argv.
  const auto &args = process.program_->arguments;
  for (size_t i = 0; i + 1 < args.size(); ++i) {
    if (args[i] == "agent" && args[i + 1] == "exec") {
      return true;
    }
  }
  return false;
}

std::optional<ptpb::AgentSession> AgentSessionAnnotator::ParseAgentExecArgs(
    const std::vector<std::string> &args) {
  ptpb::AgentSession session;
  session.set_session_id(GenerateUUID());

  auto *started_at = session.mutable_started_at();
  started_at->set_seconds(std::time(nullptr));

  std::string session_name;
  std::string policy;
  size_t tag_count = 0;

  // Find the index of "exec" after "agent" to start parsing options.
  size_t parse_start = 0;
  for (size_t i = 0; i + 1 < args.size(); ++i) {
    if (args[i] == "agent" && args[i + 1] == "exec") {
      parse_start = i + 2;
      break;
    }
  }

  bool found_separator = false;
  for (size_t i = parse_start; i < args.size(); ++i) {
    if (args[i] == "--") {
      found_separator = true;
      // Infer session name from the first token after "--" if not set.
      if (session_name.empty() && i + 1 < args.size()) {
        // Use basename of the command.
        const std::string &cmd = args[i + 1];
        auto slash = cmd.rfind('/');
        session_name =
            (slash != std::string::npos) ? cmd.substr(slash + 1) : cmd;
      }
      break;
    }

    if (args[i] == "--session-name" && i + 1 < args.size()) {
      session_name = args[++i];
    } else if (args[i] == "--policy" && i + 1 < args.size()) {
      policy = args[++i];
    } else if (args[i] == "--tag" && i + 1 < args.size()) {
      const std::string &tag = args[++i];
      auto colon = tag.find(':');
      if (colon == std::string::npos) {
        continue;  // Skip malformed tags (no colon).
      }
      std::string key = tag.substr(0, colon);
      std::string value = tag.substr(colon + 1);

      if (key.size() > kMaxAgentSessionTagKeyBytes ||
          value.size() > kMaxAgentSessionTagValueBytes) {
        continue;  // Skip oversized tags.
      }
      if (tag_count >= kMaxAgentSessionTags) {
        continue;  // Skip excess tags.
      }

      (*session.mutable_tags())[key] = value;
      ++tag_count;
    }
  }

  if (!found_separator) {
    return std::nullopt;
  }

  session.set_session_name(session_name);
  session.set_policy(policy);
  return session;
}

void AgentSessionAnnotator::AnnotateFork(ProcessTree &tree,
                                         const Process &parent,
                                         const Process &child) {
  if (auto annotation = tree.GetAnnotation<AgentSessionAnnotator>(parent)) {
    tree.AnnotateProcess(child, std::move(*annotation));
  }
}

void AgentSessionAnnotator::AnnotateExec(ProcessTree &tree,
                                         const Process &orig_process,
                                         const Process &new_process) {
  // Propagate existing annotation across exec.
  auto existing = tree.GetAnnotation<AgentSessionAnnotator>(orig_process);

  if (IsSantactlAgentExec(new_process)) {
    auto parsed = ParseAgentExecArgs(new_process.program_->arguments);
    if (parsed) {
      // Handle nested sessions: inherit parent session ID and merge tags.
      if (existing) {
        parsed->set_parent_session_id((*existing)->session().session_id());
        // Merge parent tags, inner values win on conflict.
        for (const auto &[key, value] : (*existing)->session().tags()) {
          if (parsed->tags().find(key) == parsed->tags().end()) {
            (*parsed->mutable_tags())[key] = value;
          }
        }
      }
      tree.AnnotateProcess(new_process, std::make_shared<AgentSessionAnnotator>(
                                            std::move(*parsed)));
      return;
    }
  }

  if (existing) {
    tree.AnnotateProcess(new_process, std::move(*existing));
  }
}

std::optional<ptpb::Annotations> AgentSessionAnnotator::Proto() const {
  if (session_.session_id().empty()) {
    return std::nullopt;
  }
  ptpb::Annotations annotations;
  *annotations.mutable_agent_session() = session_;
  return annotations;
}

}  // namespace santa::santad::process_tree
