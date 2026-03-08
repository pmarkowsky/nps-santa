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
#ifndef SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_AGENT_SESSION_H
#define SANTA__SANTAD_PROCESSTREE_ANNOTATIONS_AGENT_SESSION_H

#include <cstddef>
#include <optional>
#include <string>

#include "Source/santad/ProcessTree/annotations/annotator.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"

namespace santa::santad::process_tree {

inline constexpr size_t kMaxAgentSessionTags = 16;
inline constexpr size_t kMaxAgentSessionTagKeyBytes = 256;
inline constexpr size_t kMaxAgentSessionTagValueBytes = 1024;

class AgentSessionAnnotator : public Annotator {
 public:
  AgentSessionAnnotator() = default;
  explicit AgentSessionAnnotator(
      ::santa::pb::v1::process_tree::AgentSession session)
      : session_(std::move(session)) {}

  void AnnotateFork(ProcessTree &tree, const Process &parent,
                    const Process &child) override;
  void AnnotateExec(ProcessTree &tree, const Process &orig_process,
                    const Process &new_process) override;

  std::optional<::santa::pb::v1::process_tree::Annotations> Proto()
      const override;

  const ::santa::pb::v1::process_tree::AgentSession &session() const {
    return session_;
  }

 private:
  static bool IsSantactlAgentExec(const Process &process);
  static std::optional<::santa::pb::v1::process_tree::AgentSession>
  ParseAgentExecArgs(const std::vector<std::string> &args);

  ::santa::pb::v1::process_tree::AgentSession session_;

  // The signing ID used to identify santactl binaries.
  static constexpr const char *kSantactlSigningID =
      "com.northpolesec.santa.ctl";
};

}  // namespace santa::santad::process_tree

#endif
