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
#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <vector>

#include "Source/santad/ProcessTree/annotations/agent_session.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "Source/santad/ProcessTree/process_tree_test_helpers.h"

using namespace santa::santad::process_tree;
namespace ptpb = ::santa::pb::v1::process_tree;

@interface AgentSessionAnnotatorTest : XCTestCase
@property std::shared_ptr<ProcessTreeTestPeer> tree;
@property std::shared_ptr<const Process> initProc;
@end

@implementation AgentSessionAnnotatorTest

- (void)setUp {
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<AgentSessionAnnotator>());
  self.tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  self.initProc = self.tree->InsertInit();
}

- (void)testAnnotatesSantactlAgentExec {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // Fork init -> PID 2
  const struct Pid santactl_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, santactl_pid);

  // Exec santactl agent exec --policy restricted -- claude
  const struct Pid santactl_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program santactl_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--policy", "restricted", "--tag", "team:platform",
                    "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto santactl = *self.tree->Get(santactl_pid);
  self.tree->HandleExec(event_id++, *santactl, santactl_exec_pid, santactl_prog, cred);

  // Verify annotation on santactl process.
  auto proc = *self.tree->Get(santactl_exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*proc);
  XCTAssertTrue(annotation.has_value());

  const auto &session = (*annotation)->session();
  XCTAssertFalse(session.session_id().empty());
  XCTAssertEqual(session.session_name(), "claude");
  XCTAssertEqual(session.policy(), "restricted");
  XCTAssertEqual(session.tags().at("team"), "platform");
  XCTAssertTrue(session.parent_session_id().empty());
}

- (void)testAnnotationPropagatesOnFork {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // Fork init -> PID 2
  const struct Pid santactl_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, santactl_pid);

  // Exec santactl agent exec -- claude
  const struct Pid santactl_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program santactl_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto santactl = *self.tree->Get(santactl_pid);
  self.tree->HandleExec(event_id++, *santactl, santactl_exec_pid, santactl_prog, cred);

  // Fork agent -> child PID 3
  auto agent = *self.tree->Get(santactl_exec_pid);
  const struct Pid child_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *agent, child_pid);

  // Verify child inherits annotation.
  auto child = *self.tree->Get(child_pid);
  auto child_annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*child);
  XCTAssertTrue(child_annotation.has_value());
  XCTAssertEqual((*child_annotation)->session().session_name(), "claude");
}

- (void)testAnnotationPersistsThroughExec {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // Fork init -> PID 2
  const struct Pid santactl_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, santactl_pid);

  // Exec santactl agent exec -- /bin/bash
  const struct Pid santactl_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program santactl_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--", "/bin/bash"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto santactl = *self.tree->Get(santactl_pid);
  self.tree->HandleExec(event_id++, *santactl, santactl_exec_pid, santactl_prog, cred);

  // execvp replaces santactl with bash (same PID, new pidversion).
  const struct Pid bash_pid = {.pid = 2, .pidversion = 4};
  const struct Program bash_prog = {
      .executable = "/bin/bash",
      .arguments = {"/bin/bash"},
  };
  auto agent = *self.tree->Get(santactl_exec_pid);
  self.tree->HandleExec(event_id++, *agent, bash_pid, bash_prog, cred);

  // Annotation persists through the exec.
  auto bash = *self.tree->Get(bash_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*bash);
  XCTAssertTrue(annotation.has_value());
  XCTAssertEqual((*annotation)->session().session_name(), "bash");
}

- (void)testAnnotationPropagatesToGrandchildren {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // Fork init -> PID 2
  const struct Pid santactl_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, santactl_pid);

  // Exec santactl agent exec -- claude
  const struct Pid santactl_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program santactl_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto santactl = *self.tree->Get(santactl_pid);
  self.tree->HandleExec(event_id++, *santactl, santactl_exec_pid, santactl_prog, cred);

  // Fork agent -> child PID 3
  auto agent = *self.tree->Get(santactl_exec_pid);
  const struct Pid child_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *agent, child_pid);

  // Child execs node.
  const struct Pid node_pid = {.pid = 3, .pidversion = 4};
  const struct Program node_prog = {
      .executable = "/usr/local/bin/node",
      .arguments = {"node", "script.js"},
  };
  auto child = *self.tree->Get(child_pid);
  self.tree->HandleExec(event_id++, *child, node_pid, node_prog, cred);

  // Fork node -> grandchild PID 4
  auto node = *self.tree->Get(node_pid);
  const struct Pid grandchild_pid = {.pid = 4, .pidversion = 4};
  self.tree->HandleFork(event_id++, *node, grandchild_pid);

  auto grandchild = *self.tree->Get(grandchild_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*grandchild);
  XCTAssertTrue(annotation.has_value());
  XCTAssertEqual((*annotation)->session().session_name(), "claude");
}

- (void)testNestedSessionSetsParentAndMergesTags {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  // Fork init -> PID 2
  const struct Pid outer_pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, outer_pid);

  // Outer: santactl agent exec --tag env:prod -- claude
  const struct Pid outer_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program outer_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--tag", "env:prod", "--tag", "team:platform",
                    "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto outer = *self.tree->Get(outer_pid);
  self.tree->HandleExec(event_id++, *outer, outer_exec_pid, outer_prog, cred);

  // Fork agent -> PID 3
  auto outer_agent = *self.tree->Get(outer_exec_pid);
  const struct Pid inner_pid = {.pid = 3, .pidversion = 3};
  self.tree->HandleFork(event_id++, *outer_agent, inner_pid);

  // Inner: santactl agent exec --tag team:infra -- codex
  const struct Pid inner_exec_pid = {.pid = 3, .pidversion = 4};
  const struct Program inner_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--tag", "team:infra", "--", "codex"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto inner = *self.tree->Get(inner_pid);
  self.tree->HandleExec(event_id++, *inner, inner_exec_pid, inner_prog, cred);

  auto inner_proc = *self.tree->Get(inner_exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*inner_proc);
  XCTAssertTrue(annotation.has_value());

  const auto &session = (*annotation)->session();
  XCTAssertEqual(session.session_name(), "codex");

  // parent_session_id should be the outer session's ID.
  auto outer_annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*outer_agent);
  XCTAssertEqual(session.parent_session_id(), (*outer_annotation)->session().session_id());

  // Inner tag wins on conflict (team), parent tag inherited (env).
  XCTAssertEqual(session.tags().at("team"), "infra");
  XCTAssertEqual(session.tags().at("env"), "prod");
}

- (void)testIgnoresNonSantactlBinary {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  const struct Pid pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, pid);

  // Some other binary with "agent exec" in args but wrong signing ID.
  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {
      .executable = "/usr/local/bin/other",
      .arguments = {"other", "agent", "exec", "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.example.other",
              .team_id = "OTHERTEAM",
              .cdhash = "def456",
              .is_platform_binary = false,
          },
  };
  auto proc = *self.tree->Get(pid);
  self.tree->HandleExec(event_id++, *proc, exec_pid, prog, cred);

  auto result = *self.tree->Get(exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*result);
  XCTAssertFalse(annotation.has_value());
}

- (void)testIgnoresNonAgentExecCommand {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  const struct Pid pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, pid);

  // santactl with a different subcommand (e.g., "status").
  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "status"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto proc = *self.tree->Get(pid);
  self.tree->HandleExec(event_id++, *proc, exec_pid, prog, cred);

  auto result = *self.tree->Get(exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*result);
  XCTAssertFalse(annotation.has_value());
}

- (void)testTagSizeLimitsEnforced {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  const struct Pid pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, pid);

  // Build args with an oversized tag key.
  std::string oversized_key(kMaxAgentSessionTagKeyBytes + 1, 'k');
  std::string tag = oversized_key + ":value";

  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--tag", tag, "--tag", "valid:tag", "--",
                    "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto proc = *self.tree->Get(pid);
  self.tree->HandleExec(event_id++, *proc, exec_pid, prog, cred);

  auto result = *self.tree->Get(exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*result);
  XCTAssertTrue(annotation.has_value());

  const auto &session = (*annotation)->session();
  // Oversized tag should be skipped, valid tag should be present.
  XCTAssertEqual(session.tags().size(), 1);
  XCTAssertEqual(session.tags().at("valid"), "tag");
}

- (void)testSessionNameInferredFromCommand {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  const struct Pid pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, pid);

  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--", "/usr/local/bin/claude-code"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto proc = *self.tree->Get(pid);
  self.tree->HandleExec(event_id++, *proc, exec_pid, prog, cred);

  auto result = *self.tree->Get(exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*result);
  XCTAssertTrue(annotation.has_value());
  XCTAssertEqual((*annotation)->session().session_name(), "claude-code");
}

- (void)testExplicitSessionName {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  const struct Pid pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, pid);

  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--session-name", "my-session", "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto proc = *self.tree->Get(pid);
  self.tree->HandleExec(event_id++, *proc, exec_pid, prog, cred);

  auto result = *self.tree->Get(exec_pid);
  auto annotation = self.tree->GetAnnotation<AgentSessionAnnotator>(*result);
  XCTAssertTrue(annotation.has_value());
  XCTAssertEqual((*annotation)->session().session_name(), "my-session");
}

- (void)testProtoExport {
  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 0, .gid = 0};

  const struct Pid pid = {.pid = 2, .pidversion = 2};
  self.tree->HandleFork(event_id++, *self.initProc, pid);

  const struct Pid exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--policy", "strict", "--", "claude"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "TESTTEAMID",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto proc = *self.tree->Get(pid);
  self.tree->HandleExec(event_id++, *proc, exec_pid, prog, cred);

  // ExportAnnotations should include agent_session.
  auto annotations = self.tree->ExportAnnotations(exec_pid);
  XCTAssertTrue(annotations.has_value());
  XCTAssertTrue(annotations->has_agent_session());
  XCTAssertEqual(annotations->agent_session().policy(), "strict");
  XCTAssertEqual(annotations->agent_session().session_name(), "claude");
}

@end
