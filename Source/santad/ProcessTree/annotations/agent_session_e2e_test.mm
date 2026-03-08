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

/// End-to-end test: process tree annotation -> CEL policy evaluation.
///
/// Simulates the full pipeline:
///   1. santactl agent exec recognized by annotator on AUTH_EXEC
///   2. execvp replaces santactl with the agent binary (annotation persists)
///   3. Agent forks child processes (annotation propagates)
///   4. CEL rules evaluated on a child's exec event see agent_session fields

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>

#include <memory>
#include <string>
#include <vector>

#include "Source/common/cel/Activation.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/Evaluator.h"
#include "Source/santad/ProcessTree/annotations/agent_session.h"
#include "Source/santad/ProcessTree/process.h"
#include "Source/santad/ProcessTree/process_tree.pb.h"
#include "Source/santad/ProcessTree/process_tree_test_helpers.h"

using namespace santa::santad::process_tree;
namespace ptpb = ::santa::pb::v1::process_tree;

@interface AgentSessionE2ETest : XCTestCase
@end

@implementation AgentSessionE2ETest

/// Full pipeline: santactl agent exec -> execvp -> fork child -> CEL evaluation on child.
- (void)testAgentSessionCELEvaluation {
  // --- Phase 1: Build process tree and simulate agent session ---
  std::vector<std::unique_ptr<Annotator>> annotators;
  annotators.emplace_back(std::make_unique<AgentSessionAnnotator>());
  auto tree = std::make_shared<ProcessTreeTestPeer>(std::move(annotators));
  auto initProc = tree->InsertInit();

  uint64_t event_id = 1;
  const struct Cred cred = {.uid = 501, .gid = 20};

  // init -> fork PID 2
  const struct Pid santactl_pid = {.pid = 2, .pidversion = 2};
  tree->HandleFork(event_id++, *initProc, santactl_pid);

  // PID 2 exec: santactl agent exec --policy restricted --tag team:platform -- claude --model opus
  const struct Pid santactl_exec_pid = {.pid = 2, .pidversion = 3};
  const struct Program santactl_prog = {
      .executable = "/usr/local/bin/santactl",
      .arguments = {"santactl", "agent", "exec", "--policy", "restricted", "--tag", "team:platform",
                    "--", "claude", "--model", "opus"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.northpolesec.santa.ctl",
              .team_id = "EQHXZ8M8AV",
              .cdhash = "abc123",
              .is_platform_binary = false,
          },
  };
  auto santactl = *tree->Get(santactl_pid);
  tree->HandleExec(event_id++, *santactl, santactl_exec_pid, santactl_prog, cred);

  // execvp: santactl (PID 2) replaced by claude binary. Annotation persists.
  const struct Pid claude_pid = {.pid = 2, .pidversion = 4};
  const struct Program claude_prog = {
      .executable = "/usr/local/bin/claude",
      .arguments = {"claude", "--model", "opus"},
      .code_signing =
          CodeSigningInfo{
              .signing_id = "com.anthropic.claude-code",
              .team_id = "Q6L2SF6YDW",
              .cdhash = "def456",
              .is_platform_binary = false,
          },
  };
  auto santactl_proc = *tree->Get(santactl_exec_pid);
  tree->HandleExec(event_id++, *santactl_proc, claude_pid, claude_prog, cred);

  // claude forks a child: PID 3 (e.g., node subprocess)
  auto claude = *tree->Get(claude_pid);
  const struct Pid child_pid = {.pid = 3, .pidversion = 3};
  tree->HandleFork(event_id++, *claude, child_pid);

  // Child execs: node script.js
  const struct Pid node_pid = {.pid = 3, .pidversion = 4};
  const struct Program node_prog = {
      .executable = "/usr/local/bin/node",
      .arguments = {"node", "script.js"},
  };
  auto child = *tree->Get(child_pid);
  tree->HandleExec(event_id++, *child, node_pid, node_prog, cred);

  // node forks git: PID 4
  auto node = *tree->Get(node_pid);
  const struct Pid git_pid = {.pid = 4, .pidversion = 4};
  tree->HandleFork(event_id++, *node, git_pid);

  // git execs
  const struct Pid git_exec_pid = {.pid = 4, .pidversion = 5};
  const struct Program git_prog = {
      .executable = "/usr/bin/git",
      .arguments = {"git", "push"},
  };
  auto git_fork = *tree->Get(git_pid);
  tree->HandleExec(event_id++, *git_fork, git_exec_pid, git_prog, cred);

  // --- Phase 2: Verify annotation propagated to grandchild ---
  auto git_proc = *tree->Get(git_exec_pid);
  auto annotation = tree->GetAnnotation<AgentSessionAnnotator>(*git_proc);
  XCTAssertTrue(annotation.has_value(), @"git grandchild should have agent_session annotation");

  const auto &session = (*annotation)->session();
  XCTAssertEqual(session.session_name(), "claude");
  XCTAssertEqual(session.policy(), "restricted");
  XCTAssertEqual(session.tags().at("team"), "platform");

  // --- Phase 3: Verify telemetry export includes agent_session ---
  auto exported = tree->ExportAnnotations(git_exec_pid);
  XCTAssertTrue(exported.has_value());
  XCTAssertTrue(exported->has_agent_session());
  XCTAssertEqual(exported->agent_session().session_id(), session.session_id());

  // --- Phase 4: CEL evaluation with the agent_session ---
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok(), @"Failed to create CEL evaluator: %s", sut.status().message().data());

  // Build a CEL activation as if we're evaluating the git exec event.
  auto target = std::make_unique<ExecutableFileT>();
  // signing_id for git would be "platform:com.apple.git" but we just need something for the test
  target->set_signing_id("platform:com.apple.git");

  santa::cel::Activation<true> activation(
      std::move(target),
      ^std::vector<std::string>() {
        return {"git", "push"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 501;
      },
      ^std::string() {
        return "/Users/dev/project";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      session);  // Pass the agent_session from the annotation

  // Rule: block sudo inside agent sessions
  {
    auto result = sut.value()->CompileAndEvaluate(
        "agent_session.policy == 'restricted' ? BLOCKLIST : ALLOWLIST", activation);
    XCTAssertTrue(result.ok(), @"CEL eval failed: %s", result.status().message().data());
    XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    XCTAssertFalse(result.value().cacheable, @"agent_session access should prevent caching");
  }

  // Rule: check tag value
  {
    auto result = sut.value()->CompileAndEvaluate(
        "agent_session.tags['team'] == 'platform' ? BLOCKLIST : ALLOWLIST", activation);
    XCTAssertTrue(result.ok(), @"CEL eval failed: %s", result.status().message().data());
    XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
  }

  // Rule: check session_name
  {
    auto result = sut.value()->CompileAndEvaluate(
        "agent_session.session_name == 'claude' ? BLOCKLIST : ALLOWLIST", activation);
    XCTAssertTrue(result.ok(), @"CEL eval failed: %s", result.status().message().data());
    XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
  }

  // Rule: non-matching policy allows
  {
    auto result = sut.value()->CompileAndEvaluate(
        "agent_session.policy == 'permissive' ? BLOCKLIST : ALLOWLIST", activation);
    XCTAssertTrue(result.ok(), @"CEL eval failed: %s", result.status().message().data());
    XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
  }

  // Rule: session_id is non-empty (UUID was generated)
  {
    auto result = sut.value()->CompileAndEvaluate(
        "agent_session.session_id != '' ? BLOCKLIST : ALLOWLIST", activation);
    XCTAssertTrue(result.ok(), @"CEL eval failed: %s", result.status().message().data());
    XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
  }
}

/// Verify that processes outside an agent session do not have agent_session available.
- (void)testNoAgentSessionCELEvaluation {
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  // Activation without agent_session (default: nullopt).
  auto target = std::make_unique<ExecutableFileT>();
  target->set_signing_id("platform:com.apple.sudo");
  santa::cel::Activation<true> activation(
      std::move(target),
      ^std::vector<std::string>() {
        return {"sudo", "rm", "-rf", "/"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 501;
      },
      ^std::string() {
        return "/";
      },
      ^std::vector<AncestorT>() {
        return {};
      });

  // A rule that checks agent_session.policy should not match when there is no session.
  // agent_session is not bound, so accessing it should produce an error/no match.
  auto result = sut.value()->CompileAndEvaluate(
      "agent_session.policy == 'restricted' ? BLOCKLIST : ALLOWLIST", activation);
  // When agent_session is not present, the expression should fail to evaluate
  // (unbound variable), which is the correct behavior — the rule doesn't apply.
  XCTAssertFalse(result.ok(), @"Expected evaluation to fail when agent_session is not present");
}

@end
