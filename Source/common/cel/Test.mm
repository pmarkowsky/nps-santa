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

#include "Source/common/cel/Activation.h"
#include "Source/common/cel/AgeFunction.h"
#include "Source/common/cel/CELProtoTraits.h"
#include "Source/common/cel/Evaluator.h"

#import <Foundation/Foundation.h>
#import <XCTest/XCTest.h>
#include <cstddef>

#include <optional>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "google/protobuf/arena.h"

@interface CELTest : XCTestCase
@end

@implementation CELTest

- (void)testBasic {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  f->set_is_platform_binary(false);
  f->set_team_id("EQHXZ8M8AV");
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {{"DYLD_INSERT_LIBRARIES", "1"}};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  if (!sut.ok()) {
    XCTFail("Failed to create evaluator: %s", sut.status().message().data());
  }

  {
    // Test bad expression.
    auto result = sut.value()->CompileAndEvaluate("foo", activation);
    if (result.ok()) XCTFail("Expected failure to evaluate, got ok!");
  }
  {
    // Timestamp comparison by seconds.
    auto result =
        sut.value()->CompileAndEvaluate("target.signing_time >= timestamp(1748436989)", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Timestamp comparison by date string.
    auto result = sut.value()->CompileAndEvaluate(
        "target.signing_time >= timestamp('2025-05-28T12:00:00Z')", activation);
    if (!result.ok()) {
      XCTFail(@"Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Static - is_platform_binary on target
    auto result = sut.value()->CompileAndEvaluate("target.is_platform_binary == false", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Static - team_id on target
    auto result = sut.value()->CompileAndEvaluate("target.team_id == 'EQHXZ8M8AV'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Combined - is_platform_binary and team_id
    auto result = sut.value()->CompileAndEvaluate(
        "!target.is_platform_binary && target.team_id == 'EQHXZ8M8AV'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Re-use of a compiled expression.
    google::protobuf::Arena arena;
    auto expr =
        sut.value()->Compile("target.signing_time >= timestamp('2025-05-28T12:00:00Z')", &arena);
    if (!expr.ok()) {
      XCTFail("Failed to compile: %s", expr.status().message().data());
    }

    auto result = sut.value()->Evaluate(expr.value().get(), activation, &arena);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, true);
    }

    auto f2 = std::make_unique<ExecutableFileT>();
    f2->mutable_signing_time()->set_seconds(1716916129);
    santa::cel::Activation<true> activation2(
        std::move(f2),
        ^std::vector<std::string>() {
          return {"hello", "world"};
        },
        ^std::map<std::string, std::string>() {
          return {{"DYLD_INSERT_LIBRARIES", "1"}};
        },
        ^uid_t() {
          return 501;
        },
        ^std::string() {
          return "/Users/foo";
        },
        ^std::string() {
          return "/usr/bin/test";
        },
        ^std::vector<santa::cel::v2::Ancestor>() {
          return {};
        },
        ^std::vector<FileDescriptorT>() {
          return {};
        });

    auto result2 = sut.value()->Evaluate(expr.value().get(), activation2, &arena);
    if (!result2.ok()) {
      XCTFail("Failed to evaluate: %s", result2.status().message().data());
    } else {
      XCTAssertEqual(result2.value().value, ReturnValue::BLOCKLIST);
      XCTAssertEqual(result2.value().cacheable, true);
    }
  }
  {
    // Dynamic - process args
    auto result = sut.value()->CompileAndEvaluate("args[0] == 'hello'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Dynamic, env vars, ternary
    auto result = sut.value()->CompileAndEvaluate(
        "! has(envs.DYLD_INSERT_LIBRARIES) ? ALLOWLIST : BLOCKLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test memoization
    __block int argsCallCount = 0;
    santa::cel::Activation<true> activation(
        std::move(f),
        ^std::vector<std::string>() {
          argsCallCount++;
          return {"hello", "world"};
        },
        ^std::map<std::string, std::string>() {
          return {{"DYLD_INSERT_LIBRARIES", "1"}};
        },
        ^uid_t() {
          return 0;
        },
        ^std::string {
          return "/";
        },
        ^std::string() {
          return "/usr/bin/test";
        },
        ^std::vector<santa::cel::v2::Ancestor>() {
          return {};
        },
        ^std::vector<FileDescriptorT>() {
          return {};
        });

    auto result = sut.value()->CompileAndEvaluate(
        "args[0] == 'foo' || args[0] == 'bar' || args[0] == 'hello'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
    XCTAssertEqual(argsCallCount, 1);
  }
  {
    // Test args.join(' ') - joining arguments with space
    auto result = sut.value()->CompileAndEvaluate("args.join(' ') == 'hello world'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Dynamic - filepath via path field
    auto result = sut.value()->CompileAndEvaluate("path == '/usr/bin/test'", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Dynamic - path with startsWith
    auto result = sut.value()->CompileAndEvaluate("path.startsWith('/usr/bin')", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testAuditReturnValue {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  XCTAssertEqual(santa::cel::CELProtoTraits<true>::AUDIT, ::santa::cel::v2::AUDIT);

  auto f = std::make_unique<ExecutableFileT>();
  f->set_team_id("EQHXZ8M8AV");
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Static - AUDIT returned when team_id matches
    auto result = sut.value()->CompileAndEvaluate(
        "target.team_id == 'EQHXZ8M8AV' ? AUDIT : ALLOWLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::AUDIT);
      XCTAssertEqual(result.value().cacheable, true);
    }
  }
  {
    // Dynamic - AUDIT returned when args non-empty
    auto result = sut.value()->CompileAndEvaluate("size(args) > 0 ? AUDIT : ALLOWLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::AUDIT);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testV2Only {
  auto argsFn = ^std::vector<std::string>() {
    return {"hello", "world"};
  };
  auto envsFn = ^std::map<std::string, std::string>() {
    return {{"DYLD_INSERT_LIBRARIES", "1"}};
  };
  auto euidFn = ^uid_t() {
    return 0;
  };
  auto cwdFn = ^std::string() {
    return "/";
  };
  auto pathFn = ^std::string() {
    return "/usr/bin/test";
  };
  auto ancestorsV1Fn = ^std::vector<santa::cel::CELProtoTraits<false>::AncestorT>() {
    return {};
  };
  auto ancestorsV2Fn = ^std::vector<santa::cel::CELProtoTraits<true>::AncestorT>() {
    return {};
  };
  auto fdsV1Fn = ^std::vector<santa::cel::CELProtoTraits<false>::FileDescriptorT>() {
    return {};
  };
  auto fdsV2Fn = ^std::vector<santa::cel::CELProtoTraits<true>::FileDescriptorT>() {
    return {};
  };

  {
    // V1
    auto f = std::make_unique<santa::cel::CELProtoTraits<false>::ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    santa::cel::Activation<false> activation(std::move(f), argsFn, envsFn, euidFn, cwdFn, pathFn,
                                             ancestorsV1Fn, fdsV1Fn);
    auto sut = santa::cel::Evaluator<false>::Create();
    XCTAssertTrue(sut.ok());

    // V1 does not support the TOUCHID return value
    auto result =
        sut.value()->CompileAndEvaluate("euid == 0 ? REQUIRE_TOUCHID : BLOCKLIST", activation);
    XCTAssertFalse(result.ok());
  }

  {
    // V2
    using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
    auto f = std::make_unique<santa::cel::CELProtoTraits<true>::ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1748436989);
    santa::cel::Activation<true> activation(std::move(f), argsFn, envsFn, euidFn, cwdFn, pathFn,
                                            ancestorsV2Fn, fdsV2Fn);
    auto sut = santa::cel::Evaluator<true>::Create();
    XCTAssertTrue(sut.ok());

    // V2 _does_ support the TOUCHID return value
    auto result =
        sut.value()->CompileAndEvaluate("euid == 0 ? REQUIRE_TOUCHID : BLOCKLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testFds {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;
  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        FileDescriptorT fd0;
        fd0.set_fd(0);
        fd0.set_type(FileDescriptorT::FD_TYPE_VNODE);
        FileDescriptorT fd1;
        fd1.set_fd(1);
        fd1.set_type(FileDescriptorT::FD_TYPE_PIPE);
        FileDescriptorT fd2;
        fd2.set_fd(2);
        fd2.set_type(FileDescriptorT::FD_TYPE_SOCKET);
        return {fd0, fd1, fd2};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Test fds size
    auto result = sut.value()->CompileAndEvaluate("size(fds) == 3", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test fd number access
    auto result = sut.value()->CompileAndEvaluate("fds[0].fd == 0u", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test fd type enum comparison
    auto result = sut.value()->CompileAndEvaluate("fds[0].type == FD_TYPE_VNODE", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test exists comprehension over fds
    auto result =
        sut.value()->CompileAndEvaluate("fds.exists(f, f.type == FD_TYPE_SOCKET)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
  {
    // Test no match with exists
    auto result =
        sut.value()->CompileAndEvaluate("fds.exists(f, f.type == FD_TYPE_KQUEUE)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
      XCTAssertEqual(result.value().cacheable, false);
    }
  }
}

- (void)testTouchIDCooldownFunctions {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation<true> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {"hello", "world"};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  {
    // Test require_touchid_with_cooldown_minutes returns REQUIRE_TOUCHID
    auto result =
        sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(10)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 10ULL);
    }
  }
  {
    // Test require_touchid_only_with_cooldown_minutes returns REQUIRE_TOUCHID_ONLY
    auto result = sut.value()->CompileAndEvaluate("require_touchid_only_with_cooldown_minutes(5)",
                                                  activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID_ONLY);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 5ULL);
    }
  }
  {
    // Test conditional usage with cooldown function
    auto result = sut.value()->CompileAndEvaluate(
        "euid == 0 ? require_touchid_with_cooldown_minutes(15) : ALLOWLIST", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 15ULL);
    }
  }
  {
    // Test standard REQUIRE_TOUCHID constant (no cooldown function) - should have no cooldown
    auto result = sut.value()->CompileAndEvaluate("REQUIRE_TOUCHID", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertFalse(result.value().touchIDCooldownMinutes.has_value());
    }
  }
  {
    // Test negative value is treated as 0
    auto result =
        sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(-5)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 0ULL);
    }
  }
  {
    // Test zero cooldown
    auto result =
        sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(0)", activation);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::REQUIRE_TOUCHID);
      XCTAssertTrue(result.value().touchIDCooldownMinutes.has_value());
      XCTAssertEqual(result.value().touchIDCooldownMinutes.value(), 0ULL);
    }
  }
}

- (void)testTouchIDCooldownNotAvailableInV1 {
  using ExecutableFileT = santa::cel::CELProtoTraits<false>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<false>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<false>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1748436989);
  santa::cel::Activation<false> activation(
      std::move(f),
      ^std::vector<std::string>() {
        return {};
      },
      ^std::map<std::string, std::string>() {
        return {};
      },
      ^uid_t() {
        return 0;
      },
      ^std::string() {
        return "/";
      },
      ^std::string() {
        return "/usr/bin/test";
      },
      ^std::vector<AncestorT>() {
        return {};
      },
      ^std::vector<FileDescriptorT>() {
        return {};
      });

  auto sut = santa::cel::Evaluator<false>::Create();
  XCTAssertTrue(sut.ok());

  // V1 should not support TouchID cooldown functions
  auto result =
      sut.value()->CompileAndEvaluate("require_touchid_with_cooldown_minutes(10)", activation);
  XCTAssertFalse(result.ok());
}

- (void)testDaysFunction {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto f = std::make_unique<ExecutableFileT>();
  f->mutable_signing_time()->set_seconds(1699999200);
  santa::cel::Activation<true> activation(
      std::move(f), ^std::vector<std::string>() { return {}; },
      ^std::map<std::string, std::string>() { return {}; }, ^uid_t() { return 0; },
      ^std::string() { return "/"; }, ^std::string() { return "/usr/bin/test"; },
      ^std::vector<AncestorT>() { return {}; }, ^std::vector<FileDescriptorT>() { return {}; });

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  // days(30) is 720 hours.
  auto result = sut.value()->CompileAndEvaluate(
      "days(30) == duration('720h') ? ALLOWLIST : BLOCKLIST", activation);
  if (!result.ok()) {
    XCTFail("Failed to evaluate: %s", result.status().message().data());
  } else {
    XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
  }
}

- (void)testAgeFunction {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  // Helper to build an activation for a binary signed at `signingSeconds`.
  auto makeActivation = [](int64_t signingSeconds) {
    auto f = std::make_unique<ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(signingSeconds);
    return std::make_unique<santa::cel::Activation<true>>(
        std::move(f), ^std::vector<std::string>() { return {}; },
        ^std::map<std::string, std::string>() { return {}; }, ^uid_t() { return 0; },
        ^std::string() { return "/"; }, ^std::string() { return "/usr/bin/test"; },
        ^std::vector<AncestorT>() { return {}; }, ^std::vector<FileDescriptorT>() { return {}; });
  };

  // Both values are hour-aligned: 1699999200 and +40 days (3,456,000s = 960h).
  const int64_t kSigned = 1699999200;
  const int64_t kNow = kSigned + 40 * 86400;  // exactly 40 days later
  santa::cel::SetClockOverrideForTesting(absl::FromUnixSeconds(kNow));

  {
    // age is exactly 40 days == 960h.
    auto act = makeActivation(kSigned);
    auto result = sut.value()->CompileAndEvaluate(
        "age(target.signing_time) == duration('960h') ? ALLOWLIST : BLOCKLIST", *act);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    }
  }
  {
    // Quantization: advancing 'now' by 30 minutes (still in the same hour
    // bucket) leaves the computed age unchanged at 960h.
    santa::cel::SetClockOverrideForTesting(absl::FromUnixSeconds(kNow + 1800));
    auto act = makeActivation(kSigned);
    auto result = sut.value()->CompileAndEvaluate(
        "age(target.signing_time) == duration('960h') ? ALLOWLIST : BLOCKLIST", *act);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    }
    santa::cel::SetClockOverrideForTesting(absl::FromUnixSeconds(kNow));
  }
  {
    // Future signing time clamps to zero age.
    auto act = makeActivation(kNow + 86400);  // signed 1 day in the "future"
    auto result = sut.value()->CompileAndEvaluate(
        "age(target.signing_time) == duration('0') ? ALLOWLIST : BLOCKLIST", *act);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    }
  }

  santa::cel::ClearClockOverrideForTesting();
}

- (void)testOlderThanFunction {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  auto makeActivation = [](int64_t signingSeconds, bool setSecure) {
    auto f = std::make_unique<ExecutableFileT>();
    if (signingSeconds >= 0) f->mutable_signing_time()->set_seconds(signingSeconds);
    if (setSecure && signingSeconds >= 0) f->mutable_secure_signing_time()->set_seconds(signingSeconds);
    return std::make_unique<santa::cel::Activation<true>>(
        std::move(f), ^std::vector<std::string>() { return {}; },
        ^std::map<std::string, std::string>() { return {}; }, ^uid_t() { return 0; },
        ^std::string() { return "/"; }, ^std::string() { return "/usr/bin/test"; },
        ^std::vector<AncestorT>() { return {}; }, ^std::vector<FileDescriptorT>() { return {}; });
  };

  const int64_t kSigned = 1699999200;
  const int64_t kNow = kSigned + 40 * 86400;  // 40 days old
  santa::cel::SetClockOverrideForTesting(absl::FromUnixSeconds(kNow));

  {
    // 40 days old > 30 days -> older_than true -> BLOCKLIST branch.
    auto act = makeActivation(kSigned, /*setSecure=*/false);
    auto result = sut.value()->CompileAndEvaluate(
        "older_than(target.signing_time, days(30)) ? BLOCKLIST : ALLOWLIST", *act);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    }
  }
  {
    // 40 days old is NOT older than 50 days -> false -> ALLOWLIST branch.
    auto act = makeActivation(kSigned, /*setSecure=*/false);
    auto result = sut.value()->CompileAndEvaluate(
        "older_than(target.signing_time, days(50)) ? BLOCKLIST : ALLOWLIST", *act);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    }
  }
  {
    // Unsigned binary: secure_signing_time unset (epoch 0) -> very large age ->
    // older_than(..., days(30)) is true.
    auto act = makeActivation(kSigned, /*setSecure=*/false);  // secure_signing_time left unset
    auto result = sut.value()->CompileAndEvaluate(
        "older_than(target.secure_signing_time, days(30)) ? BLOCKLIST : ALLOWLIST", *act);
    if (!result.ok()) {
      XCTFail("Failed to evaluate: %s", result.status().message().data());
    } else {
      XCTAssertEqual(result.value().value, ReturnValue::BLOCKLIST);
    }
  }

  santa::cel::ClearClockOverrideForTesting();
}

- (void)testAgeCacheability {
  using ReturnValue = santa::cel::CELProtoTraits<true>::ReturnValue;
  using ExecutableFileT = santa::cel::CELProtoTraits<true>::ExecutableFileT;
  using AncestorT = santa::cel::CELProtoTraits<true>::AncestorT;
  using FileDescriptorT = santa::cel::CELProtoTraits<true>::FileDescriptorT;

  auto sut = santa::cel::Evaluator<true>::Create();
  XCTAssertTrue(sut.ok());

  auto makeActivation = []() {
    auto f = std::make_unique<ExecutableFileT>();
    f->mutable_signing_time()->set_seconds(1699999200);
    f->set_is_platform_binary(false);
    return std::make_unique<santa::cel::Activation<true>>(
        std::move(f), ^std::vector<std::string>() { return {}; },
        ^std::map<std::string, std::string>() { return {}; }, ^uid_t() { return 0; },
        ^std::string() { return "/"; }, ^std::string() { return "/usr/bin/test"; },
        ^std::vector<AncestorT>() { return {}; }, ^std::vector<FileDescriptorT>() { return {}; });
  };

  santa::cel::SetClockOverrideForTesting(absl::FromUnixSeconds(1699999200 + 40 * 86400));

  {
    // older_than reads the clock -> NOT cacheable.
    auto act = makeActivation();
    auto result = sut.value()->CompileAndEvaluate(
        "older_than(target.signing_time, days(30)) ? BLOCKLIST : ALLOWLIST", *act);
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().cacheable, false);
  }
  {
    // age reads the clock -> NOT cacheable.
    auto act = makeActivation();
    auto result = sut.value()->CompileAndEvaluate(
        "age(target.signing_time) > days(30) ? BLOCKLIST : ALLOWLIST", *act);
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().cacheable, false);
  }
  {
    // days() alone never reads the clock -> cacheable.
    auto act = makeActivation();
    auto result = sut.value()->CompileAndEvaluate(
        "days(30) == duration('720h') ? ALLOWLIST : BLOCKLIST", *act);
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().cacheable, true);
  }
  {
    // Static expression -> cacheable (regression guard).
    auto act = makeActivation();
    auto result = sut.value()->CompileAndEvaluate("target.is_platform_binary == false", *act);
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().cacheable, true);
  }
  {
    // Short-circuit: older_than is never evaluated, so the clock is never read
    // -> cacheable.
    auto act = makeActivation();
    auto result = sut.value()->CompileAndEvaluate(
        "(false && older_than(target.signing_time, days(30))) ? BLOCKLIST : ALLOWLIST", *act);
    XCTAssertTrue(result.ok());
    XCTAssertEqual(result.value().value, ReturnValue::ALLOWLIST);
    XCTAssertEqual(result.value().cacheable, true);
  }

  santa::cel::ClearClockOverrideForTesting();
}

@end
