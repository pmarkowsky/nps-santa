/// Copyright 2026 North Pole Security, Inc.
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

#ifndef SANTA_COMMON_CEL_AGEFUNCTION_H
#define SANTA_COMMON_CEL_AGEFUNCTION_H

#include "absl/status/status.h"
#include "absl/time/time.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "compiler/compiler.h"
#include "eval/public/cel_function_registry.h"
#include "eval/public/cel_options.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

// Register the relative-age helper declarations at compile time (type checking).
// These functions are only available in CELv2.
absl::Status AddAgeCompilerLibrary(::cel::CompilerBuilder& builder);

// Register the relative-age helper implementations at runtime.
absl::Status RegisterAgeFunctions(
    ::google::api::expr::runtime::CelFunctionRegistry* registry,
    const ::google::api::expr::runtime::InterpreterOptions& options);

// Clock-read tracking. age()/older_than() set the flag when they read the
// clock. The intended consumer is Evaluator::Evaluate (wired up in a later
// change): it will reset the flag before evaluation and read it after to
// determine whether the result is time-dependent (and therefore not cacheable).
void ResetClockRead();
bool ClockWasRead();

// Test-only clock override. When set, QuantizedNow() reads this instead of
// absl::Now(). thread_local so concurrent test cases stay independent.
void SetClockOverrideForTesting(absl::Time t);
void ClearClockOverrideForTesting();

}  // namespace cel
}  // namespace santa

#endif  // SANTA_COMMON_CEL_AGEFUNCTION_H
