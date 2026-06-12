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

#include "Source/common/cel/AgeFunction.h"

#include <cstdint>
#include <optional>

#include "absl/status/status.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"

// CEL headers have warnings and our config turns them into errors.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshorten-64-to-32"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include "common/decl.h"
#include "common/type.h"
#include "internal/status_macros.h"
#include "runtime/function_adapter.h"
#pragma clang diagnostic pop

namespace santa {
namespace cel {

namespace {

using ::cel::BoolType;
using ::cel::DurationType;
using ::cel::IntType;
using ::cel::MakeFunctionDecl;
using ::cel::MakeOverloadDecl;
using ::cel::TimestampType;

// "now" is bucketed to this quantum so relative-age verdicts are stable within
// the bucket (top of the current hour).
absl::Duration ClockQuantum() { return absl::Hours(1); }

// thread_local so concurrent santad evaluations and concurrent test cases each
// see their own state.
thread_local std::optional<absl::Time> tClockOverride;
thread_local bool tClockWasRead = false;

// Current time, quantized down to the start of the current ClockQuantum bucket.
absl::Time QuantizedNow() {
  absl::Time now = tClockOverride.has_value() ? *tClockOverride : absl::Now();
  absl::Duration sinceEpoch = now - absl::UnixEpoch();
  absl::Duration remainder;
  int64_t buckets = absl::IDivDuration(sinceEpoch, ClockQuantum(), &remainder);
  return absl::UnixEpoch() + ClockQuantum() * buckets;
}

// age(timestamp) -> duration : QuantizedNow() - ts, clamped to >= 0.
absl::Duration AgeImpl(absl::Time ts, const google::protobuf::DescriptorPool*,
                       google::protobuf::MessageFactory*, google::protobuf::Arena*) {
  tClockWasRead = true;
  absl::Duration age = QuantizedNow() - ts;
  return age < absl::ZeroDuration() ? absl::ZeroDuration() : age;
}

// days(int) -> duration : n days. Pure; does not read the clock.
absl::Duration DaysImpl(int64_t n, const google::protobuf::DescriptorPool*,
                        google::protobuf::MessageFactory*, google::protobuf::Arena*) {
  return absl::Hours(24 * n);
}

// older_than(timestamp, duration) -> bool : age(ts) > d.
bool OlderThanImpl(absl::Time ts, absl::Duration d, const google::protobuf::DescriptorPool*,
                   google::protobuf::MessageFactory*, google::protobuf::Arena*) {
  tClockWasRead = true;
  absl::Duration age = QuantizedNow() - ts;
  if (age < absl::ZeroDuration()) age = absl::ZeroDuration();
  return age > d;
}

absl::Status RegisterAgeDecls(::cel::TypeCheckerBuilder& builder) {
  CEL_ASSIGN_OR_RETURN(
      auto age_decl,
      MakeFunctionDecl("age", MakeOverloadDecl("age_timestamp", DurationType(), TimestampType())));
  CEL_ASSIGN_OR_RETURN(
      auto days_decl,
      MakeFunctionDecl("days", MakeOverloadDecl("days_int", DurationType(), IntType())));
  CEL_ASSIGN_OR_RETURN(
      auto older_than_decl,
      MakeFunctionDecl("older_than", MakeOverloadDecl("older_than_timestamp_duration", BoolType(),
                                                      TimestampType(), DurationType())));

  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(age_decl)));
  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(days_decl)));
  CEL_RETURN_IF_ERROR(builder.AddFunction(std::move(older_than_decl)));
  return absl::OkStatus();
}

}  // namespace

void ResetClockRead() { tClockWasRead = false; }
bool ClockWasRead() { return tClockWasRead; }

void SetClockOverrideForTesting(absl::Time t) { tClockOverride = t; }
void ClearClockOverrideForTesting() { tClockOverride = std::nullopt; }

absl::Status AddAgeCompilerLibrary(::cel::CompilerBuilder& builder) {
  return builder.AddLibrary(::cel::CompilerLibrary::FromCheckerLibrary({"age", &RegisterAgeDecls}));
}

absl::Status RegisterAgeFunctions(::google::api::expr::runtime::CelFunctionRegistry* registry,
                                  const ::google::api::expr::runtime::InterpreterOptions& options) {
  // These are eager (non-lazy, non-contextual) global overloads. If an
  // expression calls age()/older_than() with a *literal* timestamp argument
  // (e.g. older_than(timestamp('2020-01-01T00:00:00Z'), days(30))), the call is
  // fully constant and the compiler's constant-folding pass evaluates it once
  // at Compile() time: the clock is read then, the verdict is frozen, and the
  // runtime clock-read flag is never set (so the result is treated as
  // cacheable). Real rules pass target.signing_time / target.secure_signing_time
  // — a non-constant field access — so folding does not occur and the runtime
  // path (clock read + non-cacheable) is taken. Authors should not pass literal
  // timestamps to these helpers.
  auto& func_registry = registry->InternalGetRegistry();

  CEL_RETURN_IF_ERROR((::cel::UnaryFunctionAdapter<absl::Duration, absl::Time>::RegisterGlobalOverload(
      "age", &AgeImpl, func_registry)));
  CEL_RETURN_IF_ERROR((::cel::UnaryFunctionAdapter<absl::Duration, int64_t>::RegisterGlobalOverload(
      "days", &DaysImpl, func_registry)));
  CEL_RETURN_IF_ERROR(
      (::cel::BinaryFunctionAdapter<bool, absl::Time, absl::Duration>::RegisterGlobalOverload(
          "older_than", &OlderThanImpl, func_registry)));

  return absl::OkStatus();
}

}  // namespace cel
}  // namespace santa
