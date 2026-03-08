load("@rules_cc//cc:defs.bzl", "cc_library")
load("//:helper.bzl", "santa_unit_test")

package(
    default_visibility = ["//:santa_package_group"],
)

cc_library(
    name = "annotator",
    hdrs = ["annotator.h"],
    deps = [
        "//Source/santad/ProcessTree:process_tree_cc_proto",
    ],
)

cc_library(
    name = "originator",
    srcs = ["originator.cc"],
    hdrs = ["originator.h"],
    deps = [
        ":annotator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "@abseil-cpp//absl/container:flat_hash_map",
    ],
)

cc_library(
    name = "agent_session",
    srcs = ["agent_session.cc"],
    hdrs = ["agent_session.h"],
    deps = [
        ":annotator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "@abseil-cpp//absl/strings",
    ],
)

santa_unit_test(
    name = "originator_test",
    srcs = ["originator_test.mm"],
    deps = [
        ":originator",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
    ],
)

santa_unit_test(
    name = "agent_session_test",
    srcs = ["agent_session_test.mm"],
    deps = [
        ":agent_session",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
    ],
)

santa_unit_test(
    name = "agent_session_e2e_test",
    srcs = ["agent_session_e2e_test.mm"],
    deps = [
        ":agent_session",
        "//Source/common/cel:CEL",
        "//Source/santad/ProcessTree:process",
        "//Source/santad/ProcessTree:process_tree_cc_proto",
        "//Source/santad/ProcessTree:process_tree_test_helpers",
    ],
)
