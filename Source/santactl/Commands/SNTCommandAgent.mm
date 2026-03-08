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

#include <errno.h>
#include <string.h>
#include <unistd.h>

#import "Source/santactl/SNTCommand.h"
#import "Source/santactl/SNTCommandController.h"

@interface SNTCommandAgent : SNTCommand <SNTCommandProtocol>
@end

@implementation SNTCommandAgent

REGISTER_COMMAND_NAME(@"agent")

+ (BOOL)requiresRoot {
  return NO;
}

+ (BOOL)requiresDaemonConn {
  return NO;
}

+ (NSString *)shortHelpText {
  return @"Launch an AI coding agent with process tree annotation.";
}

+ (NSString *)longHelpText {
  return @"Usage: santactl agent exec [options] -- <command> [args...]\n"
         @"\n"
         @"Options:\n"
         @"  --session-name <name>  Human-readable session label (default: inferred from command)\n"
         @"  --policy <name>        Named policy set for CEL rule matching\n"
         @"  --tag <key:value>      Repeatable key:value tag (max 16 tags)\n"
         @"\n"
         @"Launches the given command via execvp. santad's annotator recognizes this\n"
         @"invocation and applies an agent_session annotation to the process tree,\n"
         @"which propagates to all child processes.\n"
         @"\n"
         @"Examples:\n"
         @"  santactl agent exec -- claude\n"
         @"  santactl agent exec --policy restricted -- claude --flag\n"
         @"  santactl agent exec --tag team:platform --tag env:prod -- codex";
}

- (void)runWithArguments:(NSArray *)arguments {
  if (arguments.count == 0 || ![arguments[0] isEqualToString:@"exec"]) {
    [self printErrorUsageAndExit:@"Expected subcommand: exec"];
  }

  // Parse arguments after "exec".
  NSMutableArray *agentArgs = [NSMutableArray array];
  NSString *commandPath = nil;
  BOOL foundSeparator = NO;

  for (NSUInteger i = 1; i < arguments.count; i++) {
    NSString *arg = arguments[i];

    if ([arg isEqualToString:@"--"]) {
      foundSeparator = YES;
      // Remaining args are the command and its arguments.
      for (NSUInteger j = i + 1; j < arguments.count; j++) {
        [agentArgs addObject:arguments[j]];
      }
      break;
    }

    // Consume known options (they are parsed by santad's annotator from argv,
    // not here, but we skip them to validate the command line).
    if ([arg isEqualToString:@"--session-name"] || [arg isEqualToString:@"--policy"] ||
        [arg isEqualToString:@"--tag"]) {
      i++;  // Skip the value.
      continue;
    }

    [self printErrorUsageAndExit:[NSString stringWithFormat:@"Unknown option: %@", arg]];
  }

  if (!foundSeparator || agentArgs.count == 0) {
    [self printErrorUsageAndExit:@"No command specified after '--'"];
  }

  NSString *command = agentArgs[0];

  // Resolve the command path if not absolute.
  if (![command hasPrefix:@"/"]) {
    commandPath = [self resolveInPath:command];
    if (!commandPath) {
      fprintf(stderr, "santactl agent exec: command not found: %s\n", command.UTF8String);
      exit(127);
    }
  } else {
    commandPath = command;
  }

  // Build argv for execvp.
  int argc = (int)agentArgs.count;
  const char **argv = (const char **)calloc(argc + 1, sizeof(char *));
  for (int j = 0; j < argc; j++) {
    argv[j] = [agentArgs[j] UTF8String];
  }
  argv[argc] = NULL;

  execvp(commandPath.UTF8String, (char *const *)argv);

  // If we get here, execvp failed.
  fprintf(stderr, "santactl agent exec: execvp failed: %s\n", strerror(errno));
  exit(126);
}

- (NSString *)resolveInPath:(NSString *)command {
  NSString *pathEnv = [NSProcessInfo processInfo].environment[@"PATH"];
  if (!pathEnv) return nil;

  for (NSString *dir in [pathEnv componentsSeparatedByString:@":"]) {
    NSString *fullPath = [dir stringByAppendingPathComponent:command];
    if ([[NSFileManager defaultManager] isExecutableFileAtPath:fullPath]) {
      return fullPath;
    }
  }
  return nil;
}

@end
