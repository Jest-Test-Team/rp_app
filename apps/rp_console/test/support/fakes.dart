// Test doubles. The simulated device lives in lib/demo (also used by demo mode).
import 'dart:convert';

import 'package:rp_console/core/provision/ssh_bootstrap.dart';

export 'package:rp_console/demo/demo_device.dart';

/// A scripted shell: answers by command prefix and records everything.
class FakeShell implements Shell {
  FakeShell(this.answers);
  final List<(String, ExecResult)> answers;
  final execs = <(String, String?)>[];
  bool closed = false;

  @override
  Future<ExecResult> exec(String command, {List<int>? stdin}) async {
    execs.add((command, stdin == null ? null : utf8.decode(stdin)));
    for (final (prefix, r) in answers) {
      if (command.startsWith(prefix) || command.contains(prefix)) return r;
    }
    return ExecResult(0, '', '');
  }

  @override
  Future<void> close() async => closed = true;
}
