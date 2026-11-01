// Path B (plan §4.6): set up a Raspberry Pi that is already running, over a
// one-time SSH session with the user's own (non-root) account.
//
// * The SSH host key is shown / pinned trust-on-first-use.
// * The password is used for this session only and never stored. It is
//   written only to the stdin of `sudo -S -v` — never into a command line,
//   an environment variable or a log. If sudo needs no password it is not
//   sent at all (a stray line on stdin would be read by the next command).
// * The installer is downloaded over HTTPS and its SHA-256 checked before it
//   runs; `rpctl setup --json` then reports the pairing code over the same
//   authenticated channel, so the app can pin the device's certificate.

import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:dartssh2/dartssh2.dart';

import '../pairing/pairing.dart';
import 'bootfs.dart' show defaultRepo;

class ExecResult {
  ExecResult(this.code, this.stdout, this.stderr);
  final int code;
  final String stdout;
  final String stderr;
}

/// One command per call; `stdin` is written then closed.
abstract class Shell {
  Future<ExecResult> exec(String command, {List<int>? stdin});
  Future<void> close();
}

enum BootstrapStep { checking, downloading, installing, done }

class BootstrapError implements Exception {
  BootstrapError(this.code, this.message);
  final String code;
  final String message;
  @override
  String toString() => 'BootstrapError($code: $message)';
}

class Bootstrapper {
  Bootstrapper(
    this.shell, {
    required this.tag,
    required this.installSha256,
    this.repo = defaultRepo,
    this.pairingMinutes = 30,
  }) {
    if (!RegExp(r'^v\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$').hasMatch(tag)) throw ArgumentError('bad tag');
    if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(installSha256)) throw ArgumentError('bad sha256');
    if (!RegExp(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$').hasMatch(repo)) throw ArgumentError('bad repo');
    if (pairingMinutes < 1 || pairingMinutes > 1440) throw ArgumentError('bad minutes');
  }

  final Shell shell;
  final String tag;
  final String installSha256;
  final String repo;
  final int pairingMinutes;

  static const _supported = {'armv7l', 'aarch64'};

  /// Run the setup. `password` is used only if sudo asks for one.
  Future<PairingCode> run({required String host, String? password, void Function(BootstrapStep)? onStep}) async {
    onStep?.call(BootstrapStep.checking);
    final arch = (await shell.exec('uname -m')).stdout.trim();
    if (!_supported.contains(arch)) {
      throw BootstrapError(
        'unsupported_arch',
        arch == 'armv6l'
            ? 'Raspberry Pi 1 and Zero (ARMv6) are not supported.'
            : 'This device ($arch) is not supported.',
      );
    }
    final passwordless = (await shell.exec('sudo -n true')).code == 0;
    if (!passwordless && (password == null || password.isEmpty)) {
      throw BootstrapError('password_needed', 'Enter the password of this account (used once, never stored).');
    }

    onStep?.call(BootstrapStep.downloading);
    final url = 'https://github.com/$repo/releases/download/$tag/install.sh';
    final dl = await shell.exec(
      "curl -fsSL --proto =https --retry 5 -o /tmp/rp-install.sh '$url' && "
      "echo '$installSha256  /tmp/rp-install.sh' | sha256sum -c -",
    );
    if (dl.code != 0) {
      throw BootstrapError('download_failed', 'Could not download and verify the installer: ${_tail(dl.stderr)}');
    }

    onStep?.call(BootstrapStep.installing);
    final steps =
        "sudo -n bash /tmp/rp-install.sh --release $tag --repo $repo </dev/null >&2 && "
        "sudo -n rpctl --json setup --pairing-minutes $pairingMinutes </dev/null; rc=\$?; rm -f /tmp/rp-install.sh; exit \$rc";
    final ExecResult r;
    if (passwordless) {
      r = await shell.exec(steps);
    } else {
      // One exec: `sudo -S -v` consumes exactly the first stdin line and
      // caches the credential for the `sudo -n` calls that follow.
      r = await shell.exec("sudo -S -p '' -v && { $steps; }", stdin: utf8.encode('$password\n'));
    }
    if (r.code != 0) {
      if (!passwordless && r.stderr.contains('incorrect password')) {
        throw BootstrapError('wrong_password', 'The password was not accepted.');
      }
      throw BootstrapError('setup_failed', 'Setup failed: ${_tail(r.stderr.isEmpty ? r.stdout : r.stderr)}');
    }
    final last = r.stdout.trim().split('\n').last;
    final Object? report;
    try {
      report = jsonDecode(last);
    } on FormatException {
      throw BootstrapError('setup_failed', 'Unexpected output from the device.');
    }
    final pairing = report is Map ? report['pairing'] : null;
    if (pairing is! Map) {
      throw BootstrapError(
        'already_paired',
        'This device already has an app paired. Pair from that app (Add phone), or run `sudo rpctl pairing new` on the device.',
      );
    }
    onStep?.call(BootstrapStep.done);
    // Connect to the address we reached over SSH (".local" may not resolve).
    final p = Map<String, Object?>.from(pairing)..['host'] = host;
    return PairingCode.parse(jsonEncode(p));
  }

  static String _tail(String s) {
    final t = s.trim();
    return t.length > 300 ? '…${t.substring(t.length - 300)}' : t;
  }
}

/// A real SSH session (dartssh2).
class DartSshShell implements Shell {
  DartSshShell._(this._client);
  final SSHClient _client;

  /// `verifyHostKey` receives the key type and SHA-256 fingerprint (hex);
  /// return false to abort (e.g. it changed since last time).
  static Future<DartSshShell> connect({
    required String host,
    int port = 22,
    required String user,
    String? password,
    List<SSHKeyPair>? keys,
    required FutureOr<bool> Function(String type, String sha256Hex) verifyHostKey,
  }) async {
    final socket = await SSHSocket.connect(host, port, timeout: const Duration(seconds: 10));
    final client = SSHClient(
      socket,
      username: user,
      identities: keys,
      onPasswordRequest: password == null ? null : () => password,
      onVerifyHostKey: (type, fp) => verifyHostKey(type, fp.map((b) => b.toRadixString(16).padLeft(2, '0')).join()),
    );
    await client.authenticated;
    return DartSshShell._(client);
  }

  @override
  Future<ExecResult> exec(String command, {List<int>? stdin}) async {
    final s = await _client.execute(command);
    final out = BytesBuilder(), err = BytesBuilder();
    final a = s.stdout.listen(out.add).asFuture<void>();
    final b = s.stderr.listen(err.add).asFuture<void>();
    if (stdin != null) s.stdin.add(Uint8List.fromList(stdin));
    await s.stdin.close();
    await s.done;
    await Future.wait([a, b]);
    return ExecResult(
      s.exitCode ?? -1,
      utf8.decode(out.takeBytes(), allowMalformed: true),
      utf8.decode(err.takeBytes(), allowMalformed: true),
    );
  }

  @override
  Future<void> close() async => _client.close();
}
