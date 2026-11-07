import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/provision/ssh_bootstrap.dart';

import '../support/fakes.dart';

const sha = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
final pairing = jsonEncode({
  'config_written': false,
  'pairing': {
    'v': 1,
    'host': 'raspberrypi.local',
    'port': 8443,
    'device': kDevice,
    'secret': kSecret,
    'cert': 'cc' * 32,
  },
});

FakeShell shell({
  bool passwordless = false,
  String arch = 'armv7l',
  String setupOut = '',
  int setupCode = 0,
  int dlCode = 0,
  String err = '',
}) => FakeShell([
  ('uname -m', ExecResult(0, '$arch\n', '')),
  ('sudo -n true', ExecResult(passwordless ? 0 : 1, '', 'sudo: a password is required')),
  ('curl -fsSL', ExecResult(dlCode, '', dlCode == 0 ? '' : 'sha256sum: WARNING: 1 computed checksum did NOT match')),
  ('rpctl --json setup', ExecResult(setupCode, setupOut.isEmpty ? 'log line\n$pairing\n' : setupOut, err)),
]);

Future<Object?> caught(Future<Object?> f) async {
  try {
    await f;
    return null;
  } catch (e) {
    return e;
  }
}

void main() {
  const pw = 'hunter2-very-secret';

  test('password goes only to stdin of sudo -S -v, never into a command', () async {
    final sh = shell();
    final code = await Bootstrapper(sh, tag: 'v0.2.0', installSha256: sha).run(host: '192.0.2.10', password: pw);
    expect(code.secret, kSecret);
    expect(code.host, '192.0.2.10', reason: 'connect to the address we reached over SSH');
    expect(code.cert, 'cc' * 32);
    for (final (cmd, stdin) in sh.execs) {
      expect(cmd, isNot(contains(pw)));
      if (stdin != null) {
        expect(cmd, startsWith("sudo -S -p '' -v && "));
        expect(stdin, '$pw\n');
      }
    }
    expect(sh.execs.where((e) => e.$2 != null), hasLength(1));
    final install = sh.execs.firstWhere((e) => e.$1.contains('rp-install.sh --release')).$1;
    expect(install, contains('sudo -n bash /tmp/rp-install.sh --release v0.2.0'));
    expect(install, contains('</dev/null'), reason: 'nothing after sudo -v may read the password line');
  });

  test('passwordless sudo: the password is never sent', () async {
    final sh = shell(passwordless: true);
    await Bootstrapper(sh, tag: 'v0.2.0', installSha256: sha).run(host: 'h', password: pw);
    expect(sh.execs.every((e) => e.$2 == null), isTrue);
    expect(sh.execs.any((e) => e.$1.contains('sudo -S')), isFalse);
  });

  test('the installer is checked against the pinned SHA-256 before it runs', () async {
    final sh = shell(dlCode: 1);
    await expectLater(
      Bootstrapper(sh, tag: 'v0.2.0', installSha256: sha).run(host: 'h', password: pw),
      throwsA(isA<BootstrapError>().having((e) => e.code, 'code', 'download_failed')),
    );
    expect(sh.execs.any((e) => e.$1.contains('rp-install.sh --release')), isFalse);
    final dl = sh.execs.firstWhere((e) => e.$1.startsWith('curl')).$1;
    expect(dl, contains("echo '$sha  /tmp/rp-install.sh' | sha256sum -c -"));
    expect(dl, contains('--proto =https'));
  });

  test('unsupported boards stop before anything is downloaded', () async {
    final sh = shell(arch: 'armv6l');
    await expectLater(
      Bootstrapper(sh, tag: 'v0.2.0', installSha256: sha).run(host: 'h', password: pw),
      throwsA(isA<BootstrapError>().having((e) => e.code, 'code', 'unsupported_arch')),
    );
    expect(sh.execs.any((e) => e.$1.startsWith('curl')), isFalse);
  });

  test('a password is required when sudo asks for one', () async {
    await expectLater(
      Bootstrapper(shell(), tag: 'v0.2.0', installSha256: sha).run(host: 'h'),
      throwsA(isA<BootstrapError>().having((e) => e.code, 'code', 'password_needed')),
    );
  });

  test('wrong password and setup failures are reported without echoing secrets', () async {
    final e1 = await caught(
      Bootstrapper(
        shell(setupCode: 1, err: 'sudo: 1 incorrect password attempt'),
        tag: 'v0.2.0',
        installSha256: sha,
      ).run(host: 'h', password: pw),
    );
    expect((e1 as BootstrapError).code, 'wrong_password');
    expect(e1.message, isNot(contains(pw)));
    final e2 = await caught(
      Bootstrapper(
        shell(setupOut: '{"pairing": null}\n'),
        tag: 'v0.2.0',
        installSha256: sha,
      ).run(host: 'h', password: pw),
    );
    expect((e2 as BootstrapError).code, 'already_paired');
    final e3 = await caught(
      Bootstrapper(
        shell(setupOut: 'garbage'),
        tag: 'v0.2.0',
        installSha256: sha,
      ).run(host: 'h', password: pw),
    );
    expect((e3 as BootstrapError).code, 'setup_failed');
  });

  test('inputs that end up in commands are validated', () {
    final sh = shell();
    expect(() => Bootstrapper(sh, tag: "v0.2.0'; reboot; '", installSha256: sha), throwsArgumentError);
    expect(() => Bootstrapper(sh, tag: 'v0.2.0', installSha256: 'x'), throwsArgumentError);
    expect(() => Bootstrapper(sh, tag: 'v0.2.0', installSha256: sha, repo: 'a/b c'), throwsArgumentError);
  });
}
