// The SD-card files must be byte-identical to rp_core::provision (shared
// goldens), parse as YAML with the expected structure, and keep the pairing
// secret out of user-data.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rp_console/core/provision/bootfs.dart';
import 'package:yaml/yaml.dart';

ProvisionSpec spec(String name) => ProvisionSpec.fromJson(
  jsonDecode(File('../../test/fixtures/provision/$name.spec.json').readAsStringSync()) as Map<String, Object?>,
);

Map<String, Object?> golden(String name) =>
    (jsonDecode(File('../../test/fixtures/provision/$name.files.json').readAsStringSync()) as Map)
        .cast<String, Object?>();

void main() {
  for (final name in ['minimal', 'full']) {
    test('$name card matches the Rust golden files', () {
      expect(files(spec(name)), golden(name));
    });
  }

  test('user-data is valid cloud-config with the secret off the card first', () {
    final s = spec('full');
    final f = files(s);
    final ud = loadYaml(f['user-data']!) as YamlMap;
    expect(ud['hostname'], 'rp-garage');
    expect(ud['ssh_pwauth'], false);
    expect(ud['users'][0]['lock_passwd'], true);
    final run = (ud['runcmd'] as YamlList).map((e) => e.toString()).toList();
    final shred = run.indexWhere((c) => c.contains('shred'));
    final download = run.indexWhere((c) => c.contains('rp-install.sh'));
    expect(shred, greaterThanOrEqualTo(0));
    expect(shred, lessThan(download));
    expect(f['user-data'], isNot(contains(s.pairingSecret)));
    final nc = loadYaml(f['network-config']!) as YamlMap;
    final aps = nc['network']['wifis']['wlan0']['access-points'] as YamlMap;
    expect(aps.keys.single, 'Example "Home": Wi-Fi #2');
    expect(aps.values.single['password'], 'p@ss: w0rd\'"\\x');
  });

  test('invalid input is rejected (same rules as Rust)', () {
    final bad = ProvisionSpec(
      hostname: 'bad host',
      tag: 'main; rm -rf /',
      installSha256: 'x',
      repo: 'evil',
      pairingSecret: '0123456789abcdef' * 4,
      instanceId: 'rp-1',
      adminUser: 'Root',
      adminKey: 'ssh-ed25519 AAA\nrm -rf /',
      wifi: WifiSpec(ssid: '', password: 'short', country: 'TWN'),
    );
    expect(validate(bad), hasLength(9));
    expect(() => files(bad), throwsA(isA<InvalidSpec>()));
  });

  test('meta-data gets a fresh instance id like Rust', () {
    expect(metaData('dsmode: local\ninstance_id: rpios-old\n', 'rp-new'), 'dsmode: local\ninstance_id: rp-new\n');
    expect(metaData('', 'x'), 'dsmode: local\ninstance_id: x\n');
    expect(metaData('a: 1\n\nb: 2\r\n', 'x'), 'a: 1\n\nb: 2\ndsmode: local\ninstance_id: x\n');
  });

  test('writeCard refuses anything but a flashed boot partition', () {
    final d = Directory.systemTemp.createTempSync('rp-boot');
    addTearDown(() => d.deleteSync(recursive: true));
    expect(() => writeCard(d, spec('minimal')), throwsStateError);
    File('${d.path}/cmdline.txt').writeAsStringSync('console=serial0');
    File('${d.path}/meta-data').writeAsStringSync('dsmode: local\ninstance_id: old\n');
    final written = writeCard(d, spec('minimal'));
    expect(written, containsAll(['user-data', 'rp-pairing.toml', 'meta-data']));
    expect(File('${d.path}/meta-data').readAsStringSync(), contains('instance_id: rp-1793500000'));
    expect(File('${d.path}/network-config').existsSync(), isFalse);
  });
}
