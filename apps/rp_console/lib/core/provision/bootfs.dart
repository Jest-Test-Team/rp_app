// Path A (plan §4.6): prepare a freshly flashed SD card so the device
// installs rp on first boot and waits to be paired. A Dart port of
// rp_core::provision — both must produce the same bytes; the shared golden
// files in test/fixtures/provision pin that.

import 'dart:convert';
import 'dart:io';

const bootMount = '/boot/firmware';
const defaultRepo = 'Jest-Test-Team/rp_app';

class WifiSpec {
  WifiSpec({required this.ssid, required this.password, required this.country});
  final String ssid;
  final String password;
  final String country;

  static WifiSpec? fromJson(Object? j) => j is Map
      ? WifiSpec(ssid: j['ssid'] as String, password: j['password'] as String, country: j['country'] as String)
      : null;
}

class ProvisionSpec {
  ProvisionSpec({
    required this.hostname,
    required this.tag,
    required this.installSha256,
    this.repo = defaultRepo,
    required this.pairingSecret,
    required this.instanceId,
    this.adminUser,
    this.adminKey,
    this.wifi,
    this.timezone,
  });

  final String hostname;
  final String tag;
  final String installSha256;
  final String repo;
  final String pairingSecret;
  final String instanceId;
  final String? adminUser;
  final String? adminKey;
  final WifiSpec? wifi;
  final String? timezone;

  static ProvisionSpec fromJson(Map<String, Object?> j) {
    final admin = j['admin'];
    return ProvisionSpec(
      hostname: j['hostname'] as String,
      tag: j['tag'] as String,
      installSha256: j['install_sha256'] as String,
      repo: j['repo'] as String,
      pairingSecret: j['pairing_secret'] as String,
      instanceId: j['instance_id'] as String,
      adminUser: admin is List ? admin[0] as String : null,
      adminKey: admin is List ? admin[1] as String : null,
      wifi: WifiSpec.fromJson(j['wifi']),
      timezone: j['timezone'] as String?,
    );
  }
}

/// JSON strings are valid YAML double-quoted scalars (as in the Rust code).
String _q(String s) => jsonEncode(s);

bool _alnum(int c) => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
bool _all(String s, bool Function(int) f) => s.codeUnits.every(f);

List<String> validate(ProvisionSpec s) {
  final e = <String>[];
  final hostOk =
      s.hostname.isNotEmpty &&
      s.hostname.length <= 63 &&
      _all(s.hostname, (c) => _alnum(c) || c == 45) &&
      !s.hostname.startsWith('-');
  if (!hostOk) e.add("hostname: 1-63 letters, digits or '-'");
  final rest = s.tag.length > 1 ? s.tag.substring(1) : '';
  final tagOk =
      s.tag.startsWith('v') &&
      s.tag.length <= 32 &&
      _all(rest, (c) => _alnum(c) || c == 46 || c == 45) &&
      rest.split('.').length >= 3;
  if (!tagOk) e.add('tag: a release tag like v0.2.0');
  final hex64 = RegExp(r'^[0-9a-fA-F]{64}$');
  if (!hex64.hasMatch(s.installSha256)) e.add('install_sha256: 64 hex characters');
  if (!hex64.hasMatch(s.pairingSecret)) e.add('pairing_secret: 64 hex characters');
  final repoOk =
      s.repo.split('/').length == 2 && _all(s.repo, (c) => _alnum(c) || c == 47 || c == 45 || c == 95 || c == 46);
  if (!repoOk) e.add('repo: OWNER/NAME');
  if (s.instanceId.isEmpty || s.instanceId.length > 64 || !_all(s.instanceId, (c) => _alnum(c) || c == 45)) {
    e.add("instance_id: letters, digits or '-'");
  }
  final u = s.adminUser, k = s.adminKey;
  if (u != null && k != null) {
    final uOk =
        u.isNotEmpty &&
        u.length <= 32 &&
        RegExp(r'^[a-z_]').hasMatch(u) &&
        _all(u, (c) => (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 95 || c == 45);
    if (!uOk) e.add('admin user: a lowercase Linux user name');
    final parts = k.split(RegExp(r'\s+')).where((p) => p.isNotEmpty).toList();
    final kOk =
        parts.length >= 2 &&
        !k.contains('\n') &&
        !k.contains('\r') &&
        const ['ssh-ed25519', 'ecdsa-sha2-nistp256', 'sk-ssh-ed25519@openssh.com', 'ssh-rsa'].contains(parts[0]) &&
        _all(parts[1], (c) => _alnum(c) || c == 43 || c == 47 || c == 61);
    if (!kOk) e.add('admin key: one OpenSSH public key line');
  }
  final w = s.wifi;
  if (w != null) {
    final ssidBytes = utf8.encode(w.ssid).length;
    if (w.ssid.isEmpty || ssidBytes > 32 || w.ssid.runes.any((r) => r < 32 || (r >= 127 && r < 160))) {
      e.add('wifi ssid: 1-32 bytes');
    }
    if (w.password.length < 8 || w.password.length > 63 || !_all(w.password, (c) => c >= 32 && c <= 126)) {
      e.add('wifi password: 8-63 printable ASCII characters');
    }
    if (w.country.length != 2 || !_all(w.country, (c) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122))) {
      e.add('wifi country: two-letter code');
    }
  }
  final tz = s.timezone;
  if (tz != null && (tz.isEmpty || !_all(tz, (c) => _alnum(c) || c == 47 || c == 95 || c == 45 || c == 43))) {
    e.add('timezone: an IANA name like Asia/Taipei');
  }
  return e;
}

String firstbootCommand(ProvisionSpec s) {
  final url = 'https://github.com/${s.repo}/releases/download/${s.tag}/install.sh';
  return 'set -e; exec >>/var/log/rp-firstboot.log 2>&1; '
      'curl -fsSL --proto =https --retry 20 --retry-all-errors --retry-delay 5 -o /root/rp-install.sh $url; '
      "echo '${s.installSha256}  /root/rp-install.sh' | sha256sum -c -; "
      'bash /root/rp-install.sh --release ${s.tag} --repo ${s.repo}; '
      'rpctl setup --no-pairing; '
      'echo rp-firstboot: done';
}

class InvalidSpec implements Exception {
  InvalidSpec(this.errors);
  final List<String> errors;
  @override
  String toString() => errors.join('; ');
}

/// The files to write into the boot partition.
Map<String, String> files(ProvisionSpec s) {
  final errs = validate(s);
  if (errs.isNotEmpty) throw InvalidSpec(errs);
  final ud = StringBuffer('#cloud-config\n# Generated by RP Security (rp provisioning v1)\n')
    ..write('hostname: ${_q(s.hostname)}\nmanage_etc_hosts: true\n');
  if (s.timezone != null) ud.write('timezone: ${_q(s.timezone!)}\n');
  if (s.adminUser != null && s.adminKey != null) {
    ud.write(
      '\nusers:\n- name: ${_q(s.adminUser!)}\n  groups: users,adm,sudo,netdev\n  shell: /bin/bash\n'
      '  lock_passwd: true\n  ssh_authorized_keys:\n  - ${_q(s.adminKey!.trim())}\n\nssh_pwauth: false\n',
    );
  } else {
    ud.write('\nssh_pwauth: false\n');
  }
  ud.write('\nruncmd:\n');
  final w = s.wifi;
  if (w != null) {
    ud.write('- [rfkill, unblock, wifi]\n');
    ud.write('- [raspi-config, nonint, do_wifi_country, ${_q(w.country.toUpperCase())}]\n');
  }
  if (s.adminUser != null) ud.write('- [systemctl, enable, --now, ssh]\n');
  ud.write('- [install, -d, -m, "0755", /etc/rp]\n');
  ud.write('- [install, -m, "0600", $bootMount/rp-pairing.toml, /etc/rp/pairing.toml]\n');
  ud.write('- [shred, -u, $bootMount/rp-pairing.toml]\n');
  ud.write('- [sh, -c, ${_q(firstbootCommand(s))}]\n');
  final out = <String, String>{'user-data': ud.toString()};
  if (w != null) {
    out['network-config'] =
        '# Generated by RP Security (rp provisioning v1)\nnetwork:\n  version: 2\n'
        '  renderer: NetworkManager\n  wifis:\n    wlan0:\n      dhcp4: true\n      optional: true\n'
        '      regulatory-domain: ${_q(w.country.toUpperCase())}\n      access-points:\n'
        '        ${_q(w.ssid)}:\n          password: ${_q(w.password)}\n';
  }
  out['rp-pairing.toml'] =
      '# One-time pairing secret; moved to /etc/rp and shredded on first boot.\n'
      'secret = "${s.pairingSecret.toLowerCase()}"\n';
  return out;
}

String metaData(String existing, String instanceId) {
  // Same as Rust's str::lines(): no trailing empty line, '\r' stripped.
  final raw = existing.split('\n');
  if (raw.isNotEmpty && raw.last.isEmpty) raw.removeLast();
  final lines = raw
      .map((l) => l.endsWith('\r') ? l.substring(0, l.length - 1) : l)
      .where((l) => !l.startsWith('instance_id:') && !l.startsWith('instance-id:'))
      .toList();
  if (!lines.any((l) => l.startsWith('dsmode:'))) lines.add('dsmode: local');
  lines.add('instance_id: $instanceId');
  return '${lines.join('\n')}\n';
}

/// A mounted Raspberry Pi OS boot partition (desktop only).
bool isBootPartition(Directory d) =>
    File('${d.path}/cmdline.txt').existsSync() && File('${d.path}/meta-data').existsSync();

/// Likely mount points of a freshly flashed card.
List<Directory> candidateBootPartitions() {
  final c = <String>[];
  if (Platform.isMacOS) c.add('/Volumes/bootfs');
  if (Platform.isLinux) {
    final user = Platform.environment['USER'] ?? '';
    c.addAll(['/media/$user/bootfs', '/run/media/$user/bootfs', '/media/bootfs']);
  }
  if (Platform.isWindows) {
    for (var l = 'D'.codeUnitAt(0); l <= 'Z'.codeUnitAt(0); l++) {
      c.add('${String.fromCharCode(l)}:\\');
    }
  }
  return [for (final p in c) Directory(p)].where((d) => d.existsSync() && isBootPartition(d)).toList();
}

/// Write the card. Returns the file names written.
List<String> writeCard(Directory boot, ProvisionSpec s) {
  if (!isBootPartition(boot)) throw StateError('not a freshly flashed Raspberry Pi OS boot partition');
  final f = files(s);
  for (final e in f.entries) {
    File('${boot.path}/${e.key}').writeAsStringSync(e.value, flush: true);
  }
  final meta = File('${boot.path}/meta-data');
  meta.writeAsStringSync(metaData(meta.readAsStringSync(), s.instanceId), flush: true);
  return [...f.keys, 'meta-data'];
}
