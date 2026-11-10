import 'package:flutter/widgets.dart';

import '../core/api/client.dart';
import '../core/storage/vault.dart';
import 'services.dart';

class AppState extends ChangeNotifier {
  AppState(this.services);

  final Services services;
  List<PairedDevice> devices = [];
  bool loaded = false;
  final Map<String, RpClient> _clients = {};

  /// 'system', 'en' or 'zh' (Traditional Chinese).
  String language = 'system';
  Set<String> _vpnAsked = {};

  static const languages = ['system', 'en', 'zh'];

  Locale? get locale => switch (language) {
    'en' => const Locale('en'),
    'zh' => const Locale('zh', 'TW'),
    _ => null,
  };

  Future<void> setLanguage(String l) async {
    if (!languages.contains(l)) return;
    language = l;
    notifyListeners();
    await services.vault.setPref('language', l == 'system' ? null : l);
  }

  /// Whether the "use a VPN?" prompt was already shown for this device.
  bool vpnAsked(String deviceId) => _vpnAsked.contains(deviceId);

  Future<void> markVpnAsked(String deviceId) async {
    _vpnAsked = {..._vpnAsked, deviceId};
    await services.vault.setPref('vpn_asked', _vpnAsked.toList()..sort());
  }

  Future<void> load() async {
    final p = await services.vault.prefs();
    final l = p['language'];
    language = l is String && languages.contains(l) ? l : 'system';
    final asked = p['vpn_asked'];
    _vpnAsked = asked is List ? asked.whereType<String>().toSet() : {};
    devices = await services.vault.devices();
    loaded = true;
    notifyListeners();
  }

  Future<RpClient> client(PairedDevice d) async => _clients[d.key] ??= await services.clientFor(d);

  Future<void> add(PairedDevice d) async {
    await services.vault.saveDevice(d);
    _clients.remove(d.key);
    await load();
  }

  /// The device's VPN addresses from `/v1/vpn/status` (one mode or both):
  /// Tailscale IPv4 first, then its MagicDNS name, then the WireGuard address.
  static List<String> vpnHostsFrom(Map<String, Object?> st) {
    Map<String, Object?> part(String mode) {
      final nested = st[mode];
      if (nested is Map) return nested.cast<String, Object?>();
      return st['mode'] == mode ? st : const {};
    }

    final ts = part('tailscale'), wg = part('wireguard');
    final addrs = (ts['addresses'] is List ? ts['addresses']! as List : const []).whereType<String>().toList()
      ..sort((a, b) => (a.contains(':') ? 1 : 0) - (b.contains(':') ? 1 : 0));
    return [
      ...addrs.where((a) => !a.contains(':')),
      if (ts['dns_name'] is String && (ts['dns_name']! as String).isNotEmpty) ts['dns_name']! as String,
      if (wg['address'] is String) wg['address']! as String,
    ];
  }

  /// Remember how to reach [d] over the VPN (learned while it is reachable).
  Future<void> learnVpnHosts(PairedDevice d, RpClient c) async {
    final hosts = vpnHostsFrom(await c.vpnStatus());
    if (hosts.isEmpty) return;
    await setVpnHosts(d, {...hosts, ...d.vpnHosts}.toList());
  }

  /// Set the VPN addresses (also typed in by the user); the next connection
  /// uses them.
  Future<void> setVpnHosts(PairedDevice d, List<String> hosts) async {
    final cur = devices.firstWhere((x) => x.key == d.key, orElse: () => d);
    if (cur.vpnHosts.length == hosts.length && cur.vpnHosts.every(hosts.contains)) return;
    await services.vault.saveDevice(cur.copyWith(vpnHosts: hosts));
    devices = await services.vault.devices();
    notifyListeners();
  }

  /// Drop the cached connection (e.g. after new addresses were added).
  void reconnect(PairedDevice d) => _clients.remove(d.key);

  /// Does the device answer on [host] with its paired certificate?
  Future<bool> reaches(PairedDevice d, String host) async {
    try {
      await services
          .transport(host, d.port, d.certSha256)
          .request('GET', '/v1/info')
          .timeout(const Duration(seconds: 6));
      return true;
    } catch (_) {
      return false;
    }
  }

  /// Save a profile of [base] that always connects through a VPN at [host]
  /// ('tailscale' / 'wireguard'); replaces an earlier profile of that kind.
  Future<PairedDevice> addVpnProfile(PairedDevice base, String profile, String host, String label) async {
    final p = PairedDevice(
      deviceId: base.deviceId,
      name: '${base.name} · $label',
      host: host,
      port: base.port,
      certSha256: base.certSha256,
      adminId: base.adminId,
      addedAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
      profile: profile,
    );
    await add(p);
    return devices.firstWhere((x) => x.key == p.key, orElse: () => p);
  }

  /// Forget a device and all its VPN profiles (after removing RP Security).
  Future<void> forgetAll(String deviceId) async {
    for (final d in devices.where((x) => x.deviceId == deviceId).toList()) {
      await services.vault.removeDevice(d.key);
      _clients.remove(d.key);
    }
    await load();
  }

  Future<void> forget(PairedDevice d) async {
    await services.vault.removeDevice(d.key);
    _clients.remove(d.key);
    await load();
  }
}
