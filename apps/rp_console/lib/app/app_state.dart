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

  Future<RpClient> client(PairedDevice d) async => _clients[d.deviceId] ??= await services.clientFor(d);

  Future<void> add(PairedDevice d) async {
    await services.vault.saveDevice(d);
    _clients.remove(d.deviceId);
    await load();
  }

  Future<void> forget(PairedDevice d) async {
    await services.vault.removeDevice(d.deviceId);
    _clients.remove(d.deviceId);
    await load();
  }
}
