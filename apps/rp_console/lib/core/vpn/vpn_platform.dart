// The phone's VPN situation: which VPN apps are installed and whether a VPN
// is up (Android, via MainActivity's "rp/vpn" channel). Away from home the
// app reaches the Raspberry Pi only through Tailscale or WireGuard.

import 'package:flutter/services.dart';

const kTailscalePackage = 'com.tailscale.ipn';
const kWireguardPackage = 'com.wireguard.android';

class VpnApps {
  const VpnApps({required this.tailscale, required this.wireguard});
  final bool tailscale;
  final bool wireguard;
  bool get any => tailscale || wireguard;
}

abstract class VpnPlatform {
  Future<VpnApps> installedApps();

  /// Whether any VPN (Tailscale, WireGuard, …) is up on this phone.
  Future<bool> vpnActive();
  Future<bool> openApp(String package);
  Future<bool> openStore(String package);
}

class AndroidVpnPlatform implements VpnPlatform {
  static const _ch = MethodChannel('rp/vpn');

  @override
  Future<VpnApps> installedApps() async {
    final m = await _ch.invokeMapMethod<String, bool>('installedApps') ?? const {};
    return VpnApps(tailscale: m[kTailscalePackage] ?? false, wireguard: m[kWireguardPackage] ?? false);
  }

  @override
  Future<bool> vpnActive() async => await _ch.invokeMethod<bool>('vpnActive') ?? false;

  @override
  Future<bool> openApp(String package) async => await _ch.invokeMethod<bool>('openApp', {'package': package}) ?? false;

  @override
  Future<bool> openStore(String package) async =>
      await _ch.invokeMethod<bool>('openStore', {'package': package}) ?? false;
}
