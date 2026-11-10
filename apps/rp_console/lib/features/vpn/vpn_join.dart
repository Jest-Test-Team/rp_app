// "Use this VPN with the app": opened by tapping Tailscale or WireGuard under
// VPN › Status. It gets this phone onto that VPN (opens Tailscale; for
// WireGuard adds this phone as a WireGuard device and hands the config to the
// WireGuard app), checks that the Pi answers through it, and saves a VPN
// profile of the Pi in the device list that always connects that way — so
// the app works while the phone's VPN (or the Pi as exit node) is on.

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/storage/vault.dart';
import '../../core/vpn/vpn_platform.dart';
import '../../widgets/common.dart';
import 'vpn_page.dart';

/// The Pi's addresses on [mode] from `/v1/vpn/status` (one mode or both).
List<String> vpnAddresses(Map<String, Object?> status, String mode) {
  final hosts = AppState.vpnHostsFrom({
    'mode': 'both',
    mode: str(status['mode']) == 'both' ? asMap(status[mode]) : (str(status['mode']) == mode ? status : const {}),
  });
  return hosts;
}

class VpnJoinPage extends StatefulWidget {
  const VpnJoinPage({
    super.key,
    required this.mode,
    required this.app,
    required this.device,
    required this.client,
    required this.status,
    required this.cfg,
    required this.serverPublic,
  });

  /// 'tailscale' or 'wireguard'.
  final String mode;
  final AppState app;
  final PairedDevice device;
  final RpClient client;
  final Map<String, Object?> status;
  final Map<String, Object?> cfg;
  final String? serverPublic;

  @override
  State<VpnJoinPage> createState() => _VpnJoinPageState();
}

class _VpnJoinPageState extends State<VpnJoinPage> {
  VpnPlatform? get vpn => widget.app.services.vpn;
  bool get isTs => widget.mode == 'tailscale';
  String get label => isTs ? 'Tailscale' : 'WireGuard';
  String get package => isTs ? kTailscalePackage : kWireguardPackage;

  bool? phoneVpnOn;
  bool? appInstalled;
  String? conf; // WireGuard config made for this phone (this visit only)
  String? savedAt;
  bool busy = false;
  String? message;
  bool messageIsError = false;

  List<String> get addresses => vpnAddresses(widget.status, widget.mode);

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final v = vpn;
    if (v == null) return;
    try {
      final on = await v.vpnActive();
      final apps = await v.installedApps();
      if (!mounted) return;
      setState(() {
        phoneVpnOn = on;
        appInstalled = isTs ? apps.tailscale : apps.wireguard;
      });
    } catch (_) {}
  }

  void _say(String m, {bool error = false}) => setState(() {
    message = m;
    messageIsError = error;
  });

  Future<void> _addPhone() async {
    final s = S.of(context);
    final name = await showDialog<String>(
      context: context,
      builder: (_) => const NameDialog(initial: 'this-phone'),
    );
    if (name == null || !mounted) return;
    final c = await addWireguardPeer(context, widget.client, widget.cfg, widget.serverPublic, name);
    if (c == null || !mounted) return;
    setState(() => conf = c);
    final v = vpn;
    if (v != null) {
      final at = await v.saveConfig('rp-$name.conf', c);
      if (!mounted) return;
      setState(() => savedAt = at);
    }
    _say(savedAt != null ? s('join.wg.saved', {'path': savedAt!}) : s('join.wg.qr'));
  }

  Future<void> _createProfile() async {
    final s = S.of(context);
    final candidates = addresses;
    if (candidates.isEmpty) {
      _say(s('join.noaddress', {'vpn': label}), error: true);
      return;
    }
    setState(() => busy = true);
    try {
      for (final h in candidates) {
        if (await widget.app.reaches(widget.device, h)) {
          final p = await widget.app.addVpnProfile(widget.device, widget.mode, h, label);
          if (!mounted) return;
          _say(s('join.done', {'name': p.name, 'host': h}));
          return;
        }
      }
      if (mounted) _say(s('join.unreachable', {'vpn': label, 'hosts': candidates.join(', ')}), error: true);
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final v = vpn;
    final t = Theme.of(context).textTheme;
    return Scaffold(
      appBar: AppBar(title: Text(s('join.title', {'vpn': label}))),
      body: ListView(
        key: Key('join-${widget.mode}'),
        padding: const EdgeInsets.all(16),
        children: [
          Text(s('join.body', {'vpn': label})),
          const SizedBox(height: 12),
          Card(
            child: ListTile(
              leading: const Icon(Icons.router_outlined),
              title: Text(s('join.address', {'vpn': label})),
              subtitle: Text(addresses.isEmpty ? '-' : addresses.join('\n'), key: const Key('join-addresses')),
            ),
          ),
          if (phoneVpnOn != null)
            Card(
              child: ListTile(
                key: const Key('join-phone-vpn'),
                leading: Icon(phoneVpnOn! ? Icons.vpn_lock : Icons.vpn_key_off_outlined),
                title: Text(phoneVpnOn! ? s('conn.vpn.on') : s('conn.vpn.off')),
              ),
            ),
          const SizedBox(height: 8),
          // Step 1: this phone on the VPN.
          Text(s('join.step1', {'vpn': label}), style: t.titleSmall),
          const SizedBox(height: 4),
          if (!isTs) ...[
            Text(s('join.wg.step1')),
            const SizedBox(height: 8),
            FilledButton.tonalIcon(
              key: const Key('join-wg-add'),
              onPressed: _addPhone,
              icon: const Icon(Icons.add),
              label: Text(s('join.wg.add')),
            ),
            if (conf != null) ...[
              const SizedBox(height: 8),
              Center(
                child: QrImageView(key: const Key('join-wg-qr'), data: conf!, size: 200, backgroundColor: Colors.white),
              ),
              TextButton.icon(
                onPressed: () => copyText(context, conf!),
                icon: const Icon(Icons.copy),
                label: Text(s('common.copy')),
              ),
            ],
          ] else
            Text(s('join.ts.step1')),
          if (v != null) ...[
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const Key('join-open'),
              onPressed: () async {
                if (appInstalled == false) {
                  await v.openStore(package);
                } else {
                  await v.openApp(package);
                }
              },
              icon: Icon(appInstalled == false ? Icons.download : Icons.open_in_new),
              label: Text(appInstalled == false ? s('join.install', {'vpn': label}) : s('conn.open', {'app': label})),
            ),
          ],
          const SizedBox(height: 16),
          // Step 2: a profile that always uses the VPN.
          Text(s('join.step2'), style: t.titleSmall),
          const SizedBox(height: 4),
          Text(s('join.step2.body', {'vpn': label})),
          const SizedBox(height: 8),
          FilledButton.icon(
            key: const Key('join-create'),
            onPressed: busy ? null : _createProfile,
            icon: busy
                ? const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.vpn_lock),
            label: Text(s('join.create', {'vpn': label})),
          ),
          if (message != null)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: Text(
                message!,
                key: const Key('join-message'),
                style: messageIsError ? TextStyle(color: Theme.of(context).colorScheme.error) : null,
              ),
            ),
        ],
      ),
    );
  }
}
