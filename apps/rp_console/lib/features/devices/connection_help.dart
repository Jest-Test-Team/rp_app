// Shown when the Raspberry Pi answers on none of its addresses: says whether
// this phone's VPN is on, opens the VPN app, and lets the user add the Pi's
// VPN address (as shown in the Tailscale app) — still pinned to the paired
// certificate, so a wrong address can only fail, never impersonate the Pi.

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/storage/vault.dart';
import '../../core/vpn/vpn_platform.dart';

final _hostRe = RegExp(r'^[A-Za-z0-9.\-:]{1,253}$');

class ConnectionHelp extends StatefulWidget {
  const ConnectionHelp({
    super.key,
    required this.device,
    required this.vpn,
    required this.onAddHost,
    required this.onRetry,
  });
  final PairedDevice device;
  final VpnPlatform? vpn;
  final Future<void> Function(String host) onAddHost;
  final VoidCallback onRetry;

  @override
  State<ConnectionHelp> createState() => _ConnectionHelpState();
}

class _ConnectionHelpState extends State<ConnectionHelp> {
  final host = TextEditingController();
  bool? vpnOn;
  VpnApps? apps;
  String? error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final v = widget.vpn;
    if (v == null) return;
    try {
      final (on, a) = (await v.vpnActive(), await v.installedApps());
      if (mounted) {
        setState(() {
          vpnOn = on;
          apps = a;
        });
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final d = widget.device;
    return ListView(
      key: const Key('conn-help'),
      padding: const EdgeInsets.all(16),
      children: [
        Icon(Icons.cloud_off, size: 48, color: Theme.of(context).colorScheme.error),
        const SizedBox(height: 8),
        Text(s('conn.title'), textAlign: TextAlign.center, style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        Text(
          s('conn.tried', {
            'hosts': [d.host, ...d.vpnHosts].join(', '),
          }),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 16),
        if (vpnOn != null)
          Card(
            child: ListTile(
              key: const Key('conn-vpn-state'),
              leading: Icon(vpnOn! ? Icons.vpn_lock : Icons.vpn_key_off_outlined),
              title: Text(vpnOn! ? s('conn.vpn.on') : s('conn.vpn.off')),
              subtitle: Text(vpnOn! ? s('conn.vpn.on.body') : s('conn.vpn.off.body')),
            ),
          ),
        if (apps?.tailscale ?? false)
          OutlinedButton.icon(
            key: const Key('conn-open-tailscale'),
            onPressed: () => widget.vpn!.openApp(kTailscalePackage),
            icon: const Icon(Icons.open_in_new),
            label: Text(s('conn.open', {'app': 'Tailscale'})),
          ),
        if (apps?.wireguard ?? false)
          OutlinedButton.icon(
            key: const Key('conn-open-wireguard'),
            onPressed: () => widget.vpn!.openApp(kWireguardPackage),
            icon: const Icon(Icons.open_in_new),
            label: Text(s('conn.open', {'app': 'WireGuard'})),
          ),
        const SizedBox(height: 16),
        Text(s('conn.addhost'), style: Theme.of(context).textTheme.titleSmall),
        const SizedBox(height: 8),
        TextField(
          key: const Key('conn-host'),
          controller: host,
          autocorrect: false,
          keyboardType: TextInputType.url,
          decoration: InputDecoration(
            labelText: s('conn.addhost.label'),
            helperText: s('conn.addhost.body'),
            helperMaxLines: 4,
            errorText: error,
          ),
        ),
        const SizedBox(height: 8),
        Row(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            TextButton(key: const Key('conn-retry'), onPressed: widget.onRetry, child: Text(s('common.retry'))),
            const SizedBox(width: 8),
            FilledButton(
              key: const Key('conn-add'),
              onPressed: () async {
                final h = host.text.trim().replaceAll(RegExp(r'\.$'), '');
                if (!_hostRe.hasMatch(h)) {
                  setState(() => error = s('conn.addhost.bad'));
                  return;
                }
                await widget.onAddHost(h);
              },
              child: Text(s('conn.addhost.save')),
            ),
          ],
        ),
      ],
    );
  }
}
