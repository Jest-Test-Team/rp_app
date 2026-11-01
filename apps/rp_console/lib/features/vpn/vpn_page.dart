import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/change_sheet.dart';
import '../../widgets/common.dart';

class WgKeys {
  WgKeys(this.privateB64, this.publicB64);
  final String privateB64;
  final String publicB64;

  static Future<WgKeys> generate() async {
    final kp = await X25519().newKeyPair();
    final priv = await kp.extractPrivateKeyBytes();
    final pub = await kp.extractPublicKey();
    return WgKeys(base64.encode(priv), base64.encode(pub.bytes));
  }
}

/// Address of peer `host` in an IPv4 `subnet` (e.g. 198.51.100.0/24 and 2 → .2).
String peerAddress(String subnet, int host) {
  final ip = subnet.split('/').first.split('.').map(int.parse).toList();
  final n = ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3]) + host;
  return [(n >> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255].join('.');
}

int nextFreeHost(List<Map<String, Object?>> peers, String subnet) {
  final prefix = int.parse(subnet.split('/').last);
  final max = (1 << (32 - prefix)) - 2;
  for (var h = 2; h <= max; h++) {
    if (!peers.any((p) => p['host'] == h)) return h;
  }
  throw StateError('subnet full');
}

/// Same layout as rp_core::wg::client_config.
String clientConfig({
  required String privateKey,
  required String address,
  required String dns,
  required String serverPublic,
  required String endpoint,
}) =>
    '[Interface]\nPrivateKey = $privateKey\nAddress = $address/32\nDNS = $dns\n\n'
    '[Peer]\nPublicKey = $serverPublic\nEndpoint = $endpoint\n'
    '# All traffic, including IPv6, goes through the tunnel so nothing leaks.\n'
    'AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n';

class VpnPage extends StatelessWidget {
  const VpnPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) => Loader<(Map<String, Object?>, Map<String, Object?>, Status, Capabilities)>(
    load: () async => (
      await client.moduleConfig('vpn'),
      await client.vpnStatus(),
      await client.status(),
      await client.capabilities(),
    ),
    builder: (context, d, reload) {
      final cfg = asMap(asMap(d.$1['config'])['vpn']);
      final s = S.of(context);
      return RefreshIndicator(
        onRefresh: () async => reload(),
        child: ListView(
          children: [
            Section(
              title: s('vpn.status'),
              children: [
                for (final e in d.$2.entries)
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    title: Text(e.key),
                    trailing: Text('${e.value}'),
                  ),
              ],
            ),
            VpnForm(
              client: client,
              cfg: cfg,
              caps: d.$4.module('vpn'),
              authKeySet: d.$3.secretSet('tailscale_auth_key'),
              onSaved: reload,
            ),
            if (str(cfg['mode']) == 'wireguard')
              Peers(
                client: client,
                cfg: cfg,
                serverPublic: d.$3.raw['wireguard_public_key'] as String?,
                onSaved: reload,
              ),
          ],
        ),
      );
    },
  );
}

class VpnForm extends StatefulWidget {
  const VpnForm({
    super.key,
    required this.client,
    required this.cfg,
    required this.caps,
    required this.authKeySet,
    required this.onSaved,
  });
  final RpClient client;
  final Map<String, Object?> cfg;
  final ModuleCapability caps;
  final bool authKeySet;
  final VoidCallback onSaved;
  @override
  State<VpnForm> createState() => _VpnFormState();
}

class _VpnFormState extends State<VpnForm> {
  late String mode = str(widget.cfg['mode'], 'tailscale');
  late final hostname = TextEditingController(text: str(asMap(widget.cfg['tailscale'])['hostname']));
  late final endpoint = TextEditingController(text: str(asMap(widget.cfg['wireguard'])['endpoint']));
  final authKey = TextEditingController();

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final modes = widget.caps.options.isEmpty ? ['tailscale'] : widget.caps.options;
    return Section(
      title: s('module.vpn'),
      children: [
        SegmentedButton<String>(
          key: const Key('vpn-mode'),
          segments: [for (final m in modes) ButtonSegment(value: m, label: Text(m))],
          selected: {mode},
          onSelectionChanged: (v) => setState(() => mode = v.first),
        ),
        const SizedBox(height: 12),
        if (mode == 'tailscale') ...[
          TextField(
            key: const Key('vpn-hostname'),
            controller: hostname,
            decoration: const InputDecoration(labelText: 'Hostname'),
          ),
          const SizedBox(height: 12),
          TextField(
            key: const Key('vpn-authkey'),
            controller: authKey,
            obscureText: true,
            autocorrect: false,
            decoration: InputDecoration(labelText: s('vpn.authkey'), helperText: s('vpn.authkey.body')),
          ),
        ] else
          TextField(
            key: const Key('vpn-endpoint'),
            controller: endpoint,
            decoration: const InputDecoration(labelText: 'Endpoint (host:port)'),
          ),
        const SizedBox(height: 12),
        Align(
          alignment: Alignment.centerRight,
          child: FilledButton(
            key: const Key('vpn-save'),
            onPressed: () async {
              final key = authKey.text.trim();
              final patch = <String, Object?>{'vpn.mode': mode};
              if (mode == 'tailscale') {
                if (hostname.text.trim().isNotEmpty) patch['vpn.tailscale.hostname'] = hostname.text.trim();
                if (key.isNotEmpty || widget.authKeySet) patch['vpn.tailscale.auth_key_file'] = '/etc/rp/tailscale.key';
              } else if (endpoint.text.trim().isNotEmpty) {
                patch['vpn.wireguard.endpoint'] = endpoint.text.trim();
              }
              final ok = await showChange(
                context,
                widget.client,
                'vpn',
                patch,
                before: key.isEmpty ? null : () => widget.client.setSecret('tailscale_auth_key', key),
              );
              authKey.clear();
              if (ok) widget.onSaved();
            },
            child: Text(s('common.save')),
          ),
        ),
      ],
    );
  }
}

class Peers extends StatelessWidget {
  const Peers({super.key, required this.client, required this.cfg, required this.serverPublic, required this.onSaved});
  final RpClient client;
  final Map<String, Object?> cfg;
  final String? serverPublic;
  final VoidCallback onSaved;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final wg = asMap(cfg['wireguard']);
    final peers = asList(wg['peers']).map(asMap).toList();
    return Section(
      title: s('vpn.peers'),
      trailing: IconButton(
        key: const Key('vpn-addpeer'),
        icon: const Icon(Icons.add),
        tooltip: s('vpn.addpeer'),
        onPressed: () async {
          final name = await showDialog<String>(context: context, builder: (_) => const _NameDialog());
          if (name == null || !context.mounted) return;
          final keys = await WgKeys.generate();
          final subnet = str(wg['subnet'], '10.88.0.0/24');
          final host = nextFreeHost(peers, subnet);
          final next = [
            ...peers,
            {'name': name, 'public_key': keys.publicB64, 'host': host},
          ];
          if (!context.mounted) return;
          final ok = await showChange(context, client, 'vpn', {'vpn.wireguard.peers': next});
          if (!ok || !context.mounted) return;
          final conf = clientConfig(
            privateKey: keys.privateB64,
            address: peerAddress(subnet, host),
            dns: str(wg['client_dns'], '1.1.1.1'),
            serverPublic: serverPublic ?? '<server key>',
            endpoint: str(wg['endpoint'], '<PUBLIC_HOST>:51820'),
          );
          await showDialog<void>(
            context: context,
            builder: (c) => AlertDialog(
              title: Text(s('vpn.peer.qr')),
              content: SizedBox(
                width: 260,
                child: QrImageView(key: const Key('wg-qr'), data: conf, backgroundColor: Colors.white),
              ),
              actions: [FilledButton(onPressed: () => Navigator.pop(c), child: Text(s('common.close')))],
            ),
          );
          onSaved();
        },
      ),
      children: [
        for (final p in peers)
          ListTile(
            key: Key('peer-${p['name']}'),
            contentPadding: EdgeInsets.zero,
            leading: const Icon(Icons.phone_iphone),
            title: Text(str(p['name'])),
            subtitle: Text(peerAddress(str(wg['subnet'], '10.88.0.0/24'), integer(p['host']))),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline),
              onPressed: () async {
                final next = peers.where((x) => x['name'] != p['name']).toList();
                if (await showChange(context, client, 'vpn', {'vpn.wireguard.peers': next})) onSaved();
              },
            ),
          ),
      ],
    );
  }
}

class _NameDialog extends StatefulWidget {
  const _NameDialog();
  @override
  State<_NameDialog> createState() => _NameDialogState();
}

class _NameDialogState extends State<_NameDialog> {
  final c = TextEditingController();
  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final ok = RegExp(r'^[A-Za-z0-9_-]{1,32}$').hasMatch(c.text);
    return AlertDialog(
      title: Text(s('vpn.addpeer')),
      content: TextField(
        key: const Key('peer-name'),
        controller: c,
        autofocus: true,
        onChanged: (_) => setState(() {}),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s('common.cancel'))),
        FilledButton(onPressed: ok ? () => Navigator.pop(context, c.text) : null, child: Text(s('common.save'))),
      ],
    );
  }
}
