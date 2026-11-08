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

bool usesWireguard(String mode) => mode == 'wireguard' || mode == 'both';
bool usesTailscale(String mode) => mode == 'tailscale' || mode == 'both';

/// Status lines in words, for one mode or both (`/v1/vpn/status`).
List<(String, String, bool)> vpnStatusLines(S s, Map<String, Object?> st) {
  if (st['configured'] == false) return [(s('vpn.status.none'), '', false)];
  (String, String, bool) line(Map<String, Object?> m) {
    final ok = m['available'] == true;
    final mode = str(m['mode']);
    final peers = m['peers'];
    final n = peers is List ? peers.length : integer(peers);
    final what = mode == 'tailscale'
        ? (str(m['backend_state']).isEmpty ? '' : str(m['backend_state']))
        : s('vpn.status.peers', {'n': n});
    return (s('vpn.mode.$mode', {}, mode), ok ? (what.isEmpty ? s('vpn.status.up') : what) : s('vpn.status.down'), ok);
  }

  if (str(st['mode']) == 'both') return [line(asMap(st['tailscale'])), line(asMap(st['wireguard']))];
  return [line(st)];
}

class VpnPage extends StatelessWidget {
  const VpnPage({super.key, required this.client, this.suggestedMode, this.publicIp});
  final RpClient client;

  /// Mode picked in the first-visit prompt (preselected in the form).
  final String? suggestedMode;
  final Future<String?> Function()? publicIp;

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
                for (final (name, state, ok) in vpnStatusLines(s, d.$2))
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: Icon(ok ? Icons.check_circle_outline : Icons.radio_button_unchecked),
                    title: Text(name),
                    trailing: Text(state),
                  ),
              ],
            ),
            VpnForm(
              client: client,
              cfg: cfg,
              caps: d.$4.module('vpn'),
              authKeySet: d.$3.secretSet('tailscale_auth_key'),
              onSaved: reload,
              suggestedMode: suggestedMode,
              publicIp: publicIp,
            ),
            if (usesWireguard(str(cfg['mode'])))
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
    this.suggestedMode,
    this.publicIp,
  });
  final RpClient client;
  final Map<String, Object?> cfg;
  final ModuleCapability caps;
  final bool authKeySet;
  final VoidCallback onSaved;
  final String? suggestedMode;
  final Future<String?> Function()? publicIp;
  @override
  State<VpnForm> createState() => _VpnFormState();
}

class _VpnFormState extends State<VpnForm> {
  late String mode = _initialMode();
  bool detecting = false;

  String _initialMode() {
    final options = widget.caps.options.isEmpty ? ['tailscale'] : widget.caps.options;
    final want = widget.suggestedMode;
    if (want != null && options.contains(want)) return want;
    return str(widget.cfg['mode'], 'tailscale');
  }

  Future<void> _detect() async {
    final f = widget.publicIp;
    if (f == null) return;
    setState(() => detecting = true);
    final ip = await f();
    if (!mounted) return;
    setState(() => detecting = false);
    final port = asMap(widget.cfg['wireguard'])['listen_port'] ?? 51820;
    if (ip != null) {
      endpoint.text = '$ip:$port';
    } else {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(S.of(context)('vpn.endpoint.nodetect'))));
    }
  }

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
          segments: [
            for (final m in modes)
              ButtonSegment(
                value: m,
                label: Text(s('vpn.mode.$m', {}, m), key: Key('vpn-mode-$m')),
              ),
          ],
          selected: {mode},
          onSelectionChanged: (v) => setState(() => mode = v.first),
        ),
        const SizedBox(height: 8),
        Text(s('vpn.mode.$mode.body', {}, ''), style: Theme.of(context).textTheme.bodySmall),
        const SizedBox(height: 12),
        if (usesTailscale(mode)) ...[
          TextField(
            key: const Key('vpn-hostname'),
            controller: hostname,
            decoration: InputDecoration(labelText: s('vpn.hostname')),
          ),
          const SizedBox(height: 12),
          TextField(
            key: const Key('vpn-authkey'),
            controller: authKey,
            obscureText: true,
            autocorrect: false,
            decoration: InputDecoration(labelText: s('vpn.authkey'), helperText: s('vpn.authkey.body')),
          ),
          const SizedBox(height: 12),
        ],
        if (usesWireguard(mode)) ...[
          TextField(
            key: const Key('vpn-endpoint'),
            controller: endpoint,
            decoration: InputDecoration(
              labelText: s('vpn.endpoint'),
              helperText: s('vpn.endpoint.body'),
              helperMaxLines: 4,
              suffixIcon: widget.publicIp == null
                  ? null
                  : IconButton(
                      key: const Key('vpn-detect'),
                      tooltip: s('vpn.endpoint.detect'),
                      onPressed: detecting ? null : _detect,
                      icon: detecting
                          ? const SizedBox.square(dimension: 16, child: CircularProgressIndicator(strokeWidth: 2))
                          : const Icon(Icons.my_location),
                    ),
            ),
          ),
          const SizedBox(height: 8),
          Card(
            child: ListTile(
              leading: const Icon(Icons.router_outlined),
              title: Text(s('vpn.portforward')),
              subtitle: Text(
                s('vpn.portforward.body', {'port': asMap(widget.cfg['wireguard'])['listen_port'] ?? 51820}),
              ),
            ),
          ),
        ],
        const SizedBox(height: 12),
        Align(
          alignment: Alignment.centerRight,
          child: FilledButton(
            key: const Key('vpn-save'),
            onPressed: () async {
              final key = authKey.text.trim();
              final patch = <String, Object?>{'vpn.mode': mode};
              if (usesTailscale(mode)) {
                if (hostname.text.trim().isNotEmpty) patch['vpn.tailscale.hostname'] = hostname.text.trim();
                if (key.isNotEmpty || widget.authKeySet) patch['vpn.tailscale.auth_key_file'] = '/etc/rp/tailscale.key';
              }
              if (usesWireguard(mode) && endpoint.text.trim().isNotEmpty) {
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
