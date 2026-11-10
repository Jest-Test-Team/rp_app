import 'package:flutter/material.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/routing_transport.dart';
import '../../core/api/transport.dart';
import '../../core/storage/vault.dart';
import '../../widgets/common.dart';
import '../ap/ap_page.dart';
import '../dns/dns_page.dart';
import '../firewall/firewall_page.dart';
import '../health/overview_page.dart';
import '../mcp/mcp_page.dart';
import '../settings/settings_page.dart';
import '../vpn/vpn_page.dart';
import 'connection_help.dart';

const _vpnTab = 4;

/// What the first-visit VPN prompt offers, given the modes the device can run
/// and the mode already configured (null = none). Empty = nothing to ask.
List<String> vpnChoices(List<String> options, String? current) {
  final both = options.contains('both');
  return switch (current) {
    null || '' => options,
    'tailscale' || 'wireguard' => both ? ['both'] : [],
    _ => [],
  };
}

class DeviceScreen extends StatefulWidget {
  const DeviceScreen({super.key, required this.app, required this.device});
  final AppState app;
  final PairedDevice device;

  @override
  State<DeviceScreen> createState() => _DeviceScreenState();
}

class _DeviceScreenState extends State<DeviceScreen> with SingleTickerProviderStateMixin {
  late final tabs = TabController(length: 7, vsync: this);
  String? suggestedMode;
  bool _asking = false;

  @override
  void dispose() {
    tabs.dispose();
    super.dispose();
  }

  /// Once per device: offer a VPN (Tailscale, WireGuard, or both).
  Future<void> _maybeAskVpn(RpClient client) async {
    final app = widget.app, id = widget.device.deviceId;
    if (_asking || app.vpnAsked(id)) return;
    _asking = true;
    try {
      final caps = (await client.capabilities()).module('vpn');
      final cfg = asMap(asMap((await client.moduleConfig('vpn'))['config'])['vpn']);
      final current = cfg.isEmpty ? null : str(cfg['mode']);
      final choices = caps.available ? vpnChoices(caps.options, current) : <String>[];
      if (choices.isEmpty || !mounted) {
        await app.markVpnAsked(id);
        return;
      }
      final pick = await showDialog<String>(
        context: context,
        builder: (_) => VpnPromptDialog(choices: choices, current: current),
      );
      await app.markVpnAsked(id);
      if (pick == null || !mounted) return;
      setState(() => suggestedMode = pick);
      tabs.animateTo(_vpnTab);
    } catch (_) {
      // Unreachable device etc.: ask again next time.
    } finally {
      _asking = false;
    }
  }

  PairedDevice get device =>
      widget.app.devices.firstWhere((d) => d.key == widget.device.key, orElse: () => widget.device);

  bool _learned = false;
  String? route;

  /// Remember the Pi's VPN addresses while it is reachable, and show the path.
  Future<void> _learn(RpClient c) async {
    final t = c.transport;
    if (t is RoutingTransport && t.host != route && mounted) setState(() => route = t.host);
    if (_learned || device.profile.isNotEmpty) return; // a VPN profile has one fixed address
    _learned = true;
    try {
      await widget.app.learnVpnHosts(device, c);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final labels = [
      (s('dev.overview'), Icons.dashboard_outlined),
      (s('dev.dns'), Icons.dns_outlined),
      (s('dev.ap'), Icons.wifi_tethering),
      (s('dev.firewall'), Icons.local_fire_department_outlined),
      (s('dev.vpn'), Icons.vpn_lock_outlined),
      (s('dev.mcp'), Icons.smart_toy_outlined),
      (s('dev.settings'), Icons.settings_outlined),
    ];
    final app = widget.app;
    return Scaffold(
      appBar: AppBar(
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(widget.device.name),
            if (route != null)
              Text(
                route == widget.device.host && widget.device.profile.isEmpty
                    ? s('conn.via.lan', {'host': route!})
                    : s('conn.via.vpn', {'host': route!}),
                key: const Key('conn-route'),
                style: Theme.of(context).textTheme.bodySmall,
              ),
          ],
        ),
        bottom: TabBar(
          controller: tabs,
          isScrollable: true,
          tabAlignment: TabAlignment.start,
          tabs: [for (final (label, icon) in labels) Tab(key: Key('tab-$label'), text: label, icon: Icon(icon))],
        ),
      ),
      body: Loader<(RpClient, bool)>(
        // Reach the Pi first (home address or VPN); if nothing answers, say
        // why instead of an error on every tab.
        load: () async {
          final c = await app.client(device);
          try {
            await c.info();
            return (c, true);
          } catch (e) {
            if (e is PinMismatch || e is ApiException) rethrow;
            return (c, false);
          }
        },
        builder: (context, d, reload) {
          final (client, reachable) = d;
          if (!reachable) {
            return ConnectionHelp(
              device: device,
              vpn: app.services.vpn,
              onRetry: reload,
              onAddHost: (h) async {
                await app.setVpnHosts(device, [h, ...device.vpnHosts.where((x) => x != h)]);
                app.reconnect(widget.device);
                reload();
              },
            );
          }
          WidgetsBinding.instance.addPostFrameCallback((_) {
            _maybeAskVpn(client);
            _learn(client);
          });
          return TabBarView(
            controller: tabs,
            children: [
              OverviewPage(client: client),
              DnsPage(client: client),
              ApPage(client: client),
              FirewallPage(client: client),
              VpnPage(
                key: ValueKey('vpn-$suggestedMode'),
                client: client,
                suggestedMode: suggestedMode,
                publicIp: app.services.publicIp,
                app: app,
                device: device,
              ),
              McpPage(client: client),
              SettingsPage(app: app, device: widget.device, client: client),
            ],
          );
        },
      ),
    );
  }
}

class VpnPromptDialog extends StatelessWidget {
  const VpnPromptDialog({super.key, required this.choices, this.current});
  final List<String> choices;
  final String? current;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return AlertDialog(
      key: const Key('vpn-prompt'),
      icon: const Icon(Icons.vpn_lock_outlined),
      title: Text(current == null ? s('vpn.prompt.title') : s('vpn.prompt.add.title')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(current == null ? s('vpn.prompt.body') : s('vpn.prompt.add.body', {'mode': s('vpn.mode.$current')})),
            const SizedBox(height: 12),
            for (final c in choices)
              Card(
                child: ListTile(
                  key: Key('vpn-pick-$c'),
                  title: Text(current == null ? s('vpn.mode.$c', {}, c) : s('vpn.prompt.add.$c', {}, c)),
                  subtitle: Text(s('vpn.mode.$c.body', {}, '')),
                  onTap: () => Navigator.pop(context, c),
                ),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(
          key: const Key('vpn-pick-later'),
          onPressed: () => Navigator.pop(context),
          child: Text(s('vpn.prompt.later')),
        ),
      ],
    );
  }
}
