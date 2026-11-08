import 'package:flutter/material.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/storage/vault.dart';
import '../../widgets/common.dart';
import '../ap/ap_page.dart';
import '../dns/dns_page.dart';
import '../firewall/firewall_page.dart';
import '../health/overview_page.dart';
import '../mcp/mcp_page.dart';
import '../settings/settings_page.dart';
import '../vpn/vpn_page.dart';

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
        title: Text(widget.device.name),
        bottom: TabBar(
          controller: tabs,
          isScrollable: true,
          tabAlignment: TabAlignment.start,
          tabs: [for (final (label, icon) in labels) Tab(key: Key('tab-$label'), text: label, icon: Icon(icon))],
        ),
      ),
      body: Loader<RpClient>(
        load: () => app.client(widget.device),
        builder: (context, client, _) {
          WidgetsBinding.instance.addPostFrameCallback((_) => _maybeAskVpn(client));
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
