import 'package:flutter/material.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/storage/vault.dart';
import '../../widgets/common.dart';
import '../ap/ap_page.dart';
import '../dns/dns_page.dart';
import '../firewall/firewall_page.dart';
import '../health/overview_page.dart';
import '../mcp/mcp_page.dart';
import '../settings/settings_page.dart';
import '../vpn/vpn_page.dart';

class DeviceScreen extends StatelessWidget {
  const DeviceScreen({super.key, required this.app, required this.device});
  final AppState app;
  final PairedDevice device;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final tabs = [
      (s('dev.overview'), Icons.dashboard_outlined),
      (s('dev.dns'), Icons.dns_outlined),
      (s('dev.ap'), Icons.wifi_tethering),
      (s('dev.firewall'), Icons.local_fire_department_outlined),
      (s('dev.vpn'), Icons.vpn_lock_outlined),
      (s('dev.mcp'), Icons.smart_toy_outlined),
      (s('dev.settings'), Icons.settings_outlined),
    ];
    return DefaultTabController(
      length: tabs.length,
      child: Scaffold(
        appBar: AppBar(
          title: Text(device.name),
          bottom: TabBar(
            isScrollable: true,
            tabAlignment: TabAlignment.start,
            tabs: [for (final (label, icon) in tabs) Tab(key: Key('tab-$label'), text: label, icon: Icon(icon))],
          ),
        ),
        body: Loader<RpClient>(
          load: () => app.client(device),
          builder: (context, client, _) => TabBarView(
            children: [
              OverviewPage(client: client),
              DnsPage(client: client),
              ApPage(client: client),
              FirewallPage(client: client),
              VpnPage(client: client),
              McpPage(client: client),
              SettingsPage(app: app, device: device, client: client),
            ],
          ),
        ),
      ),
    );
  }
}
