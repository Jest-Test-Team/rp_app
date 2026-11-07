import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/common.dart';
import '../onboarding/onboarding.dart' show CapabilityList;

class OverviewPage extends StatelessWidget {
  const OverviewPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Loader<(Map<String, Object?>, Capabilities)>(
      load: () async => (await client.health(), await client.capabilities()),
      builder: (context, d, reload) {
        final (h, caps) = d;
        final ok = str(h['status']) == 'ok';
        final mem = asMap(h['memory']);
        final uv = flag(h['under_voltage']);
        return RefreshIndicator(
          onRefresh: () async => reload(),
          child: ListView(
            children: [
              Section(
                title: s('health.title'),
                trailing: Chip(
                  key: const Key('health-status'),
                  avatar: Icon(ok ? Icons.check : Icons.warning_amber, size: 18),
                  label: Text(ok ? s('health.ok') : s('health.warn')),
                ),
                children: [
                  StatGrid(
                    tiles: [
                      StatTile(label: s('health.cpu'), value: '${asMap(h['cpu'])['load1'] ?? '-'}'),
                      StatTile(
                        label: s('health.mem'),
                        value: '${mem['available_mb'] ?? '-'} / ${mem['total_mb'] ?? '-'} MB',
                      ),
                      StatTile(
                        label: s('health.temp'),
                        value: h['temperature_c'] == null ? '-' : '${h['temperature_c']} °C',
                      ),
                      StatTile(
                        key: const Key('health-power'),
                        label: s('health.power'),
                        value: uv ? s('health.power.low') : s('health.power.ok'),
                        warn: uv,
                      ),
                    ],
                  ),
                  for (final a in asList(h['alerts']))
                    ListTile(
                      leading: const Icon(Icons.warning_amber),
                      title: Text('$a'),
                      contentPadding: EdgeInsets.zero,
                    ),
                ],
              ),
              Section(
                title: s('caps.title'),
                children: [CapabilityList(caps: caps)],
              ),
            ],
          ),
        );
      },
    );
  }
}
