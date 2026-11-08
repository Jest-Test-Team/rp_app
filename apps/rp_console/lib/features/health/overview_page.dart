import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/common.dart';
import '../onboarding/onboarding.dart' show CapabilityList;

/// rp-agent's `/v1/health` (crates/rp-agent/src/collect.rs `health()`) in
/// display form. Missing values become null, shown as "-".
class HealthView {
  HealthView(Map<String, Object?> h)
    : status = str(h['status'], 'ok'),
      load = asList(h['load']).whereType<num>().map((n) => n.toDouble()).toList(),
      memTotalMb = _mb(h['mem_total_kb']),
      memAvailableMb = _mb(h['mem_available_kb']),
      cpuMhz = h['cpu_mhz'] is num ? (h['cpu_mhz']! as num).toInt() : null,
      temperatureC = h['temperature_c'] is num ? (h['temperature_c']! as num).toDouble() : null,
      diskUsedPercent = h['disk_used_percent'] is num ? (h['disk_used_percent']! as num).toInt() : null,
      uptimeS = h['uptime_s'] is num ? (h['uptime_s']! as num).toInt() : null,
      underVoltage = flag(h['under_voltage']),
      alerts = asList(h['alerts']).map(asMap).toList();

  static int? _mb(Object? kb) => kb is num ? (kb / 1024).round() : null;

  final String status;
  final List<double> load;
  final int? memTotalMb, memAvailableMb, cpuMhz, diskUsedPercent, uptimeS;
  final double? temperatureC;
  final bool underVoltage;
  final List<Map<String, Object?>> alerts;

  bool get ok => status == 'ok';

  /// "0.21 · 0.18 · 0.15" (1, 5, 15 minutes).
  String get loadText => load.isEmpty ? '-' : load.map((l) => l.toStringAsFixed(2)).join(' · ');

  String get memText => memAvailableMb == null
      ? '-'
      : memTotalMb == null
      ? '$memAvailableMb MB'
      : '$memAvailableMb / $memTotalMb MB';

  bool get memLow => memAvailableMb != null && memTotalMb != null && memAvailableMb! * 10 < memTotalMb!;

  String get tempText => temperatureC == null ? '-' : '${temperatureC!.toStringAsFixed(1)} °C';

  String get diskText => diskUsedPercent == null ? '-' : '$diskUsedPercent %';

  String uptimeText(S s) {
    final u = uptimeS;
    if (u == null) return '-';
    final d = u ~/ 86400, h = (u % 86400) ~/ 3600, m = (u % 3600) ~/ 60;
    return d > 0 ? s('health.uptime.dh', {'d': '$d', 'h': '$h'}) : s('health.uptime.hm', {'h': '$h', 'm': '$m'});
  }
}

class OverviewPage extends StatelessWidget {
  const OverviewPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Loader<(Map<String, Object?>, Capabilities)>(
      load: () async => (await client.health(), await client.capabilities()),
      builder: (context, d, reload) {
        final (raw, caps) = d;
        final h = HealthView(raw);
        return RefreshIndicator(
          onRefresh: () async => reload(),
          child: ListView(
            children: [
              Section(
                title: s('health.title'),
                trailing: Chip(
                  key: const Key('health-status'),
                  avatar: Icon(h.ok ? Icons.check : Icons.warning_amber, size: 18),
                  label: Text(h.ok ? s('health.ok') : s('health.warn')),
                ),
                children: [
                  StatGrid(
                    tiles: [
                      StatTile(
                        key: const Key('health-cpu'),
                        label: h.cpuMhz == null ? s('health.cpu') : '${s('health.cpu')} · ${h.cpuMhz} MHz',
                        value: h.loadText,
                      ),
                      StatTile(key: const Key('health-mem'), label: s('health.mem'), value: h.memText, warn: h.memLow),
                      StatTile(label: s('health.temp'), value: h.tempText, warn: (h.temperatureC ?? 0) >= 70),
                      StatTile(
                        key: const Key('health-power'),
                        label: s('health.power'),
                        value: h.underVoltage ? s('health.power.low') : s('health.power.ok'),
                        warn: h.underVoltage,
                      ),
                      StatTile(label: s('health.disk'), value: h.diskText, warn: (h.diskUsedPercent ?? 0) >= 90),
                      StatTile(label: s('health.uptime'), value: h.uptimeText(s)),
                    ],
                  ),
                  if (h.load.isNotEmpty)
                    Padding(
                      padding: const EdgeInsets.only(top: 4),
                      child: Text(s('health.load.hint'), style: Theme.of(context).textTheme.bodySmall),
                    ),
                  for (final a in h.alerts)
                    ListTile(
                      key: Key('alert-${str(a['kind'])}'),
                      leading: Icon(
                        str(a['level']) == 'critical' ? Icons.error_outline : Icons.warning_amber,
                        color: str(a['level']) == 'critical' ? Theme.of(context).colorScheme.error : null,
                      ),
                      title: Text(s('health.alert.${str(a['kind'])}', {}, str(a['kind']))),
                      subtitle: Text(str(a['detail'])),
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
