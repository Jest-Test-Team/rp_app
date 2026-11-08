// Firewall rules in plain language: ready-made protections (templates),
// rules for one device picked from the connected devices, and every rule
// shown as a sentence. The device validates and renders the rules
// (rp_core::firewall); nothing here is nftables text.

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/change_sheet.dart';
import '../../widgets/common.dart';

const zones = ['iot', 'vpn', 'lan', 'wan', 'device'];
const protos = ['any', 'tcp', 'udp', 'icmp'];
const actions = ['drop', 'reject', 'accept'];

/// What a rule is about, in everyday terms (proto + ports).
class Service {
  const Service(this.id, this.proto, this.ports);
  final String id;
  final String proto;
  final List<int> ports;
}

const services = [
  Service('any', 'any', []),
  Service('web', 'tcp', [80, 443]),
  Service('dns', 'udp', [53]),
  Service('telnet', 'tcp', [23, 2323]),
  Service('files', 'tcp', [445, 139]),
  Service('remote', 'tcp', [22, 3389, 5900]),
  Service('printing', 'tcp', [631, 9100]),
];

/// The preset matching a rule, or 'custom'.
String serviceOf(Map<String, Object?> r) {
  final proto = str(r['proto'], 'any');
  final ports = asList(r['ports']).whereType<int>().toList();
  for (final sv in services) {
    if (sv.proto == proto && sv.ports.length == ports.length && sv.ports.every(ports.contains)) return sv.id;
  }
  return 'custom';
}

final _mac = RegExp(r'^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$');
final _ipv4 = RegExp(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$');

/// "192.0.2.10" → "192.0.2.10/32"; a CIDR is kept; null if invalid.
String? hostNet(String text) {
  final t = text.trim();
  if (t.isEmpty) return null;
  final parts = t.split('/');
  final m = _ipv4.firstMatch(parts.first);
  if (m == null || [1, 2, 3, 4].any((i) => int.parse(m.group(i)!) > 255)) return null;
  if (parts.length == 1) return '$t/32';
  final p = int.tryParse(parts[1]);
  return parts.length == 2 && p != null && p >= 8 && p <= 32 ? t : null;
}

/// A rule as the API expects it (rp_schema::FwRule). Returns an error key or null.
String? validateRule(Map<String, Object?> r) {
  final name = str(r['name']);
  if (name.trim().isEmpty || name.length > 40 || !RegExp(r'^[A-Za-z0-9 _-]+$').hasMatch(name)) return 'name';
  if (r['from'] == 'device') return 'from';
  if (r['from'] == r['to'] && r['to'] != 'device') return 'to';
  // Home network <-> internet goes through the router, never through the Pi.
  if ({r['from'], r['to']}.containsAll(['lan', 'wan'])) return 'lanwan';
  final ports = asList(r['ports']);
  if (ports.isNotEmpty && !(r['proto'] == 'tcp' || r['proto'] == 'udp')) return 'proto';
  if (ports.any((p) => p is! int || p < 1 || p > 65535)) return 'ports';
  if (r['to'] == 'device' && r['action'] != 'accept' && ports.isEmpty) return 'ports';
  final macs = asList(r['src_mac']);
  if (macs.any((m) => m is! String || !_mac.hasMatch(m))) return 'mac';
  if (macs.isNotEmpty && !(r['from'] == 'lan' || r['from'] == 'iot')) return 'mac';
  if (asList(r['dest']).any((d) => d is! String || hostNet(d) == null)) return 'dest';
  return null;
}

List<int>? parsePorts(String text) {
  if (text.trim().isEmpty) return [];
  final out = <int>[];
  for (final p in text.split(',')) {
    final n = int.tryParse(p.trim());
    if (n == null || n < 1 || n > 65535) return null;
    out.add(n);
  }
  return out;
}

/// A device someone can pick (IoT Wi-Fi client, home-network device).
class KnownDevice {
  const KnownDevice({required this.mac, required this.ip, required this.name, required this.zone});
  final String mac;
  final String ip;
  final String name;
  final String zone;
}

/// "Block · Smart-home Wi-Fi (plug) → Internet · Telnet"
String describeRule(S s, Map<String, Object?> r, List<KnownDevice> devices) {
  String who(String zone, List<Object?> macs, List<Object?> ips) {
    final z = s('fw.zone.$zone');
    final names = [
      for (final m in macs.whereType<String>())
        devices.where((d) => d.mac.toLowerCase() == m.toLowerCase()).map((d) => d.name).firstOrNull ?? m,
      ...ips.whereType<String>().map((i) => i.replaceAll('/32', '')),
    ];
    return names.isEmpty ? z : '$z (${names.join(', ')})';
  }

  final sv = serviceOf(r);
  final what = sv == 'custom'
      ? '${str(r['proto'], 'any').toUpperCase()} ${asList(r['ports']).join(', ')}'.trim()
      : s('fw.svc.$sv');
  return '${s('fw.act.${str(r['action'], 'drop')}')} · '
      '${who(str(r['from']), asList(r['src_mac']), asList(r['src']))} → '
      '${who(str(r['to']), const [], asList(r['dest']))} · $what';
}

/// Ready-made protections. [build] gets the picked device and address.
class FwTemplate {
  const FwTemplate(
    this.id, {
    this.zone = 'iot',
    this.needsDevice = false,
    this.needsAddress = false,
    required this.build,
  });
  final String id;

  /// Only offered when this zone exists on the device ('iot' = IoT Wi-Fi, 'vpn').
  final String zone;
  final bool needsDevice;
  final bool needsAddress;
  final List<Map<String, Object?>> Function(KnownDevice? device, String? address) build;
}

/// A rule name the device accepts (letters, digits, space, - and _; 1-40).
String ruleName(String text) {
  final t = text.replaceAll(RegExp(r'[^A-Za-z0-9 _-]'), '').trim();
  return t.isEmpty ? 'rule' : (t.length > 40 ? t.substring(0, 40).trim() : t);
}

String _nameOf(KnownDevice? d) => d?.name ?? 'device';

final templates = [
  FwTemplate(
    'pause',
    needsDevice: true,
    build: (d, _) => [
      {
        'name': ruleName('Pause ${_nameOf(d)}'),
        'from': 'iot',
        'src_mac': [d!.mac],
        'to': 'wan',
        'proto': 'any',
        'ports': <int>[],
        'action': 'drop',
        'log': false,
      },
    ],
  ),
  FwTemplate(
    'telnet',
    build: (_, _) => [
      {
        'name': 'No Telnet from smart devices',
        'from': 'iot',
        'to': 'wan',
        'proto': 'tcp',
        'ports': [23, 2323],
        'action': 'reject',
        'log': true,
      },
    ],
  ),
  FwTemplate(
    'forcedns',
    build: (_, _) => [
      {
        'name': 'Smart devices use this DNS',
        'from': 'iot',
        'to': 'wan',
        'proto': 'udp',
        'ports': [53],
        'action': 'reject',
        'log': false,
      },
      {
        'name': 'Smart devices use this DNS tcp',
        'from': 'iot',
        'to': 'wan',
        'proto': 'tcp',
        'ports': [53, 853],
        'action': 'reject',
        'log': false,
      },
    ],
  ),
  FwTemplate(
    'iot_reach',
    needsDevice: true,
    needsAddress: true,
    build: (d, ip) => [
      {
        'name': ruleName('Let ${_nameOf(d)} reach home'),
        'from': 'iot',
        'src_mac': [d!.mac],
        'to': 'lan',
        'dest': [ip!],
        'proto': 'any',
        'ports': <int>[],
        'action': 'accept',
        'log': false,
      },
    ],
  ),
  FwTemplate(
    'vpn_nas',
    zone: 'vpn',
    needsAddress: true,
    build: (_, ip) => [
      {
        'name': ruleName('VPN users reach ${ip!.replaceAll('/32', '').replaceAll('.', '-')}'),
        'from': 'vpn',
        'to': 'lan',
        'dest': [ip],
        'proto': 'any',
        'ports': <int>[],
        'action': 'accept',
        'log': false,
      },
    ],
  ),
];

class FirewallPage extends StatelessWidget {
  const FirewallPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) => Loader<(Map<String, Object?>, Map<String, Object?>, Map<String, Object?>)>(
    load: () async => (await client.firewallRules(), await client.apClients(), await client.moduleConfig('vpn')),
    builder: (context, d, reload) {
      final ap = d.$2;
      final devices = [
        for (final c in asList(ap['clients']).map(asMap))
          if (str(c['mac']).isNotEmpty)
            KnownDevice(
              mac: str(c['mac']),
              ip: str(c['ip']),
              name: str(c['hostname']).isEmpty ? str(c['ip']) : str(c['hostname']),
              zone: 'iot',
            ),
      ];
      final hasZone = {'iot': ap['configured'] != false, 'vpn': asMap(asMap(d.$3['config'])['vpn']).isNotEmpty};
      return RuleList(
        client: client,
        rules: asList(d.$1['rules']).map(asMap).toList(),
        devices: devices,
        hasZone: hasZone,
        onSaved: reload,
      );
    },
  );
}

class RuleList extends StatefulWidget {
  const RuleList({
    super.key,
    required this.client,
    required this.rules,
    required this.onSaved,
    this.devices = const [],
    this.hasZone = const {'iot': true, 'vpn': true},
  });
  final RpClient client;
  final List<Map<String, Object?>> rules;
  final List<KnownDevice> devices;
  final Map<String, bool> hasZone;
  final VoidCallback onSaved;
  @override
  State<RuleList> createState() => _RuleListState();
}

class _RuleListState extends State<RuleList> {
  late List<Map<String, Object?>> rules = [for (final r in widget.rules) Map.of(r)];
  bool dirty = false;

  Future<void> _edit([int? i]) async {
    final r = await showDialog<Map<String, Object?>>(
      context: context,
      builder: (_) => RuleDialog(initial: i == null ? null : rules[i], devices: widget.devices),
    );
    if (r == null) return;
    setState(() {
      if (i == null) {
        rules.add(r);
      } else {
        rules[i] = r;
      }
      dirty = true;
    });
  }

  Future<void> _useTemplate(FwTemplate t) async {
    final picked = await showDialog<(KnownDevice?, String?)>(
      context: context,
      builder: (_) => TemplateDialog(template: t, devices: widget.devices),
    );
    if (picked == null) return;
    setState(() {
      rules.addAll(t.build(picked.$1, picked.$2));
      dirty = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final offered = templates.where((t) => widget.hasZone[t.zone] ?? false).toList();
    return ListView(
      children: [
        if (offered.isNotEmpty)
          Section(
            title: s('fw.templates'),
            children: [
              Text(s('fw.templates.body'), style: Theme.of(context).textTheme.bodySmall),
              for (final t in offered)
                ListTile(
                  key: Key('fw-tpl-${t.id}'),
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.shield_outlined),
                  title: Text(s('fw.tpl.${t.id}')),
                  subtitle: Text(s('fw.tpl.${t.id}.body')),
                  trailing: const Icon(Icons.add),
                  onTap: () => _useTemplate(t),
                ),
            ],
          ),
        Section(
          title: s('fw.rules'),
          trailing: IconButton(
            key: const Key('fw-add'),
            onPressed: () => _edit(),
            icon: const Icon(Icons.add),
            tooltip: s('fw.add'),
          ),
          children: [
            Text(s('fw.mgmt'), style: Theme.of(context).textTheme.bodySmall),
            if (rules.isEmpty) Padding(padding: const EdgeInsets.only(top: 8), child: Text(s('fw.empty'))),
            ReorderableListView(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              buildDefaultDragHandles: true,
              onReorderItem: (a, b) => setState(() {
                rules.insert(b, rules.removeAt(a));
                dirty = true;
              }),
              children: [
                for (final (i, r) in rules.indexed)
                  ListTile(
                    key: Key('fw-rule-$i'),
                    contentPadding: EdgeInsets.zero,
                    leading: Icon(r['action'] == 'accept' ? Icons.check_circle_outline : Icons.block),
                    title: Text(str(r['name'])),
                    subtitle: Text(describeRule(s, r, widget.devices)),
                    onTap: () => _edit(i),
                    trailing: IconButton(
                      key: Key('fw-del-$i'),
                      icon: const Icon(Icons.delete_outline),
                      onPressed: () => setState(() {
                        rules.removeAt(i);
                        dirty = true;
                      }),
                    ),
                  ),
              ],
            ),
            if (rules.length > 1) Text(s('fw.order'), style: Theme.of(context).textTheme.bodySmall),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton(
                key: const Key('fw-save'),
                onPressed: dirty
                    ? () async {
                        if (await showChange(context, widget.client, 'firewall', {'firewall.rules': rules})) {
                          setState(() => dirty = false);
                          widget.onSaved();
                        }
                      }
                    : null,
                child: Text(s('common.save')),
              ),
            ),
          ],
        ),
      ],
    );
  }
}

/// Picks what a template needs: a device and/or an address at home.
class TemplateDialog extends StatefulWidget {
  const TemplateDialog({super.key, required this.template, required this.devices});
  final FwTemplate template;
  final List<KnownDevice> devices;
  @override
  State<TemplateDialog> createState() => _TemplateDialogState();
}

class _TemplateDialogState extends State<TemplateDialog> {
  KnownDevice? device;
  final address = TextEditingController();
  String? error;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final t = widget.template;
    final candidates = widget.devices.where((d) => d.zone == t.zone).toList();
    return AlertDialog(
      title: Text(s('fw.tpl.${t.id}')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(s('fw.tpl.${t.id}.body')),
            if (t.needsDevice) ...[
              const SizedBox(height: 12),
              Text(s('fw.pick.device'), style: Theme.of(context).textTheme.titleSmall),
              if (candidates.isEmpty) Text(s('fw.pick.none')),
              RadioGroup<KnownDevice>(
                groupValue: device,
                onChanged: (v) => setState(() => device = v),
                child: Column(
                  children: [
                    for (final d in candidates)
                      RadioListTile<KnownDevice>(
                        key: Key('fw-pick-${d.mac}'),
                        contentPadding: EdgeInsets.zero,
                        value: d,
                        title: Text(d.name),
                        subtitle: Text('${d.ip} · ${d.mac}'),
                      ),
                  ],
                ),
              ),
            ],
            if (t.needsAddress) ...[
              const SizedBox(height: 12),
              TextField(
                key: const Key('fw-tpl-address'),
                controller: address,
                keyboardType: TextInputType.number,
                decoration: InputDecoration(labelText: s('fw.pick.address'), helperText: s('fw.pick.address.body')),
              ),
            ],
            if (error != null)
              Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Text(error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s('common.cancel'))),
        FilledButton(
          key: const Key('fw-tpl-ok'),
          onPressed: () {
            final ip = t.needsAddress ? hostNet(address.text) : null;
            if (t.needsDevice && device == null) {
              setState(() => error = s('fw.pick.device'));
              return;
            }
            if (t.needsAddress && ip == null) {
              setState(() => error = s('fw.err.dest'));
              return;
            }
            Navigator.pop(context, (device, ip));
          },
          child: Text(s('fw.tpl.add')),
        ),
      ],
    );
  }
}

class RuleDialog extends StatefulWidget {
  const RuleDialog({super.key, this.initial, this.devices = const []});
  final Map<String, Object?>? initial;
  final List<KnownDevice> devices;
  @override
  State<RuleDialog> createState() => _RuleDialogState();
}

class _RuleDialogState extends State<RuleDialog> {
  late final name = TextEditingController(text: str(widget.initial?['name']));
  late final ports = TextEditingController(text: asList(widget.initial?['ports']).join(', '));
  late final dest = TextEditingController(
    text: asList(widget.initial?['dest']).whereType<String>().map((d) => d.replaceAll('/32', '')).join(', '),
  );
  late String from = str(widget.initial?['from'], 'iot');
  late String to = str(widget.initial?['to'], 'wan');
  late String service = widget.initial == null ? 'any' : serviceOf(widget.initial!);
  late String proto = str(widget.initial?['proto'], 'tcp');
  late String action = str(widget.initial?['action'], 'drop');
  late bool log = flag(widget.initial?['log']);
  late final Set<String> macs = asList(widget.initial?['src_mac']).whereType<String>().toSet();
  String? error;

  Widget _dd(
    String label,
    String value,
    List<String> items,
    String Function(String) text,
    ValueChanged<String> on,
    String key,
  ) => Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: DropdownButtonFormField<String>(
      key: Key(key),
      initialValue: value,
      isExpanded: true,
      decoration: InputDecoration(labelText: label),
      items: [
        for (final i in items)
          DropdownMenuItem(
            value: i,
            child: Text(text(i), key: Key('$key-$i')),
          ),
      ],
      onChanged: (v) => setState(() => on(v ?? value)),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final pickable = widget.devices.where((d) => d.zone == from).toList();
    return AlertDialog(
      title: Text(s('fw.add')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            TextField(
              key: const Key('fw-name'),
              controller: name,
              decoration: InputDecoration(labelText: s('fw.name'), helperText: s('fw.name.body')),
            ),
            const SizedBox(height: 12),
            _dd(s('fw.from'), from, zones.where((z) => z != 'device').toList(), (z) => s('fw.zone.$z'), (v) {
              from = v;
              macs.clear();
            }, 'fw-from'),
            if (pickable.isNotEmpty) ...[
              Text(s('fw.only'), style: Theme.of(context).textTheme.bodySmall),
              Wrap(
                spacing: 6,
                children: [
                  for (final d in pickable)
                    FilterChip(
                      key: Key('fw-dev-${d.mac}'),
                      label: Text(d.name),
                      selected: macs.contains(d.mac),
                      onSelected: (v) => setState(() => v ? macs.add(d.mac) : macs.remove(d.mac)),
                    ),
                ],
              ),
              const SizedBox(height: 12),
            ],
            _dd(s('fw.to'), to, zones, (z) => s('fw.zone.$z'), (v) => to = v, 'fw-to'),
            if (to == 'lan' || to == 'iot')
              Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: TextField(
                  key: const Key('fw-dest'),
                  controller: dest,
                  decoration: InputDecoration(labelText: s('fw.dest'), helperText: s('fw.dest.body')),
                ),
              ),
            _dd(
              s('fw.what'),
              service,
              [for (final sv in services) sv.id, 'custom'],
              (v) => s('fw.svc.$v'),
              (v) => service = v,
              'fw-service',
            ),
            if (service == 'custom') ...[
              _dd(s('fw.proto'), proto, protos, (p) => p.toUpperCase(), (v) => proto = v, 'fw-proto'),
              TextField(
                key: const Key('fw-ports'),
                controller: ports,
                decoration: InputDecoration(labelText: s('fw.ports')),
              ),
              const SizedBox(height: 12),
            ],
            _dd(s('fw.action'), action, actions, (a) => s('fw.act.$a.long'), (v) => action = v, 'fw-action'),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: Text(s('fw.log')),
              value: log,
              onChanged: (v) => setState(() => log = v),
            ),
            if (error != null)
              Text(
                error!,
                key: const Key('fw-error'),
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
          ],
        ),
      ),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: Text(s('common.cancel'))),
        FilledButton(
          key: const Key('fw-ok'),
          onPressed: () {
            final sv = services.where((x) => x.id == service).firstOrNull;
            final p = sv?.ports ?? parsePorts(ports.text);
            final dests = (to == 'lan' || to == 'iot')
                ? dest.text.split(',').map((e) => e.trim()).where((e) => e.isNotEmpty).toList()
                : <String>[];
            final r = <String, Object?>{
              'name': name.text.trim(),
              'from': from,
              if (macs.isNotEmpty) 'src_mac': macs.toList(),
              'to': to,
              if (dests.isNotEmpty) 'dest': [for (final d in dests) hostNet(d) ?? d],
              'proto': sv?.proto ?? proto,
              'ports': p ?? [-1],
              'action': action,
              'log': log,
            };
            final bad = validateRule(r);
            if (bad != null) {
              setState(() => error = s('fw.err.$bad'));
              return;
            }
            Navigator.pop(context, r);
          },
          child: Text(s('common.save')),
        ),
      ],
    );
  }
}
