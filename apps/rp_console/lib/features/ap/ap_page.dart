import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../widgets/change_sheet.dart';
import '../../widgets/common.dart';

class ApPage extends StatelessWidget {
  const ApPage({super.key, required this.client});
  final RpClient client;

  @override
  Widget build(BuildContext context) => Loader<(Capabilities, Map<String, Object?>, Status, Map<String, Object?>)>(
    load: () async =>
        (await client.capabilities(), await client.moduleConfig('ap'), await client.status(), await client.apClients()),
    builder: (context, d, reload) {
      final cap = d.$1.module('ap');
      if (!cap.available) return ListView(children: [UnavailableBanner(cap: cap)]);
      return RefreshIndicator(
        onRefresh: () async => reload(),
        child: ListView(
          children: [
            ApForm(
              client: client,
              cfg: asMap(asMap(d.$2['config'])['ap']),
              cap: cap,
              passphraseSet: d.$3.secretSet('ap_passphrase'),
              onSaved: reload,
            ),
            Section(
              title: S.of(context)('ap.clients'),
              children: [
                for (final c in asList(d.$4['clients']).map(asMap))
                  ListTile(
                    dense: true,
                    contentPadding: EdgeInsets.zero,
                    leading: const Icon(Icons.devices_other),
                    title: Text(str(c['hostname'], str(c['mac']))),
                    subtitle: Text('${str(c['ip'])} · ${str(c['mac'])}'),
                    trailing: flag(c['new']) ? const Chip(label: Text('new')) : null,
                  ),
              ],
            ),
          ],
        ),
      );
    },
  );
}

class ApForm extends StatefulWidget {
  const ApForm({
    super.key,
    required this.client,
    required this.cfg,
    required this.cap,
    required this.passphraseSet,
    required this.onSaved,
  });
  final RpClient client;
  final Map<String, Object?> cfg;
  final ModuleCapability cap;
  final bool passphraseSet;
  final VoidCallback onSaved;

  @override
  State<ApForm> createState() => _ApFormState();
}

class _ApFormState extends State<ApForm> {
  late final ssid = TextEditingController(text: str(widget.cfg['ssid']));
  late final country = TextEditingController(text: str(widget.cfg['country'], 'TW'));
  late final subnet = TextEditingController(text: str(widget.cfg['subnet']));
  final pass = TextEditingController();
  late int channel = integer(widget.cfg['channel'], 6);
  late bool blockDot = flag(widget.cfg['block_dot']);
  late bool lanReach = widget.cfg['lan_can_reach_clients'] != false;
  late String iface = str(widget.cfg['interface'], widget.cap.options.isEmpty ? 'wlan0' : widget.cap.options.first);
  String? error;

  bool get enabled => widget.cfg.isNotEmpty;

  @override
  void dispose() {
    for (final c in [ssid, country, subnet, pass]) {
      c.dispose();
    }
    super.dispose();
  }

  /// The patch for the change set; null (and `error` set) when invalid.
  Map<String, Object?>? patch() {
    final s = S.of(context);
    final ss = ssid.text.trim();
    if (ss.isEmpty || ss.length > 32) return _err(s('ap.ssid'));
    final p = pass.text;
    if (p.isNotEmpty && (p.length < 8 || p.length > 63)) return _err(s('ap.passphrase'));
    if (!widget.passphraseSet && p.isEmpty) return _err(s('ap.passphrase'));
    if (!RegExp(r'^[A-Za-z]{2}$').hasMatch(country.text.trim())) return _err(s('ap.country'));
    final out = <String, Object?>{
      'ap.interface': iface,
      'ap.ssid': ss,
      'ap.country': country.text.trim().toUpperCase(),
      'ap.channel': channel,
      'ap.block_dot': blockDot,
      'ap.lan_can_reach_clients': lanReach,
    };
    if (subnet.text.trim().isNotEmpty) out['ap.subnet'] = subnet.text.trim();
    setState(() => error = null);
    return out;
  }

  Map<String, Object?>? _err(String field) {
    setState(() => error = field);
    return null;
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    final wpa2Only = widget.cap.notes.contains('wpa2_only');
    return Section(
      title: enabled ? s('module.ap') : s('ap.enable'),
      children: [
        TextField(
          key: const Key('ap-ssid'),
          controller: ssid,
          decoration: InputDecoration(labelText: s('ap.ssid')),
        ),
        const SizedBox(height: 12),
        TextField(
          key: const Key('ap-pass'),
          controller: pass,
          obscureText: true,
          autocorrect: false,
          enableSuggestions: false,
          decoration: InputDecoration(
            labelText: s('ap.passphrase'),
            helperText: widget.passphraseSet ? s('ap.passphrase.set') : null,
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: TextField(
                key: const Key('ap-country'),
                controller: country,
                decoration: InputDecoration(labelText: s('ap.country')),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: DropdownButtonFormField<int>(
                key: const Key('ap-channel'),
                initialValue: channel,
                decoration: InputDecoration(labelText: s('ap.channel')),
                items: [for (var c = 1; c <= 13; c++) DropdownMenuItem(value: c, child: Text('$c'))],
                onChanged: (v) => setState(() => channel = v ?? channel),
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        TextField(
          key: const Key('ap-subnet'),
          controller: subnet,
          decoration: InputDecoration(labelText: s('ap.subnet'), hintText: '10.77.0.0/24'),
        ),
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: const Icon(Icons.lock_outline),
          title: Text(s('ap.security')),
          subtitle: Text(wpa2Only ? 'WPA2-Personal · ${s.reason('wpa2_only')}' : 'WPA2-Personal'),
        ),
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: const Icon(Icons.shield_outlined),
          title: Text(s('ap.isolation')),
          subtitle: Text(s('ap.isolation.body')),
        ),
        SwitchListTile(
          key: const Key('ap-dot'),
          contentPadding: EdgeInsets.zero,
          title: Text(s('ap.dot')),
          subtitle: Text(s('ap.dot.body')),
          value: blockDot,
          onChanged: (v) => setState(() => blockDot = v),
        ),
        SwitchListTile(
          key: const Key('ap-lanreach'),
          contentPadding: EdgeInsets.zero,
          title: Text(s('ap.lanreach')),
          value: lanReach,
          onChanged: (v) => setState(() => lanReach = v),
        ),
        if (error != null)
          Text(
            error!,
            key: const Key('ap-error'),
            style: TextStyle(color: Theme.of(context).colorScheme.error),
          ),
        Align(
          alignment: Alignment.centerRight,
          child: FilledButton(
            key: const Key('ap-save'),
            onPressed: () async {
              final p = patch();
              if (p == null) return;
              final secret = pass.text;
              final ok = await showChange(
                context,
                widget.client,
                'ap',
                p,
                before: secret.isEmpty ? null : () => widget.client.setSecret('ap_passphrase', secret),
              );
              pass.clear();
              if (ok) widget.onSaved();
            },
            child: Text(s('common.save')),
          ),
        ),
      ],
    );
  }
}
