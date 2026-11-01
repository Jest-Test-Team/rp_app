// "Add Raspberry Pi": six steps (plan §4.6).
//
//  1. Path: new SD card (desktop) · already running (SSH) · pairing code
//  2. Prepare: write the card / install over SSH / enter the code
//  3. Find the device (mDNS, or an address)
//  4. Pair: both sides prove the code; the certificate is pinned
//  5. What this hardware can run
//  6. Verify: a signed session works

import 'dart:io';

import 'package:flutter/material.dart';

import '../../app/app_state.dart';
import '../../app/strings.dart';
import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/api/transport.dart';
import '../../core/auth/admin_key.dart';
import '../../core/discovery/discovery.dart';
import '../../core/pairing/pairing.dart';
import '../../core/provision/bootfs.dart' as bootfs;
import '../../core/provision/ssh_bootstrap.dart';
import '../../core/storage/vault.dart';
import '../../widgets/common.dart';

enum SetupPath { card, ssh, code }

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key, required this.app});
  final AppState app;

  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  int step = 0;
  SetupPath? path;
  PairingCode? code;
  PairedDevice? paired;
  RpClient? client;
  String? error;
  bool busy = false;
  String progress = '';

  final codeText = TextEditingController();
  final hostText = TextEditingController();
  final userText = TextEditingController(text: 'pi');
  final passText = TextEditingController();
  final nameText = TextEditingController(text: Platform.isAndroid || Platform.isIOS ? 'Phone' : 'Computer');
  final bootDir = TextEditingController();
  final hostname = TextEditingController(text: 'rp-security');
  final ssid = TextEditingController();
  final wifiPass = TextEditingController();
  final country = TextEditingController(text: 'TW');
  List<Found> found = [];

  S get s => S.of(context);

  @override
  void initState() {
    super.initState();
    if (widget.app.services.desktop) {
      final c = bootfs.candidateBootPartitions();
      if (c.isNotEmpty) bootDir.text = c.first.path;
    }
  }

  @override
  void dispose() {
    for (final c in [codeText, hostText, userText, passText, nameText, bootDir, hostname, ssid, wifiPass, country]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _run(Future<void> Function() f) async {
    setState(() {
      busy = true;
      error = null;
    });
    try {
      await f();
    } on PinMismatch {
      error = s('pair.pin');
    } on PairingFailed catch (e) {
      error = s('pair.failed', {'why': e.reason});
    } on BootstrapError catch (e) {
      error = e.message;
    } on bootfs.InvalidSpec catch (e) {
      error = e.toString();
    } on FormatException catch (e) {
      error = e.message;
    } on ApiException catch (e) {
      error = e.code == 'pairing_closed' || e.code == 'unauthorized' ? s('pair.failed', {'why': e.message}) : e.message;
    } catch (e) {
      error = '${s('common.error')}: $e';
    } finally {
      if (mounted) setState(() => busy = false);
    }
  }

  // ------------------------------------------------------------ actions

  Future<void> _writeCard() => _run(() async {
    final rel = await widget.app.services.release();
    final wifi = ssid.text.trim().isEmpty
        ? null
        : bootfs.WifiSpec(ssid: ssid.text.trim(), password: wifiPass.text, country: country.text.trim());
    final secret = randomHex(32);
    final spec = bootfs.ProvisionSpec(
      hostname: hostname.text.trim(),
      tag: rel.tag,
      installSha256: rel.installSha256,
      pairingSecret: secret,
      instanceId: 'rp-${DateTime.now().millisecondsSinceEpoch ~/ 1000}',
      wifi: wifi,
    );
    bootfs.writeCard(Directory(bootDir.text.trim()), spec);
    wifiPass.clear();
    code = PairingCode(host: '${spec.hostname}.local', port: 8443, secret: secret);
    progress = s('onb.card.done');
  });

  Future<void> _installOverSsh() => _run(() async {
    final host = hostText.text.trim();
    final rel = await widget.app.services.release();
    final password = passText.text;
    final shell = await widget.app.services.shell(
      host: host,
      user: userText.text.trim(),
      password: password,
      verifyHostKey: (type, fp) => _askHostKey(host, '$type SHA256:$fp'),
    );
    try {
      final b = Bootstrapper(shell, tag: rel.tag, installSha256: rel.installSha256);
      code = await b.run(
        host: host,
        password: password,
        onStep: (st) => setState(
          () => progress = switch (st) {
            BootstrapStep.checking => s('onb.ssh.checking'),
            BootstrapStep.downloading => s('onb.ssh.downloading'),
            BootstrapStep.installing => s('onb.ssh.installing'),
            BootstrapStep.done => '',
          },
        ),
      );
    } finally {
      passText.clear();
      await shell.close();
    }
  });

  Future<bool> _askHostKey(String host, String fp) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (c) => AlertDialog(
        content: Text(s('onb.ssh.hostkey', {'host': host, 'fp': fp})),
        actions: [
          TextButton(onPressed: () => Navigator.pop(c, false), child: Text(s('common.cancel'))),
          FilledButton(
            key: const Key('hostkey-trust'),
            onPressed: () => Navigator.pop(c, true),
            child: Text(s('common.next')),
          ),
        ],
      ),
    );
    return ok ?? false;
  }

  void _parseCode() {
    try {
      code = PairingCode.parse(codeText.text, host: hostText.text.trim().isEmpty ? null : hostText.text.trim());
      error = null;
    } on FormatException catch (e) {
      code = null;
      error = e.message;
    }
    setState(() {});
  }

  Future<void> _scan() => _run(() async {
    found = await widget.app.services.discoverer.scan();
  });

  void _useHost(String host, int port) {
    final c = code;
    if (c == null) return;
    setState(() => code = PairingCode(host: host, port: port, secret: c.secret, device: c.device, cert: c.cert));
  }

  Future<void> _pair() => _run(() async {
    final c = code!;
    final key = await widget.app.services.vault.adminKey();
    final t = widget.app.services.transport(c.host, c.port, c.cert);
    final cl = RpClient(t);
    final r = await cl.pair(c, key, nameText.text.trim().isEmpty ? 'App' : nameText.text.trim());
    final d = PairedDevice(
      deviceId: r.deviceId,
      name: c.host.replaceAll('.local', ''),
      host: c.host,
      port: c.port,
      certSha256: r.certSha256,
      adminId: r.adminId,
      addedAt: DateTime.now().millisecondsSinceEpoch ~/ 1000,
    );
    await widget.app.add(d);
    paired = d;
    client = await widget.app.client(d);
    step = 4;
  });

  // -------------------------------------------------------------- steps

  bool get _canNext => switch (step) {
    0 => path != null,
    1 => code != null && !busy,
    2 => code != null,
    4 => true,
    _ => false,
  };

  void _next() => setState(() {
    error = null;
    progress = '';
    step = switch (step) {
      1 when path != SetupPath.card => 3,
      _ => step + 1,
    };
    if (step == 2) _scan();
  });

  void _back() => setState(() {
    error = null;
    step = switch (step) {
      3 when path != SetupPath.card => 1,
      _ => step - 1,
    };
  });

  @override
  Widget build(BuildContext context) {
    final titles = [
      'onb.path.title',
      _prepareTitle,
      'onb.find.title',
      'onb.pair.title',
      'onb.caps.title',
      'onb.verify.title',
    ];
    return Scaffold(
      appBar: AppBar(title: Text(s('onb.title'))),
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            LinearProgressIndicator(value: (step + 1) / 6),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 16, 16, 0),
              child: Text(
                s('onb.step', {'n': step + 1}),
                key: const Key('onb-step'),
                style: Theme.of(context).textTheme.labelLarge,
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 8),
              child: Text(s(titles[step]), style: Theme.of(context).textTheme.headlineSmall),
            ),
            Expanded(
              child: SingleChildScrollView(padding: const EdgeInsets.all(16), child: _body()),
            ),
            if (error != null)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Text(
                  error!,
                  key: const Key('onb-error'),
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            if (progress.isNotEmpty)
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 16),
                child: Text(progress, key: const Key('onb-progress')),
              ),
            if (busy) const Padding(padding: EdgeInsets.all(8), child: LinearProgressIndicator()),
            Padding(
              padding: const EdgeInsets.all(16),
              child: Row(
                children: [
                  if (step > 0 && step < 4) TextButton(onPressed: busy ? null : _back, child: Text(s('common.back'))),
                  const Spacer(),
                  if (step == 5)
                    FilledButton(
                      key: const Key('onb-finish'),
                      onPressed: () => Navigator.of(context).pop(paired),
                      child: Text(s('onb.finish')),
                    )
                  else if (step != 3)
                    FilledButton(
                      key: const Key('onb-next'),
                      onPressed: _canNext ? _next : null,
                      child: Text(s('common.next')),
                    ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  String get _prepareTitle => switch (path) {
    SetupPath.card => 'onb.card.title',
    SetupPath.ssh => 'onb.ssh.title',
    _ => 'onb.code.title',
  };

  Widget _body() => switch (step) {
    0 => _pathStep(),
    1 => switch (path!) {
      SetupPath.card => _cardStep(),
      SetupPath.ssh => _sshStep(),
      SetupPath.code => _codeStep(),
    },
    2 => _findStep(),
    3 => _pairStep(),
    4 => _capsStep(),
    _ => _verifyStep(),
  };

  Widget _pathCard(SetupPath p, String key, IconData icon, {bool enabled = true}) => Card(
    child: RadioListTile<SetupPath>(
      key: Key('path-${p.name}'),
      value: p,
      enabled: enabled,
      secondary: Icon(icon),
      title: Text(s(key)),
      subtitle: Text(s('$key.body')),
    ),
  );

  Widget _pathStep() => RadioGroup<SetupPath>(
    groupValue: path,
    onChanged: (v) => setState(() => path = v),
    child: Column(
      children: [
        _pathCard(SetupPath.card, 'onb.path.card', Icons.sd_card_outlined, enabled: widget.app.services.desktop),
        _pathCard(SetupPath.ssh, 'onb.path.ssh', Icons.terminal),
        _pathCard(SetupPath.code, 'onb.path.code', Icons.qr_code_2),
      ],
    ),
  );

  Widget _field(
    TextEditingController c,
    String label,
    String key, {
    bool obscure = false,
    ValueChanged<String>? onChanged,
  }) => Padding(
    padding: const EdgeInsets.only(bottom: 12),
    child: TextField(
      key: Key(key),
      controller: c,
      obscureText: obscure,
      autocorrect: false,
      enableSuggestions: !obscure,
      onChanged: onChanged,
      decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
    ),
  );

  Widget _cardStep() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      _field(bootDir, s('onb.card.dir'), 'bootfs-field'),
      if (bootDir.text.isEmpty)
        Padding(padding: const EdgeInsets.only(bottom: 12), child: Text(s('onb.card.notfound'))),
      _field(hostname, s('onb.card.hostname'), 'hostname-field'),
      Text(s('onb.card.wifi'), style: Theme.of(context).textTheme.titleSmall),
      const SizedBox(height: 8),
      _field(ssid, s('onb.card.wifi.ssid'), 'ssid-field'),
      _field(wifiPass, s('onb.card.wifi.password'), 'wifipass-field', obscure: true),
      _field(country, s('onb.card.country'), 'country-field'),
      FilledButton.tonal(
        key: const Key('card-write'),
        onPressed: busy ? null : _writeCard,
        child: Text(s('onb.card.write')),
      ),
    ],
  );

  Widget _sshStep() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      _field(hostText, s('onb.ssh.host'), 'ssh-host'),
      _field(userText, s('onb.ssh.user'), 'ssh-user'),
      _field(passText, s('onb.ssh.password'), 'ssh-password', obscure: true),
      FilledButton.tonal(
        key: const Key('ssh-run'),
        onPressed: busy ? null : _installOverSsh,
        child: Text(s('onb.ssh.run')),
      ),
    ],
  );

  Widget _codeStep() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      Padding(
        padding: const EdgeInsets.only(bottom: 12),
        child: TextField(
          key: const Key('code-field'),
          controller: codeText,
          minLines: 2,
          maxLines: 5,
          autocorrect: false,
          onChanged: (_) => _parseCode(),
          decoration: InputDecoration(labelText: s('onb.code.paste'), border: const OutlineInputBorder()),
        ),
      ),
      _field(hostText, s('onb.code.host'), 'host-field', onChanged: (_) => _parseCode()),
      if (code != null) ListTile(leading: const Icon(Icons.check), title: Text('${code!.host}:${code!.port}')),
    ],
  );

  Widget _findStep() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      Row(
        children: [
          Expanded(child: Text(busy ? s('onb.find.scanning') : (found.isEmpty ? s('onb.find.none') : ''))),
          IconButton(onPressed: busy ? null : _scan, icon: const Icon(Icons.refresh), tooltip: s('common.refresh')),
        ],
      ),
      for (final f in found)
        Card(
          child: ListTile(
            key: Key('found-${f.host}'),
            leading: const Icon(Icons.router_outlined),
            title: Text(f.name),
            subtitle: Text('${f.connectHost}:${f.port}'),
            selected: code?.host == f.connectHost,
            onTap: () => _useHost(f.connectHost, f.port),
          ),
        ),
      const SizedBox(height: 12),
      _field(
        hostText,
        s('onb.code.host'),
        'find-host',
        onChanged: (v) {
          if (v.trim().isNotEmpty) _useHost(v.trim(), code?.port ?? 8443);
        },
      ),
      if (code != null) Text('→ ${code!.host}:${code!.port}', key: const Key('find-target')),
    ],
  );

  Widget _pairStep() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      _field(nameText, s('onb.pair.name'), 'name-field'),
      if (code != null) ListTile(leading: const Icon(Icons.lan_outlined), title: Text('${code!.host}:${code!.port}')),
      FilledButton(
        key: const Key('pair-button'),
        onPressed: busy || code == null ? null : _pair,
        child: Text(s('onb.pair.go')),
      ),
    ],
  );

  Widget _capsStep() => Column(
    crossAxisAlignment: CrossAxisAlignment.stretch,
    children: [
      Text(s('onb.pair.ok'), key: const Key('paired-ok')),
      const SizedBox(height: 12),
      Loader<Capabilities>(
        load: () => client!.capabilities(),
        builder: (context, caps, _) => CapabilityList(caps: caps),
      ),
    ],
  );

  Widget _verifyStep() => Loader<Map<String, Object?>>(
    load: () async {
      await client!.openSession();
      return client!.health();
    },
    builder: (context, h, _) => ListTile(
      key: const Key('verify-ok'),
      leading: const Icon(Icons.verified_outlined, color: Colors.green),
      title: Text(s('onb.verify.ok')),
      subtitle: Text('${s('health.title')}: ${str(h['status'], '-')}'),
    ),
  );
}

class CapabilityList extends StatelessWidget {
  const CapabilityList({super.key, required this.caps});
  final Capabilities caps;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    const order = ['base', 'dns', 'ap', 'vpn', 'firewall', 'agent', 'api'];
    final names = [...order.where(caps.moduleNames.contains), ...caps.moduleNames.where((m) => !order.contains(m))];
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        ListTile(
          contentPadding: EdgeInsets.zero,
          leading: const Icon(Icons.memory),
          title: Text(caps.model),
          subtitle: Text('${caps.arch} · ${caps.ramMb} MB'),
        ),
        for (final m in names)
          Builder(
            builder: (context) {
              final c = caps.module(m);
              return ListTile(
                key: Key('cap-$m'),
                contentPadding: EdgeInsets.zero,
                leading: Icon(
                  c.available ? Icons.check_circle_outline : Icons.block,
                  color: c.available ? Colors.green : Colors.grey,
                ),
                title: Text(s.module(m)),
                subtitle: Text(
                  [
                    if (c.available) s('caps.available'),
                    ...c.reasons.map(s.reason),
                    ...c.notes.map(s.reason),
                  ].join(' · '),
                ),
              );
            },
          ),
      ],
    );
  }
}
