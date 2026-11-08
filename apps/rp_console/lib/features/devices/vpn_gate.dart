// Away from home the app reaches the Raspberry Pi only through a VPN, so a
// phone without Tailscale or WireGuard is asked — and kept asking — to
// install one. Checked at start and whenever the app comes back (e.g. from
// the store).

import 'package:flutter/material.dart';

import '../../app/strings.dart';
import '../../core/vpn/vpn_platform.dart';

class VpnGate extends StatefulWidget {
  const VpnGate({super.key, required this.vpn, required this.child});
  final VpnPlatform? vpn;
  final Widget child;
  @override
  State<VpnGate> createState() => _VpnGateState();
}

class _VpnGateState extends State<VpnGate> with WidgetsBindingObserver {
  bool _showing = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    WidgetsBinding.instance.addPostFrameCallback((_) => _check());
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState s) {
    if (s == AppLifecycleState.resumed) _check();
  }

  Future<void> _check() async {
    final vpn = widget.vpn;
    if (vpn == null || !mounted) return;
    VpnApps apps;
    try {
      apps = await vpn.installedApps();
    } catch (_) {
      return; // cannot tell: never lock the user out
    }
    if (!mounted) return;
    if (apps.any) {
      if (_showing) Navigator.of(context, rootNavigator: true).pop();
      return;
    }
    if (_showing) return;
    _showing = true;
    await showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => PopScope(
        canPop: false,
        child: InstallVpnDialog(vpn: vpn, onCheck: _check),
      ),
    );
    _showing = false;
  }

  @override
  Widget build(BuildContext context) => widget.child;
}

class InstallVpnDialog extends StatelessWidget {
  const InstallVpnDialog({super.key, required this.vpn, required this.onCheck});
  final VpnPlatform vpn;
  final Future<void> Function() onCheck;

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return AlertDialog(
      key: const Key('vpn-install'),
      icon: const Icon(Icons.vpn_lock_outlined),
      title: Text(s('vpngate.title')),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(s('vpngate.body')),
            const SizedBox(height: 12),
            FilledButton.icon(
              key: const Key('vpngate-tailscale'),
              onPressed: () => vpn.openStore(kTailscalePackage),
              icon: const Icon(Icons.download),
              label: Text(s('vpngate.tailscale')),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              key: const Key('vpngate-wireguard'),
              onPressed: () => vpn.openStore(kWireguardPackage),
              icon: const Icon(Icons.download),
              label: Text(s('vpngate.wireguard')),
            ),
          ],
        ),
      ),
      actions: [TextButton(key: const Key('vpngate-check'), onPressed: onCheck, child: Text(s('vpngate.check')))],
    );
  }
}
