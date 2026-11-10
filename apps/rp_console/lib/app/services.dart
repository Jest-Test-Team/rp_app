// Everything the UI needs from the outside world, injectable for tests.

import 'package:flutter/widgets.dart';

import '../core/api/client.dart';
import '../core/api/routing_transport.dart';
import '../core/api/transport.dart';
import '../core/vpn/vpn_platform.dart';
import '../core/discovery/discovery.dart';
import '../core/provision/ssh_bootstrap.dart';
import '../core/storage/vault.dart';
import 'release.dart';

typedef TransportFactory = Transport Function(String host, int port, String? pin);
typedef ShellFactory = Future<Shell> Function({
  required String host,
  required String user,
  required String password,
  required Future<bool> Function(String type, String fp) verifyHostKey,
});

class Services {
  Services({
    required this.vault,
    required this.discoverer,
    TransportFactory? transport,
    ShellFactory? shell,
    Future<ReleaseInfo> Function()? release,
    Future<String?> Function()? latest,
    this.desktop = false,
    this.demoPairingCode,
    this.scanQr,
    Future<String?> Function()? publicIp,
    this.vpn,
  }) : transport = transport ?? ((h, p, pin) => PinnedTransport(host: h, port: p, pin: pin)),
       shell =
           shell ??
           (({required host, required user, required password, required verifyHostKey}) =>
               DartSshShell.connect(host: host, user: user, password: password, verifyHostKey: verifyHostKey)),
       release = release ?? fetchRelease,
       latest = latest ?? latestTag,
       publicIp = publicIp ?? fetchPublicIp;

  final Vault vault;
  final Discoverer discoverer;
  final TransportFactory transport;
  final ShellFactory shell;
  final Future<ReleaseInfo> Function() release;
  final Future<String?> Function() latest;

  /// The home network's public IP (WireGuard endpoint suggestion).
  final Future<String?> Function() publicIp;

  /// Demo mode: the simulated device's pairing code (shown and pre-filled).
  final String? demoPairingCode;

  /// Opens the camera and returns the text of a scanned QR code (null when
  /// cancelled). Null on platforms without a scanner (the code is pasted).
  final Future<String?> Function(BuildContext context)? scanQr;

  /// The phone's VPN apps and state (Android); null elsewhere (no VPN check).
  final VpnPlatform? vpn;

  /// Can write SD cards (desktop builds).
  final bool desktop;

  /// A client that reaches [d] at home or over the VPN (see RoutingTransport).
  Future<RpClient> clientFor(PairedDevice d) async => RpClient(
    RoutingTransport(
      lanHost: d.host,
      vpnHosts: d.vpnHosts,
      open: (h) => transport(h, d.port, d.certSha256),
      vpnActive: () async => await vpn?.vpnActive() ?? false,
    ),
    key: await vault.adminKey(),
    deviceId: d.deviceId,
  );
}
