// Everything the UI needs from the outside world, injectable for tests.

import '../core/api/client.dart';
import '../core/api/transport.dart';
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
    this.desktop = false,
  }) : transport = transport ?? ((h, p, pin) => PinnedTransport(host: h, port: p, pin: pin)),
       shell =
           shell ??
           (({required host, required user, required password, required verifyHostKey}) =>
               DartSshShell.connect(host: host, user: user, password: password, verifyHostKey: verifyHostKey)),
       release = release ?? fetchRelease;

  final Vault vault;
  final Discoverer discoverer;
  final TransportFactory transport;
  final ShellFactory shell;
  final Future<ReleaseInfo> Function() release;

  /// Can write SD cards (desktop builds).
  final bool desktop;

  Future<RpClient> clientFor(PairedDevice d) async =>
      RpClient(transport(d.host, d.port, d.certSha256), key: await vault.adminKey(), deviceId: d.deviceId);
}
