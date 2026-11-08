// Reaches one paired device over whichever path works: its home-network
// address or its VPN addresses (Tailscale name / IPs, WireGuard address).
// With the phone's VPN up the VPN addresses are tried first — with an exit
// node, even the home address is routed into the tunnel and is unreachable.
// Every path is pinned to the same certificate, so a wrong path fails closed.

import 'dart:async';
import 'dart:io';

import 'transport.dart';

typedef HostTransport = Transport Function(String host);

class RoutingTransport implements Transport {
  RoutingTransport({
    required this.lanHost,
    required this.vpnHosts,
    required this.open,
    required this.vpnActive,
    this.probeTimeout = const Duration(seconds: 4),
  });

  final String lanHost;
  final List<String> vpnHosts;
  final HostTransport open;
  final Future<bool> Function() vpnActive;
  final Duration probeTimeout;

  String? _host;
  Transport? _t;

  /// The address in use (null until the first request).
  String? get host => _host;
  bool get viaVpn => _host != null && _host != lanHost;

  @override
  String? get seenCert => _t?.seenCert;

  Future<List<String>> candidates() async {
    final vpn = [
      for (final h in vpnHosts)
        if (h.isNotEmpty && h != lanHost) h,
    ];
    bool up;
    try {
      up = await vpnActive();
    } catch (_) {
      up = false;
    }
    return up ? [...vpn, lanHost] : [lanHost, ...vpn];
  }

  /// Errors that mean "try another path". A pin mismatch never is.
  static bool _unreachable(Object e) =>
      e is Unreachable ||
      e is SocketException ||
      e is TimeoutException ||
      e is HandshakeException ||
      e is HttpException ||
      (e is ApiException && e.status == 403); // this path's network is not allowed

  /// Find a reachable address (GET /v1/info, pinned).
  Future<Transport> _connect({String? skip}) async {
    Object? last;
    for (final h in await candidates()) {
      if (h == skip) continue;
      final t = open(h);
      try {
        await t.request('GET', '/v1/info').timeout(probeTimeout);
        _host = h;
        return _t = t;
      } catch (e) {
        if (!_unreachable(e)) rethrow; // e.g. a certificate mismatch: never fall through
        last = e;
      }
    }
    throw last ?? const SocketException('no route to the device');
  }

  @override
  Future<Object?> request(String method, String path, {Object? body, String? token}) async {
    final t = _t ?? await _connect();
    try {
      return await t.request(method, path, body: body, token: token);
    } catch (e) {
      if (!_unreachable(e)) rethrow;
      // The network changed (VPN switched on/off, left home): pick again.
      final failed = _host;
      _t = null;
      _host = null;
      final next = await _connect(skip: failed);
      return next.request(method, path, body: body, token: token);
    }
  }
}
