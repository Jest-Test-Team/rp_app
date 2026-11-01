// The console API, typed. Reads use a session; every change is signed with
// the app's admin key and verified by the device (rp-privd).

import '../auth/admin_key.dart';
import '../pairing/pairing.dart';
import 'models.dart';
import 'transport.dart';

/// The device's pairing proof did not match: wrong code, or a man in the middle.
class PairingFailed implements Exception {
  PairingFailed(this.reason);
  final String reason;
  @override
  String toString() => 'PairingFailed($reason)';
}

class PairResult {
  PairResult({required this.adminId, required this.deviceId, required this.certSha256});
  final String adminId;
  final String deviceId;
  final String certSha256;
}

class RpClient {
  RpClient(this.transport, {this.key, this.deviceId});

  final Transport transport;
  AdminKey? key;
  String? deviceId;
  String? _token;

  // ---------------------------------------------------------------- public

  Future<DeviceInfo> info() async => DeviceInfo(asMap(await transport.request('GET', '/v1/info')));

  /// Pair with a one-time code. Verifies the device's proof over the
  /// certificate actually seen on this connection before trusting it.
  Future<PairResult> pair(PairingCode code, AdminKey key, String name) async {
    final info = await this.info();
    final device = info.deviceId;
    if (code.device != null && code.device != device) throw PairingFailed('device id differs from the code');
    final seen = transport.seenCert;
    if (seen == null) throw PairingFailed('no certificate seen');
    if (code.cert != null && !sameHex(code.cert!, seen)) throw PairingFailed('certificate differs from the code');
    final nonce = randomHex(16);
    final secret = hexDecode(code.secret);
    final proof = await hmacHex(secret, clientMessage(device, key.publicKeyB64, nonce));
    final r = asMap(
      await transport.request(
        'POST',
        '/v1/pairing',
        body: {'name': name, 'public_key': key.publicKeyB64, 'client_nonce': nonce, 'proof': proof},
      ),
    );
    final cert = str(r['cert_sha256']);
    final adminId = str(r['admin_id']);
    final expect = await hmacHex(secret, serverMessage(device, key.publicKeyB64, nonce, cert, adminId));
    if (!sameHex(expect, str(r['server_proof']))) throw PairingFailed('the device could not prove the code');
    if (!sameHex(cert, seen) || transport.seenCert != seen) throw PairingFailed('certificate changed during pairing');
    this.key = key;
    deviceId = device;
    return PairResult(adminId: adminId, deviceId: device, certSha256: cert);
  }

  // --------------------------------------------------------------- session

  Future<SignedEnvelope> _sign(Map<String, Object?> op) {
    final k = key, d = deviceId;
    if (k == null || d == null) throw StateError('not paired');
    return k.sign(d, op);
  }

  Future<String> openSession() async {
    final env = await _sign({'op': 'session'});
    final r = asMap(await transport.request('POST', '/v1/session', body: env.toJson()));
    return _token = str(r['token']);
  }

  Future<void> logout() async {
    final t = _token;
    _token = null;
    if (t != null) await transport.request('DELETE', '/v1/session', token: t);
  }

  Future<Object?> _get(String path) async {
    _token ??= await openSession();
    try {
      return await transport.request('GET', path, token: _token);
    } on ApiException catch (e) {
      if (e.status != 401) rethrow;
      _token = await openSession();
      return transport.request('GET', path, token: _token);
    }
  }

  Future<Map<String, Object?>> _signed(String method, String path, Map<String, Object?> op) async {
    final env = await _sign(op);
    return asMap(await transport.request(method, path, body: env.toJson()));
  }

  // ----------------------------------------------------------------- reads

  Future<Map<String, Object?>> me() async => asMap(await _get('/v1/me'));
  Future<Capabilities> capabilities() async => Capabilities(asMap(await _get('/v1/capabilities')));
  Future<Status> status() async => Status(asMap(await _get('/v1/status')));
  Future<Map<String, Object?>> modules() async => asMap(await _get('/v1/modules'));
  Future<Map<String, Object?>> config() async => asMap(await _get('/v1/config'));
  Future<Map<String, Object?>> moduleConfig(String id) async =>
      asMap(await _get('/v1/modules/${Uri.encodeComponent(id)}/config'));
  Future<List<ChangeSet>> changesets() async =>
      asList(asMap(await _get('/v1/changesets'))['changesets']).map((c) => ChangeSet(asMap(c))).toList();
  Future<ChangeSet> changeset(String id) async => ChangeSet(asMap(await _get('/v1/changesets/${_id(id)}')));
  Future<List<Map<String, Object?>>> admins() async =>
      asList(asMap(await _get('/v1/admins'))['admins']).map(asMap).toList();
  Future<Map<String, Object?>> pendingActions() async => asMap(await _get('/v1/actions/pending'));
  Future<Map<String, Object?>> mcpTools() async => asMap(await _get('/v1/mcp/tools'));
  Future<Map<String, Object?>> mcpClients() async => asMap(await _get('/v1/mcp/clients'));
  Future<Map<String, Object?>> health() async => asMap(await _get('/v1/health'));
  Future<Map<String, Object?>> inventory() async => asMap(await _get('/v1/inventory'));
  Future<Map<String, Object?>> apClients() async => asMap(await _get('/v1/ap/clients'));
  Future<Map<String, Object?>> vpnStatus() async => asMap(await _get('/v1/vpn/status'));
  Future<Map<String, Object?>> dnsEvents({int sinceMins = 60, int limit = 100, String? action}) async =>
      asMap(await _get('/v1/dns/events?since_mins=$sinceMins&limit=$limit${action == null ? '' : '&action=$action'}'));
  Future<Map<String, Object?>> dnsStats({int sinceMins = 1440}) async =>
      asMap(await _get('/v1/dns/stats?since_mins=$sinceMins'));
  Future<Map<String, Object?>> flows() async => asMap(await _get('/v1/flows'));
  Future<Map<String, Object?>> firewallRules() async => asMap(await _get('/v1/firewall/rules'));
  Future<Map<String, Object?>> auditEvents() async => asMap(await _get('/v1/audit/events'));
  Future<Map<String, Object?>> openapi() async => asMap(await transport.request('GET', '/v1/openapi.json'));

  // --------------------------------------------------------------- changes

  static final _idRe = RegExp(r'^[0-9a-f]{16}$');
  static String _id(String id) {
    if (!_idRe.hasMatch(id)) throw ArgumentError('bad change set id');
    return id;
  }

  Future<ChangeSet> createChangeset(String module, int expectedRevision, Map<String, Object?> patch) async => ChangeSet(
    await _signed('POST', '/v1/changesets', {
      'op': 'create_changeset',
      'module': module,
      'expected_revision': expectedRevision,
      'patch': patch,
    }),
  );

  Future<ChangeSet> preflight(String id) async =>
      ChangeSet(await _signed('POST', '/v1/changesets/${_id(id)}/preflight', {'op': 'preflight', 'id': id}));

  Future<ChangeSet> apply(String id, {int confirmSecs = 120}) async => ChangeSet(
    await _signed('POST', '/v1/changesets/${_id(id)}/apply', {'op': 'apply', 'id': id, 'confirm_secs': confirmSecs}),
  );

  Future<ChangeSet> confirm(String id) async =>
      ChangeSet(await _signed('POST', '/v1/changesets/${_id(id)}/confirm', {'op': 'confirm', 'id': id}));

  Future<ChangeSet> rollback(String id) async =>
      ChangeSet(await _signed('POST', '/v1/changesets/${_id(id)}/rollback', {'op': 'rollback', 'id': id}));

  /// Store a secret on the device. Only a fingerprint comes back.
  Future<Map<String, Object?>> setSecret(String name, String value) =>
      _signed('PUT', '/v1/secrets/${Uri.encodeComponent(name)}', {'op': 'set_secret', 'name': name, 'value': value});

  Future<Map<String, Object?>> approve(String actionId) =>
      _signed('POST', '/v1/actions/${Uri.encodeComponent(actionId)}/approve', {'op': 'approve', 'action_id': actionId});

  Future<Map<String, Object?>> deny(String actionId) =>
      _signed('POST', '/v1/actions/${Uri.encodeComponent(actionId)}/deny', {'op': 'deny', 'action_id': actionId});

  Future<Map<String, Object?>> revokeAdmin(String adminId) =>
      _signed('DELETE', '/v1/admins/${Uri.encodeComponent(adminId)}', {'op': 'revoke_admin', 'admin_id': adminId});

  Future<Map<String, Object?>> openPairing({int validMinutes = 10}) =>
      _signed('POST', '/v1/pairing/open', {'op': 'open_pairing', 'valid_minutes': validMinutes});

  /// Returns the new client's token: show it once, never store it.
  Future<Map<String, Object?>> mcpAddClient(String name, List<String> capabilities) =>
      _signed('POST', '/v1/mcp/clients', {'op': 'mcp_add_client', 'name': name, 'capabilities': capabilities});

  Future<Map<String, Object?>> mcpRemoveClient(String name) =>
      _signed('DELETE', '/v1/mcp/clients/${Uri.encodeComponent(name)}', {'op': 'mcp_remove_client', 'name': name});
}
