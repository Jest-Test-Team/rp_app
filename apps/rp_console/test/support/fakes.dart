// Test doubles. FakeDevice behaves like rp-api in front of rp-privd closely
// enough for unit and widget tests: it checks Ed25519 signatures, nonces and
// the URL binding, pairing proofs, sessions, and runs change sets through
// the same states. The contract tests (test/contract) use the real server.

import 'dart:async';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:rp_console/core/api/transport.dart';
import 'package:rp_console/core/auth/admin_key.dart';
import 'package:rp_console/core/pairing/pairing.dart';
import 'package:rp_console/core/provision/ssh_bootstrap.dart';

const kDevice = '00112233445566778899aabbccddeeff';
const kSecret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const kCert = 'ce5a1f2e00000000000000000000000000000000000000000000000000000000';

class Call {
  Call(this.method, this.path, this.body, this.token);
  final String method;
  final String path;
  final Object? body;
  final String? token;
}

class FakeDevice implements Transport {
  FakeDevice({this.secret = kSecret, this.cert = kCert, this.certSeen, this.impostor = false});

  /// Accepts any pairing proof but does not know the secret (a spoofed device).
  final bool impostor;

  final String secret;
  final String cert;

  /// Certificate the "connection" presents (defaults to [cert]; set to
  /// simulate a man in the middle).
  String? certSeen;
  @override
  String? get seenCert => certSeen ?? cert;

  final calls = <Call>[];
  final admins = <String, String>{}; // id -> public key b64
  final nonces = <String>{};
  final tokens = <String>{};
  bool pairingOpen = true;
  int revision = 1;
  bool unreachable = false;
  int failNextGets = 0;
  final changes = <String, Map<String, Object?>>{};
  final secrets = <String, bool>{'ap_passphrase': false, 'tailscale_auth_key': false};
  final secretValues = <String, String>{};
  Map<String, Object?> caps = {
    'device': {'model': 'Raspberry Pi 2 Model B Rev 1.1', 'arch': 'armv7l', 'ram_mb': 920, 'supported': true},
    'interfaces': [],
    'modules': {
      'base': {'available': true, 'reasons': [], 'notes': [], 'options': []},
      'dns': {'available': true, 'reasons': [], 'notes': [], 'options': []},
      'ap': {
        'available': true,
        'reasons': [],
        'notes': ['wpa2_only'],
        'options': ['wlan0'],
      },
      'vpn': {
        'available': true,
        'reasons': [],
        'notes': [],
        'options': ['tailscale', 'wireguard'],
      },
      'firewall': {'available': true, 'reasons': [], 'notes': [], 'options': []},
    },
  };
  Map<String, Object?> config = {
    'dns': {
      'upstreams': ['198.51.100.53:53'],
      'block': [],
      'allow': [],
      'block_suspicious': false,
      'suspicious_threshold': 60,
    },
    'ap': null,
    'vpn': null,
    'firewall': null,
  };
  final actions = <Map<String, Object?>>[];
  final mcpClients = <Map<String, Object?>>[];
  String? preflightFail;
  bool applyFails = false;

  ApiException _err(int s, String code, String msg, [Object? details]) => ApiException(s, code, msg, details);

  @override
  Future<Object?> request(String method, String path, {Object? body, String? token}) async {
    calls.add(Call(method, path, body, token));
    if (unreachable) throw const SocketLikeException();
    final p = path.split('?').first;
    if (method == 'GET' && p == '/v1/info') {
      return {
        'device_id': kDevice,
        'version': '0.2.0',
        'api_version': 1,
        'paired': admins.isNotEmpty,
        'pairing_open': pairingOpen,
        'cert_sha256': cert,
      };
    }
    if (method == 'POST' && p == '/v1/pairing') return _pair((body as Map).cast<String, Object?>());
    if (method == 'GET' && p == '/v1/openapi.json') return {'paths': {}};
    if (method == 'GET') {
      if (token == null || !tokens.contains(token)) throw _err(401, 'unauthorized', 'a valid session is required');
      if (failNextGets > 0) {
        failNextGets--;
        throw const SocketLikeException();
      }
      return _read(p);
    }
    final env = (body as Map).cast<String, Object?>();
    final op = await _verify(env);
    return _write(method, p, op);
  }

  Future<Map<String, Object?>> _pair(Map<String, Object?> b) async {
    if (!pairingOpen) throw _err(403, 'pairing_closed', 'pairing is not open');
    final pk = b['public_key'] as String, nonce = b['client_nonce'] as String;
    final want = await hmacHex(hexDecode(secret), clientMessage(kDevice, pk, nonce));
    if (!impostor && !sameHex(want, b['proof'] as String)) throw _err(401, 'unauthorized', 'wrong pairing code');
    final id = await adminIdFor(pk);
    admins[id] = pk;
    pairingOpen = false;
    return {
      'admin_id': id,
      'device_id': kDevice,
      'cert_sha256': cert,
      'server_proof': impostor
          ? 'ab' * 32
          : await hmacHex(hexDecode(secret), serverMessage(kDevice, pk, nonce, cert, id)),
    };
  }

  Future<Map<String, Object?>> _verify(Map<String, Object?> env) async {
    final id = env['admin_id'] as String;
    final pk = admins[id];
    if (pk == null) throw _err(401, 'unauthorized', 'unknown or revoked admin');
    final nonce = env['nonce'] as String;
    final exp = env['expires_at'] as int;
    final payload = env['payload'] as String;
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    if (exp <= now || exp > now + 300) throw _err(401, 'unauthorized', 'expired');
    final ok = await Ed25519().verify(
      signingBytes(kDevice, id, nonce, exp, payload),
      signature: Signature(
        base64.decode(env['signature'] as String),
        publicKey: SimplePublicKey(base64.decode(pk), type: KeyPairType.ed25519),
      ),
    );
    if (!ok) throw _err(401, 'unauthorized', 'bad signature');
    if (!nonces.add(nonce)) throw _err(401, 'unauthorized', 'request was already used');
    return (jsonDecode(payload) as Map).cast<String, Object?>();
  }

  void _bound(Map<String, Object?> op, String want, [String? field, String? value]) {
    if (op['op'] != want) throw _err(400, 'bad_request', "signed operation must be '$want'");
    if (field != null && op[field] != value) throw _err(400, 'bad_request', "signed '$field' does not match the URL");
  }

  Object? _read(String p) {
    if (p == '/v1/status') {
      return {
        'revision': revision,
        'modules': {},
        'secrets': secrets,
        'device_id': kDevice,
        'wireguard_public_key': 'U2VydmVyUHVibGljS2V5U2VydmVyUHVibGljS2V5MDA=',
      };
    }
    if (p == '/v1/me') return {'admin_id': admins.keys.first, 'name': 'test'};
    if (p == '/v1/capabilities') return caps;
    if (p == '/v1/health') {
      return {
        'status': 'ok',
        'alerts': [],
        'cpu': {'load1': 0.2},
        'memory': {'total_mb': 920, 'available_mb': 600},
        'temperature_c': 45.0,
        'under_voltage': false,
      };
    }
    final mc = RegExp(r'^/v1/modules/(\w+)/config$').firstMatch(p);
    if (mc != null) {
      return {
        'module': mc.group(1),
        'revision': revision,
        'config': {mc.group(1)!: config[mc.group(1)]},
      };
    }
    if (p == '/v1/dns/stats') {
      return {
        'total': 1000,
        'blocked': 120,
        'block_rate': 0.12,
        'top_blocked': [
          {'domain': 'ads.example', 'count': 50},
        ],
      };
    }
    if (p == '/v1/dns/events') {
      return {
        'events': [
          {'qname': 'ads.example', 'client': '192.0.2.20', 'action': 'blocked', 'reason': 'blocklist'},
        ],
      };
    }
    if (p == '/v1/ap/clients') {
      return {
        'clients': [
          {'ip': '198.51.100.150', 'mac': '02:00:00:00:00:01', 'hostname': 'plug', 'new': true},
        ],
      };
    }
    if (p == '/v1/vpn/status') return {'mode': 'tailscale', 'running': true};
    if (p == '/v1/firewall/rules') return {'rules': (config['firewall'] as Map?)?['rules'] ?? []};
    if (p == '/v1/actions/pending') return {'actions': actions};
    if (p == '/v1/mcp/tools') {
      return {
        'tools': [
          {'name': 'get_system_health', 'tier': 'read', 'description': 'Health'},
          {'name': 'block_device', 'tier': 'privileged', 'description': 'Block'},
        ],
      };
    }
    if (p == '/v1/mcp/clients') return {'configured': true, 'clients': mcpClients};
    if (p == '/v1/audit/events') {
      return {
        'chain': {'ok': true},
        'entries': [],
      };
    }
    if (p == '/v1/admins') {
      return {
        'admins': [
          for (final e in admins.entries) {'id': e.key, 'name': 'app', 'added_at': 0},
        ],
      };
    }
    final cs = RegExp(r'^/v1/changesets/([0-9a-f]{16})$').firstMatch(p);
    if (cs != null) {
      final c = changes[cs.group(1)];
      if (c == null) throw _err(404, 'not_found', 'unknown change set');
      return c;
    }
    if (p == '/v1/changesets') return {'changesets': changes.values.toList()};
    throw _err(404, 'not_found', 'no such endpoint');
  }

  Future<Object?> _write(String method, String p, Map<String, Object?> op) async {
    if (p == '/v1/session') {
      _bound(op, 'session');
      final t = 'rps_${randomHex(32)}';
      tokens.add(t);
      return {'token': t, 'expires_in': 900, 'admin_id': admins.keys.first, 'name': 'test'};
    }
    if (method == 'POST' && p == '/v1/changesets') {
      _bound(op, 'create_changeset');
      if (op['expected_revision'] != revision) {
        throw _err(409, 'conflict', 'the configuration changed', {'current_revision': revision});
      }
      final id = randomHex(8);
      final patch = (op['patch'] as Map).cast<String, Object?>();
      return changes[id] = {
        'id': id,
        'module': op['module'],
        'status': 'created',
        'base_revision': revision,
        'patch': patch,
        'config_diff': patch.entries.map((e) => '+${e.key} = ${jsonEncode(e.value)}').join('\n'),
        'files': [
          {'path': '/etc/rp/${op['module']}.conf', 'diff': '+x'},
        ],
        'checks': [],
      };
    }
    final m = RegExp(r'^/v1/changesets/([0-9a-f]{16})/(\w+)$').firstMatch(p);
    if (m != null) {
      final id = m.group(1)!, verb = m.group(2)!;
      _bound(op, verb, 'id', id);
      final c = changes[id]!;
      switch (verb) {
        case 'preflight':
          if (preflightFail != null) {
            final d = {
              ...c,
              'checks': [
                {'name': preflightFail, 'status': 'fail', 'detail': 'nope'},
              ],
            };
            throw _err(422, 'preflight_failed', 'preflight checks failed', d);
          }
          c['status'] = 'preflighted';
          c['checks'] = [
            {'name': 'mgmt_if', 'status': 'pass', 'detail': 'eth0 is up'},
          ];
        case 'apply':
          if (applyFails) {
            c['status'] = 'failed';
            c['verification'] = [
              {'name': 'hostapd_active', 'status': 'fail', 'detail': 'x'},
            ];
            throw _err(422, 'apply_failed', 'post-apply checks failed; rolled back', c);
          }
          c['status'] = 'awaiting_confirm';
          c['deadline'] = DateTime.now().millisecondsSinceEpoch ~/ 1000 + (op['confirm_secs'] as int? ?? 120);
          revision++;
          _applyPatch(c['module'] as String, (c['patch'] as Map).cast<String, Object?>());
        case 'confirm':
          if (c['status'] != 'awaiting_confirm') throw _err(409, 'state', 'change set is ${c['status']}');
          c['status'] = 'confirmed';
        case 'rollback':
          c['status'] = 'rolled_back';
          revision++;
      }
      return c;
    }
    final sec = RegExp(r'^/v1/secrets/(\w+)$').firstMatch(p);
    if (sec != null) {
      _bound(op, 'set_secret', 'name', sec.group(1));
      secrets[sec.group(1)!] = true;
      secretValues[sec.group(1)!] = op['value'] as String;
      return {'name': sec.group(1), 'set': true, 'fingerprint': 'abc123'};
    }
    final act = RegExp(r'^/v1/actions/(\w+)/(approve|deny)$').firstMatch(p);
    if (act != null) {
      _bound(op, act.group(2)!, 'action_id', act.group(1));
      final a = actions.firstWhere((x) => x['id'] == act.group(1));
      a['status'] = act.group(2) == 'approve' ? 'executed' : 'denied';
      return a;
    }
    if (method == 'POST' && p == '/v1/mcp/clients') {
      _bound(op, 'mcp_add_client');
      mcpClients.add({'name': op['name'], 'capabilities': op['capabilities']});
      return {'name': op['name'], 'token': 'rpt_${randomHex(32)}'};
    }
    final mr = RegExp(r'^/v1/mcp/clients/([\w-]+)$').firstMatch(p);
    if (method == 'DELETE' && mr != null) {
      _bound(op, 'mcp_remove_client', 'name', mr.group(1));
      mcpClients.removeWhere((c) => c['name'] == mr.group(1));
      return {'removed': mr.group(1)};
    }
    if (p == '/v1/pairing/open') {
      _bound(op, 'open_pairing');
      pairingOpen = true;
      return {'secret': secret, 'device_id': kDevice, 'cert_sha256': cert, 'expires_at': 0};
    }
    final ad = RegExp(r'^/v1/admins/(\w+)$').firstMatch(p);
    if (method == 'DELETE' && ad != null) {
      _bound(op, 'revoke_admin', 'admin_id', ad.group(1));
      admins.remove(ad.group(1));
      return {'revoked': ad.group(1)};
    }
    throw _err(404, 'not_found', 'no such endpoint');
  }

  void _applyPatch(String module, Map<String, Object?> patch) {
    final sect = <String, Object?>{...?(config[module] as Map?)?.cast<String, Object?>()};
    patch.forEach((k, v) => sect[k.split('.').last] = v);
    config[module] = sect;
  }
}

class SocketLikeException implements Exception {
  const SocketLikeException();
}

/// A scripted shell: answers by command prefix and records everything.
class FakeShell implements Shell {
  FakeShell(this.answers);
  final List<(String, ExecResult)> answers;
  final execs = <(String, String?)>[];
  bool closed = false;

  @override
  Future<ExecResult> exec(String command, {List<int>? stdin}) async {
    execs.add((command, stdin == null ? null : utf8.decode(stdin)));
    for (final (prefix, r) in answers) {
      if (command.startsWith(prefix) || command.contains(prefix)) return r;
    }
    return ExecResult(0, '', '');
  }

  @override
  Future<void> close() async => closed = true;
}
