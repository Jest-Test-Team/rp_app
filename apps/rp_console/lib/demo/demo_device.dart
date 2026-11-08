// An in-memory simulated device: behaves like rp-api in front of rp-privd
// closely enough for the UI — it checks Ed25519 signatures, nonces and the
// URL binding, pairing proofs, sessions, and runs change sets through the
// same states. Used by demo mode (e.g. the browser preview) and the tests.
// The contract tests (test/contract) use the real server instead.

import 'dart:async';
import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:rp_console/core/api/models.dart' show str;
import 'package:rp_console/core/api/transport.dart';
import 'package:rp_console/core/auth/admin_key.dart';
import 'package:rp_console/core/pairing/pairing.dart';

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
  List<Map<String, Object?>> healthAlerts = [];
  int feedUpdates = 0;
  int? feedsUpdatedAt;
  Set<String> feedFails = {};
  static List<String> asStrings(Object? v) => v is List ? v.whereType<String>().toList() : [];
  static const feedCatalog = [
    {
      'id': 'stevenblack',
      'name': 'StevenBlack unified hosts',
      'blocks': 'ads, trackers and known malware domains',
      'license': 'MIT',
      'homepage': 'https://github.com/StevenBlack/hosts',
      'approx_entries': 80000,
      'balanced': true,
    },
    {
      'id': 'urlhaus',
      'name': 'URLhaus malware domains (abuse.ch)',
      'blocks': 'sites currently spreading malware',
      'license': 'CC0 (data) / MIT (list)',
      'homepage': 'https://urlhaus.abuse.ch/',
      'approx_entries': 20000,
      'balanced': true,
    },
    {
      'id': 'phishing_army',
      'name': 'Phishing Army',
      'blocks': 'phishing and scam sites',
      'license': 'CC BY-NC 4.0 (free for personal use)',
      'homepage': 'https://phishing.army/',
      'approx_entries': 150000,
      'balanced': true,
    },
    {
      'id': 'hagezi_tif_mini',
      'name': 'HaGeZi Threat Intelligence (mini)',
      'blocks': 'malware, phishing, scam and C2',
      'license': 'GPL-3.0',
      'homepage': 'https://github.com/hagezi/dns-blocklists',
      'approx_entries': 190000,
      'balanced': false,
    },
    {
      'id': 'hagezi_light',
      'name': 'HaGeZi Light',
      'blocks': 'ads, trackers and telemetry',
      'license': 'GPL-3.0',
      'homepage': 'https://github.com/hagezi/dns-blocklists',
      'approx_entries': 160000,
      'balanced': false,
    },
  ];
  final mcpClients = <Map<String, Object?>>[];
  String? preflightFail;
  String live = 'v0.2.0';
  String? previous;
  bool signingKey = true;
  bool uninstalled = false;
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
    final run = RegExp(r'^/v1/mcp/tools/(\w+)/run$').firstMatch(p);
    if (method == 'POST' && run != null) {
      if (token == null || !tokens.contains(token)) throw _err(401, 'unauthorized', 'a valid session is required');
      return _runTool(run.group(1)!, asArgs(body));
    }
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
      // Same shape as rp-agent's /v1/health (and rp-api's fake, which a Rust
      // test pins to the agent).
      return {
        'load': [0.21, 0.18, 0.15],
        'mem_total_kb': 944000,
        'mem_available_kb': 624640,
        'temperature_c': 47.2,
        'under_voltage': false,
        'cpu_mhz': 900,
        'cpu_max_mhz': 900,
        'disk_used_percent': 31,
        'ntp_synchronized': true,
        'uptime_s': 86400.0,
        'modules': {},
        'status': 'ok',
        'alerts': healthAlerts,
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
      final enabled = asStrings((config['dns'] as Map?)?['feeds']);
      return {
        'total': 1000,
        'blocked': 120,
        'block_rate': 0.12,
        'top_blocked': [
          {'domain': 'ads.example', 'count': 50},
        ],
        'feeds': {
          'enabled': enabled,
          'catalog': feedCatalog,
          'updated_at': feedsUpdatedAt,
          'status': [
            for (final id in enabled)
              {
                'id': id,
                'entries': feedFails.contains(id) ? 0 : 1000,
                'updated_at': feedsUpdatedAt,
                'error': feedFails.contains(id) ? 'download failed: HTTP 503' : null,
                'ok': !feedFails.contains(id),
              },
          ],
        },
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
    if (p == '/v1/vpn/status') {
      return {
        'configured': true,
        'mode': 'tailscale',
        'available': true,
        'backend_state': 'Running',
        'addresses': ['198.51.100.7', 'fd7a:115c:a1e0::7'],
        'dns_name': 'rp-demo.tail0000.ts.net',
      };
    }
    if (p == '/v1/firewall/rules') return {'rules': (config['firewall'] as Map?)?['rules'] ?? []};
    if (p == '/v1/actions/pending') return {'actions': actions};
    if (p == '/v1/mcp/tools') {
      return {
        'tools': [
          {
            'name': 'get_system_health',
            'tier': 'read',
            'description': 'Load, memory, temperature',
            'input_schema': {'type': 'object', 'properties': {}, 'required': []},
          },
          {
            'name': 'get_device_inventory',
            'tier': 'read',
            'description': 'Devices on the networks',
            'input_schema': {'type': 'object', 'properties': {}, 'required': []},
          },
          {
            'name': 'query_dns_events',
            'tier': 'read',
            'description': 'Blocked and suspicious DNS queries',
            'input_schema': {
              'type': 'object',
              'properties': {
                'since_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 10080, 'default': 60},
                'action': {
                  'type': 'string',
                  'enum': ['blocked', 'suspicious'],
                },
              },
              'required': [],
            },
          },
          {
            'name': 'block_device',
            'tier': 'privileged',
            'description': 'REQUEST blocking an access-point client by IP',
            'input_schema': {
              'type': 'object',
              'properties': {
                'ip': {'type': 'string'},
                'ttl_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 1440, 'default': 60},
                'reason': {'type': 'string', 'maxLength': 200},
              },
              'required': ['ip'],
            },
          },
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
    if (p == '/v1/update') {
      return {'live': live, 'previous': previous, 'running_version': '0.2.0', 'signing_key': signingKey, 'history': []};
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
    if (p == '/v1/update') {
      _bound(op, 'install_update');
      if (!signingKey) throw _err(422, 'verification_failed', 'no update signing key on this device');
      previous = live;
      live = op['tag'] as String;
      return {'tag': live, 'previous': previous};
    }
    if (p == '/v1/dns/feeds/update') {
      _bound(op, 'update_dns_feeds');
      feedUpdates++;
      feedsUpdatedAt = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      return {'started': true};
    }
    if (p == '/v1/update/rollback') {
      _bound(op, 'rollback_update');
      if (previous == null) throw _err(409, 'state', 'nothing to roll back to');
      final x = live;
      live = previous!;
      previous = x;
      return {'tag': live};
    }
    if (p == '/v1/uninstall') {
      _bound(op, 'uninstall');
      if (op['confirm_device_id'] != kDevice) throw _err(400, 'invalid', 'confirm_device_id');
      uninstalled = true;
      admins.clear();
      return {
        'removed': ['base', 'api'],
      };
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

  static Map<String, Object?> asArgs(Object? b) => b is Map ? b.cast<String, Object?>() : {};

  Object? _runTool(String name, Map<String, Object?> args) {
    Object? result;
    switch (name) {
      case 'get_system_health':
        result = _read('/v1/health');
      case 'get_device_inventory':
        result = {
          'devices': [
            {'ip': '192.0.2.20', 'mac': '02:00:00:00:00:20', 'iface': 'eth0', 'hostname': 'laptop', 'new': false},
            {'ip': '198.51.100.150', 'mac': '02:00:00:00:00:01', 'iface': 'wlan0', 'hostname': 'plug', 'new': true},
          ],
          'count': 2,
          'new_in_last_24h': 1,
        };
      case 'query_dns_events':
        result = _read('/v1/dns/events');
      case 'get_vpn_status':
        result = _read('/v1/vpn/status');
      case 'list_pending_actions':
        result = {'actions': actions};
      case 'block_device' || 'isolate_client':
        final target = str(args[name == 'block_device' ? 'ip' : 'mac']);
        if (target.isEmpty) {
          throw _err(400, 'invalid', "missing required argument '${name == 'block_device' ? 'ip' : 'mac'}'");
        }
        final id = randomHex(4);
        actions.add({
          'id': id,
          'tool': name,
          'args': args,
          'summary': '${name == 'block_device' ? 'Block' : 'Isolate'} $target for ${args['ttl_minutes'] ?? 60} minutes',
          'principal': 'console-test',
          'status': 'pending',
        });
        result = {'id': id, 'status': 'pending'};
      case 'scan_network':
        result = {'scanned': 254, 'found': 3};
      case 'get_flows' || 'get_audit_log' || 'inspect_arp_table' || 'inspect_usb':
        result = {'entries': []};
      default:
        throw _err(400, 'invalid', "unknown tool '$name'");
    }
    final tier = switch (name) {
      'block_device' || 'isolate_client' => 'privileged',
      'scan_network' => 'active',
      _ => 'read',
    };
    return {'tool': name, 'tier': tier, 'result': result};
  }

  void _applyPatch(String module, Map<String, Object?> patch) {
    final sect = <String, Object?>{...?(config[module] as Map?)?.cast<String, Object?>()};
    patch.forEach((k, v) => sect[k.split('.').last] = v);
    config[module] = sect;
  }
}

class SocketLikeException implements Unreachable {
  const SocketLikeException();
}
