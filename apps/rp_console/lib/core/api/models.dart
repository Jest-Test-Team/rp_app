// Typed views over the API's JSON. Unknown fields are ignored so a newer
// device does not break an older app.

Map<String, Object?> asMap(Object? v) => v is Map ? v.cast<String, Object?>() : const {};
List<Object?> asList(Object? v) => v is List ? v : const [];
String str(Object? v, [String d = '']) => v is String ? v : d;
int integer(Object? v, [int d = 0]) => v is int ? v : (v is num ? v.toInt() : d);
bool flag(Object? v) => v == true;

class DeviceInfo {
  DeviceInfo(this.raw);
  final Map<String, Object?> raw;
  String get deviceId => str(raw['device_id']);
  String get version => str(raw['version']);
  int get apiVersion => integer(raw['api_version']);
  bool get paired => flag(raw['paired']);
  bool get pairingOpen => flag(raw['pairing_open']);
  String? get certSha256 => raw['cert_sha256'] as String?;
}

class ModuleCapability {
  ModuleCapability(this.raw);
  final Map<String, Object?> raw;
  bool get available => flag(raw['available']);
  List<String> get reasons => asList(raw['reasons']).whereType<String>().toList();
  List<String> get notes => asList(raw['notes']).whereType<String>().toList();
  List<String> get options => asList(raw['options']).whereType<String>().toList();
}

class Capabilities {
  Capabilities(this.raw);
  final Map<String, Object?> raw;
  Map<String, Object?> get device => asMap(raw['device']);
  String get model => str(device['model'], 'Unknown device');
  String get arch => str(device['arch']);
  int get ramMb => integer(device['ram_mb']);
  bool get supported => flag(device['supported']);
  List<Map<String, Object?>> get interfaces => asList(raw['interfaces']).map(asMap).toList();
  ModuleCapability module(String name) => ModuleCapability(asMap(asMap(raw['modules'])[name]));
  Iterable<String> get moduleNames => asMap(raw['modules']).keys;
}

class Check {
  Check(this.raw);
  final Map<String, Object?> raw;
  String get name => str(raw['name']);
  String get status => str(raw['status']);
  String get detail => str(raw['detail']);
  bool get failed => status == 'fail';
}

enum ChangeStatus {
  created,
  preflighted,
  applying,
  awaitingConfirm,
  confirmed,
  rolledBack,
  failed,
  superseded,
  unknown,
}

ChangeStatus parseStatus(String s) => switch (s) {
  'created' => ChangeStatus.created,
  'preflighted' => ChangeStatus.preflighted,
  'applying' => ChangeStatus.applying,
  'awaiting_confirm' => ChangeStatus.awaitingConfirm,
  'confirmed' => ChangeStatus.confirmed,
  'rolled_back' => ChangeStatus.rolledBack,
  'failed' => ChangeStatus.failed,
  'superseded' => ChangeStatus.superseded,
  _ => ChangeStatus.unknown,
};

class ChangeSet {
  ChangeSet(this.raw);
  final Map<String, Object?> raw;
  String get id => str(raw['id']);
  String get module => str(raw['module']);
  ChangeStatus get status => parseStatus(str(raw['status']));
  int get baseRevision => integer(raw['base_revision']);
  String get configDiff => str(raw['config_diff']);
  List<Map<String, Object?>> get files => asList(raw['files']).map(asMap).toList();
  List<Check> get checks => asList(raw['checks']).map((c) => Check(asMap(c))).toList();
  List<Check> get verification => asList(raw['verification']).map((c) => Check(asMap(c))).toList();
  List<String> get steps => asList(raw['steps']).whereType<String>().toList();
  int? get deadline => raw['deadline'] is int ? raw['deadline'] as int : null;
  String? get error => raw['error'] as String?;
}

class Status {
  Status(this.raw);
  final Map<String, Object?> raw;
  int get revision => integer(raw['revision']);
  Map<String, Object?> module(String m) => asMap(asMap(raw['modules'])[m]);
  bool secretSet(String name) => flag(asMap(raw['secrets'])[name]);
}
