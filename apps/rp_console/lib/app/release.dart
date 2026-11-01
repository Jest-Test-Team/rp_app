// The rp release the app installs on new devices. The installer's SHA-256
// is read from the release's SHA256SUMS over HTTPS (GitHub's certificate);
// the device then verifies every archive against the same file.

import 'dart:convert';
import 'dart:io';

import '../core/provision/bootfs.dart' show defaultRepo;

const kReleaseTag = 'v0.2.0';
const kRepo = defaultRepo;

class ReleaseInfo {
  ReleaseInfo(this.tag, this.installSha256);
  final String tag;
  final String installSha256;
}

/// Find install.sh's line in a SHA256SUMS file.
String? installShaFrom(String sums) {
  for (final line in const LineSplitter().convert(sums)) {
    final m = RegExp(r'^([0-9a-f]{64})\s+\*?install\.sh$').firstMatch(line.trim());
    if (m != null) return m.group(1);
  }
  return null;
}

Future<ReleaseInfo> fetchRelease({String tag = kReleaseTag, String repo = kRepo}) async {
  final c = HttpClient()..connectionTimeout = const Duration(seconds: 15);
  try {
    final req = await c.getUrl(Uri.parse('https://github.com/$repo/releases/download/$tag/SHA256SUMS'));
    final resp = await req.close();
    if (resp.statusCode != 200) throw HttpException('SHA256SUMS: HTTP ${resp.statusCode}');
    final sha = installShaFrom(await resp.transform(utf8.decoder).join());
    if (sha == null) throw const FormatException('install.sh missing from SHA256SUMS');
    return ReleaseInfo(tag, sha);
  } finally {
    c.close(force: true);
  }
}
