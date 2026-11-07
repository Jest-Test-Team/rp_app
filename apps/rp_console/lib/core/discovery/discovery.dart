// Finding devices on the local network: mDNS `_rp-security._tcp` (published
// by the api module's avahi service). Discovery is only a convenience: a
// found device is trusted only after pairing proves the code.

import 'dart:async';
import 'dart:io';

import 'package:multicast_dns/multicast_dns.dart';

const serviceType = '_rp-security._tcp.local';

class Found {
  Found({required this.name, required this.host, required this.port, this.address});
  final String name;
  final String host;
  final int port;
  final InternetAddress? address;

  /// Prefer the resolved address (".local" names don't resolve everywhere).
  String get connectHost => address?.address ?? host;
}

abstract class Discoverer {
  Future<List<Found>> scan({Duration timeout});
}

class MdnsDiscoverer implements Discoverer {
  @override
  Future<List<Found>> scan({Duration timeout = const Duration(seconds: 3)}) async {
    final client = MDnsClient();
    final out = <Found>[];
    try {
      await client.start();
      await for (final ptr in client.lookup<PtrResourceRecord>(
        ResourceRecordQuery.serverPointer(serviceType),
        timeout: timeout,
      )) {
        await for (final srv in client.lookup<SrvResourceRecord>(
          ResourceRecordQuery.service(ptr.domainName),
          timeout: timeout,
        )) {
          InternetAddress? addr;
          await for (final ip in client.lookup<IPAddressResourceRecord>(
            ResourceRecordQuery.addressIPv4(srv.target),
            timeout: timeout,
          )) {
            addr = ip.address;
            break;
          }
          final name = ptr.domainName.replaceFirst('.$serviceType', '');
          if (!out.any((f) => f.host == srv.target && f.port == srv.port)) {
            out.add(Found(name: name, host: srv.target, port: srv.port, address: addr));
          }
        }
      }
    } on SocketException {
      // No multicast on this network / platform: manual entry still works.
    } finally {
      client.stop();
    }
    return out;
  }
}

/// Fixed answers (tests, demo mode).
class StaticDiscoverer implements Discoverer {
  StaticDiscoverer(this.found);
  final List<Found> found;
  @override
  Future<List<Found>> scan({Duration timeout = const Duration(seconds: 3)}) async => found;
}
