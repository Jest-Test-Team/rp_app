// Camera scanner for the pairing QR code (Android and iOS). Returns the first
// QR text that parses as a pairing code; nothing is stored or sent.

import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../../app/strings.dart';
import '../../core/pairing/pairing.dart';

Future<String?> scanPairingQr(BuildContext context) =>
    Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => const QrScannerPage()));

class QrScannerPage extends StatefulWidget {
  const QrScannerPage({super.key});
  @override
  State<QrScannerPage> createState() => _QrScannerPageState();
}

class _QrScannerPageState extends State<QrScannerPage> {
  final controller = MobileScannerController(formats: const [BarcodeFormat.qrCode]);
  bool done = false;
  String? hint;

  @override
  void dispose() {
    controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture c) {
    if (done) return;
    for (final b in c.barcodes) {
      final text = b.rawValue;
      if (text == null) continue;
      try {
        PairingCode.parse(text);
      } on FormatException {
        setState(() => hint = S.of(context)('onb.scan.notours'));
        continue;
      }
      done = true;
      Navigator.of(context).pop(text);
      return;
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = S.of(context);
    return Scaffold(
      appBar: AppBar(title: Text(s('onb.scan.title'))),
      body: Stack(
        fit: StackFit.expand,
        children: [
          MobileScanner(
            controller: controller,
            onDetect: _onDetect,
            errorBuilder: (context, e) => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Text(s('onb.scan.nocamera'), textAlign: TextAlign.center),
              ),
            ),
          ),
          Align(
            alignment: Alignment.bottomCenter,
            child: Container(
              width: double.infinity,
              color: Colors.black54,
              padding: const EdgeInsets.all(16),
              child: Text(
                hint ?? s('onb.scan.body'),
                style: const TextStyle(color: Colors.white),
                textAlign: TextAlign.center,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
