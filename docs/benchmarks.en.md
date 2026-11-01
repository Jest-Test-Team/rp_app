# Performance and detection measurements

[繁體中文](benchmarks.md) | **English**

Unless noted otherwise, everything was measured on a **Raspberry Pi 2 Model B Rev 1.1** (4× Cortex-A7, armhf, Raspberry Pi OS trixie, kernel 6.18).

## Crypto (openssl speed, single core)

| Algorithm | Throughput |
|---|---|
| ChaCha20-Poly1305 (used by WireGuard) | about 53 MB/s (about 420 Mbit/s) |
| AES-128-GCM | about 13 MB/s |

Conclusion: WireGuard's crypto is not the bottleneck; AES-based OpenVPN is a poor fit for this board.

## Firewall forwarding (`70_performance`, veth inside network namespaces)

| Scenario | Throughput |
|---|---|
| No rules | about 2578 Mbit/s |
| VPN filter + NAT rules | about 2239 Mbit/s (about 13% overhead) |

veth is an in-memory copy, so this measures the CPU cost of the rules, not real network throughput. The real ceiling is eth0's 100 Mbps (over USB 2.0) and the upload bandwidth; the ruleset is far below that ceiling.

**Not yet measured**: real throughput through a WireGuard / Tailscale tunnel (needs a live VPN and a remote client).

## DNS (rp-dns)

| Item | Result |
|---|---|
| Resident memory (RSS) | 4.8 MB |
| Binary size (armv7) | 2.9 MB |
| Blocked names (answered locally) | p95 0.57 ms |
| Forwarded to public DNS | p50 7.9 ms / p95 20.7 ms |
| Querying public DNS directly (baseline) | p50 7.3 ms / p95 20.5 ms |
| Added latency | p50 about +0.6 ms, p95 about +0.1 ms |

### Large blocklist

| Item | Result |
|---|---|
| StevenBlack hosts imported | 76,744 domains (6 invalid lines skipped) |
| RSS after import | 8.5 MB (service limit 96 MB) |
| SIGHUP reload | Takes effect immediately, listener not interrupted |

## Suspicious-name detection (`32_dns_detection`, default threshold 60)

| Sample | Count | Result |
|---|---|---|
| Benign names (including unusual CDN / video / cloud host names) | 159 | **0%** false positives |
| DNS tunnel style (hex / base32 payloads) | 150 | **99.3%** detected |
| DGA style (fixed-seed generated) | 150 | **83.3%** detected |

Before tuning (threshold 70, without the new signals): DGA 0%, tunnel 55%. The scoring was tuned on these samples, so the figures are reproducible estimates, not a guarantee for every network.

## Binary sizes (armv7, release)

| Binary | Size |
|---|---|
| rpctl | 1.8 MB |
| rp-dns | 2.9 MB |
| rp-agent | 2.7 MB |
| rp-mcp | 1.5 MB |
| Release archive | about 4.4 MB per target |

## Reproduce

```bash
# On the Pi (root, isolated namespaces)
RP_ALLOW_ROOT=1 sudo -E test/run.sh perf
# Any machine (no root needed)
test/run.sh dns            # includes 32_dns_detection
test/.venv/bin/robot test/suites/71_dns_performance.robot
```

Results are written to `test/results/perf.json` and `test/results/detection.json`.
