# Threat model

[繁體中文](threat-model.md) | **English**

## Assets

- Confidentiality of the home LAN and homelab (VPN users and IoT devices must not reach them)
- Control of the device itself (root, firewall)
- The admin's continued access to the device (not locking yourself out with your own change)
- Secrets: VPN keys, AP passphrase, tokens
- Integrity of the audit log

## Attackers and mitigations

| Attacker | Goal | Mitigation | Test |
|---|---|---|---|
| An AI model steered by prompt injection | Arbitrary scans, firewall changes, command execution | Capability tiers; strict argument validation (rejects unknown keys, control and shell characters, CIDRs outside the allow list, IPv6, /0, oversized ranges); never goes through a shell; privileged actions can only be "requested" | `40_security` |
| Same | Approve its own request | No MCP method or tool can approve; only `rpctl approve` on the device | `40_security` "A Model Cannot Approve Its Own Request" |
| Same | Modify a stored request | Approval re-validates the stored content (treated as data, not trusted input) | `40_security` "Tampered Stored Request" |
| Malicious IoT device | Inject commands through DHCP host names or USB descriptor strings | The agent rejects malformed names and keeps printable ASCII only; MCP strips control characters and limits length; tool descriptions mark results as untrusted data | `34_mcp_integration` "Sanitises Device-Supplied Names" |
| Malicious IoT device | Reach the LAN, attack other IoT devices or the management interface | AP isolation: hostapd `ap_isolate`, hairpin drop, LAN and private ranges dropped, no IPv6, no access to the device's SSH | `30_integration` IoT cases |
| Malicious IoT device | Change IP or keep existing connections after quarantine | Quarantine by IP and MAC, dropped before conntrack accepts established flows (`mod_prefilter`) | `30_integration` quarantine cases |
| Malicious IoT device | Bypass the DNS firewall with DoH / DoT | Port 853 connections (DoT / DoQ) are logged; DoH cannot be fully blocked by DNS alone (known limitation) | `23_ap_cli` |
| VPN user (friend) | Reach the home LAN / homelab | The forward chain blocks the LAN, RFC1918, CGNAT, link-local, ULA and multicast; only explicit `allow_lan` exceptions | `30_integration` VPN cases |
| Someone who stole the MCP SSH key | Get a shell or tunnel into the LAN | The key is restricted in `authorized_keys` with `restrict,command="rp-mcp --stdio"`: no other commands, no pty, forwarding refused; stdio is read-only by default | On-device check ([status.en.md](status.en.md)) |
| Someone who stole the admin's password | Log in over SSH | SSH accepts keys only (`ssh.password_auth = false`); the admin key is passphrase-protected | On-device check ([status.en.md](status.en.md)) |
| Other programs or browsers on the LAN | Call the local MCP | One bearer token per client; any request with an `Origin` header is refused (DNS rebinding) | `40_security` |
| Other programs on the LAN | Call the agent directly | The agent token differs from MCP tokens; the agent trusts only rp-mcp | `40_security` |
| Network attacker | HTTP request smuggling, oversized requests | Chunked encoding refused, header and body limits, timeouts, connection limits | `40_security`, `rp-http` unit tests |
| DNS abuser | Flooding, malformed packets | Per-client token bucket rate limit; malformed packets dropped | `31_dns_integration` |
| Tamperer | Modify or delete audit records | Hash-chained JSONL; `rpctl audit verify` pinpoints the modified or deleted line; multiple writers use a file lock | `40_security`, `rp-policy` unit tests |
| The admin | Lock themselves out with a bad rule | preflight checks the current SSH source; `nft -c` validates first; the dead-man timer rolls back automatically | `20_cli`, `60_e2e` (destructive) |

## Known limitations

- The DNS firewall only protects clients that use this device as their DNS server. DoH bypasses it; DoT / DoQ are only logged.
- Devices on the main LAN cannot be blocked: this device is not their gateway. Privileged tools only act on AP clients.
- Scoring is a deterministic heuristic; its measured rates come from fixed samples (see [benchmarks.en.md](benchmarks.en.md)) and are not guaranteed for every network.
- Protection of the Wi-Fi password relies on file permissions; anyone holding the SD card can read it.
- No TLS interception (deliberately excluded).
