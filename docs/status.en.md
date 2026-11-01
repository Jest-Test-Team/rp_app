# Deployment status and to-dos

[繁體中文](status.md) | **English**

> This page records what **this device** currently runs and what is still missing. Network values are always placeholders.

## Device

| Item | Status |
|---|---|
| Hardware | Raspberry Pi 2 Model B Rev 1.1, Edimax EW-7811Un (2.4 GHz) |
| OS | Raspberry Pi OS Lite 32-bit (trixie), flashed with the SD scripts, first boot via cloud-init |
| Uplink | **eth0 (100 Mbps)**: uplink and management interface; wlan0 is the IoT AP |
| Installed | `rpctl`, `rp-dns`, `rp-agent`, `rp-mcp` (deployed with `deploy/install.sh --from-source --host`) |
| Configuration | `/etc/rp/rp.toml`: `device.wan_if = "eth0"`, `lan_cidrs = ["<LAN_CIDR>"]` |

## Modules

| Module | Status | Notes |
|---|---|---|
| `base` | ✅ Applied and confirmed | Inbound dropped by default; SSH from the LAN only; mDNS kept; journal capped at 64 MB / 2 weeks; **key-only SSH** (password and keyboard-interactive disabled) |
| `dns` | ✅ Applied and confirmed | Upstreams 1.1.1.1 / 9.9.9.9 / 8.8.8.8; StevenBlack blocklist imported (76,744 domains, RSS 8.5 MB) |
| `agent` | ✅ Applied | rp-agent and rp-mcp listen on 127.0.0.1 only; agent token `0640 root:rp-mcp-clients` |
| `vpn` | ✅ Applied and confirmed (Tailscale) | Exit node advertised (`0.0.0.0/0`, `::/0`), `--accept-dns=false`; **awaiting approval in the admin console**; VPN clients cannot reach the LAN (`allow_lan = []`) |
| `ap` | ✅ Applied and confirmed | wlan0 is the AP (2.4 GHz, channel 6, WPA2); IoT subnet 10.77.0.0/24; `block_dot = true` (DoT / DoQ rejected); passphrase in `/etc/rp/ap.psk` (0600) |

## Device health (`get_system_health`)

| Item | Latest reading |
|---|---|
| Status | **ok** (previously critical: under-voltage) |
| Alert | none; no Undervoltage entries in either boot since Ethernet was connected, and the soak records the alarm every 5 minutes (all 0 so far) |
| Temperature | about 50 °C (AP + VPN running) |
| Clock | NTP synchronized |
| Disk | 20% |

> ⚠️ The device runs from a dedicated power supply, yet the kernel logs intermittent "Undervoltage detected" (below about 4.63 V under load). Common causes: a thin or long micro-USB cable dropping voltage, or a supply that cannot deliver its rated current. Use the official 5.1 V / 2.5 A supply with a short, thick cable. Under-voltage can cause throttling, SD card corruption and USB adapter drop-outs.
>
> Reboot check (with all five modules applied, 2026-11-01): SSH back in about 36 seconds; rp-firewall, rp-dns, rp-agent, rp-mcp, the AP (hostapd / dnsmasq) and tailscaled all start automatically; forwarding, DoT rejection, VPN / AP-to-LAN blocking and the input `policy drop` are all in place; the Tailscale exit node is still approved.

## SSH admin access

- Admin key `~/.ssh/rp_admin_ed25519` (passphrase-protected; the passphrase is stored in the macOS keychain). A `Host <PI_HOST>` block in `~/.ssh/config` sets `IdentityFile` and `IdentitiesOnly yes`
- The device accepts key logins only; sudo still asks for the account password
- New computer or lost key: log in locally with a screen and keyboard, set `ssh.password_auth` in `/etc/rp/rp.toml` back to `true`, then `sudo rpctl apply base && sudo rpctl confirm` (macOS cannot write the card's ext4 root partition directly)

## MCP connection

- Claude Code has `rp-gateway` (user scope), connected via SSH stdio
- Uses the dedicated key `~/.ssh/rp_mcp_ed25519`, restricted on the device to `restrict,command="/usr/local/bin/rp-mcp --stdio"` (no shell, no pty, no forwarding)
- Read-only tools only for now (`stdio_capabilities = ["read"]`)

## On-device verification

| Check | Result |
|---|---|
| New SSH session and mDNS after applying base | ✅ |
| DNS: normal resolution (UDP / TCP), NXDOMAIN for blocked names, events recorded | ✅ |
| `rpctl dns block/unblock` takes effect immediately | ✅ |
| MCP stdio: initialize, 12 tools, health / inventory / flows (conntrack), scan refused | ✅ |
| Restricted key: no other commands, no pty, forwarding refused | ✅ |
| Network namespace integration tests (Pi kernel) | 16 / 16 |
| e2e (non-destructive) | 6 / 6 |
| e2e (device in use, `RP_E2E_ALLOW_IN_USE=1`, all five modules applied) | 8 passed, 3 destructive cases skipped by design (real apply / re-apply / rollback verified separately with ap) |
| Every daemon matches the config version (`rp-dns check`, `rp-agent snapshot`, `rpctl check`) | ✅ after redeploying all binaries; the old rp-dns rejects `block_dot` (now caught by an e2e case) |
| `ssh.password_auth = false`: new key session works, password-only login refused (`Permission denied (publickey)`), confirmed with `sshd -T` | ✅ |
| mac80211_hwsim AP tests (Pi kernel) | 5 / 5 |
| CI (Linux, Windows ps1, hwsim, root netns, armv7 / aarch64 cross build) | ✅ all green |
| GHA release dry run (3 targets, SHA256SUMS, SBOM) | ✅ all green |
| Switch to eth0: `mgmt_if` carrier, no changes for base / dns / agent | ✅ |
| SSH anti-lockout check through sudo (`ssh_lockout`): PASS inside the allow list, FAIL outside | ✅ |
| `apply ap`: new eth0 SSH session, wlan0 in AP mode, hostapd / dnsmasq active, device still online, `rpctl confirm` | ✅ |
| A real IoT client joining | ✅ gets 10.77.0.x, signal about -53 dBm |
| IoT client internet access | ❌→fixed: the ap module never enabled `ip_forward`; it now renders `/etc/sysctl.d/91-rp-ap.conf`, re-applied and confirmed, `ip_forward=1` |
| netns integration tests after the fix (Pi kernel) | 16 / 16 (with the old rpctl 4 / 8 AP tests fail, proving the tests now catch it) |
| IoT client internet access (after the fix) | ✅ websites load; conntrack: 51 flows to the internet, 3 to the gateway |
| IoT client isolation: router admin page | ✅ fails (dropped); 0 conntrack flows to any private / LAN address |
| IoT client DoT (853) | ✅ `block_dot = true`: TCP / UDP 853 rejected (netns test: reachable by default, refused when enabled, web unaffected) |
| `rpctl rollback ap` (apply → re-apply with a change → rollback) | ✅ every AP file, firewall rule and forwarding removed; wlan0 rejoins the original Wi-Fi by itself (reloading the driver if needed) |
| 24-hour AP stability | 🔄 recording: one sample every 5 minutes in `/var/lib/rp/ap/soak.log` (stops after 288 samples; a reboot ends it) |
| AP throughput (iPhone, -41 dBm, 65 Mbit/s link) | Peak download 12.6 Mbit/s (5 s window); upload not captured; CPU load ≤ 0.34 |

## To-dos (need the user)

1. **Fix the power supply**: use the official 5.1 V / 2.5 A supply or a shorter, thicker micro-USB cable (intermittent under-voltage now)
2. **Point the router's DHCP DNS at this device**, keeping a public DNS server as the second entry (fail-open)
3. **IoT AP**: keep at least 3 devices joined (24-hour stability test) and run a speed test on one of them (throughput); also add a DHCP reservation for eth0 on the router
4. **VPN**: approve the exit node in the Tailscale admin console; on each device install Tailscale and pick the exit node (see [gateway.en.md](gateway.en.md#4-vpn-exit-node)); **revoke the used auth key**
5. ~~Push tag `v0.1.0`~~ ✅ released: https://github.com/Jest-Test-Team/rp_app/releases/tag/v0.1.0 (checksum verified and `rpctl` run on the Pi)
