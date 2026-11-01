# Deployment status and to-dos

[繁體中文](status.md) | **English**

> This page records what **this device** currently runs and what is still missing. Network values are always placeholders.

## Device

| Item | Status |
|---|---|
| Hardware | Raspberry Pi 2 Model B Rev 1.1, Edimax EW-7811Un (2.4 GHz) |
| OS | Raspberry Pi OS Lite 32-bit (trixie), flashed with the SD scripts, first boot via cloud-init |
| Uplink | **eth0 (100 Mbps)**: uplink and management interface; wlan0 is still joined to the original Wi-Fi and will become the IoT AP |
| Installed | `rpctl`, `rp-dns`, `rp-agent`, `rp-mcp` (deployed with `deploy/install.sh --from-source --host`) |
| Configuration | `/etc/rp/rp.toml`: `device.wan_if = "eth0"`, `lan_cidrs = ["<LAN_CIDR>"]` |

## Modules

| Module | Status | Notes |
|---|---|---|
| `base` | ✅ Applied and confirmed | Inbound dropped by default; SSH from the LAN only; mDNS kept; journal capped at 64 MB / 2 weeks; **key-only SSH** (password and keyboard-interactive disabled) |
| `dns` | ✅ Applied and confirmed | Upstreams 1.1.1.1 / 9.9.9.9 / 8.8.8.8; StevenBlack blocklist imported (76,744 domains, RSS 8.5 MB) |
| `agent` | ✅ Applied | rp-agent and rp-mcp listen on 127.0.0.1 only; agent token `0640 root:rp-mcp-clients` |
| `vpn` | ⏸ Not applied | Needs a Tailscale auth key, or a public WireGuard endpoint with UDP forwarded on the router |
| `ap` | ⏸ Ready to apply | Ethernet is connected; preflight only lacks the AP passphrase (`rpctl ap set-passphrase`), and the IoT SSID needs choosing |

## Device health (`get_system_health`)

| Item | Latest reading |
|---|---|
| Status | **critical** |
| Alert | **Under-voltage** (firmware `rpi_volt` alarm): the power supply is too weak |
| Temperature | about 42 °C |
| Clock | NTP synchronized |
| Disk | 20% |

> ⚠️ The device runs from a dedicated power supply, yet the kernel logs intermittent "Undervoltage detected" (below about 4.63 V under load). Common causes: a thin or long micro-USB cable dropping voltage, or a supply that cannot deliver its rated current. Use the official 5.1 V / 2.5 A supply with a short, thick cable. Under-voltage can cause throttling, SD card corruption and USB adapter drop-outs.
>
> Reboot check: rp-firewall, rp-dns, rp-agent and rp-mcp all start automatically; the firewall and DNS blocking keep working.

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
| `ssh.password_auth = false`: new key session works, password-only login refused (`Permission denied (publickey)`), confirmed with `sshd -T` | ✅ |
| mac80211_hwsim AP tests (Pi kernel) | 5 / 5 |
| CI (Linux, Windows ps1, hwsim, root netns, armv7 / aarch64 cross build) | ✅ all green |
| GHA release dry run (3 targets, SHA256SUMS, SBOM) | ✅ all green |
| Switch to eth0: `mgmt_if` carrier, no changes for base / dns / agent | ✅ |
| SSH anti-lockout check through sudo (`ssh_lockout`): PASS inside the allow list, FAIL outside | ✅ |

## To-dos (need the user)

1. **Fix the power supply**: use the official 5.1 V / 2.5 A supply or a shorter, thicker micro-USB cable (intermittent under-voltage now)
2. **Point the router's DHCP DNS at this device**, keeping a public DNS server as the second entry (fail-open)
3. **IoT AP**: choose the SSID and set the passphrase (`sudo rpctl ap set-passphrase`) → `apply ap`; also add a DHCP reservation for eth0 on the router
4. **VPN**: provide a Tailscale auth key (or decide on WireGuard)
5. **Push tag `v0.1.0`** → an official GitHub Release (after which `install.sh`'s default release download works)
