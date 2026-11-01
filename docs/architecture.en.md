# Architecture

[繁體中文](architecture.md) | **English**

## Components

| Binary | Runs on | Role | Privileges |
|---|---|---|---|
| `rpctl` | Device (root) | Configuration, preflight, apply / confirm / rollback, approving privileged actions, MCP client management, audit verification | Run by the admin with sudo |
| `rp-dns` | Device (systemd) | Filtering, logging DNS forwarder | DynamicUser, only `CAP_NET_BIND_SERVICE` |
| `rp-agent` | Device (systemd) | Read-only observation API, scans, privileged action **requests** | root but only `CAP_DAC_READ_SEARCH` + `CAP_NET_ADMIN`, `ProtectSystem=strict` |
| `rp-mcp` | Device or homelab | MCP server (stdio / Streamable HTTP); every call goes through rp-policy | DynamicUser, no capabilities, secrets via `LoadCredential` |
| `rp-probe` | Tests / audit | Secret scanning, DNS / MCP / throughput test tooling | — |

Libraries: `rp-schema` (configuration types), `rp-core` (validation, rendering, apply engine, modules), `rp-policy` (authorization, validation, approvals, audit), `rp-http` (minimal HTTP/1.1).

## How MCP clients connect

| Transport | Identity | Capabilities | Audit |
|---|---|---|---|
| SSH stdio (`ssh <host> rp-mcp --stdio`) | The SSH user; must be in the `rp-mcp-clients` group or use a forced-command key | `mcp.stdio_capabilities` (default `read`) | Falls back to `~/.local/state/rp-mcp/` when the system log is not writable |
| Streamable HTTP (`POST /mcp`) | One bearer token per client (`rpctl mcp add-client`) | Per-client configuration | `/var/lib/rp-mcp/audit.jsonl` |

The `rp-mcp-clients` group is deliberately not called `rp-mcp`: `DynamicUser=` in `rp-mcp.service` allocates a user and group with that name.

## Data plane vs control plane

```
                    ┌──────────── control plane (may be down) ────────────┐
 AI client ──MCP──▶ │ rp-mcp ──token──▶ rp-agent ──(read-only)──▶ /proc /sys DB │
                    │    │ can only "request" privileged actions               │
                    └────┼──────────────────────────────────────────────────────┘
                         ▼
               pending request (file) ── a human runs `rpctl approve <id>` on the device
                                                     │
 ┌──────────── data plane (independent of the control plane) ──▼──────────┐
 │ nftables (table inet rp) · WireGuard / Tailscale · rp-dns · hostapd / dnsmasq │
 └────────────────────────────────────────────────────────────────────────┘
```

- VPN, DNS, AP and the firewall keep working while MCP / agent are stopped.
- The model never gets root, and no MCP method can approve an action.

## Modules (`rpctl apply <module>`)

| Module | Files managed | Depends on | Dead-man timer |
|---|---|---|---|
| `base` | nftables baseline, `rp-firewall.service`, sysctl hardening, sshd drop-in, unattended-upgrades, journald limits | — | yes |
| `vpn` | `nft.d/50-vpn.nft`, forwarding sysctl, WireGuard config or Tailscale apt source | base | yes |
| `dns` | `rp-dns.service`, `nft.d/40-dns.nft` | base | yes |
| `ap` | hostapd / dnsmasq config and units, NetworkManager hand-over, `nft.d/60-ap.nft` | base | yes |
| `agent` | `rp-agent.service`, `rp-mcp.service` | base | no |

## Composable firewall

`base` owns `/etc/rp/nftables.nft`:

- Declares `table inet rp`, its sets and chains, and three extension chains:
  - `mod_prefilter`: jumped to by the **first** rule of input / forward, before conntrack accepts established flows (used by quarantine)
  - `mod_input`, `mod_forward`: after the base rules, before logging and the default drop
- Ends with `include "/etc/rp/nft.d/*.nft"`

Each module owns only its own snippet and can be applied / rolled back independently. The full ruleset is still loaded atomically with a single `nft -f`. When validating, a module builds a check-only combined file ("base + own snippet") and checks it with `nft -c`.

## Apply flow

1. render → diff (no difference means done; idempotent)
2. preflight: root, OS, required tools, management interface carrier, **the current SSH source is in the allow list**, key-only SSH needs an existing key, AP must not be on the management interface
3. Stage every file and **back up** every file that will be replaced (manifest)
4. Pre-package steps, early files (e.g. apt sources), `apt-get install` (waits up to 120 s for the dpkg lock)
5. Validate the staged files (`nft -c`, `dnsmasq --test`, `rp-dns check` …) — the live system is still untouched
6. Install files atomically (tmp + rename, explicit permissions)
7. Activation steps; any failure restores the backup automatically
8. Firewall-type modules start a dead-man timer: without `rpctl confirm` in time, the change rolls back automatically

## Privileged action flow

```
model ─ tools/call block_device {ip, ttl} ─▶ rp-mcp: capability check → rate limit → strict args → audit
       ─▶ rp-agent: validate again (AP clients only, not the gateway, TTL cap) → store as pending → audit
human ─ sudo rpctl approve <id> ─▶ re-validate the stored request → nft add element … timeout Nm → audit
                                 (the kernel removes it on expiry; after a firewall reload quarantine-restore re-adds the remaining time)
```

## Where secrets live

| Secret | Location | Permissions | In rendered files / backups? |
|---|---|---|---|
| WireGuard server private key | Generated on the device at `/etc/rp/wireguard/private.key` | 0600 | No (loaded via `PostUp`) |
| WireGuard client private key | Printed once by `rpctl vpn add-peer` | — | No |
| Tailscale auth key | The file `vpn.tailscale.auth_key_file` points to | Set by the admin | No |
| AP passphrase | Written by `rpctl ap set-passphrase` to `/etc/rp/ap.psk` | 0600 (from creation) | No (hostapd uses `wpa_psk_file`) |
| agent token | Generated on the device at `/etc/rp/agent.token` | 0640 `root:rp-mcp-clients` | No (systemd's rp-mcp gets it as a credential; group members can use stdio) |
| Admin SSH key | Workstation `~/.ssh/rp_admin_ed25519` | 0600, passphrase in the macOS keychain | No |
| MCP dedicated SSH key | Workstation `~/.ssh/rp_mcp_ed25519` | 0600, no passphrase | No; the device restricts it with a forced command to `rp-mcp --stdio` only |
| MCP client token | Printed once; stored as SHA-256 | 0600 | No |
