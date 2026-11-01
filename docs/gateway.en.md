# Edge Security Gateway: install and operate

[繁體中文](gateway.md) | **English**

> Every network value here is a placeholder or a documentation range (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Replace them with your own.

## 1. Install

> Until a GitHub Release is published (by pushing a tag), the default release download returns 404; use `--from-source` first.

### Directly on the Pi

```bash
curl -fsSLO https://github.com/<OWNER>/<REPO>/releases/latest/download/install.sh
bash install.sh                    # download the release, verify SHA256SUMS, install
bash install.sh --release v0.1.0   # a specific version
bash install.sh --from-source      # build with cargo on the Pi (slow)
```

### From macOS / Linux to the Pi

```bash
deploy/install.sh --host <USER>@<PI_HOST>                 # release
deploy/install.sh --host <USER>@<PI_HOST> --from-source   # cross-compile locally with cargo-zigbuild
```

### From Windows to the Pi

```powershell
./deploy/install.ps1 -Target <USER>@<PI_HOST>
./deploy/install.ps1 -Target <USER>@<PI_HOST> -FromSource   # needs cargo-zigbuild + zig
```

The installer only places the binaries (`rpctl`, `rp-dns`, `rp-agent`, `rp-mcp`) and an example `/etc/rp/rp.toml`; it never changes networking. Uninstall with `--uninstall` (keeps configuration) or `--uninstall --purge`.

- With `--host` from an interactive terminal, the remote sudo prompts through `ssh -t`
- Running it directly on a Mac (without `--host`) is refused: local install is Linux-only

## 2. Configure and apply

Edit `/etc/rp/rp.toml` (example: `configs/rp.example.toml`). Every module follows the same flow:

```bash
sudo rpctl check                      # validate the configuration
sudo rpctl preflight <module>         # safety checks
sudo rpctl apply <module> --dry-run   # show the diff and the commands that would run
sudo rpctl apply <module>
sudo rpctl confirm                    # firewall-type changes: confirm in time or they roll back automatically
sudo rpctl status
sudo rpctl rollback <module>
```

Suggested order: `base` → `dns` → `vpn` → (after Ethernet is connected) `ap` → `agent`.

With Wi-Fi only and no Ethernet yet: set `device.wan_if = "wlan0"`. `base`, `dns` and `agent` all work; `vpn` works with limited bandwidth (one 2.4 GHz radio sends and receives); `ap` is refused.

Package installation waits up to 120 seconds for the dpkg lock (for example while apt's daily update runs).

## 3. base

- Drops all inbound traffic by default; SSH is allowed only from `ssh.allow_from` (defaults to `device.lan_cidrs`); mDNS is allowed so `<hostname>.local` keeps working
- sysctl hardening, sshd hardening (the drop-in is named `10-rp.conf` so it wins over cloud-init's), unattended-upgrades
- Set `ssh.password_auth = false` only after confirming key login works; preflight refuses it when there is no `authorized_keys`
- journald limits (less SD card wear): `base.journal_max_mb` (default 64; 0 leaves journald unmanaged)

### Device health

`rp-agent snapshot health` (or MCP `get_system_health`) reports temperature, under-voltage, CPU frequency, NTP, disk and memory, plus a `status` (ok / warning / critical) and `alerts`:

| Alert | Threshold |
|---|---|
| under_voltage | firmware alarm is 1 (critical) |
| temperature | ≥ 70 °C warning, ≥ 80 °C critical |
| disk | ≥ 90% warning, ≥ 95% critical |
| memory | < 10% available warning |
| clock | NTP not synchronized warning |

## 4. VPN exit node

```toml
[vpn]
mode = "tailscale"          # or "wireguard"
allow_lan = []              # by default friends cannot touch the LAN at all

[vpn.tailscale]
auth_key_file = "/etc/rp/tailscale.key"   # a file path only; never put the key in rp.toml
```

- **Tailscale**: after applying, approve the exit node in the admin console, then share the machine with your friends' tailnet with "Allow use as an exit node".
- **WireGuard**: forward UDP `listen_port` on your router. Add a client:

```bash
sudo rpctl vpn add-peer <NAME> --write   # prints the client config and QR (shown once) and writes rp.toml
sudo rpctl apply vpn
sudo rpctl vpn remove-peer <NAME> && sudo rpctl apply vpn   # revoke
```

## 5. DNS firewall

```toml
[dns]
upstreams = ["1.1.1.1:53", "9.9.9.9:53"]
blocklists = ["/etc/rp/dns/blocklist.txt"]
block = ["ads.example"]
allow = ["cdn.ads.example"]
block_suspicious = false     # log suspicious names only, at first
```

- Point your router's DHCP DNS at this device, **and keep a public DNS server as the second entry** (fail-open)
- Show events: `rp-dns events --action blocked`; test the scoring: `rp-dns score <name>`
- Manage the blocklist (the first file in `dns.blocklists`; entries are validated and de-duplicated, comments are kept, and rp-dns reloads automatically):

```bash
sudo rpctl dns block ads.example tracker.example   # add (including subdomains)
sudo rpctl dns unblock tracker.example             # remove
sudo rpctl dns list                                # list
sudo rpctl dns import ./hosts.txt                  # merge a hosts-format or one-domain-per-line list
sudo rpctl dns import --url https://<LIST_URL>     # https only
```

## 6. IoT / guest AP

Prerequisite: eth0 is cabled and set as the management interface.

```toml
[ap]
interface = "wlan0"
ssid = "<IOT_SSID>"
country = "TW"
subnet = "10.77.0.0/24"
```

```bash
sudo rpctl ap set-passphrase     # no echo; stored 0600; never appears in configs or backups
sudo rpctl apply ap
sudo rpctl rollback ap           # hand wlan0 back to NetworkManager and rejoin the original Wi-Fi
```

## 7. Agent and MCP

```toml
[agent]
[mcp]
listen = "127.0.0.1:9851"        # for remote use, change to the Tailscale address
```

```bash
sudo rpctl apply agent
sudo rpctl mcp add-client <NAME> --cap read          # the token is shown once
sudo rpctl mcp add-client <NAME> --cap read,active,privileged
sudo systemctl restart rp-mcp
```

Ways to connect:

- Streamable HTTP: `http://<MCP_LISTEN>/mcp` with header `Authorization: Bearer <TOKEN>` (listens on 127.0.0.1 by default; the base firewall does not open 9851 either)
- stdio: first `sudo usermod -aG rp-mcp-clients <USER>` and log in again, then `ssh <USER>@<PI_HOST> rp-mcp --stdio` (read capability only by default; audit goes to `~/.local/state/rp-mcp/`)

### Connecting Claude Code (recommended: a restricted dedicated key)

MCP clients start in the background and cannot type a passphrase, so use a dedicated key without a passphrase that **can only run rp-mcp**:

```bash
ssh-keygen -t ed25519 -N '' -f ~/.ssh/rp_mcp_ed25519 -C 'rp-mcp'
# Add one line to ~/.ssh/authorized_keys on the device (restrict = no shell, no pty, no forwarding):
#   restrict,command="/usr/local/bin/rp-mcp --stdio" ssh-ed25519 AAAA... rp-mcp
claude mcp add --scope user rp-gateway -- \
  ssh -i ~/.ssh/rp_mcp_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes <USER>@<PI_HOST> rp-mcp --stdio
claude mcp list        # rp-gateway: ✔ Connected
```

If the key leaks, the holder can only use MCP's read-only tools; revoke it by deleting that line from authorized_keys.

Privileged actions:

```bash
sudo rpctl actions           # list requests
sudo rpctl approve <ID>      # human approval; expires automatically after its deadline
sudo rpctl deny <ID>
sudo rpctl audit verify      # verify the audit hash chain
```

## 8. Tests

```bash
test/run.sh                                     # static unit cli installer security
test/run.sh integration                         # DNS / MCP (no root needed); netns cases need root
RP_ALLOW_ROOT=1 sudo -E test/run.sh integration # Linux: includes the network namespace topology
RP_E2E_HOST=<USER>@<PI_HOST> test/run.sh e2e    # real device (non-destructive)
RP_E2E_APPLY=1 RP_E2E_HOST=… test/run.sh e2e    # includes real apply / rollback (needs a wired management link)
```

On a device that is already in use (`/etc/rp/rp.toml` exists) e2e skips by default; `RP_E2E_ALLOW_IN_USE=1` runs only the read-only checks.

Test levels and tags: `static`, `unit`, `cli`, `integration`, `security`, `installer`, `e2e`, `perf`, `hwsim`, `requires-root`, `requires-pi`.
