# rp_app — Raspberry Pi Edge Security Gateway

[繁體中文](README.md) | **English**

Two parts:

1. **Headless wireless setup** (this page): scripts that re-image an SD card with Raspberry Pi OS Lite (32-bit, Trixie) so the Pi joins Wi-Fi over a USB adapter and enables SSH on first boot.
2. **Edge Security Gateway** (Rust): a VPN exit node (Tailscale / WireGuard; friends cannot reach your LAN), a DNS firewall, an isolated IoT access point, a read-only observation agent, and a policy-controlled MCP server whose privileged actions need human approval. → [docs/gateway.en.md](docs/gateway.en.md)

### Current status

This Pi 2B uses eth0 as its uplink and runs `base` (firewall baseline, key-only SSH), `dns` (DNS firewall with the StevenBlack list), `ap` (wlan0 as an isolated IoT AP) and `agent` (agent + MCP). Claude Code can query it over SSH with read-only tools. VPN is waiting on a Tailscale key. See [docs/status.en.md](docs/status.en.md).

### Gateway quick start

```bash
# Deploy from macOS / Linux to the Pi (until a GitHub Release is published use --from-source; needs zig + cargo-zigbuild)
deploy/install.sh --host <USER>@<PI_HOST> --from-source

# On the Pi: preflight and dry-run each module before applying; confirm firewall changes before the deadline
sudo rpctl preflight base && sudo rpctl apply base --dry-run
sudo rpctl apply base && sudo rpctl confirm
```

Common operations:

| Task | Command |
|---|---|
| Block / unblock a domain | `sudo rpctl dns block <domain>` / `sudo rpctl dns unblock <domain>` |
| Import a public blocklist | `sudo rpctl dns import --url https://<LIST_URL>` |
| Show blocked queries | `rp-dns events --action blocked` |
| Module status / undo | `sudo rpctl status` / `sudo rpctl rollback <module>` |
| Connect Claude Code | See [docs/gateway.en.md](docs/gateway.en.md#connecting-claude-code-recommended-a-restricted-dedicated-key) |
| Approve privileged requests | `sudo rpctl actions`, `sudo rpctl approve <id>` |
| Verify the audit log | `sudo rpctl audit verify` |

### Development and tests

```bash
cargo test --workspace            # Rust unit tests
test/run.sh                       # Robot: static unit cli installer security
test/run.sh integration           # DNS / MCP integration (network namespaces too when run as root on Linux)
```

Docs: [docs/](docs/README.en.md)　Status: [status](docs/status.en.md)　Architecture: [architecture](docs/architecture.en.md)　Threat model: [threat-model](docs/threat-model.en.md)　Measurements: [benchmarks](docs/benchmarks.en.md)　Troubleshooting: [troubleshooting](docs/troubleshooting.en.md)

---

## Headless wireless setup

> ⚠️ Flashing **erases the whole SD card**.

## 0. Prepare `local.env`

```bash
cp local.env.example local.env   # listed in .gitignore, never committed
```

| Variable | Meaning |
|---|---|
| `PI_HOSTNAME` | Host name; SSH uses `<name>.local`. Default `raspberrypi` |
| `PI_USER` / `PI_PASSWORD` | Login account (current images have no default `pi / raspberry` account) |
| `WIFI_SSID` / `WIFI_PASSWORD` | A **2.4 GHz** WPA2 network |
| `WIFI_COUNTRY` | e.g. `TW` |
| `SD_DISK` | The SD card's disk id, e.g. `disk5` (see step 1) |

You can pick `WIFI_SSID` from the networks this Mac has saved; type the password yourself:

```bash
./scripts/wifi-ssid.sh          # list saved networks and choose a number
./scripts/wifi-ssid.sh --list   # list only
```

## 1. Find the SD card

```bash
./scripts/00-preflight.sh
```

Lists every external disk. **A disk of the right size is not necessarily the SD card**: on this Mac a `HYPERDISPLY` USB display adapter also shows up as 15.7 GB; the script flags and refuses it. Put the SD card's id into `SD_DISK`.

## 2. Download the image

```bash
./scripts/01-download-image.sh
```

Downloads the latest Pi OS Lite armhf image into `.cache/` and verifies its SHA-256. Skipped if already downloaded.

## 3. Flash

```bash
./scripts/02-flash-sd.sh disk5 --dry-run   # show what would happen
./scripts/02-flash-sd.sh disk5             # really write; needs sudo and asks you to type disk5 again
```

Safety checks: must equal `SD_DISK`, be an external removable whole disk, not the Mac's boot disk, smaller than 64 GB, and not HYPERDISPLY.

## 4. Write the first-boot configuration

```bash
./scripts/03-configure-boot.sh
```

Writes cloud-init `user-data` (account, password hash, SSH), `network-config` (Wi-Fi, country) and the `ssh` marker into `/Volumes/bootfs`, prints a masked copy, then ejects the card.

- The login password is written only as a SHA-512 hash.
- **The Wi-Fi password is stored in plain text on the boot partition** (a cloud-init limitation). Don't lend the card out.

## 5. Boot and connect

1. Put the card back in the Pi, **keep the Edimax adapter plugged in**, and power it on.
2. The first boot of a Pi 2 is slow (partition resize, cloud-init): wait 3–5 minutes.

```bash
./scripts/04-find-pi.sh      # waits up to 8 minutes and prints the IP once found
./scripts/ssh-pi.sh          # = ssh $PI_USER@$PI_HOSTNAME.local (clears the old host key first)
```

Once connected, check:

```bash
hostname; nmcli -f IN-USE,SSID,CHAN,SIGNAL dev wifi | grep "^\*"; ip -4 -br addr show wlan0
```

## If it won't connect

- The Edimax adapter is **2.4 GHz only**; a router that offers only 5 GHz or only WPA3 will not work.
- You can start with a phone hotspot (enable "Maximize Compatibility" / 2.4 GHz) and join the Mac to the same hotspot.
- When `04-find-pi.sh` cannot resolve `.local`, it scans the ARP table and lists Raspberry Pi / Edimax MACs and IPs.
- To redo the Wi-Fi settings, put the card back in the Mac and rerun step 4 only. The script writes a new `instance_id` every time, so cloud-init re-applies everything on the next boot — no re-flash needed.

## Fallback: Raspberry Pi Imager GUI

If you prefer not to use the scripts, use Imager (`brew install --cask raspberry-pi-imager`):

1. Insert the card, open Imager: device **Raspberry Pi 2**, OS **Raspberry Pi OS Lite (32-bit)**, storage = the SD card (double-check it is not HYPERDISPLY).
2. Next → "Edit settings": host name `raspberrypi`, your own account, Wi-Fi SSID/password, country; on the "Services" tab enable SSH (password login).
3. After writing, follow step 5: boot, `./scripts/04-find-pi.sh`, `./scripts/ssh-pi.sh`.
