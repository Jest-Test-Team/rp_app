# Troubleshooting

[繁體中文](troubleshooting.md) | **English**

## Quick checks

| Symptom | Check first |
|---|---|
| The Pi never shows up on the network | Does the Wi-Fi offer 2.4 GHz, is it WPA2, are the Mac and the Pi on the same network |
| `.local` does not resolve but the Pi may be online | The ARP scan that `04-find-pi.sh` runs after timing out |
| Not sure whether it booted | Put the card back in the Mac; see "Did the Pi boot?" below |
| SSH host key warning | Re-imaging changes the key; use `ssh-pi.sh` (removes the old key first) |
| `sudo` asks for a password | Enter `PI_PASSWORD` |

## Known problems and root causes

### 1. Wi-Fi never connects: netplan defaults to systemd-networkd

**Symptom**: the Pi boots and cloud-init runs, but it never appears on the network.

**Cause**: cloud-init on Pi OS trixie is configured with `renderers: ['netplan', 'network-manager']`. Without an explicit renderer netplan generates systemd-networkd configuration, but only NetworkManager is enabled — networkd is not — so `wlan0` is never configured.

**How it was confirmed**: reading the image's ext4 partition directly with `debugfs` from `e2fsprogs`: the renderers in `/etc/cloud/cloud.cfg`, only `NetworkManager.service` in `multi-user.target.wants`, and an empty `/etc/netplan`.

**Fix**: add `renderer: NetworkManager` to `network-config` (matching what the official Imager generates).

### 2. Boot hangs: calling systemd from bootcmd

**Symptom**: with diagnostics enabled, the green LED blinks for about 5 seconds, goes dark, then stays on; `rp-diag.txt` has only the early marker and the `ssh` marker file was never consumed.

**Cause**: cloud-init's `bootcmd` runs before `sysinit.target`, when D-Bus is not up yet.

- `systemd-run --on-active=…` waits for the timer to start; the timer depends on sysinit; sysinit waits for cloud-init — a deadlock.
- `--no-block` still hangs, because connecting to D-Bus itself waits.

**Fix**: `bootcmd` only takes snapshots that need no systemd; the full diagnostics moved to `runcmd` (late boot, when D-Bus and NetworkManager are ready).

**Rule**: never call `systemctl`, `systemd-run`, `nmcli` or anything else that needs D-Bus from `bootcmd`.

### 3. 5 GHz networks

The Edimax EW-7811Un supports 2.4 GHz only. A Mac on 5 GHz does not mean the router has no 2.4 GHz band; a dual-band router with one shared name works as is. Otherwise enter the 2.4 GHz SSID, or use a phone hotspot (with "Maximize Compatibility").

### 4. macOS hides the SSID

Without Location permission, `ipconfig getsummary` and `system_profiler` show the SSID as `<redacted>`. `networksetup -listpreferredwirelessnetworks` still lists saved networks, which is what `wifi-ssid.sh` uses.

## Did the Pi boot?

No network needed — put the card back in the Mac and check:

| Sign | Meaning |
|---|---|
| The Linux partition grew from about 2 GB to nearly the whole card | The first-boot partition resize finished |
| `resize` is gone from `cmdline.txt` | Same as above |
| `cmdline.txt` gained `cfg80211.ieee80211_regdom=<COUNTRY>` | `runcmd` ran `raspi-config do_wifi_country` |
| The `ssh` marker file is gone | `sshswitch.service` ran; boot reached its late stage |
| The `ssh` marker file is still there | Boot never reached multi-user |

## LEDs (Pi 2)

| LED | Meaning |
|---|---|
| Red steady | Power |
| Green flickering irregularly during boot | Reading the SD card |
| Green steady from power-on, never blinking | Usually no bootable image was found |
| Green repeating a fixed number of blinks | A boot error code |

The kernel takes over the green LED, so after boot it says nothing about Wi-Fi; rely on the diagnostics file.

## Boot diagnostics (--diag)

```bash
./scripts/03-configure-boot.sh --diag
```

1. Put the card in the Pi and boot; wait about 6 minutes (including the 60 seconds `full` mode waits).
2. Unplug power and put the card back in the Mac.
3. Read the result:

```bash
cat /Volumes/bootfs/rp-diag.txt
```

What to look for:

| Section | Look at |
|---|---|
| `lsusb` | Is the Edimax `7392:7811` present |
| dmesg | Did `rtl8192cu` load and did firmware `rtl8192cufw_TMSC.bin` load |
| `rfkill list` | Is wlan soft- or hard-blocked |
| `nmcli … device` | `wlan0` state (connected / disconnected / unavailable) |
| `nmcli … wifi list` | Was the target SSID seen, on which channel |
| NetworkManager log | Authentication failures, network not found, etc. |

If there is only the early marker and no `full dump`, boot never reached `runcmd`; see "Boot hangs" above.

When done, run `03-configure-boot.sh` once more without `--diag` to remove the diagnostics script.

## Reading the card's ext4 partition (advanced)

macOS cannot read ext4 directly. To inspect the image:

```bash
brew install e2fsprogs
xz -dkc .cache/<image>.img.xz > .cache/image.img
# after extracting the second partition according to the partition table:
$(brew --prefix e2fsprogs)/sbin/debugfs -R "cat /etc/cloud/cloud.cfg" .cache/root.ext4
```

Reading the physical card (`/dev/diskNs2`) needs sudo. Delete the decompressed image (several GB) afterwards.

## Gateway known issues (found and handled during development and on-device testing)

| Symptom | Cause | Resolution |
|---|---|---|
| Changing `ssh.password_auth` has no effect | sshd keeps the **first** value it reads; cloud-init's `50-cloud-init.conf` was read first | rpctl's drop-in is named `10-rp.conf` so it sorts first |
| The uplink loses its IPv6 address after enabling IPv6 forwarding | With forwarding=1 the kernel ignores RAs by default | The vpn module also sets `accept_ra = 2` |
| Still forwarding after rolling back VPN | Deleting a sysctl file does not change the live value | Rollback explicitly runs `sysctl -w net.ipv4.ip_forward=0` |
| DNS port conflict after installing `dnsmasq` | The full `dnsmasq` package auto-starts and binds port 53 | Install only `dnsmasq-base` and run it DHCP-only (`port=0`) |
| Management access lost after applying AP | wlan0 was also the management interface | Config validation and preflight both refuse an AP on the management interface; connect eth0 first |
| Every DNS query is 400 ms slower | The first upstream is down and every query waits for its timeout | A failed upstream is skipped for 30 seconds (hold-down) |
| A quarantined IoT device keeps its existing connections | The rule was checked after conntrack accepted established flows | Quarantine rules live in `mod_prefilter`, which runs first |
| `audit verify` reports a broken chain | rp-agent and `rpctl approve` both write the same file and the agent cached a stale chain head | Every write takes a file lock and re-reads the chain head |
| `get_flows` is always empty | Recent kernels have no `/proc/net/nf_conntrack` | The agent uses `conntrack -L -o extended` (the agent module installs `conntrack`) |
| Quarantine disappears after a firewall reload | A reload rebuilds the table and timed elements go with it | After `rp-firewall` starts / reloads, `rpctl quarantine-restore` re-adds the remaining time |
| `get_system_health` reports critical: under_voltage | Weak power: voltage drop on a thin / long micro-USB cable or a supply short on current (below about 4.63 V under load) | Use a 5 V / 2.5 A supply; the agent reads the firmware `rpi_volt` alarm (the sandbox cannot see `vcgencmd`) |
| `apply` fails in `apt-get install` | apt's daily update / unattended-upgrades holds the dpkg lock | apt runs with `-o DPkg::Lock::Timeout=120`; on failure no files have been installed yet |
| `rp-mcp.service` fails to start (`217/USER`) | A separately created `rp-mcp` group clashed with the same-named user that `DynamicUser=` allocates | The token group was renamed to `rp-mcp-clients`; remove an old `rp-mcp` group with `groupdel` |
| `ssh <host> rp-mcp --stdio` cannot read the agent token | The token was readable by root only | The token is now `0640 root:rp-mcp-clients`; `usermod -aG rp-mcp-clients <user>` and log in again |
| After connecting Ethernet `ssh <PI_HOST>.local` sometimes times out | mDNS advertises both the eth0 and wlan0 addresses, and replies to the wlan0 address leave via eth0 | Connect to the eth0 address; once wlan0 becomes the AP only eth0 remains |
| SSH says `Permission denied (publickey)` | `ssh.password_auth = false` is set and this computer has no authorized key | Use an authorized key (`ssh -i <KEY>`), or log in locally with a screen and keyboard, set `password_auth` back to `true`, and `rpctl apply base` |
| preflight says `ssh_lockout … not running over SSH` while you are on SSH | sudo resets the environment and drops `SSH_CONNECTION` | rpctl now reads `SSH_CONNECTION` from its ancestor processes |
| `install.sh --host` hangs at sudo | The remote has no TTY so sudo cannot prompt | Interactive runs use `ssh -t` |
| `not valid!` in a plain list was taken as the domain `not` | Only the first word of a multi-word line was used | Non-hosts-format lines with several words are invalid (fixed in both rp-dns and `rpctl dns import`) |

## MCP (Claude Code) does not connect

```bash
claude mcp list                                    # is rp-gateway ✔ Connected
ssh -i ~/.ssh/rp_mcp_ed25519 -o BatchMode=yes <USER>@<PI_HOST> </dev/null; echo $?   # does the key log in
sudo systemctl status rp-agent                     # is the agent running on the device
id <USER> | grep rp-mcp-clients                    # plain SSH stdio needs this group
```

## Gateway quick diagnostics

```bash
sudo rpctl status                 # per module: applied, confirmed, pending changes
sudo rpctl preflight <module>     # pre-apply safety checks
sudo nft list table inet rp       # the live ruleset
sudo journalctl -u rp-firewall -u rp-dns -u rp-agent -u rp-mcp -u rp-ap-hostapd -n 100
sudo rpctl audit verify           # is the audit chain intact
```
