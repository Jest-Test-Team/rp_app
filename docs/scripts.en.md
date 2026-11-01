# Scripts

[繁體中文](scripts.md) | **English**

All scripts live in `rp_app/scripts/`. They are written in bash (`pi-diag.sh` is POSIX sh and runs on the Pi) and pass `shellcheck`.

These scripts are for **flashing and first boot**. The gateway tools are written in Rust (`rpctl`, `rp-dns`, `rp-agent`, `rp-mcp`) and installed with `deploy/install.sh` / `deploy/install.ps1`; see [gateway.en.md](gateway.en.md).

## lib.sh

Shared functions, `source`d by the other scripts; not meant to be run directly.

| Function | Purpose |
|---|---|
| `load_env KEY...` | Loads `local.env` and requires the listed variables to be set and not `CHANGE_ME` |
| `yaml_str VALUE` | Emits a JSON double-quoted string (also valid YAML) so special characters cannot break the config |
| `cached_image` | Returns the newest `.img.xz` in `.cache/` |
| `die` / `warn` / `info` / `ok` | Coloured messages |
| `confirm` | Requires the user to type a given text before continuing |

The environment variable `RP_ENV_FILE` selects a different settings file (for tests).

## 00-preflight.sh

Checks the required tools and lists every physical external disk with name, size and partitions. Disks that look like a Pi card (`boot`, `bootfs`, `Linux` partitions) are marked as likely SD cards; known USB display adapters get a warning. **Writes nothing.**

## 01-download-image.sh

1. Follows the redirects of `IMAGE_URL` to get the real file name.
2. Downloads the official `.sha256`.
3. Skips the download if a cached file exists with the right hash; otherwise downloads, verifies and aborts on a mismatch.

## 02-flash-sd.sh

```
02-flash-sd.sh DISK [--dry-run]
```

Safety checks that must all pass before writing:

| Check | Why |
|---|---|
| Format `diskN` | Whole disks only |
| Equals `SD_DISK` in `local.env` | The argument and the settings file must agree, catching typos |
| `Device Location` is External | Excludes internal disks |
| `Removable Media` is Removable | Excludes external hard drives |
| Not the Mac's boot disk | Last line of defence |
| Smaller than 64 GB | Excludes large devices that are not SD cards |
| Name is not a known USB display adapter | These also appear as removable disks |
| Type the disk id to confirm | Human confirmation |

Then runs `diskutil unmountDisk`, `xz -dc | sudo dd of=/dev/rdiskN bs=4m`, `sync`, and waits for `bootfs` to mount. `--dry-run` only runs the checks and lists the commands.

## 03-configure-boot.sh

```
03-configure-boot.sh [BOOT_DIR] [--no-eject] [--diag]
```

Writes to the boot partition (default `/Volumes/bootfs`):

| File | Contents |
|---|---|
| `user-data` | Host name, time zone, user (`openssl passwd -6` hash), `ssh_pwauth: true`, `runcmd` (unblock rfkill, set the Wi-Fi country, enable ssh) |
| `network-config` | netplan v2: `renderer: NetworkManager`, `wlan0` DHCP, regulatory domain, SSID and password |
| `meta-data` | Sets `instance_id` to a timestamp so cloud-init re-applies |
| `ssh` | Empty file that makes `sshswitch.service` enable SSH |

Every user-supplied string is quoted with `yaml_str`. The printed copy masks the password hash and the Wi-Fi password.

| Option | Effect |
|---|---|
| `BOOT_DIR` | Use a different directory (for tests) |
| `--no-eject` | Do not eject when done |
| `--diag` | Add boot diagnostics; see [troubleshooting.en.md](troubleshooting.en.md#boot-diagnostics---diag) |

## 04-find-pi.sh

```
04-find-pi.sh [TIMEOUT_SECONDS]   # default 480
```

Pings `<PI_HOSTNAME>.local` and probes port 22 every 5 seconds. On timeout it ping-sweeps the local /24, then looks up Raspberry Pi and Edimax MAC prefixes in the ARP table and lists candidate IPs with their SSH status.

## ssh-pi.sh

```
ssh-pi.sh [HOST_OR_IP] [ssh options...]
```

Removes the old host key with `ssh-keygen -R`, then logs in to `<PI_USER>@<host>` with `StrictHostKeyChecking=accept-new`.

## wifi-ssid.sh

```
wifi-ssid.sh [SSID | --list]
```

Gets the Mac's saved Wi-Fi networks from `networksetup -listpreferredwirelessnetworks`, lets you choose one, writes it shell-quoted to `WIFI_SSID` in `local.env`, and reloads to verify. **It writes only the SSID and never reads or writes any password.**

## pi-diag.sh

Runs on the Pi; `03-configure-boot.sh --diag` copies it to the boot partition. Results go to `rp-diag.txt` on the boot partition, readable from the Mac without sudo. Wi-Fi password strings are masked.

| Mode | When | Contents |
|---|---|---|
| `early` | cloud-init `bootcmd` (early boot, every boot) | Model, kernel, `lsusb`, `ip link`, Wi-Fi driver dmesg |
| `full` | cloud-init `runcmd` (late boot, once per instance) | After 60 s: cloud-init status, rfkill, IPs, NetworkManager devices and connections, scanned Wi-Fi, driver dmesg, NetworkManager log, cloud-init errors |

## Managing the blocklist (rpctl dns)

There is no need to edit `/etc/rp/dns/blocklist.txt` by hand; manage it with `rpctl` (Rust). See [gateway.en.md](gateway.en.md#5-dns-firewall).

```bash
sudo rpctl dns block ads.example tracker.example   # add (subdomains are blocked too)
sudo rpctl dns unblock tracker.example             # remove
sudo rpctl dns list                                # list
sudo rpctl dns import ./hosts.txt                  # merge a hosts-format or one-domain-per-line list
sudo rpctl dns import --url https://<LIST_URL>     # https only, size-limited
```
