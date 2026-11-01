# Installation steps

[繁體中文](setup.md) | **English**

> ⚠️ Flashing **erases the whole SD card**.

Run every command from the `rp_app/` directory.

## 1. Prepare the settings file

```bash
cp local.env.example local.env
chmod 600 local.env
```

| Variable | Meaning |
|---|---|
| `PI_HOSTNAME` | Host name; SSH uses `<PI_HOSTNAME>.local`. Default `raspberrypi` |
| `PI_USER` | Login account (lowercase alphanumerics; current images have no default `pi` account) |
| `PI_PASSWORD` | Login password |
| `WIFI_SSID` | Name of a **2.4 GHz** Wi-Fi network |
| `WIFI_PASSWORD` | Wi-Fi password (WPA2, at least 8 characters) |
| `WIFI_COUNTRY` | Wi-Fi country code, e.g. `TW` for Taiwan |
| `SD_DISK` | The SD card's disk id (found in step 2) |
| `IMAGE_URL` | Image source; defaults to the latest Pi OS Lite armhf |

You can pick `WIFI_SSID` from the networks the Mac has saved:

```bash
./scripts/wifi-ssid.sh          # list and choose a number
./scripts/wifi-ssid.sh --list   # list only
```

Networks with `5G` in the name are flagged; the Edimax adapter cannot use 5 GHz.

## 2. Find the SD card

```bash
./scripts/00-preflight.sh
```

Lists every external disk and its partitions. **The same size does not mean it is the SD card**: devices such as USB display adapters can also appear as external disks; the script flags and refuses them. Once sure, put the id (e.g. `diskN`) into `SD_DISK`.

## 3. Download the image

```bash
./scripts/01-download-image.sh
```

Downloads into `.cache/` (gitignored) and verifies the official SHA-256; an already downloaded and verified image is skipped.

## 4. Flash

```bash
./scripts/02-flash-sd.sh <SD_DISK> --dry-run   # run the checks and list the commands only
./scripts/02-flash-sd.sh <SD_DISK>             # actually write
```

A real write asks you to type the disk id again and enter the Mac's sudo password. Because it is interactive, run it in **Terminal.app**.

## 5. Write the first-boot configuration

```bash
./scripts/03-configure-boot.sh
```

Writes `user-data`, `network-config` and the `ssh` marker file, refreshes `instance_id` in `meta-data`, prints a masked copy, and ejects the card.

## 6. Boot

1. Put the card back in the Pi, **keep the USB Wi-Fi adapter plugged in**, and power it on.
2. The first boot resizes the partition and runs cloud-init; a Pi 2 needs about 3–5 minutes.

```bash
./scripts/04-find-pi.sh      # waits up to 8 minutes by default and prints the IP once found
./scripts/ssh-pi.sh          # ssh <PI_USER>@<PI_HOSTNAME>.local
```

`ssh-pi.sh` first removes the old host key for that name (re-imaging changes it), then logs in with `accept-new`.

## 7. Verify

After logging in, run:

```bash
hostname
cat /proc/device-tree/model
nmcli -f IN-USE,SSID,CHAN,SIGNAL dev wifi | grep '^\*'
ip -4 -br addr show wlan0
systemctl is-active ssh NetworkManager
cloud-init status
```

Expected:

- `wlan0` is `UP` with a LAN address
- The current channel is between 1 and 13 (2.4 GHz)
- `ssh` and `NetworkManager` are both `active`
- `cloud-init status` reports `done`

> Pi OS Lite does not ship `iw`; use `nmcli` to inspect Wi-Fi.

## Changing Wi-Fi or the account

No re-flash needed:

1. Shut the Pi down and put the card back in the Mac.
2. Edit `local.env`.
3. Rerun `./scripts/03-configure-boot.sh`.

The script writes a new `instance_id` each time, so cloud-init treats the card as a new machine and re-applies everything on the next boot.

## Fallback: Raspberry Pi Imager

Without the scripts, use the official Imager (`brew install --cask raspberry-pi-imager`):

1. Device **Raspberry Pi 2**, OS **Raspberry Pi OS Lite (32-bit)**, storage = the SD card.
2. "Edit settings": host name, account and password, Wi-Fi SSID / password, country; on the "Services" tab enable SSH (password login).
3. After writing, boot and verify as in steps 6 and 7.

## Next: Edge Security Gateway

Once you can log in over SSH, deploy the gateway: see [gateway.en.md](gateway.en.md); current progress is in [status.en.md](status.en.md).
