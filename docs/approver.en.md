# Hardware approval key (ESP32-S3)

[繁體中文](approver.md) | **English**

With an `[approver]` section in the config, **approving** any privileged action (`block_device`, `isolate_client`, …) also needs someone to **hold the button** on an ESP32-S3 next to the device, on top of `rpctl approve` or the console app's admin signature. A fooled or stolen Claude session, MCP client or phone cannot change the firewall without that press. **Denying** needs no key.

## How it works

```
rpctl approve <id> / console approval (rp-privd)
        │  admin_ops::decide → approver::confirm
        ▼
  ASK <action id> <digest> <nonce>   ──USB serial──►  ESP32-S3 (blinks amber)
                                                        │ hold BOOT 3 s = approve
                                                        │ short press = deny; wait_seconds = timeout
  DECIDE <id> A|D <Ed25519 signature> ◄────────────────┘
        │  hwkey::verify: enrolled key, same action, same nonce
        ▼
  run and audit (decided_by = admin:<who>+key:<key name>)
```

- Protocol: `crates/rp-wire` (no_std; the Pi and the firmware build the same source), one message per line, hex fields.
- The signature covers a domain tag, the action id, the **action digest** (SHA-256 over principal, tool, args, summary, ttl, created/expiry), a one-time nonce from the gateway, and the decision. Old signatures, signatures for another action, and "deny" signatures cannot approve.
- The private key is generated from the hardware TRNG on first boot and stored in the S3's flash (`nvs` partition, 0x9000); only the public key leaves the board.
- Deny on the key **denies** the request; a timeout, an unplugged key or a bad signature leaves it `pending`.

## Install

### 1. Flash the firmware (on a Mac)

```bash
cargo install espup espflash --locked && espup install
. ~/export-esp.sh
cd firmware/approver-s3
cargo build --release
espflash flash --chip esp32s3 target/xtensa-esp32s3-none-elf/release/approver-s3
```

Use the S3's **USB** port (native USB Serial/JTAG, `303a:1001`). `espflash flash` keeps the key across updates; `espflash erase-flash` destroys it (enroll again afterwards).

### 2. Connect to the Pi

> ⚠️ This Pi 2B has logged undervoltage. Put the S3 on a **powered USB hub**, not on the Pi's own USB power.

```bash
sudo cp firmware/approver-s3/99-rp-approver.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
ls -l /dev/rp-approver
```

### 3. Enroll and enable

```bash
sudo rpctl approver enroll --name main
sudo rpctl approver enroll --name backup    # with a second board plugged in (recommended)
sudo rpctl approver list
```

Add to `/etc/rp/rp.toml`:

```toml
[approver]
# port = "/dev/rp-approver"
# keys_file = "/etc/rp/approver-keys.toml"
# wait_seconds = 60        # 10-300
```

## Backup key (ESP32-WROOM) and profiles

`firmware/board-esp32` is the classic ESP32 firmware; it shares `crates/rp-board` (protocol, button rules, profiles) with the S3. The WROOM talks through its USB-UART bridge (CH9102, `1a86:55d4`, `/dev/ttyUSB*` on the Pi); the button is BOOT and the light is the blue LED on GPIO2 (fast blink while a request waits, solid once held long enough).

```bash
cd firmware/board-esp32 && cargo build --release
espflash flash --chip esp32 target/xtensa-esp32-none-elf/release/board-esp32
sudo rpctl approver info --port /dev/ttyUSB0                 # chip, firmware, profile, key id
sudo rpctl approver enroll --name backup --port /dev/ttyUSB0
sudo rpctl approver profile sentry --port /dev/ttyUSB0       # switch profile (the board restarts)
```

- `backup_port` (default `/dev/rp-approver-backup`) is used when nothing is plugged in at `port`; pin the udev rule to the board's serial number (see `99-rp-approver.rules`).
- A board runs one profile at a time: the S3 has `approver`, `sentry`, `csi`; the WROOM has `approver`, `oob`, `honeypot`, `csi`. **Only `approver` answers approval requests**; in any other profile approvals fail and stay pending. Implemented: `approver`, `sentry` (S3), `oob` and `honeypot` (WROOM); `csi` so far only switches and reports.
- When opening a USB-UART port the gateway drops DTR and RTS together so the auto-download circuit does not hold a classic ESP32 in reset; before asking, it waits for the board's `INFO` and checks that it is an enrolled key in the `approver` profile.

## Board status and error log (rp-boards)

With `[approver]` (or `[boards] ports = [...]`) in the config, `sudo rpctl apply agent` also installs **`rp-boards.service`** (`rp-agent boards`). It keeps the boards' serial ports open, so whatever a board says at any time is kept.

- **Boards report on their own**: why they started (`boot reason=...`; brownouts and watchdog resets are errors), `restarted after a panic` (the panic message itself is captured too), flash write failures and other `LOG error|warn|info` lines. After a panic the board restarts instead of hanging.
- **Storage**: `/var/lib/rp/boards/<port name>.jsonl` (2000 lines per board plus one rotated file) and `status.json` (chip, firmware, profile, key id, last start reason, error count).
- **Viewing**: the console app's Settings › ESP32 boards (status, log filtered by level, copy, profile switch); Claude's read-only MCP tools `get_boards` and `get_board_logs`; the API `GET /v1/boards` and `GET /v1/boards/logs?level=warn`.
- **Switching profiles**: the app sends an admin-signed `set_board_profile`, which rp-privd passes to the board through rp-boards. Approvals and `rpctl approver info|profile|enroll` also go through rp-boards (`/run/rp-boards/boards.sock`, root only), so nothing fights over a port; only rp-wire requests pass, never raw text.
- **Sandbox**: no network (`PrivateNetwork=yes`), only ttyACM/ttyUSB devices, no capabilities. Text from boards is displayed as data, never acted on.

## Wi-Fi sentry (the S3's `sentry` profile)

Only in `sentry` does the S3 (with its external antenna) turn the radio on (never in `approver`). It receives in promiscuous mode and **never transmits**, hopping channels 1-13 every 250 ms, and looks only at 802.11 headers and SSIDs, never at payloads:

| Detects | When | Logged |
|---|---|---|
| deauth/disassoc flood | ≥ 20 from one BSSID within 10 s | `warn sentry: deauth/disassoc flood from <bssid> ...` |
| evil twin | the IoT AP's SSID (sent by rp-boards as `WATCH`, from `[ap] ssid`) advertised by a second BSSID | `warn sentry: '<ssid>' also advertised by <bssid> ...` (mesh systems and extenders trigger this too: check) |
| channel load | every 60 s | `info sentry: channel load ch1=47f/2ap ...` (f = frames, ap = access points) |

The lines go through rp-boards like any other board log: the app's ESP32 boards page and the MCP tool `get_board_logs` show them. Passive listening only; the firmware never sends frames (it does not scan or connect).

## Out-of-band console and watchdog (the WROOM's `oob` profile)

**Wiring** (three jumper wires): WROOM GPIO16 (RX) ← Pi GPIO14 (TXD, pin 8), WROOM GPIO17 (TX) → Pi GPIO15 (RXD, pin 10), GND ↔ GND (pin 6). Both sides are 3.3 V, no level shifter. Enable the Pi's serial console: `enable_uart=1` in `/boot/firmware/config.txt` and `console=serial0,115200` in `cmdline.txt` (`sudo raspi-config` › Interface › Serial: login shell "yes").

- **Normally** (the WROOM's USB on the Pi): every console line goes to rp-boards as `pi> ...`, and the board keeps the last 64; rp-boards asks `TAIL 64` (`pi< ...`) each time it reconnects, so **what the Pi printed just before it crashed** (kernel panic, OOM) can be read after the restart.
- **Rescue** (firewall, SSH or network broken): plug the WROOM's USB into a laptop and run `rpctl approver console --port /dev/cu.usbserial-...`: that is the Pi's login prompt. Ctrl-] three times leaves. rp-boards never forwards `CONSOLE`, so passthrough cannot be opened remotely.
- **Watchdog**: rp-boards sends `HB` every 10 s. With `[boards] watchdog_seconds = 300` (0 = off, the default) the board logs `watchdog: no heartbeat ...` (error, kept across restarts) when they stop; with a relay module on GPIO26 (active high) it also cuts the Pi's power for 3 s. Without a relay it only logs.

## Decoy network (the WROOM's `honeypot` profile)

The WROOM runs an access point named "<IoT SSID>-guest" by default (`[boards] decoy_ssid` to change), on channel 11, **with a random WPA2 passphrase only the board knows**, so nobody can join; legitimate users have no reason to try, so an attempt is a signal. Listening promiscuously, it only looks at **authentication / association requests sent to the decoy's BSSID**, logged at most once per device per 10 minutes: `warn honeypot: <mac> tried to authenticate with decoy '<name>'`. Probe requests are ignored (no logging of passers-by). Phones usually use random MACs.

## Switching to the quietest channel

Works with a sentry measurement from an S3 in the last 30 minutes:

```bash
sudo rpctl ap pick-channel                 # scores for 1,3,6,11 (neighbours' overlap counted)
sudo rpctl ap pick-channel --candidates 1,3 --apply   # switches only if clearly better (>= 20% less)
sudo rpctl changeset confirm <id>          # keep it, or it rolls back by itself
```

The console app's IoT Wi-Fi page shows the advice under the channel picker; "Use N", then save as usual (change set with automatic rollback). Neighbours count: channel 3 was quiet on its own but sits between busy 1, 5 and 6 (measured score 278 vs 138 for channel 1).

## Lost or broken key

Both mechanisms are available:

| Mechanism | How |
|---|---|
| Backup key | Enroll two keys (`main`, `backup`); either signature is accepted. Revoke a lost one with `sudo rpctl approver revoke <id>`. |
| Local bypass | As root on the device: `sudo rpctl approver bypass --minutes 15` (1–60). Approvals need no key until then; `--close` ends it early. Opening, closing and every approval made under a bypass are audited (`hwkey=bypass`). A hand-edited longer window is ignored. |

## Limits

- **The onboard BOOT button (GPIO0) is a stopgap**: the native USB port's DTR/RTS lines also drive GPIO0 (auto-download), so the host can **fake a press**; after flashing, GPIO0 was measured to read "pressed" until the lines changed. The firmware arms only after it sees the button released following a request, but before relying on the key, wire a push button between GPIO4 and GND and change `p.GPIO0` to `p.GPIO4` in `main.rs`.
- No screen: the key cannot show what it approves. Check `rpctl actions` or the app first; only one request waits at a time. An OLED would fix this.
- No secure boot or flash encryption: whoever holds the board can read the key from flash. Revoke a lost key right away.
- Root on the device can already edit the config and remove `[approver]`; the key protects against **remote** approvals (MCP, the app, a stolen admin key).
