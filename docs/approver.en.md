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
- A board runs one profile at a time: `approver`, `oob`, `honeypot`, `sentry`, `csi` (the S3 has no `oob`). **Only `approver` answers approval requests**; in any other profile approvals fail and stay pending. Apart from `approver`, profiles so far only switch and report; their functions are not implemented yet.
- When opening a USB-UART port the gateway drops DTR and RTS together so the auto-download circuit does not hold a classic ESP32 in reset; before asking, it waits for the board's `INFO` and checks that it is an enrolled key in the `approver` profile.

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
