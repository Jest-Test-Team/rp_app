# RP Security console (v0.2)

[繁體中文](console.md) | **English**

The console is a Flutter app (Android, iOS, macOS, Linux, Windows) that installs, pairs and manages a device. Nobody needs SSH, Rust, nftables or MCP knowledge, and the app never gets root: it signs typed operations that the device checks itself.

```
App (Flutter) ──HTTPS, pinned certificate──▶ rp-api (unprivileged, LAN / tailnet only)
                                                │ unix socket, only the rp-api user
                                                ▼
                                             rp-privd (root, socket-activated)
                                                │ verifies the admin signature, nonce, expiry
                                                ▼
                                rp-core change sets · rpctl · modules · rp-agent
```

## Add a device

The wizard has six steps. Pick one of three paths:

| Path | When | What happens |
|---|---|---|
| New SD card (desktop app) | A card freshly flashed with Raspberry Pi OS Lite by Raspberry Pi Imager, **without** OS customisation | The app writes `user-data` / `network-config` (cloud-init) and a separate one-time `rp-pairing.toml` to the boot partition. On first boot the device moves the secret to `/etc/rp`, shreds it on the card, downloads the release installer (its SHA-256 pinned) and runs `rpctl setup`. |
| Already running (SSH) | A Pi on your network you can log in to | One SSH session: the host key is shown first; the password is used once and only written to `sudo -S`, never stored; the installer is SHA-256 checked; `rpctl setup --json` returns the pairing code over the same channel. |
| Pairing code | `sudo rpctl pairing new` on the device, or another phone (Settings › Add phone) | Paste the QR text or type the 64-character code and the address. |

Then: find the device (mDNS `_rp-security._tcp`) → pair (both sides prove the code with HMAC, the device's proof covers its TLS certificate, the app pins it) → what this hardware can run (reasons in words: e.g. "Wi-Fi is how you reach this device") → verify.

The same flow without the app: `sudo rpctl setup` on the device (or `rpctl bootfs write --dir /Volumes/bootfs --tag v0.2.0 --install-sha256 …` for a card).

## Changing settings

Every change in the app is a **change set**:

1. The app sends a signed patch of allowed keys (no file paths, no raw nftables).
2. The device checks it against the current revision (edits made elsewhere → conflict), validates the whole configuration and runs preflight. Preflight checks hardware support, required modules, and that the app's own address stays allowed.
3. You review the diff of `rp.toml` and of the system files.
4. Apply: the device backs up, applies, checks itself (management link, firewall loaded, services up) and arms a rollback timer.
5. The app reconnects and confirms. If the app cannot reach the device, nothing confirms it and **the device rolls back on its own**.

| Screen | What you can do |
|---|---|
| Overview | Health (CPU, memory, temperature, under-voltage), modules and why one is unavailable |
| DNS firewall | Statistics, block / allow lists, suspicious-name blocking, recent events |
| IoT Wi-Fi | SSID, password (stored as a secret on the device, never in the change), country, channel, network, DoT blocking, connected devices |
| Firewall | Zone rules `lan / wan / iot / vpn → … / device`; they take effect before module rules; nothing that would cut off management can be saved |
| VPN | Tailscale (auth key as a secret) or WireGuard; WireGuard keys are generated in the app and the client config is shown once as a QR code |
| MCP | Approve or deny privileged requests (signed by you), clients (token shown once), tools by tier, audit chain |
| Settings | Paired apps (revoke a lost phone), add another phone, software update, remove RP Security from the device |

## Software updates

Releases are signed with minisign. A device only installs a release whose `SHA256SUMS` signature verifies with `/etc/rp/minisign.pub` (installed from the first release you install) and whose archive matches. The new `rpctl` must accept the current configuration (`rpctl check`) before anything switches. Then every binary switches at once, the running services restart, and if one does not come back the device switches back by itself. `rpctl update install --tag vX`, `rpctl update rollback`, `rpctl update status` do the same from a shell.

Maintainers: create the key once with `rp-probe release keygen --out-dir keys --password-env MINISIGN_PASSWORD`, commit `keys/minisign.pub` as `deploy/minisign.pub`, and store `minisign.key` and the password as the GitHub secrets `MINISIGN_SECRET_KEY` / `MINISIGN_PASSWORD`. The release workflow refuses to publish without a signature.

## Develop and test

```
cd apps/rp_console && flutter test test/unit test/widget
target/debug/rp-api --fake --listen 127.0.0.1:8443 --fake-pairing-secret $(openssl rand -hex 32)
test/run.sh app        # static, unit, widget, contract against the real rp-api, security
test/run.sh build      # platform builds this machine can do
```

`rp-api --fake` is not a mock: requests go through the real rp-privd logic (pairing, signatures, nonces, change sets, secrets, audit) on a simulated device, with system commands recorded instead of run.
