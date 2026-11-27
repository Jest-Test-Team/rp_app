//! approver-s3: hardware approval key for the rp gateway.
//!
//! Speaks `rp-wire` over the S3's native USB port (USB Serial/JTAG, the port
//! you flash through; `/dev/ttyACM*` on the Pi). Holds an Ed25519 key that is
//! generated on first boot from the hardware TRNG and stored in flash; only the
//! public key ever leaves the board.
//!
//! Buttons and light (onboard only, nothing to solder):
//! * idle: dim green
//! * a request is waiting: blinking amber
//! * hold BOOT for 3 s: approve (light turns solid green while held long enough)
//! * short press of BOOT: deny (red flash)
//! * the gateway gives up (CANCEL) or 310 s pass: back to idle

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]

use core::fmt::Write as _;

use ed25519_dalek::{Signer, SigningKey};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    gpio::{Input, InputConfig, Pull},
    main,
    rmt::Rmt,
    rng::{Trng, TrngSource},
    time::{Duration, Instant, Rate},
    usb::usb_serial_jtag::UsbSerialJtag,
};
use esp_hal_smartled::{buffer_size, color_order, RmtSmartLeds};
use esp_storage::FlashStorage;
use rp_wire::{HostMsg, KeyMsg};
use sha2::{Digest, Sha256};
use smart_leds::{SmartLedsWrite, RGB8};

esp_bootloader_esp_idf::esp_app_desc!();

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Start of the `nvs` partition in the default partition table. `espflash
/// flash` leaves it alone, so the key survives firmware updates; `espflash
/// erase-flash` destroys it (and the key must be enrolled again).
const KEY_OFFSET: u32 = 0x9000;
const MAGIC: &[u8; 4] = b"RPK1";
/// Backstop only: the gateway decides how long to wait (approver.wait_seconds,
/// at most 300 s) and sends CANCEL; this just clears a request nobody cancels.
const ASK_TIMEOUT: Duration = Duration::from_millis(310_000);
const LONG_PRESS: Duration = Duration::from_millis(3_000);
const MIN_PRESS: Duration = Duration::from_millis(50);

const OFF: RGB8 = RGB8 { r: 0, g: 0, b: 0 };
const IDLE: RGB8 = RGB8 { r: 0, g: 10, b: 0 };
const AMBER: RGB8 = RGB8 { r: 40, g: 18, b: 0 };
const GREEN: RGB8 = RGB8 { r: 0, g: 40, b: 0 };
const RED: RGB8 = RGB8 { r: 40, g: 0, b: 0 };

struct Ask {
    id: [u8; rp_wire::ID_LEN],
    digest: [u8; rp_wire::DIGEST_LEN],
    nonce: [u8; rp_wire::NONCE_LEN],
    since: Instant,
}

/// Load the key seed from flash, or create and store one.
fn load_or_create_key(flash: &mut FlashStorage<'_>, trng: &Trng) -> SigningKey {
    let mut rec = [0u8; 4 + 32 + 32];
    let check = |rec: &[u8; 68]| Sha256::digest(&rec[..36])[..] == rec[36..];
    if flash.read(KEY_OFFSET, &mut rec).is_ok() && &rec[..4] == MAGIC && check(&rec) {
        return SigningKey::from_bytes(rec[4..36].try_into().unwrap());
    }
    let mut seed = [0u8; 32];
    trng.read(&mut seed);
    rec[..4].copy_from_slice(MAGIC);
    rec[4..36].copy_from_slice(&seed);
    let sum = Sha256::digest(&rec[..36]);
    rec[36..].copy_from_slice(&sum);
    flash.write(KEY_OFFSET, &rec).expect("store key");
    let mut back = [0u8; 68];
    flash.read(KEY_OFFSET, &mut back).expect("read key back");
    assert!(back == rec, "key did not persist");
    SigningKey::from_bytes(&seed)
}

#[main]
fn main() -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    let _trng_source = TrngSource::new(p.RNG, p.ADC1);
    let trng = Trng::try_new().expect("TRNG");
    let mut flash = FlashStorage::new(p.FLASH);
    let key = load_or_create_key(&mut flash, &trng);
    let public_key = key.verifying_key().to_bytes();

    // BOOT (GPIO0) is a stopgap: the native USB port's DTR/RTS lines also
    // drive GPIO0 (auto-download), so the host can fake a press. Wire a push
    // button between GPIO4 and GND and use `p.GPIO4` here for a real key.
    let button = Input::new(p.GPIO0, InputConfig::default().with_pull(Pull::Up));
    let freq = Rate::from_mhz(80);
    let rmt = Rmt::new(p.RMT, freq).expect("RMT");
    // The RGB LED sits on GPIO48 (Espressif DevKitC-1 v1.0) or GPIO38 (v1.1
    // and many N16R8 clones). Drive both; the unused pin is free here.
    let mut led48 = RmtSmartLeds::<{ buffer_size::<RGB8>(1) }, _, RGB8, color_order::Grb>::new_with_memsize(
        esp_hal_smartled::WS2812_TIMING,
        rmt.channel0,
        p.GPIO48,
        1,
        freq,
    )
    .expect("LED 48");
    let mut led38 = RmtSmartLeds::<{ buffer_size::<RGB8>(1) }, _, RGB8, color_order::Grb>::new_with_memsize(
        esp_hal_smartled::WS2812_TIMING,
        rmt.channel1,
        p.GPIO38,
        1,
        freq,
    )
    .expect("LED 38");
    let mut set = |c: RGB8| {
        let _ = led48.write([c]);
        let _ = led38.write([c]);
    };

    let mut usb = UsbSerialJtag::new(p.USB_DEVICE);
    let send = |usb: &mut UsbSerialJtag<'_, _>, m: KeyMsg<'_>| {
        let mut s: heapless::String<{ rp_wire::MAX_LINE + 2 }> = heapless::String::new();
        let _ = write!(s, "{m}\n");
        let _ = usb.write(s.as_bytes());
        let _ = usb.flush_tx();
    };

    let mut line: heapless::Vec<u8, { rp_wire::MAX_LINE + 2 }> = heapless::Vec::new();
    let mut overflow = false;
    let mut ask: Option<Ask> = None;
    let mut pressed_at: Option<Instant> = None;
    // A press only counts if the button was seen released after the request
    // arrived: a stuck or already-held button can never approve anything.
    let mut armed = false;
    let mut was_down = false;
    let mut flash_until: Option<Instant> = None;
    // Boot: one second of white, so a wrong LED pin is obvious.
    set(RGB8 { r: 30, g: 30, b: 30 });
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(1000) {}
    set(IDLE);

    loop {
        // 1. Input from the gateway, one line at a time.
        while let Ok(b) = usb.read_byte() {
            if b != b'\n' {
                if line.push(b).is_err() {
                    overflow = true;
                }
                continue;
            }
            let text = core::str::from_utf8(&line).unwrap_or("");
            match (overflow, HostMsg::parse(text)) {
                (false, Some(HostMsg::Hello)) => {
                    let _ = usb.write(if button.is_low() {
                        b"# button down\n"
                    } else {
                        b"# button up\n"
                    });
                    send(&mut usb, KeyMsg::Key { public_key, version: VERSION })
                }
                (false, Some(HostMsg::Ask { id, digest, nonce })) => {
                    ask = Some(Ask { id, digest, nonce, since: Instant::now() });
                    pressed_at = None; // a press must start after the request
                    armed = false;
                }
                (false, Some(HostMsg::Cancel)) => {
                    ask = None;
                    set(IDLE);
                    send(&mut usb, KeyMsg::Ok);
                }
                _ if text.trim().is_empty() => {}
                _ => send(&mut usb, KeyMsg::Err("bad line")),
            }
            line.clear();
            overflow = false;
        }

        let now = Instant::now();

        // 2. The button: only meaningful while a request is waiting.
        let down = button.is_low();
        if down != was_down {
            was_down = down;
            // Diagnostic line; the gateway ignores anything that is not rp-wire.
            let _ = usb.write(if down { b"# button down\n" } else { b"# button up\n" });
        }
        if let Some(a) = &ask {
            if !down && pressed_at.is_none() {
                armed = true;
            }
            match (down, pressed_at) {
                (true, None) if armed => pressed_at = Some(now),
                (true, Some(t)) if now - t >= LONG_PRESS => set(GREEN),
                (false, Some(t)) => {
                    pressed_at = None;
                    let held = now - t;
                    if held >= MIN_PRESS {
                        let approve = held >= LONG_PRESS;
                        let msg = rp_wire::signing_message(&a.id, &a.digest, &a.nonce, approve);
                        let signature = key.sign(&msg).to_bytes();
                        send(&mut usb, KeyMsg::Decide { id: a.id, approve, signature });
                        set(if approve { GREEN } else { RED });
                        flash_until = Some(now + Duration::from_millis(800));
                        ask = None;
                    }
                }
                _ => {}
            }
        } else {
            pressed_at = None;
        }

        // 3. Timeouts and the light.
        if let Some(a) = &ask {
            if now - a.since >= ASK_TIMEOUT {
                send(&mut usb, KeyMsg::Timeout { id: a.id });
                ask = None;
                set(IDLE);
            } else if pressed_at.is_none() {
                let on = (now - a.since).as_millis() / 250 % 2 == 0;
                set(if on { AMBER } else { OFF });
            }
        } else if flash_until.is_some_and(|t| now >= t) {
            flash_until = None;
            set(IDLE);
        }
    }
}
