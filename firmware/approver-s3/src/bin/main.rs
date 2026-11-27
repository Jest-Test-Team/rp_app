//! rp board firmware for the ESP32-S3 (DevKitC-1 N16R8 and clones).
//!
//! The chip-independent logic (rp-wire session, approval button, profiles)
//! is `crates/rp-board`; this file only connects it to the S3's pins:
//! * link: native USB Serial/JTAG (the port you flash through; `/dev/ttyACM*`
//!   on the Pi, `303a:1001`)
//! * button: BOOT (GPIO0). Stopgap: the USB port's DTR/RTS lines also drive
//!   GPIO0; rp-board's arming rule stops a held/stuck pin from approving, but
//!   wire a push button between GPIO4 and GND for a real key.
//! * light: WS2812 RGB LED on GPIO48 or GPIO38 (both are driven)
//! * flash: key seed at 0x9000, profile at 0xA000 (inside `nvs`, which
//!   `espflash flash` keeps; `espflash erase-flash` wipes both)
//!
//! Light: white for 1 s at boot; idle colour per profile (approver green,
//! sentry blue, csi purple, honeypot cyan); a waiting request blinks amber;
//! held long enough = solid green; denied = red flash.

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]

use core::fmt::Write as _;

use ed25519_dalek::SigningKey;
use esp_backtrace as _;
use esp_hal::{
    Blocking,
    clock::CpuClock,
    gpio::{Input, InputConfig, Pull},
    main,
    rmt::Rmt,
    rng::{Trng, TrngSource},
    time::{Duration, Instant, Rate},
    usb::usb_serial_jtag::UsbSerialJtag,
};
use esp_hal_smartled::{RmtSmartLeds, buffer_size, color_order};
use esp_storage::FlashStorage;
use rp_board::{Board, Light, Out};
use rp_wire::{KeyMsg, Profile, Profiles};
use sha2::{Digest, Sha256};
use smart_leds::{RGB8, SmartLedsWrite};

esp_bootloader_esp_idf::esp_app_desc!();

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEY_OFFSET: u32 = 0x9000;
const PROFILE_OFFSET: u32 = 0xA000;
const MAGIC: &[u8; 4] = b"RPK1";
const PROFILE_MAGIC: &[u8; 4] = b"RPP1";

const OFF: RGB8 = RGB8 { r: 0, g: 0, b: 0 };
const AMBER: RGB8 = RGB8 { r: 40, g: 18, b: 0 };
const GREEN: RGB8 = RGB8 { r: 0, g: 40, b: 0 };
const RED: RGB8 = RGB8 { r: 40, g: 0, b: 0 };

fn supported() -> Profiles {
    Profiles::empty()
        .with(Profile::Approver)
        .with(Profile::Honeypot)
        .with(Profile::Sentry)
        .with(Profile::Csi)
}

fn colour(l: Light) -> RGB8 {
    match l {
        Light::Idle(Profile::Approver) => RGB8 { r: 0, g: 10, b: 0 },
        Light::Idle(Profile::Sentry) => RGB8 { r: 0, g: 0, b: 12 },
        Light::Idle(Profile::Csi) => RGB8 { r: 8, g: 0, b: 10 },
        Light::Idle(_) => RGB8 { r: 0, g: 8, b: 8 },
        Light::Waiting { on: true } => AMBER,
        Light::Waiting { on: false } => OFF,
        Light::Holding | Light::Approved => GREEN,
        Light::Denied => RED,
    }
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

fn load_profile(flash: &mut FlashStorage<'_>) -> Option<Profile> {
    let mut rec = [0u8; 5];
    flash.read(PROFILE_OFFSET, &mut rec).ok()?;
    (&rec[..4] == PROFILE_MAGIC).then(|| Profile::from_code(rec[4])).flatten()
}

fn store_profile(flash: &mut FlashStorage<'_>, p: Profile) {
    let mut rec = [0u8; 5];
    rec[..4].copy_from_slice(PROFILE_MAGIC);
    rec[4] = p.code();
    let _ = flash.write(PROFILE_OFFSET, &rec);
}

struct UsbOut<'a, 'd>(&'a mut UsbSerialJtag<'d, Blocking>);

impl Out for UsbOut<'_, '_> {
    fn msg(&mut self, m: KeyMsg<'_>) {
        let mut s: heapless::String<{ rp_wire::MAX_LINE + 2 }> = heapless::String::new();
        let _ = write!(s, "{m}\n");
        let _ = self.0.write(s.as_bytes());
        let _ = self.0.flush_tx();
    }
    fn note(&mut self, text: &str) {
        let _ = self.0.write(b"# ");
        let _ = self.0.write(text.as_bytes());
        let _ = self.0.write(b"\n");
    }
}

#[main]
fn main() -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    let _trng_source = TrngSource::new(p.RNG, p.ADC1);
    let trng = Trng::try_new().expect("TRNG");
    let mut flash = FlashStorage::new(p.FLASH);
    let key = load_or_create_key(&mut flash, &trng);
    let stored = load_profile(&mut flash);
    let mut board = Board::new(key, "esp32s3", VERSION, supported(), stored);

    let button = Input::new(p.GPIO0, InputConfig::default().with_pull(Pull::Up));
    let freq = Rate::from_mhz(80);
    let rmt = Rmt::new(p.RMT, freq).expect("RMT");
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
    let mut shown = None;
    let mut set = |c: RGB8| {
        if shown != Some(c) {
            shown = Some(c);
            let _ = led48.write([c]);
            let _ = led38.write([c]);
        }
    };

    let mut usb = UsbSerialJtag::new(p.USB_DEVICE);

    // Boot: one second of white, so a wrong LED pin is obvious.
    set(RGB8 { r: 30, g: 30, b: 30 });
    let boot = Instant::now();
    while boot.elapsed() < Duration::from_millis(1000) {}

    loop {
        let now = boot.elapsed().as_millis();
        while let Ok(b) = usb.read_byte() {
            if let Some(next) = board.on_byte(b, now, &mut UsbOut(&mut usb)) {
                store_profile(&mut flash, next);
                let t = Instant::now();
                while t.elapsed() < Duration::from_millis(50) {} // let OK drain
                esp_hal::system::software_reset();
            }
        }
        let light = board.tick(now, button.is_low(), &mut UsbOut(&mut usb));
        set(colour(light));
    }
}
