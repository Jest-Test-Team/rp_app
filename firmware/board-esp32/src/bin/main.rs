//! rp board firmware for the classic ESP32 (ESP-WROOM-32 DevKit).
//!
//! The chip-independent logic (rp-wire session, approval button, profiles)
//! is `crates/rp-board`; this file only connects it to the board's pins:
//! * link: UART0 (GPIO1/GPIO3) through the board's USB-serial bridge
//!   (CH9102/CH340/CP210x; `/dev/ttyUSB*` on the Pi), 115200 8N1
//! * button: BOOT (GPIO0). The bridge's DTR/RTS auto-reset circuit also
//!   drives GPIO0; rp-board's arming rule stops a held/stuck pin from
//!   approving, but wire a push button between GPIO4 and GND for a real key.
//! * light: the blue LED on GPIO2 (most DevKits): off when idle in
//!   `approver`, slow blink in other profiles, fast blink while a request
//!   waits, on while held long enough
//! * flash: key seed at 0x9000, profile at 0xA000 (inside `nvs`)

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]

use core::fmt::Write as _;

use ed25519_dalek::SigningKey;
use esp_backtrace as _;
use esp_hal::{
    Blocking,
    clock::CpuClock,
    gpio::{Input, InputConfig, Level, Output, OutputConfig, Pull},
    main,
    rng::{Trng, TrngSource},
    time::{Duration, Instant},
    uart::{Config as UartConfig, Uart},
};
use esp_storage::FlashStorage;
use rp_board::{Board, Light, Out};
use rp_wire::{KeyMsg, Profile, Profiles};
use sha2::{Digest, Sha256};

esp_bootloader_esp_idf::esp_app_desc!();

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEY_OFFSET: u32 = 0x9000;
const PROFILE_OFFSET: u32 = 0xA000;
const MAGIC: &[u8; 4] = b"RPK1";
const PROFILE_MAGIC: &[u8; 4] = b"RPP1";

fn supported() -> Profiles {
    Profile::ALL.into_iter().fold(Profiles::empty(), Profiles::with)
}

/// Single LED: on/off for a light at time `now` (ms).
fn lit(l: Light, now: u64) -> bool {
    match l {
        Light::Idle(Profile::Approver) => false,
        Light::Idle(_) => now % 2000 < 100,
        Light::Waiting { on } => on,
        Light::Holding | Light::Approved => true,
        Light::Denied => now % 200 < 100,
    }
}

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

struct UartOut<'a, 'd>(&'a mut Uart<'d, Blocking>);

impl UartOut<'_, '_> {
    /// `Uart::write` only fills the TX FIFO (128 bytes); keep going until
    /// everything is out, or a DECIDE line (150 bytes) gets cut.
    fn write_all(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.0.write(data) {
                Ok(n) => data = &data[n..],
                Err(_) => return,
            }
        }
    }
}

impl Out for UartOut<'_, '_> {
    fn msg(&mut self, m: KeyMsg<'_>) {
        let mut s: heapless::String<{ rp_wire::MAX_LINE + 2 }> = heapless::String::new();
        let _ = write!(s, "{m}\n");
        self.write_all(s.as_bytes());
        let _ = self.0.flush();
    }
    fn note(&mut self, text: &str) {
        self.write_all(b"# ");
        self.write_all(text.as_bytes());
        self.write_all(b"\n");
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
    let mut board = Board::new(key, "esp32", VERSION, supported(), stored);

    let button = Input::new(p.GPIO0, InputConfig::default().with_pull(Pull::Up));
    let mut led = Output::new(p.GPIO2, Level::High, OutputConfig::default());
    let mut uart = Uart::new(p.UART0, UartConfig::default())
        .expect("UART0")
        .with_tx(p.GPIO1)
        .with_rx(p.GPIO3);

    // Boot: LED on for one second.
    let boot = Instant::now();
    while boot.elapsed() < Duration::from_millis(1000) {}

    let mut buf = [0u8; 64];
    loop {
        let now = boot.elapsed().as_millis();
        if uart.read_ready() {
            let n = uart.read_buffered(&mut buf).unwrap_or(0);
            for &b in &buf[..n] {
                if let Some(next) = board.on_byte(b, now, &mut UartOut(&mut uart)) {
                    store_profile(&mut flash, next);
                    let t = Instant::now();
                    while t.elapsed() < Duration::from_millis(50) {} // let OK drain
                    esp_hal::system::software_reset();
                }
            }
        }
        let light = board.tick(now, button.is_low(), &mut UartOut(&mut uart));
        led.set_level(if lit(light, now) { Level::High } else { Level::Low });
    }
}
