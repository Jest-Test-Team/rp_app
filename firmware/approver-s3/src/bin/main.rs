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
//! Sentry profile (only then is the radio on): promiscuous receive, hopping
//! channels 1-13 every 250 ms; rp-board's sentry decides what to report.
//! Nothing is transmitted.
//!
//! Light: white for 1 s at boot; idle colour per profile (approver green,
//! sentry blue, csi purple); a waiting request blinks amber;
//! held long enough = solid green; denied = red flash.

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]

extern crate alloc;

mod ble;

use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use critical_section::Mutex;

use ed25519_dalek::SigningKey;
use esp_backtrace as _;
use embassy_time::Timer;
use esp_hal::{
    Blocking,
    clock::CpuClock,
    gpio::{Input, InputConfig, Pull},
    rmt::Rmt,
    rng::{Trng, TrngSource},
    time::{Duration, Instant, Rate},
    usb::usb_serial_jtag::UsbSerialJtag,
};
use esp_hal_smartled::{RmtSmartLeds, buffer_size, color_order};
use esp_storage::FlashStorage;
use rp_board::{Board, Effect, Light, Out};
use rp_wire::{KeyMsg, Level, Profile, Profiles};
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
    // The decoy network (honeypot) runs on the WROOM.
    Profiles::empty().with(Profile::Approver).with(Profile::Sentry).with(Profile::Csi)
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

fn store_profile(flash: &mut FlashStorage<'_>, p: Profile) -> bool {
    let mut rec = [0u8; 5];
    rec[..4].copy_from_slice(PROFILE_MAGIC);
    rec[4] = p.code();
    flash.write(PROFILE_OFFSET, &rec).is_ok() && load_profile(flash) == Some(p)
}
/// Set just before the panic handler restarts the chip; survives the reset.
#[esp_hal::ram(unstable(rtc_fast, persistent))]
static mut PANIC_MARK: u32 = 0;
const PANICKED: u32 = 0x5041_4e43; // "PANC"

/// esp-backtrace (feature `custom-halt`) calls this after printing the panic:
/// mark it, give the message time to leave, and restart instead of hanging.
#[unsafe(no_mangle)]
pub fn custom_halt() -> ! {
    unsafe { PANIC_MARK = PANICKED };
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(300) {}
    esp_hal::system::software_reset()
}

/// Why the board started, as a log line for the gateway.
fn boot_log(out: &mut dyn Out, profile: Profile) {
    let panicked = unsafe { core::ptr::addr_of!(PANIC_MARK).read_volatile() } == PANICKED;
    unsafe { PANIC_MARK = 0 };
    let reason = esp_hal::system::reset_reason();
    let mut s: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
    let level = if panicked {
        let _ = write!(s, "restarted after a panic (message above)");
        Level::Error
    } else {
        match reason {
            Some(r) => {
                let name = {
                    let mut n: heapless::String<24> = heapless::String::new();
                    let _ = write!(n, "{r:?}");
                    n
                };
                let _ = write!(s, "boot reason={name}");
                if name.contains("BrownOut") {
                    let _ = write!(s, " (supply voltage dropped: use a powered hub)");
                    Level::Error
                } else if name.contains("Wdt") {
                    let _ = write!(s, " (watchdog: the firmware hung)");
                    Level::Error
                } else {
                    Level::Info
                }
            }
            None => {
                let _ = write!(s, "boot reason=unknown");
                Level::Warn
            }
        }
    };
    out.msg(KeyMsg::Log { level, text: &s });
    let mut p: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
    let _ = write!(p, "running profile={} firmware={VERSION}", profile.as_str());
    out.msg(KeyMsg::Log { level: Level::Info, text: &p });
}


/// Management frames copied out of the radio callback (header + SSID only).
const PKT: usize = 80;
struct Pkt {
    len: u8,
    data: [u8; PKT],
}
static FRAMES: Mutex<RefCell<heapless::Deque<Pkt, 48>>> = Mutex::new(RefCell::new(heapless::Deque::new()));
/// Frames of any kind since the last drain.
static TRAFFIC: AtomicU32 = AtomicU32::new(0);
static DROPPED: AtomicU32 = AtomicU32::new(0);

fn on_packet(p: esp_radio::wifi::sniffer::PromiscuousPkt<'_>) {
    TRAFFIC.fetch_add(1, Ordering::Relaxed);
    // Management frames only (type bits 2-3 of the first byte = 0).
    if p.data.first().is_none_or(|fc| (fc >> 2) & 0b11 != 0) {
        return;
    }
    let n = p.data.len().min(PKT);
    let mut pkt = Pkt { len: n as u8, data: [0; PKT] };
    pkt.data[..n].copy_from_slice(&p.data[..n]);
    critical_section::with(|cs| {
        if FRAMES.borrow_ref_mut(cs).push_back(pkt).is_err() {
            DROPPED.fetch_add(1, Ordering::Relaxed);
        }
    });
}

/// Sends to USB, except replies to a request that came over BLE, which go
/// back to the phone (logs and notes always go to USB).
struct Route<'a, 'd> {
    usb: UsbOut<'a, 'd>,
    to_ble: bool,
}

impl Out for Route<'_, '_> {
    fn msg(&mut self, m: KeyMsg<'_>) {
        if self.to_ble && !matches!(m, KeyMsg::Log { .. }) {
            let mut l = ble::Line::new();
            let _ = write!(l, "{m}");
            let _ = ble::BLE_OUT.try_send(l);
        } else {
            self.usb.msg(m);
        }
    }
    fn note(&mut self, text: &str) {
        self.usb.note(text);
    }
}

struct UsbOut<'a, 'd>(&'a mut UsbSerialJtag<'d, Blocking>);

impl UsbOut<'_, '_> {
    /// With no host reading (powered from a charger) the USB FIFO never
    /// drains and a blocking write would hang the key: give up after 50 ms.
    fn write_all(&mut self, data: &[u8]) {
        let start = Instant::now();
        for &b in data {
            loop {
                match self.0.write_byte_nb(b) {
                    Ok(()) => break,
                    Err(_) if start.elapsed() < Duration::from_millis(50) => {}
                    Err(_) => return,
                }
            }
        }
        let _ = self.0.flush_tx_nb();
    }
}

impl Out for UsbOut<'_, '_> {
    fn msg(&mut self, m: KeyMsg<'_>) {
        let mut s: heapless::String<{ rp_wire::MAX_LINE + 2 }> = heapless::String::new();
        let _ = write!(s, "{m}\n");
        self.write_all(s.as_bytes());
    }
    fn note(&mut self, text: &str) {
        self.write_all(b"# ");
        self.write_all(text.as_bytes());
        self.write_all(b"\n");
    }
}

#[esp_rtos::main]
async fn main(_spawner: embassy_executor::Spawner) -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    // The scheduler runs in every profile (BLE for approver, Wi-Fi for sentry).
    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 73744);
    let timg0 = esp_hal::timer::timg::TimerGroup::new(p.TIMG0);
    esp_rtos::start(timg0.timer0, p.FROM_CPU_INTR0);

    let _trng_source = TrngSource::new(p.RNG, p.ADC1);
    let trng = Trng::try_new().expect("TRNG");
    let mut flash = FlashStorage::new(p.FLASH);
    let key = load_or_create_key(&mut flash, &trng);
    let stored = load_profile(&mut flash);
    let mut board = Board::new(key, "esp32s3", VERSION, supported(), stored);

    // Wi-Fi only in the sentry profile; BLE only in the approver profile.
    let mut radio = None;
    if board.profile() == Profile::Sentry {
        let mut ctl = esp_radio::wifi::WifiController::new(p.WIFI, Default::default())
            .expect("Wi-Fi controller");
        ctl.set_config(&esp_radio::wifi::Config::Station(Default::default())).expect("station mode");
        let mut sniffer = ctl.sniffer();
        sniffer.set_receive_cb(on_packet);
        sniffer.set_promiscuous_mode(true).expect("promiscuous mode");
        radio = Some((ctl, sniffer));
    }

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
    Timer::after_millis(1000).await;
    boot_log(&mut UsbOut(&mut usb), board.profile());

    // BLE name "rp-key-<first 4 hex of the key id>", address from the key.
    let pk = board.public_key();
    static NAME: static_cell::StaticCell<heapless::String<16>> = static_cell::StaticCell::new();
    let name = NAME.init({
        let mut n = heapless::String::new();
        let id = Sha256::digest(pk);
        let _ = write!(n, "rp-key-{:02x}{:02x}", id[0], id[1]);
        n
    });
    let addr = [pk[0], pk[1], pk[2], pk[3], pk[4], pk[5] | 0xc0];
    let ble_on = board.profile() == Profile::Approver;
    let ble_task = async move {
        if ble_on {
            ble::run(p.BT, name.as_str(), addr).await
        }
        core::future::pending::<()>().await
    };

    let main_loop = async move {
    let mut channel = 1u8;
    let mut hop_at = 0u64;
    let mut dropped_reported = 0u32;
    // Where the pending ASK came from: its DECIDE / TIMEOUT go back there.
    let mut ask_over_ble = false;
    loop {
        Timer::after_millis(2).await;
        let now = boot.elapsed().as_millis();
        while let Ok(line) = ble::BLE_IN.try_receive() {
            ask_over_ble = line.starts_with("ASK ") || (ask_over_ble && !line.starts_with("CANCEL"));
            for b in line.bytes().chain(Some(b'\n')) {
                let _ = board.on_byte(b, now, &mut Route { usb: UsbOut(&mut usb), to_ble: true });
            }
        }
        if let Some((ctl, _)) = &mut radio {
            // Count what arrived on the channel we are leaving, then hop.
            board.on_traffic(TRAFFIC.swap(0, Ordering::Relaxed));
            while let Some(pkt) = critical_section::with(|cs| FRAMES.borrow_ref_mut(cs).pop_front()) {
                board.on_frame(&pkt.data[..pkt.len as usize]);
            }
            if now >= hop_at {
                channel = channel % 13 + 1;
                let _ = ctl.set_channel(channel, esp_radio::wifi::SecondaryChannel::None);
                board.on_channel(channel);
                hop_at = now + 250;
            }
            let dropped = DROPPED.load(Ordering::Relaxed);
            if dropped >= dropped_reported + 1000 {
                dropped_reported = dropped;
                UsbOut(&mut usb).msg(KeyMsg::Log {
                    level: Level::Warn,
                    text: "sentry: busy air, some management frames were not inspected",
                });
            }
        }
        while let Ok(b) = usb.read_byte() {
            if b == b'A' {
                ask_over_ble = false; // an ASK from the gateway's port
            }
            if let Some(Effect::SwitchProfile(next)) = board.on_byte(b, now, &mut UsbOut(&mut usb)) {
                if !store_profile(&mut flash, next) {
                    UsbOut(&mut usb).msg(KeyMsg::Log {
                        level: Level::Error,
                        text: "could not store the new profile in flash; not restarting",
                    });
                    continue;
                }
                let t = Instant::now();
                while t.elapsed() < Duration::from_millis(50) {} // let OK drain
                esp_hal::system::software_reset();
            }
        }
        let light = board.tick(now, button.is_low(), &mut Route { usb: UsbOut(&mut usb), to_ble: ask_over_ble });
        set(colour(light));
    }
    };
    embassy_futures::join::join(ble_task, main_loop).await;
    unreachable!()
}
