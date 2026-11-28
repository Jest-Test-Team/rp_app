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
//! * honeypot profile (only then is the radio on): an access point under
//!   the decoy name (rp-boards sends it; "<IoT SSID>-guest" by default) on
//!   channel 11, WPA2 with a random passphrase only the board knows, so nobody
//!   can join; join attempts seen promiscuously on that channel are reported.
//! * oob profile: UART2 to the gateway's serial console — GPIO16 (RX) to Pi
//!   GPIO14 (TXD), GPIO17 (TX) to Pi GPIO15 (RXD), GND to GND, 115200 8N1;
//!   an optional relay on GPIO26 (active high) power-cycles the gateway when
//!   the watchdog trips. `CONSOLE` turns the USB link into a raw passthrough
//!   to the console until Ctrl-] is typed three times.

#![no_std]
#![no_main]
#![deny(clippy::mem_forget)]

extern crate alloc;

use core::cell::RefCell;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use critical_section::Mutex;

use ed25519_dalek::SigningKey;
use esp_backtrace as _;
use esp_hal::{
    Blocking,
    clock::CpuClock,
    gpio::{Input, InputConfig, Level as Pin, Output, OutputConfig, Pull},
    main,
    rng::{Trng, TrngSource},
    time::{Duration, Instant},
    uart::{Config as UartConfig, Uart},
};
use esp_storage::FlashStorage;
use rp_board::{Board, Effect, Light, Out, oob};
use rp_wire::{KeyMsg, Level, Profile, Profiles};
use sha2::{Digest, Sha256};

esp_bootloader_esp_idf::esp_app_desc!();

const VERSION: &str = env!("CARGO_PKG_VERSION");
const KEY_OFFSET: u32 = 0x9000;
const PROFILE_OFFSET: u32 = 0xA000;
const MAGIC: &[u8; 4] = b"RPK1";
const PROFILE_MAGIC: &[u8; 4] = b"RPP1";

/// No sentry here (the S3 with its antenna does that); csi switches and
/// reports but does nothing else so far.
fn supported() -> Profiles {
    Profiles::empty()
        .with(Profile::Approver)
        .with(Profile::Oob)
        .with(Profile::Honeypot)
        .with(Profile::Csi)
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


const DECOY_CHANNEL: u8 = 11;

/// Management frames copied out of the radio callback (header only).
const PKT: usize = 32;
struct Pkt {
    len: u8,
    data: [u8; PKT],
}
static FRAMES: Mutex<RefCell<heapless::Deque<Pkt, 32>>> = Mutex::new(RefCell::new(heapless::Deque::new()));
static DROPPED: AtomicU32 = AtomicU32::new(0);

fn on_packet(p: esp_radio::wifi::sniffer::PromiscuousPkt<'_>) {
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

/// (Re)start the decoy access point.
fn start_decoy(
    ctl: &mut esp_radio::wifi::WifiController<'_>,
    ssid: &[u8],
    pass: &str,
) -> Result<(), esp_radio::wifi::WifiError> {
    use esp_radio::wifi::{AuthenticationMethodConfig, Config, ap::AccessPointConfig};
    let name = core::str::from_utf8(ssid).unwrap_or("rp-guest");
    let cfg = AccessPointConfig::default()
        .with_ssid(name.try_into().map_err(|_| esp_radio::wifi::WifiError::InvalidArguments)?)
        .with_channel(DECOY_CHANNEL)
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
            pass.try_into().map_err(|_| esp_radio::wifi::WifiError::InvalidArguments)?,
        ));
    ctl.set_config(&Config::AccessPoint(cfg))
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

/// Raw passthrough between the USB link and the gateway's console, until the
/// user types Ctrl-] three times. LED on meanwhile.
fn passthrough(board: &mut Board, usb: &mut Uart<'_, Blocking>, con: &mut Uart<'_, Blocking>, led: &mut Output<'_>) {
    let mut out = UartOut(usb);
    out.write_all(b"\r\n# console: connected to the gateway; Ctrl-] three times to leave\r\n");
    led.set_high();
    let mut buf = [0u8; 64];
    'outer: loop {
        if out.0.read_ready() {
            let n = out.0.read_buffered(&mut buf).unwrap_or(0);
            for &b in &buf[..n] {
                if board.escape(b) {
                    break 'outer;
                }
                if b != oob::ESCAPE {
                    let mut c = UartOut(con);
                    c.write_all(&[b]);
                }
            }
        }
        if con.read_ready() {
            let n = con.read_buffered(&mut buf).unwrap_or(0);
            out.write_all(&buf[..n]);
        }
    }
    out.write_all(b"\r\n# console closed\r\n");
    led.set_low();
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

    // honeypot: radio on, decoy access point and promiscuous receive.
    let mut radio = None;
    let mut decoy_status: Option<(bool, [u8; 6])> = None;
    let mut decoy_pass: heapless::String<32> = heapless::String::new();
    if board.profile() == Profile::Honeypot {
        let mut raw = [0u8; 16];
        trng.read(&mut raw);
        for b in raw {
            let _ = write!(decoy_pass, "{b:02x}");
        }
        esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 98768);
        let timg0 = esp_hal::timer::timg::TimerGroup::new(p.TIMG0);
        esp_rtos::start(timg0.timer0, p.FROM_CPU_INTR0);
        let mut ctl = esp_radio::wifi::WifiController::new(p.WIFI, Default::default())
            .expect("Wi-Fi controller");
        let name = board.decoy_ssid().unwrap_or(rp_board::DEFAULT_DECOY);
        let started = start_decoy(&mut ctl, name, &decoy_pass);
        let bssid = esp_radio::wifi::Interface::access_point().mac_address();
        board.set_decoy_bssid(bssid);
        decoy_status = Some((started.is_ok(), bssid));
        let mut sniffer = ctl.sniffer();
        sniffer.set_receive_cb(on_packet);
        sniffer.set_promiscuous_mode(true).expect("promiscuous mode");
        radio = Some((ctl, sniffer));
    }

    let button = Input::new(p.GPIO0, InputConfig::default().with_pull(Pull::Up));
    let mut led = Output::new(p.GPIO2, Pin::High, OutputConfig::default());
    let mut uart = Uart::new(p.UART0, UartConfig::default())
        .expect("UART0")
        .with_tx(p.GPIO1)
        .with_rx(p.GPIO3);

    // oob: the gateway's console and the (optional) relay.
    let mut console = (board.profile() == Profile::Oob).then(|| {
        Uart::new(p.UART2, UartConfig::default())
            .expect("UART2")
            .with_tx(p.GPIO17)
            .with_rx(p.GPIO16)
    });
    let mut relay = Output::new(p.GPIO26, Pin::Low, OutputConfig::default());

    // Boot: LED on for one second.
    let boot = Instant::now();
    while boot.elapsed() < Duration::from_millis(1000) {}
    boot_log(&mut UartOut(&mut uart), board.profile());
    if let Some((ok, m)) = decoy_status {
        let mut t: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
        let _ = write!(
            t,
            "honeypot: decoy {} on ch{DECOY_CHANNEL}, bssid {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            if ok { "up" } else { "FAILED to start" },
            m[0], m[1], m[2], m[3], m[4], m[5]
        );
        UartOut(&mut uart).msg(KeyMsg::Log { level: if ok { Level::Info } else { Level::Error }, text: &t });
    }

    let mut buf = [0u8; 64];
    loop {
        let now = boot.elapsed().as_millis();
        if uart.read_ready() {
            let n = uart.read_buffered(&mut buf).unwrap_or(0);
            for &b in &buf[..n] {
                let effect = board.on_byte(b, now, &mut UartOut(&mut uart));
                if let (Some(Effect::Console), Some(con)) = (effect, console.as_mut()) {
                    passthrough(&mut board, &mut uart, con, &mut led);
                    continue;
                }
                if let (Some(Effect::Decoy(ssid, len)), Some((ctl, _))) = (effect, radio.as_mut()) {
                    let ok = start_decoy(ctl, &ssid[..len as usize], &decoy_pass).is_ok();
                    UartOut(&mut uart).msg(KeyMsg::Log {
                        level: if ok { Level::Info } else { Level::Error },
                        text: if ok { "honeypot: decoy renamed" } else { "honeypot: could not rename the decoy" },
                    });
                    continue;
                }
                if let Some(Effect::SwitchProfile(next)) = effect {
                    if !store_profile(&mut flash, next) {
                        UartOut(&mut uart).msg(KeyMsg::Log {
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
        }
        if radio.is_some() {
            while let Some(pkt) = critical_section::with(|cs| FRAMES.borrow_ref_mut(cs).pop_front()) {
                board.on_frame(&pkt.data[..pkt.len as usize]);
            }
            // Let the Wi-Fi task run (beacons): a busy loop would starve it.
            // 2 ms is ~23 bytes at 115200, well inside the 128-byte RX FIFO.
            esp_rtos::CurrentThreadHandle::get().delay(Duration::from_millis(2));
        }
        if let Some(con) = console.as_mut() {
            if con.read_ready() {
                let n = con.read_buffered(&mut buf).unwrap_or(0);
                for &b in &buf[..n] {
                    board.console_byte(b, &mut UartOut(&mut uart));
                }
            }
        }
        let light = board.tick(now, button.is_low(), &mut UartOut(&mut uart));
        if let Some(oob::Action::PowerCycle) = board.take_action() {
            // Relay (if wired) cuts the gateway's power for 3 s.
            relay.set_high();
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(3) {}
            relay.set_low();
        }
        led.set_level(if lit(light, now) { Pin::High } else { Pin::Low });
    }
}
