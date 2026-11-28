//! rp-board: what every rp ESP32 board does, independent of the chip.
//!
//! The firmware for each chip (`firmware/approver-s3`, `firmware/board-esp32`)
//! only moves bytes and pins: it feeds received bytes and the button level into
//! a [`Board`], sends the messages it produces, shows the [`Light`] it asks
//! for, and stores a new profile and restarts when told to. Everything that
//! decides something — parsing, the approval button, signing, profile checks —
//! lives here and is tested on the host.
//!
//! The approval button rules:
//! * a request (`ASK`) arms the button only once it has been seen *released*
//!   after the request arrived, so a stuck or already-held button (or a host
//!   driving the BOOT pin through the USB control lines) cannot approve;
//! * held for [`LONG_PRESS_MS`] or more = approve, a shorter press (at least
//!   [`MIN_PRESS_MS`]) = deny;
//! * only the `approver` profile answers `ASK`.

#![no_std]

pub mod honeypot;
pub mod oob;
pub mod sentry;

/// The decoy's name until the gateway sends `DECOY`.
pub const DEFAULT_DECOY: &[u8] = b"rp-guest";

/// What the firmware must do after a received line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Store this profile and restart.
    SwitchProfile(Profile),
    /// oob: hand the link over to raw passthrough to the gateway console
    /// until [`Board::escape`] says to stop.
    Console,
    /// honeypot: (re)start the decoy network under this name.
    Decoy([u8; 32], u8),
}

use ed25519_dalek::{Signer, SigningKey};
use rp_wire::{HostMsg, KeyMsg, Profile, Profiles};

pub const LONG_PRESS_MS: u64 = 3_000;
pub const MIN_PRESS_MS: u64 = 50;
/// Backstop only: the gateway decides how long to wait and sends `CANCEL`.
pub const ASK_TIMEOUT_MS: u64 = 310_000;
const RESULT_MS: u64 = 800;

/// Sink for what the board sends to the gateway.
pub trait Out {
    fn msg(&mut self, m: KeyMsg<'_>);
    /// A diagnostic line (prefixed `# `); the gateway ignores it.
    fn note(&mut self, text: &str);
}

/// What the status light should show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Light {
    /// Nothing to do, running this profile.
    Idle(Profile),
    /// A request waits for the button; `on` alternates every 250 ms.
    Waiting {
        on: bool,
    },
    /// Held long enough: releasing now approves.
    Holding,
    Approved,
    Denied,
}

struct Ask {
    id: [u8; rp_wire::ID_LEN],
    digest: [u8; rp_wire::DIGEST_LEN],
    nonce: [u8; rp_wire::NONCE_LEN],
    since: u64,
}

pub struct Board {
    key: SigningKey,
    chip: &'static str,
    version: &'static str,
    supported: Profiles,
    profile: Profile,
    line: [u8; rp_wire::MAX_LINE + 2],
    len: usize,
    overflow: bool,
    ask: Option<Ask>,
    armed: bool,
    pressed_at: Option<u64>,
    was_down: bool,
    result: Option<(Light, u64)>,
    sentry: Option<sentry::Sentry>,
    oob: Option<oob::Oob>,
    action: Option<oob::Action>,
    honeypot: Option<honeypot::Honeypot>,
    now: u64,
}

impl Board {
    /// `profile` is what the board stored; anything it does not support falls
    /// back to the first supported profile.
    pub fn new(
        key: SigningKey,
        chip: &'static str,
        version: &'static str,
        supported: Profiles,
        profile: Option<Profile>,
    ) -> Self {
        let profile = profile
            .filter(|p| supported.contains(*p))
            .or_else(|| supported.iter().next())
            .unwrap_or(Profile::Approver);
        Self {
            key,
            chip,
            version,
            supported,
            profile,
            line: [0; rp_wire::MAX_LINE + 2],
            len: 0,
            overflow: false,
            ask: None,
            armed: false,
            pressed_at: None,
            was_down: false,
            result: None,
            sentry: (profile == Profile::Sentry).then(sentry::Sentry::new),
            oob: (profile == Profile::Oob).then(oob::Oob::new),
            action: None,
            honeypot: (profile == Profile::Honeypot)
                .then(|| honeypot::Honeypot::new(DEFAULT_DECOY)),
            now: 0,
        }
    }

    /// oob profile: a byte from the gateway's console (outside passthrough).
    pub fn console_byte(&mut self, b: u8, out: &mut dyn Out) {
        if let Some(o) = &mut self.oob {
            o.console_byte(b, out);
        }
    }

    /// oob passthrough: a byte typed by the user; true = leave passthrough.
    pub fn escape(&mut self, b: u8) -> bool {
        self.oob.as_mut().is_some_and(|o| o.escape(b))
    }

    /// oob: what the watchdog asks the firmware to do (taken once).
    pub fn take_action(&mut self) -> Option<oob::Action> {
        self.action.take()
    }

    /// Sentry profile: the radio moved to channel `ch`.
    pub fn on_channel(&mut self, ch: u8) {
        if let Some(s) = &mut self.sentry {
            s.on_channel(ch);
        }
    }

    /// Sentry profile: `n` frames of any kind arrived on the current channel.
    pub fn on_traffic(&mut self, n: u32) {
        if let Some(s) = &mut self.sentry {
            s.traffic(n);
        }
    }

    /// Sentry / honeypot: one received 802.11 frame (header and SSID only).
    pub fn on_frame(&mut self, data: &[u8]) {
        let Some(f) = sentry::parse(data) else { return };
        if let Some(s) = &mut self.sentry {
            s.frame(&f);
        }
        if let Some(h) = &mut self.honeypot {
            h.frame(&f, self.now);
        }
    }

    /// honeypot: the decoy's current name and, once it runs, its address.
    pub fn decoy_ssid(&self) -> Option<&[u8]> {
        self.honeypot.as_ref().map(|h| h.ssid())
    }

    pub fn set_decoy_bssid(&mut self, bssid: [u8; 6]) {
        if let Some(h) = &mut self.honeypot {
            h.set_bssid(bssid);
        }
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Feed one received byte. Returns what the firmware must do, if anything.
    pub fn on_byte(&mut self, b: u8, now: u64, out: &mut dyn Out) -> Option<Effect> {
        if b != b'\n' {
            if self.len < self.line.len() {
                self.line[self.len] = b;
                self.len += 1;
            } else {
                self.overflow = true;
            }
            return None;
        }
        let (len, overflow) = (self.len, self.overflow);
        self.len = 0;
        self.overflow = false;
        let line = self.line;
        let text = core::str::from_utf8(&line[..len]).unwrap_or("\u{0}");
        if text.trim().is_empty() {
            return None;
        }
        let msg = if overflow { None } else { HostMsg::parse(text) };
        self.handle(msg, now, out)
    }

    fn handle(&mut self, msg: Option<HostMsg>, now: u64, out: &mut dyn Out) -> Option<Effect> {
        match msg {
            None => out.msg(KeyMsg::Err("bad line")),
            Some(HostMsg::Hello) => {
                out.msg(KeyMsg::Key { public_key: self.public_key(), version: self.version })
            }
            Some(HostMsg::Info) => out.msg(KeyMsg::Info {
                chip: self.chip,
                profile: self.profile,
                version: self.version,
                supported: self.supported,
            }),
            Some(HostMsg::SetProfile(p)) if !self.supported.contains(p) => {
                out.msg(KeyMsg::Err("profile not supported on this board"))
            }
            Some(HostMsg::SetProfile(p)) => {
                self.ask = None;
                out.msg(KeyMsg::Ok);
                if p != self.profile {
                    return Some(Effect::SwitchProfile(p));
                }
            }
            Some(HostMsg::Ask { .. }) if self.profile != Profile::Approver => {
                out.msg(KeyMsg::Err("not in the approver profile"))
            }
            Some(HostMsg::Ask { id, digest, nonce }) => {
                self.ask = Some(Ask { id, digest, nonce, since: now });
                self.armed = false;
                self.pressed_at = None;
                self.result = None;
            }
            Some(HostMsg::Watch { ssid, len }) => match &mut self.sentry {
                Some(s) => {
                    s.watch(&ssid[..len as usize]);
                    out.msg(KeyMsg::Ok);
                }
                None => out.msg(KeyMsg::Err("not in the sentry profile")),
            },
            Some(
                HostMsg::Heartbeat
                | HostMsg::Watchdog { .. }
                | HostMsg::Tail { .. }
                | HostMsg::Console,
            ) if self.oob.is_none() => out.msg(KeyMsg::Err("not in the oob profile")),
            Some(HostMsg::Heartbeat) => {
                if let Some(o) = &mut self.oob {
                    o.heartbeat(now);
                }
            }
            Some(HostMsg::Watchdog { seconds }) => {
                if let Some(o) = &mut self.oob {
                    let s = o.set_watchdog(seconds, now);
                    let mut t: heapless::String<48> = heapless::String::new();
                    let _ = core::fmt::Write::write_fmt(
                        &mut t,
                        format_args!("watchdog: {s} s (0 = off)"),
                    );
                    out.msg(KeyMsg::Log { level: rp_wire::Level::Info, text: &t });
                    out.msg(KeyMsg::Ok);
                }
            }
            Some(HostMsg::Tail { n }) => {
                if let Some(o) = &self.oob {
                    o.tail(n as usize, out);
                    out.msg(KeyMsg::Ok);
                }
            }
            Some(HostMsg::Console) => {
                out.msg(KeyMsg::Ok);
                return Some(Effect::Console);
            }
            Some(HostMsg::Decoy { ssid, len }) => {
                if let Some(h) = &mut self.honeypot {
                    let changed = h.ssid() != &ssid[..len as usize];
                    h.set_ssid(&ssid[..len as usize]);
                    out.msg(KeyMsg::Ok);
                    if changed {
                        return Some(Effect::Decoy(ssid, len));
                    }
                    return None;
                }
                out.msg(KeyMsg::Err("not in the honeypot profile"))
            }
            Some(HostMsg::Cancel) => {
                self.ask = None;
                self.pressed_at = None;
                out.msg(KeyMsg::Ok);
            }
        }
        None
    }

    /// Call often (every few ms) with the button level.
    pub fn tick(&mut self, now: u64, down: bool, out: &mut dyn Out) -> Light {
        if let Some(s) = &mut self.sentry {
            s.tick(now, &mut |level, text| out.msg(KeyMsg::Log { level, text }));
        }
        self.now = now;
        if let Some(h) = &mut self.honeypot {
            h.tick(&mut |level, text| out.msg(KeyMsg::Log { level, text }));
        }
        if let Some(a) = self.oob.as_mut().and_then(|o| o.tick(now, out)) {
            self.action = Some(a);
        }
        if down != self.was_down {
            self.was_down = down;
            out.note(if down { "button down" } else { "button up" });
        }
        let Some(a) = &self.ask else {
            self.pressed_at = None;
            return match self.result {
                Some((l, until)) if now < until => l,
                _ => {
                    self.result = None;
                    Light::Idle(self.profile)
                }
            };
        };
        if now.saturating_sub(a.since) >= ASK_TIMEOUT_MS {
            out.msg(KeyMsg::Timeout { id: a.id });
            self.ask = None;
            return Light::Idle(self.profile);
        }
        if !down && self.pressed_at.is_none() {
            self.armed = true;
        }
        match (down, self.pressed_at) {
            (true, None) if self.armed => self.pressed_at = Some(now),
            (true, Some(t)) if now - t >= LONG_PRESS_MS => return Light::Holding,
            (false, Some(t)) => {
                self.pressed_at = None;
                let held = now - t;
                if held >= MIN_PRESS_MS {
                    let approve = held >= LONG_PRESS_MS;
                    let msg = rp_wire::signing_message(&a.id, &a.digest, &a.nonce, approve);
                    let signature = self.key.sign(&msg).to_bytes();
                    out.msg(KeyMsg::Decide { id: a.id, approve, signature });
                    self.ask = None;
                    let l = if approve { Light::Approved } else { Light::Denied };
                    self.result = Some((l, now + RESULT_MS));
                    return l;
                }
            }
            _ => {}
        }
        let since = self.ask.as_ref().map_or(now, |a| a.since);
        Light::Waiting { on: ((now - since) / 250).is_multiple_of(2) }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use std::string::{String, ToString};
    use std::vec::Vec;

    #[derive(Default)]
    struct Rec {
        lines: Vec<String>,
    }
    impl Out for Rec {
        fn msg(&mut self, m: KeyMsg<'_>) {
            self.lines.push(m.to_string());
        }
        fn note(&mut self, _: &str) {}
    }

    const ID: [u8; 6] = [1, 2, 3, 4, 5, 6];
    const DIGEST: [u8; 32] = [9; 32];
    const NONCE: [u8; 16] = [7; 16];

    fn board(profile: Profile) -> Board {
        let all = Profiles::empty().with(Profile::Approver).with(Profile::Oob);
        Board::new(SigningKey::from_bytes(&[5; 32]), "esp32", "0.2.0", all, Some(profile))
    }

    fn send(b: &mut Board, line: &str, now: u64, out: &mut Rec) -> Option<Effect> {
        let mut r = None;
        for c in line.bytes().chain(Some(b'\n')) {
            r = r.or(b.on_byte(c, now, out));
        }
        r
    }

    fn ask(b: &mut Board, now: u64, out: &mut Rec) {
        let m = HostMsg::Ask { id: ID, digest: DIGEST, nonce: NONCE }.to_string();
        send(b, &m, now, out);
    }

    /// Press from `from` to `to` (ms), ticking every 10 ms; then idle a bit.
    fn press(b: &mut Board, from: u64, to: u64, out: &mut Rec) {
        let mut t = from;
        while t < to {
            b.tick(t, true, out);
            t += 10;
        }
        b.tick(to, false, out);
    }

    fn decision(b: &Board, out: &Rec) -> Option<bool> {
        let line = out.lines.iter().find(|l| l.starts_with("DECIDE"))?;
        let Some(KeyMsg::Decide { id, approve, signature }) = KeyMsg::parse(line) else {
            panic!("{line}")
        };
        assert_eq!(id, ID);
        let msg = rp_wire::signing_message(&ID, &DIGEST, &NONCE, approve);
        b.key.verifying_key().verify(&msg, &Signature::from_bytes(&signature)).unwrap();
        Some(approve)
    }

    #[test]
    fn long_press_approves_short_press_denies() {
        for (held, want) in [(3_000, true), (5_000, true), (200, false), (2_990, false)] {
            let (mut b, mut out) = (board(Profile::Approver), Rec::default());
            ask(&mut b, 0, &mut out);
            b.tick(5, false, &mut out); // released: armed
            press(&mut b, 100, 100 + held, &mut out);
            assert_eq!(decision(&b, &out), Some(want), "held {held} ms");
        }
    }

    #[test]
    fn a_held_or_stuck_button_never_decides() {
        // Down before and during the request, released 10 s later: no decision.
        let (mut b, mut out) = (board(Profile::Approver), Rec::default());
        b.tick(0, true, &mut out);
        ask(&mut b, 10, &mut out);
        press(&mut b, 20, 10_000, &mut out);
        assert_eq!(decision(&b, &out), None);
        // A real press afterwards still works.
        press(&mut b, 10_100, 10_300, &mut out);
        assert_eq!(decision(&b, &out), Some(false));
    }

    #[test]
    fn bounces_and_idle_presses_do_nothing() {
        let (mut b, mut out) = (board(Profile::Approver), Rec::default());
        press(&mut b, 0, 5_000, &mut out); // no request
        ask(&mut b, 6_000, &mut out);
        b.tick(6_001, false, &mut out);
        press(&mut b, 6_010, 6_030, &mut out); // 20 ms bounce
        assert_eq!(decision(&b, &out), None);
    }

    #[test]
    fn other_profiles_refuse_requests() {
        let (mut b, mut out) = (board(Profile::Oob), Rec::default());
        ask(&mut b, 0, &mut out);
        assert_eq!(out.lines, ["ERR not in the approver profile"]);
        b.tick(1, false, &mut out);
        press(&mut b, 10, 4_000, &mut out);
        assert_eq!(decision(&b, &out), None);
    }

    #[test]
    fn info_and_profile_switching() {
        let (mut b, mut out) = (board(Profile::Approver), Rec::default());
        send(&mut b, "INFO", 0, &mut out);
        assert_eq!(out.lines.pop().unwrap(), "INFO esp32 approver 0.2.0 approver,oob");
        assert_eq!(send(&mut b, "PROFILE sentry", 0, &mut out), None);
        assert!(out.lines.pop().unwrap().starts_with("ERR"), "not supported here");
        assert_eq!(send(&mut b, "PROFILE approver", 0, &mut out), None, "already running");
        assert_eq!(
            send(&mut b, "PROFILE oob", 0, &mut out),
            Some(Effect::SwitchProfile(Profile::Oob))
        );
        assert_eq!(out.lines.pop().unwrap(), "OK");
    }

    #[test]
    fn sentry_profile_watches_and_reports() {
        let all = Profiles::empty().with(Profile::Approver).with(Profile::Sentry);
        let mut b =
            Board::new(SigningKey::from_bytes(&[5; 32]), "c", "1", all, Some(Profile::Sentry));
        let mut out = Rec::default();
        send(&mut b, &HostMsg::watch(b"iot").unwrap().to_string(), 0, &mut out);
        assert_eq!(out.lines.pop().as_deref(), Some("OK"));
        b.on_channel(6);
        let beacon = |bssid: u8| {
            let mut f = std::vec![0x80u8, 0, 0, 0];
            f.extend([0xff; 6]);
            f.extend([2, 0, 0, 0, 0, bssid]);
            f.extend([2, 0, 0, 0, 0, bssid]);
            f.extend([0; 2 + 12]);
            f.extend([0, 3]);
            f.extend(b"iot");
            f
        };
        b.on_frame(&beacon(1));
        b.on_frame(&beacon(9));
        b.on_traffic(2);
        b.tick(sentry::SUMMARY_MS, false, &mut out);
        assert!(
            out.lines.iter().any(|l| l.starts_with("LOG warn sentry: 'iot' also advertised")),
            "{:?}",
            out.lines
        );
        assert!(out
            .lines
            .iter()
            .any(|l| l.starts_with("LOG info sentry: channel load ch6=2f/2ap")));

        let (mut a, mut out) = (board(Profile::Approver), Rec::default());
        send(&mut a, "WATCH 696f74", 0, &mut out);
        assert_eq!(out.lines.pop().as_deref(), Some("ERR not in the sentry profile"));
        a.on_frame(&beacon(1)); // ignored, no radio in approver
    }

    #[test]
    fn oob_profile_console_watchdog_and_passthrough() {
        let (mut b, mut out) = (board(Profile::Oob), Rec::default());
        b.console_byte(b'o', &mut out);
        b.console_byte(b'k', &mut out);
        b.console_byte(b'\n', &mut out);
        assert_eq!(out.lines.pop().as_deref(), Some("LOG info pi> ok"));
        send(&mut b, "TAIL 5", 0, &mut out);
        assert_eq!(out.lines, ["LOG info pi< ok", "OK"]);
        out.lines.clear();

        send(&mut b, "WATCHDOG 60", 1_000, &mut out);
        assert_eq!(out.lines, ["LOG info watchdog: 60 s (0 = off)", "OK"]);
        send(&mut b, "HB", 2_000, &mut out);
        b.tick(61_000, false, &mut out);
        assert_eq!(b.take_action(), None);
        b.tick(62_000, false, &mut out);
        assert_eq!(b.take_action(), Some(oob::Action::PowerCycle));
        assert_eq!(b.take_action(), None, "taken once");

        assert_eq!(send(&mut b, "CONSOLE", 0, &mut out), Some(Effect::Console));
        assert!(!b.escape(oob::ESCAPE) && !b.escape(oob::ESCAPE) && b.escape(oob::ESCAPE));

        // Other profiles refuse oob requests and never trip a watchdog.
        let (mut a, mut out) = (board(Profile::Approver), Rec::default());
        for l in ["HB", "WATCHDOG 60", "TAIL 3", "CONSOLE"] {
            assert_eq!(send(&mut a, l, 0, &mut out), None);
            assert_eq!(out.lines.pop().as_deref(), Some("ERR not in the oob profile"), "{l}");
        }
        assert!(!a.escape(oob::ESCAPE) && !a.escape(oob::ESCAPE) && !a.escape(oob::ESCAPE));
        let decoy = HostMsg::decoy(b"guest").unwrap().to_string();
        assert_eq!(send(&mut a, &decoy, 0, &mut out), None);
        assert_eq!(out.lines.pop().as_deref(), Some("ERR not in the honeypot profile"));
    }

    #[test]
    fn stored_profile_must_be_supported() {
        let s3 = Profiles::empty().with(Profile::Approver).with(Profile::Sentry);
        let key = || SigningKey::from_bytes(&[1; 32]);
        assert_eq!(
            Board::new(key(), "c", "1", s3, Some(Profile::Oob)).profile(),
            Profile::Approver
        );
        assert_eq!(Board::new(key(), "c", "1", s3, None).profile(), Profile::Approver);
        assert_eq!(
            Board::new(key(), "c", "1", s3, Some(Profile::Sentry)).profile(),
            Profile::Sentry
        );
    }

    #[test]
    fn garbage_and_overlong_lines_are_refused() {
        let (mut b, mut out) = (board(Profile::Approver), Rec::default());
        send(&mut b, "ASK zz", 0, &mut out);
        let long: String = core::iter::repeat_n('A', 400).collect();
        send(&mut b, &long, 0, &mut out);
        assert_eq!(out.lines, ["ERR bad line", "ERR bad line"]);
        send(&mut b, "HELLO", 0, &mut out);
        assert!(out.lines.pop().unwrap().starts_with("KEY "), "recovers after an overflow");
    }

    #[test]
    fn cancel_and_timeout() {
        let (mut b, mut out) = (board(Profile::Approver), Rec::default());
        ask(&mut b, 0, &mut out);
        send(&mut b, "CANCEL", 10, &mut out);
        b.tick(11, false, &mut out);
        press(&mut b, 20, 4_000, &mut out);
        assert_eq!(decision(&b, &out), None);

        ask(&mut b, 5_000, &mut out);
        assert_eq!(b.tick(5_000 + ASK_TIMEOUT_MS, false, &mut out), Light::Idle(Profile::Approver));
        assert!(out.lines.last().unwrap().starts_with("TIMEOUT"));
    }
}
