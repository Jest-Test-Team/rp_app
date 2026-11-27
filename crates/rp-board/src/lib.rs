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
        }
    }

    pub fn profile(&self) -> Profile {
        self.profile
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Feed one received byte. Returns a profile to store and restart into.
    pub fn on_byte(&mut self, b: u8, now: u64, out: &mut dyn Out) -> Option<Profile> {
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

    fn handle(&mut self, msg: Option<HostMsg>, now: u64, out: &mut dyn Out) -> Option<Profile> {
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
                    return Some(p);
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

    fn send(b: &mut Board, line: &str, now: u64, out: &mut Rec) -> Option<Profile> {
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
        assert_eq!(send(&mut b, "PROFILE oob", 0, &mut out), Some(Profile::Oob));
        assert_eq!(out.lines.pop().unwrap(), "OK");
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
