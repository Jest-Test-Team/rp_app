//! Out-of-band console and watchdog for the `oob` profile.
//!
//! The board's second UART is wired to the gateway's serial console (Pi
//! GPIO14/15 and GND). This module, independent of the chip:
//!
//! * splits what the console prints into lines, keeps the last [`LINES`] of
//!   them (so the lines printed just before a crash survive it) and reports
//!   each one as `LOG info pi> ...`;
//! * answers `TAIL <n>` with the kept lines, oldest first, as
//!   `LOG info pi< ...` — what rp-boards asks right after it (re)connects;
//! * runs the watchdog: rp-boards sends `HB` every few seconds; when
//!   `WATCHDOG <s>` is armed and none came for `s` seconds, it records that
//!   the gateway went silent and asks the firmware to power-cycle it (only
//!   if a relay is wired), at most once per silence;
//! * recognises the passthrough exit sequence (Ctrl-] three times).
//!
//! Console text is untrusted: kept bounded and printable, never executed.

use core::fmt::Write as _;

use rp_wire::{KeyMsg, Level};

use crate::Out;

/// Console lines kept.
pub const LINES: usize = 64;
/// Longest console line kept (the rest is cut).
pub const LINE: usize = 96;
/// Ends `CONSOLE` passthrough: Ctrl-] three times in a row.
pub const ESCAPE: u8 = 0x1d;
const MIN_WATCHDOG_S: u16 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Pulse the relay (if wired) to power-cycle the gateway.
    PowerCycle,
}

pub struct Oob {
    ring: [[u8; LINE]; LINES],
    lens: [u8; LINES],
    head: usize,
    count: usize,
    cur: [u8; LINE],
    cur_len: usize,
    last_hb: Option<u64>,
    watchdog_ms: u64,
    tripped: bool,
    escapes: u8,
}

impl Default for Oob {
    fn default() -> Self {
        Self::new()
    }
}

impl Oob {
    pub fn new() -> Self {
        Self {
            ring: [[0; LINE]; LINES],
            lens: [0; LINES],
            head: 0,
            count: 0,
            cur: [0; LINE],
            cur_len: 0,
            last_hb: None,
            watchdog_ms: 0,
            tripped: false,
            escapes: 0,
        }
    }

    fn push_line(&mut self, out: &mut dyn Out) {
        let n = self.cur_len;
        self.cur_len = 0;
        let line = self.cur;
        let text = core::str::from_utf8(&line[..n]).unwrap_or("?");
        if text.trim().is_empty() {
            return;
        }
        self.ring[self.head][..n].copy_from_slice(&line[..n]);
        self.lens[self.head] = n as u8;
        self.head = (self.head + 1) % LINES;
        self.count = (self.count + 1).min(LINES);
        let mut s: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
        let _ = write!(s, "pi> {text}");
        out.msg(KeyMsg::Log { level: Level::Info, text: &s });
    }

    fn keep(&mut self, text: &str) {
        let n = text.len().min(LINE);
        self.ring[self.head][..n].copy_from_slice(&text.as_bytes()[..n]);
        self.lens[self.head] = n as u8;
        self.head = (self.head + 1) % LINES;
        self.count = (self.count + 1).min(LINES);
    }

    /// A byte the gateway's console printed (not during passthrough).
    pub fn console_byte(&mut self, b: u8, out: &mut dyn Out) {
        match b {
            b'\n' => self.push_line(out),
            b'\r' => {}
            // Printable ASCII only; colour codes and the like become '?'.
            _ if self.cur_len < LINE => {
                self.cur[self.cur_len] = if (0x20..0x7f).contains(&b) { b } else { b'?' };
                self.cur_len += 1;
            }
            _ => {}
        }
    }

    /// `TAIL n`: the last `n` kept lines, oldest first.
    pub fn tail(&self, n: usize, out: &mut dyn Out) {
        let n = n.min(self.count);
        for i in 0..n {
            let idx = (self.head + LINES - n + i) % LINES;
            let text =
                core::str::from_utf8(&self.ring[idx][..self.lens[idx] as usize]).unwrap_or("?");
            let mut s: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
            let _ = write!(s, "pi< {text}");
            out.msg(KeyMsg::Log { level: Level::Info, text: &s });
        }
    }

    pub fn heartbeat(&mut self, now: u64) {
        self.last_hb = Some(now);
        self.tripped = false;
    }

    /// `WATCHDOG s`; returns the value in force (0 = off, else >= 30 s).
    pub fn set_watchdog(&mut self, seconds: u16, now: u64) -> u16 {
        let s = if seconds == 0 { 0 } else { seconds.max(MIN_WATCHDOG_S) };
        self.watchdog_ms = u64::from(s) * 1000;
        // Count from now: arming must not trip on an old silence.
        self.last_hb = Some(now);
        self.tripped = false;
        s
    }

    pub fn tick(&mut self, now: u64, out: &mut dyn Out) -> Option<Action> {
        let last = self.last_hb?;
        if self.watchdog_ms == 0 || self.tripped || now.saturating_sub(last) < self.watchdog_ms {
            return None;
        }
        self.tripped = true;
        let mut s: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
        let _ = write!(s, "watchdog: no heartbeat from the gateway for {} s", (now - last) / 1000);
        self.keep(&s);
        out.msg(KeyMsg::Log { level: Level::Error, text: &s });
        Some(Action::PowerCycle)
    }

    /// Passthrough: feed each byte typed by the user; true = leave passthrough.
    pub fn escape(&mut self, b: u8) -> bool {
        if b == ESCAPE {
            self.escapes += 1;
        } else {
            self.escapes = 0;
        }
        if self.escapes >= 3 {
            self.escapes = 0;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::{String, ToString};
    use std::vec::Vec;

    #[derive(Default)]
    struct Rec(Vec<String>);
    impl Out for Rec {
        fn msg(&mut self, m: KeyMsg<'_>) {
            self.0.push(m.to_string());
        }
        fn note(&mut self, _: &str) {}
    }

    fn feed(o: &mut Oob, text: &str, out: &mut Rec) {
        text.bytes().for_each(|b| o.console_byte(b, out));
    }

    #[test]
    fn console_lines_are_reported_and_kept() {
        let (mut o, mut out) = (Oob::new(), Rec::default());
        feed(&mut o, "[    0.000] Booting Linux\r\n\x1b[1mraspberrypi login: ", &mut out);
        feed(&mut o, "\n\n", &mut out);
        assert_eq!(
            out.0,
            ["LOG info pi> [    0.000] Booting Linux", "LOG info pi> ?[1mraspberrypi login: "]
        );
        out.0.clear();
        o.tail(10, &mut out);
        assert_eq!(out.0.len(), 2);
        assert!(out.0[0].starts_with("LOG info pi< [    0.000]"), "oldest first");
    }

    #[test]
    fn only_the_last_lines_survive() {
        let (mut o, mut out) = (Oob::new(), Rec::default());
        for i in 0..LINES + 5 {
            feed(&mut o, &std::format!("line {i}\n"), &mut out);
        }
        feed(&mut o, &"x".repeat(300), &mut out);
        feed(&mut o, "\n", &mut out);
        out.0.clear();
        o.tail(255, &mut out);
        assert_eq!(out.0.len(), LINES);
        assert_eq!(out.0[0], "LOG info pi< line 6");
        assert!(out.0[LINES - 1].len() <= "LOG info pi< ".len() + LINE, "long lines are cut");
    }

    #[test]
    fn watchdog_trips_once_per_silence() {
        let (mut o, mut out) = (Oob::new(), Rec::default());
        assert_eq!(o.tick(10_000_000, &mut out), None, "off by default");
        assert_eq!(o.set_watchdog(5, 0), 30, "at least 30 s");
        o.heartbeat(10_000);
        assert_eq!(o.tick(39_000, &mut out), None);
        assert_eq!(o.tick(40_000, &mut out), Some(Action::PowerCycle));
        assert!(out.0[0].starts_with("LOG error watchdog: no heartbeat"), "{:?}", out.0);
        assert_eq!(o.tick(90_000, &mut out), None, "once per silence");
        o.heartbeat(100_000);
        assert_eq!(o.tick(131_000, &mut out), Some(Action::PowerCycle), "re-armed by a heartbeat");
        // The trip is kept with the console lines, for after the restart.
        out.0.clear();
        o.tail(1, &mut out);
        assert!(out.0[0].contains("watchdog: no heartbeat"));
        o.set_watchdog(0, 0);
        o.heartbeat(0);
        assert_eq!(o.tick(10_000_000, &mut out), None, "off again");
    }

    #[test]
    fn escape_needs_three_in_a_row() {
        let mut o = Oob::new();
        assert!(!o.escape(ESCAPE) && !o.escape(ESCAPE) && !o.escape(b'a'));
        assert!(!o.escape(ESCAPE) && !o.escape(ESCAPE));
        assert!(o.escape(ESCAPE));
    }
}
