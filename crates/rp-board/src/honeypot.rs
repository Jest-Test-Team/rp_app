//! The `honeypot` profile: a decoy network nobody legitimate uses.
//!
//! The firmware runs an access point under the decoy name, protected by a
//! random WPA2 passphrase that only the board knows, so nobody can actually
//! join, and it listens promiscuously on that channel. Whoever *tries* to join
//! (an authentication or association request sent to the decoy's BSSID) is
//! either probing the area or trying to break in: that is reported, once per
//! device per [`REPEAT_MS`].
//!
//! Probe requests (phones asking "is network X here?") are not looked at:
//! that would log every passer-by.

use core::fmt::Write as _;

use rp_wire::Level;

use crate::sentry::{Frame, Kind, Mac, Ssid};

pub const REPEAT_MS: u64 = 10 * 60 * 1000;
const SEEN: usize = 16;

pub struct Honeypot {
    bssid: Option<[u8; 6]>,
    ssid: ([u8; 32], u8),
    seen: [([u8; 6], u64); SEEN],
    seen_len: usize,
    pending: Option<([u8; 6], Kind)>,
}

impl Honeypot {
    pub fn new(ssid: &[u8]) -> Self {
        let mut h = Self {
            bssid: None,
            ssid: ([0; 32], 0),
            seen: [([0; 6], 0); SEEN],
            seen_len: 0,
            pending: None,
        };
        h.set_ssid(ssid);
        h
    }

    pub fn set_ssid(&mut self, ssid: &[u8]) {
        let n = ssid.len().min(32);
        self.ssid.0[..n].copy_from_slice(&ssid[..n]);
        self.ssid.1 = n as u8;
    }

    pub fn ssid(&self) -> &[u8] {
        &self.ssid.0[..self.ssid.1 as usize]
    }

    /// The decoy access point's own address (known once it runs).
    pub fn set_bssid(&mut self, bssid: [u8; 6]) {
        self.bssid = Some(bssid);
    }

    pub fn frame(&mut self, f: &Frame<'_>, now: u64) {
        let Some(bssid) = self.bssid else { return };
        if !matches!(f.kind, Kind::Auth | Kind::AssocRequest) || f.dst != bssid || f.src == bssid {
            return;
        }
        match self.seen[..self.seen_len].iter_mut().find(|(m, _)| *m == f.src) {
            Some((_, t)) if now.saturating_sub(*t) < REPEAT_MS => return,
            Some((_, t)) => *t = now,
            None if self.seen_len < SEEN => {
                self.seen[self.seen_len] = (f.src, now);
                self.seen_len += 1;
            }
            None => {
                // Forget the oldest.
                let i = (0..SEEN).min_by_key(|&i| self.seen[i].1).unwrap_or(0);
                self.seen[i] = (f.src, now);
            }
        }
        self.pending = Some((f.src, f.kind));
    }

    pub fn tick(&mut self, log: &mut dyn FnMut(Level, &str)) {
        if let Some((mac, kind)) = self.pending.take() {
            let mut s: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
            let step = if kind == Kind::Auth { "authenticate" } else { "associate" };
            let _ = write!(
                s,
                "honeypot: {} tried to {step} with decoy '{}'",
                Mac(mac),
                Ssid(self.ssid())
            );
            log(Level::Warn, &s);
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::sentry::parse;
    use std::string::String;
    use std::vec::Vec;

    const DECOY: [u8; 6] = [0x02, 0, 0, 0, 0, 0xd0];
    const PHONE: [u8; 6] = [0x5a, 1, 2, 3, 4, 5];

    fn frame(subtype: u8, dst: [u8; 6], src: [u8; 6]) -> Vec<u8> {
        let mut f = std::vec![subtype << 4, 0, 0, 0];
        f.extend(dst);
        f.extend(src);
        f.extend(dst);
        f.extend([0, 0]);
        f
    }

    fn logs(h: &mut Honeypot) -> Vec<String> {
        let mut out = Vec::new();
        h.tick(&mut |_, t| out.push(String::from(t)));
        out
    }

    #[test]
    fn reports_join_attempts_on_the_decoy_once_per_device() {
        let mut h = Honeypot::new(b"home-guest");
        h.frame(&parse(&frame(11, DECOY, PHONE)).unwrap(), 0);
        assert!(logs(&mut h).is_empty(), "BSSID not known yet");
        h.set_bssid(DECOY);
        h.frame(&parse(&frame(11, DECOY, PHONE)).unwrap(), 1);
        assert_eq!(
            logs(&mut h),
            ["honeypot: 5a:01:02:03:04:05 tried to authenticate with decoy 'home-guest'"]
        );
        h.frame(&parse(&frame(0, DECOY, PHONE)).unwrap(), 2);
        assert!(logs(&mut h).is_empty(), "not again within 10 min");
        h.frame(&parse(&frame(0, DECOY, PHONE)).unwrap(), 2 + REPEAT_MS);
        assert_eq!(logs(&mut h).len(), 1, "again later");
    }

    #[test]
    fn ignores_other_networks_probes_and_its_own_frames() {
        let mut h = Honeypot::new(b"x");
        h.set_bssid(DECOY);
        let other = [0x02, 0, 0, 0, 0, 0x99];
        for f in [frame(11, other, PHONE), frame(4, DECOY, PHONE), frame(11, PHONE, DECOY)] {
            h.frame(&parse(&f).unwrap(), 0);
        }
        assert!(logs(&mut h).is_empty());
    }
}
