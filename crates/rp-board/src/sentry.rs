//! Passive Wi-Fi monitoring for the `sentry` profile.
//!
//! The firmware puts the radio in promiscuous mode, hops channels and feeds
//! every received frame's header to [`Sentry::frame`]; this module decides
//! what is worth reporting and [`Sentry::tick`] turns it into `LOG` lines:
//!
//! * **deauth / disassociation floods**: at least [`FLOOD`] such frames from
//!   one BSSID within [`WINDOW_MS`] (forced disconnects, the usual first step
//!   of an evil-twin or handshake-capture attack);
//! * **evil twins**: the watched SSID (`WATCH`, normally the gateway's IoT
//!   AP) advertised by more than one BSSID. Mesh systems and extenders also
//!   do this, so it is a warning to check, not proof;
//! * **channel load**: once per [`SUMMARY_MS`], frames and access points per
//!   channel, so the gateway can pick a quieter channel.
//!
//! Only headers and SSIDs are looked at; payloads are never read or kept, and
//! nothing is ever transmitted.

use core::fmt::Write as _;

use rp_wire::Level;

pub const WINDOW_MS: u64 = 10_000;
pub const FLOOD: u16 = 20;
pub const SUMMARY_MS: u64 = 60_000;
const MAX_BSSIDS: usize = 24;
const MAX_TWINS: usize = 8;
const CHANNELS: usize = 13;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Beacon,
    ProbeResponse,
    Deauth,
    Disassoc,
    OtherManagement,
    Control,
    Data,
}

/// The parts of an 802.11 frame the sentry uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    /// Address 3 (the BSSID for management frames).
    pub bssid: [u8; 6],
    /// SSID element of beacons and probe responses.
    pub ssid: Option<&'a [u8]>,
}

/// Parse the MAC header (and the SSID element of beacons / probe responses).
pub fn parse(data: &[u8]) -> Option<Frame<'_>> {
    if data.len() < 24 {
        return None;
    }
    let fc = data[0];
    let (ftype, subtype) = ((fc >> 2) & 0b11, fc >> 4);
    let kind = match (ftype, subtype) {
        (0, 8) => Kind::Beacon,
        (0, 5) => Kind::ProbeResponse,
        (0, 12) => Kind::Deauth,
        (0, 10) => Kind::Disassoc,
        (0, _) => Kind::OtherManagement,
        (1, _) => Kind::Control,
        (2, _) => Kind::Data,
        _ => return None,
    };
    let mut bssid = [0u8; 6];
    bssid.copy_from_slice(&data[16..22]);
    let ssid = match kind {
        // Fixed fields (timestamp, interval, capabilities) then elements.
        Kind::Beacon | Kind::ProbeResponse => {
            let ies = data.get(36..)?;
            (ies.len() >= 2 && ies[0] == 0)
                .then(|| ies.get(2..2 + ies[1] as usize))
                .flatten()
                .filter(|s| s.len() <= 32)
        }
        _ => None,
    };
    Some(Frame { kind, bssid, ssid })
}

struct Mac([u8; 6]);
impl core::fmt::Display for Mac {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let m = self.0;
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", m[0], m[1], m[2], m[3], m[4], m[5])
    }
}

/// Printable form of an SSID (non-ASCII bytes as `?`).
struct Ssid<'a>(&'a [u8]);
impl core::fmt::Display for Ssid<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.iter().try_for_each(|&b| {
            f.write_char(if (0x20..0x7f).contains(&b) { b as char } else { '?' })
        })
    }
}

#[derive(Default, Clone, Copy)]
struct ChannelStats {
    frames: u32,
    aps: u8,
    seen: [[u8; 6]; 16],
}

impl ChannelStats {
    fn add_ap(&mut self, bssid: [u8; 6]) {
        let n = self.aps as usize;
        if n < self.seen.len() && !self.seen[..n].contains(&bssid) {
            self.seen[n] = bssid;
            self.aps += 1;
        }
    }
}

pub struct Sentry {
    watch: Option<([u8; 32], u8)>,
    window_start: u64,
    deauth: [([u8; 6], u16); MAX_BSSIDS],
    deauth_len: usize,
    reported_flood: [[u8; 6]; MAX_BSSIDS],
    reported_flood_len: usize,
    twins: [[u8; 6]; MAX_TWINS],
    twins_len: usize,
    twins_reported: usize,
    summary_start: u64,
    channels: [ChannelStats; CHANNELS],
    channel: u8,
}

impl Default for Sentry {
    fn default() -> Self {
        Self::new()
    }
}

impl Sentry {
    pub fn new() -> Self {
        Self {
            watch: None,
            window_start: 0,
            deauth: [([0; 6], 0); MAX_BSSIDS],
            deauth_len: 0,
            reported_flood: [[0; 6]; MAX_BSSIDS],
            reported_flood_len: 0,
            twins: [[0; 6]; MAX_TWINS],
            twins_len: 0,
            twins_reported: 0,
            summary_start: 0,
            channels: [ChannelStats::default(); CHANNELS],
            channel: 1,
        }
    }

    pub fn watch(&mut self, ssid: &[u8]) {
        let mut b = [0u8; 32];
        let n = ssid.len().min(32);
        b[..n].copy_from_slice(&ssid[..n]);
        self.watch = Some((b, n as u8));
        self.twins_len = 0;
        self.twins_reported = 0;
    }

    /// The channel the radio is on now (for the per-channel numbers).
    pub fn on_channel(&mut self, ch: u8) {
        self.channel = ch.clamp(1, CHANNELS as u8);
    }

    /// Frames of any kind received on the current channel (counted by the
    /// radio callback; only management frames are looked at one by one).
    pub fn traffic(&mut self, n: u32) {
        let ch = &mut self.channels[self.channel as usize - 1];
        ch.frames = ch.frames.saturating_add(n);
    }

    pub fn frame(&mut self, f: &Frame<'_>) {
        let ch = &mut self.channels[self.channel as usize - 1];
        match f.kind {
            Kind::Deauth | Kind::Disassoc => {
                match self.deauth[..self.deauth_len].iter_mut().find(|(b, _)| *b == f.bssid) {
                    Some((_, n)) => *n = n.saturating_add(1),
                    None if self.deauth_len < MAX_BSSIDS => {
                        self.deauth[self.deauth_len] = (f.bssid, 1);
                        self.deauth_len += 1;
                    }
                    None => {}
                }
            }
            Kind::Beacon | Kind::ProbeResponse => {
                if f.kind == Kind::Beacon {
                    ch.add_ap(f.bssid);
                }
                let watched = self.watch.as_ref().map(|(s, n)| &s[..*n as usize]);
                if watched.is_some() && f.ssid == watched {
                    let known = self.twins[..self.twins_len].contains(&f.bssid);
                    if !known && self.twins_len < MAX_TWINS {
                        self.twins[self.twins_len] = f.bssid;
                        self.twins_len += 1;
                    }
                }
            }
            _ => {}
        }
    }

    /// Call regularly; reports through `log`.
    pub fn tick(&mut self, now: u64, log: &mut dyn FnMut(Level, &str)) {
        let mut s: heapless::String<{ rp_wire::MAX_LOG_TEXT }> = heapless::String::new();
        if now.saturating_sub(self.window_start) >= WINDOW_MS {
            for &(bssid, n) in &self.deauth[..self.deauth_len] {
                let new = !self.reported_flood[..self.reported_flood_len].contains(&bssid);
                if n >= FLOOD && new {
                    s.clear();
                    let _ = write!(
                        s,
                        "sentry: deauth/disassoc flood from {} ({n} frames in {} s)",
                        Mac(bssid),
                        WINDOW_MS / 1000
                    );
                    log(Level::Warn, &s);
                    if self.reported_flood_len < MAX_BSSIDS {
                        self.reported_flood[self.reported_flood_len] = bssid;
                        self.reported_flood_len += 1;
                    }
                }
            }
            self.deauth_len = 0;
            self.window_start = now;
        }
        if let Some((ssid, n)) = self.watch {
            if self.twins_len > 1 && self.twins_len > self.twins_reported {
                for &b in &self.twins[self.twins_reported.max(1)..self.twins_len] {
                    s.clear();
                    let _ = write!(
                        s,
                        "sentry: '{}' also advertised by {} ({} BSSIDs; evil twin or mesh?)",
                        Ssid(&ssid[..n as usize]),
                        Mac(b),
                        self.twins_len
                    );
                    log(Level::Warn, &s);
                }
                self.twins_reported = self.twins_len;
            }
        }
        if now.saturating_sub(self.summary_start) >= SUMMARY_MS {
            // Floods that stopped may be reported again later.
            self.reported_flood_len = 0;
            s.clear();
            let _ = write!(s, "sentry: channel load");
            for (i, c) in self.channels.iter().enumerate() {
                if c.frames == 0 {
                    continue;
                }
                let mut item: heapless::String<24> = heapless::String::new();
                let _ = write!(item, " ch{}={}f/{}ap", i + 1, c.frames, c.aps);
                if s.len() + item.len() > s.capacity() {
                    log(Level::Info, &s);
                    s.clear();
                    let _ = write!(s, "sentry: channel load (cont.)");
                }
                let _ = s.push_str(&item);
            }
            log(Level::Info, &s);
            self.channels = [ChannelStats::default(); CHANNELS];
            self.summary_start = now;
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;
    use std::vec::Vec;

    fn mgmt(subtype: u8, bssid: [u8; 6], ssid: Option<&[u8]>) -> Vec<u8> {
        let mut f = std::vec![subtype << 4, 0, 0, 0];
        f.extend([0xff; 6]); // addr1
        f.extend(bssid); // addr2
        f.extend(bssid); // addr3
        f.extend([0, 0]); // seq
        if let Some(s) = ssid {
            f.extend([0; 12]); // timestamp, interval, capabilities
            f.push(0);
            f.push(s.len() as u8);
            f.extend(s);
        }
        f
    }

    fn run(s: &mut Sentry, now: u64) -> Vec<(Level, String)> {
        let mut out = Vec::new();
        s.tick(now, &mut |l, t| out.push((l, String::from(t))));
        out
    }

    const AP: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const EVIL: [u8; 6] = [0x02, 0, 0, 0, 0, 0x66];

    #[test]
    fn parses_headers_and_ssid() {
        let b = mgmt(8, AP, Some(b"home"));
        let f = parse(&b).unwrap();
        assert_eq!((f.kind, f.bssid, f.ssid), (Kind::Beacon, AP, Some(&b"home"[..])));
        assert_eq!(parse(&mgmt(12, AP, None)).unwrap().kind, Kind::Deauth);
        assert!(parse(&[0u8; 10]).is_none(), "too short");
        let mut bad = mgmt(8, AP, Some(b"x"));
        bad[37] = 200; // SSID length past the end
        assert_eq!(parse(&bad).unwrap().ssid, None);
    }

    #[test]
    fn reports_a_deauth_flood_once() {
        let mut s = Sentry::new();
        run(&mut s, 0);
        let d = mgmt(12, EVIL, None);
        for _ in 0..FLOOD {
            s.frame(&parse(&d).unwrap());
        }
        let out = run(&mut s, WINDOW_MS);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].0, Level::Warn);
        assert!(out[0].1.contains("02:00:00:00:00:66"), "{}", out[0].1);
        for _ in 0..FLOOD {
            s.frame(&parse(&d).unwrap());
        }
        assert!(run(&mut s, 2 * WINDOW_MS).is_empty(), "not repeated every window");
    }

    #[test]
    fn a_few_deauths_are_normal() {
        let mut s = Sentry::new();
        for _ in 0..FLOOD - 1 {
            s.frame(&parse(&mgmt(10, AP, None)).unwrap());
        }
        assert!(run(&mut s, WINDOW_MS).iter().all(|(l, _)| *l == Level::Info));
    }

    #[test]
    fn warns_when_the_watched_ssid_has_a_second_bssid() {
        let mut s = Sentry::new();
        s.watch(b"home-iot");
        s.frame(&parse(&mgmt(8, AP, Some(b"home-iot"))).unwrap());
        s.frame(&parse(&mgmt(8, AP, Some(b"home-iot"))).unwrap());
        s.frame(&parse(&mgmt(8, EVIL, Some(b"other"))).unwrap());
        assert!(run(&mut s, 1).is_empty(), "one BSSID is fine");
        s.frame(&parse(&mgmt(5, EVIL, Some(b"home-iot"))).unwrap());
        let out = run(&mut s, 2);
        assert_eq!(out.len(), 1);
        assert!(
            out[0].1.contains("'home-iot' also advertised by 02:00:00:00:00:66"),
            "{}",
            out[0].1
        );
        assert!(run(&mut s, 3).is_empty(), "reported once");
    }

    #[test]
    fn a_busy_band_is_split_over_several_lines() {
        let mut s = Sentry::new();
        for ch in 1..=13 {
            s.on_channel(ch);
            s.traffic(123_456);
        }
        let out = run(&mut s, SUMMARY_MS);
        assert!(out.len() >= 2, "{out:?}");
        assert!(out.iter().all(|(_, t)| t.len() <= rp_wire::MAX_LOG_TEXT));
        let all: String = out.iter().map(|(_, t)| t.as_str()).collect();
        assert!(all.contains("ch1=") && all.contains("ch13="), "{all}");
    }

    #[test]
    fn summarises_channel_load() {
        let mut s = Sentry::new();
        s.on_channel(6);
        for i in 0..5u8 {
            s.frame(&parse(&mgmt(8, [2, 0, 0, 0, 0, i], Some(b"n"))).unwrap());
        }
        s.traffic(5);
        s.on_channel(1);
        s.frame(&parse(&mgmt(4, AP, None)).unwrap());
        s.traffic(1);
        let out = run(&mut s, SUMMARY_MS);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0],
            (Level::Info, String::from("sentry: channel load ch1=1f/0ap ch6=5f/5ap"))
        );
    }
}
