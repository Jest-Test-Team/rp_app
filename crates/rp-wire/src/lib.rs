//! rp-wire: the line protocol between the gateway and a hardware approval key.
//!
//! The key is a small board (ESP32-S3) on a USB serial port. It holds an
//! Ed25519 private key that never leaves it and signs a decision only when a
//! person presses its button. The gateway refuses to run an approved privileged
//! action without such a signature, so a remote approval (console app, a
//! compromised client) still needs someone standing next to the device.
//!
//! One message per line, ASCII, fields separated by single spaces, binary
//! fields in lowercase hex:
//!
//! | Direction | Line |
//! |---|---|
//! | gateway → key | `HELLO` |
//! | key → gateway | `KEY <public key, 64 hex> <firmware version>` |
//! | gateway → key | `ASK <action id, 12 hex> <digest, 64 hex> <nonce, 32 hex>` |
//! | key → gateway | `DECIDE <action id> <A\|D> <signature, 128 hex>` |
//! | key → gateway | `TIMEOUT <action id>` |
//! | gateway → key | `CANCEL` |
//! | key → gateway | `OK` / `ERR <text>` |
//! | gateway → board | `INFO` |
//! | board → gateway | `INFO <chip> <profile> <version> <supported profiles, comma-separated>` |
//! | gateway → board | `PROFILE <name>` (board answers `OK`, stores it and restarts) |
//! | board → gateway | `LOG <error\|warn\|info> <text>` (any time; kept by rp-boards) |
//! | gateway → board | `WATCH <ssid, hex>` (sentry: the network to guard against evil twins) |
//! | gateway → board | `HB` (oob: the gateway is alive), `WATCHDOG <seconds>` (0 = off) |
//! | gateway → board | `TAIL <n>` (oob: the last n gateway console lines, as `LOG info pi< ...`) |
//! | gateway → board | `CONSOLE` (oob: raw passthrough to the gateway console; Ctrl-] three times ends it) |
//! | gateway → board | `DECOY <ssid, hex>` (honeypot: the decoy network name) |
//!
//! Lines starting with `# ` are diagnostics; anything else a board prints
//! (boot ROM, panic messages) is kept as raw log text by the gateway.
//!
//! A board runs one [`Profile`] at a time. Only `approver` answers `ASK`; in
//! any other profile the board answers `ERR`, so approvals fail closed.
//!
//! The key signs [`signing_message`]: a domain tag, the action id, the digest
//! of the action (computed by the gateway), a fresh gateway nonce and the
//! decision. The nonce makes every signature single-use.

#![no_std]

use core::fmt::{self, Write as _};

/// Domain separation tag; bump the version if the message layout changes.
pub const DOMAIN: &[u8; 15] = b"rp-approver-v1\0";
pub const ID_LEN: usize = 6;
pub const DIGEST_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const MSG_LEN: usize = DOMAIN.len() + ID_LEN + DIGEST_LEN + NONCE_LEN + 1;
/// Longest line either side sends (DECIDE), without the newline.
pub const MAX_LINE: usize = 160;

/// The exact bytes the key signs.
pub fn signing_message(
    id: &[u8; ID_LEN],
    digest: &[u8; DIGEST_LEN],
    nonce: &[u8; NONCE_LEN],
    approve: bool,
) -> [u8; MSG_LEN] {
    let mut m = [0u8; MSG_LEN];
    let mut at = 0;
    for part in [&DOMAIN[..], &id[..], &digest[..], &nonce[..], &[approve as u8][..]] {
        m[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    m
}

/// What a board does. Stored on the board; switched from the console.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Profile {
    /// Hardware approval key (button + Ed25519 signature). Radio off.
    Approver,
    /// Out-of-band serial console and watchdog for the gateway.
    Oob,
    /// Decoy Wi-Fi network; reports who tries to join.
    Honeypot,
    /// Passive Wi-Fi monitoring: deauth floods, evil twins, channel load.
    Sentry,
    /// Wi-Fi channel state information for motion sensing.
    Csi,
}

impl Profile {
    pub const ALL: [Profile; 5] =
        [Profile::Approver, Profile::Oob, Profile::Honeypot, Profile::Sentry, Profile::Csi];

    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Approver => "approver",
            Profile::Oob => "oob",
            Profile::Honeypot => "honeypot",
            Profile::Sentry => "sentry",
            Profile::Csi => "csi",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// One byte for flash storage.
    pub fn code(self) -> u8 {
        self as u8 + 1
    }

    pub fn from_code(c: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.code() == c)
    }

    fn bit(self) -> u8 {
        1 << (self as u8)
    }
}

/// A set of profiles, e.g. what a board supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Profiles(pub u8);

impl Profiles {
    pub const fn empty() -> Self {
        Profiles(0)
    }
    pub fn with(self, p: Profile) -> Self {
        Profiles(self.0 | p.bit())
    }
    pub fn contains(self, p: Profile) -> bool {
        self.0 & p.bit() != 0
    }
    pub fn iter(self) -> impl Iterator<Item = Profile> {
        Profile::ALL.into_iter().filter(move |p| self.contains(*p))
    }
}

impl fmt::Display for Profiles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(p.as_str())?;
        }
        Ok(())
    }
}

impl Profiles {
    fn parse(s: &str) -> Option<Self> {
        let mut out = Profiles::empty();
        for name in s.split(',') {
            out = out.with(Profile::parse(name)?);
        }
        (out.0 != 0).then_some(out)
    }
}

/// Severity of a board log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        [Level::Error, Level::Warn, Level::Info].into_iter().find(|l| l.as_str() == s)
    }
}

/// Longest log text a board sends (the rest is cut).
pub const MAX_LOG_TEXT: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMsg {
    Hello,
    Ask {
        id: [u8; ID_LEN],
        digest: [u8; DIGEST_LEN],
        nonce: [u8; NONCE_LEN],
    },
    Cancel,
    Info,
    SetProfile(Profile),
    /// The SSID a sentry board guards (up to 32 bytes).
    Watch {
        ssid: [u8; 32],
        len: u8,
    },
    /// oob: the gateway is alive.
    Heartbeat,
    /// oob: act when no heartbeat came for this long (0 = off).
    Watchdog {
        seconds: u16,
    },
    /// oob: send the last `n` gateway console lines.
    Tail {
        n: u8,
    },
    /// oob: switch the link to raw passthrough to the gateway console.
    Console,
    /// honeypot: the decoy network's name (up to 32 bytes).
    Decoy {
        ssid: [u8; 32],
        len: u8,
    },
}

impl HostMsg {
    pub fn watch(ssid: &[u8]) -> Option<Self> {
        if ssid.is_empty() || ssid.len() > 32 {
            return None;
        }
        let mut b = [0u8; 32];
        b[..ssid.len()].copy_from_slice(ssid);
        Some(HostMsg::Watch { ssid: b, len: ssid.len() as u8 })
    }

    pub fn decoy(ssid: &[u8]) -> Option<Self> {
        match Self::watch(ssid)? {
            HostMsg::Watch { ssid, len } => Some(HostMsg::Decoy { ssid, len }),
            _ => None,
        }
    }
}

fn parse_ssid(hex: &str) -> Option<([u8; 32], u8)> {
    let h = hex.as_bytes();
    if h.is_empty() || h.len() > 64 || !h.len().is_multiple_of(2) {
        return None;
    }
    let mut ssid = [0u8; 32];
    for i in 0..h.len() / 2 {
        let pair = core::str::from_utf8(&h[2 * i..2 * i + 2]).ok()?;
        ssid[i] = unhex::<1>(pair)?[0];
    }
    Some((ssid, (h.len() / 2) as u8))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMsg<'a> {
    Key { public_key: [u8; 32], version: &'a str },
    Decide { id: [u8; ID_LEN], approve: bool, signature: [u8; 64] },
    Timeout { id: [u8; ID_LEN] },
    Ok,
    Err(&'a str),
    Info { chip: &'a str, profile: Profile, version: &'a str, supported: Profiles },
    Log { level: Level, text: &'a str },
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (nib(s[2 * i])? << 4) | nib(s[2 * i + 1])?;
    }
    Some(out)
}

/// Splits a line into at most `N` fields; `None` if there are more.
fn fields<const N: usize>(line: &str) -> Option<([&str; N], usize)> {
    let mut out = [""; N];
    let mut n = 0;
    for f in line.trim_end_matches(['\r', '\n']).split(' ') {
        if n == N {
            return None;
        }
        out[n] = f;
        n += 1;
    }
    Some((out, n))
}

impl fmt::Display for HostMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostMsg::Hello => f.write_str("HELLO"),
            HostMsg::Cancel => f.write_str("CANCEL"),
            HostMsg::Info => f.write_str("INFO"),
            HostMsg::SetProfile(p) => write!(f, "PROFILE {}", p.as_str()),
            HostMsg::Watch { ssid, len } => write!(f, "WATCH {}", Hex(&ssid[..*len as usize])),
            HostMsg::Decoy { ssid, len } => write!(f, "DECOY {}", Hex(&ssid[..*len as usize])),
            HostMsg::Heartbeat => f.write_str("HB"),
            HostMsg::Watchdog { seconds } => write!(f, "WATCHDOG {seconds}"),
            HostMsg::Tail { n } => write!(f, "TAIL {n}"),
            HostMsg::Console => f.write_str("CONSOLE"),
            HostMsg::Ask { id, digest, nonce } => {
                write!(f, "ASK {} {} {}", Hex(id), Hex(digest), Hex(nonce))
            }
        }
    }
}

impl HostMsg {
    pub fn parse(line: &str) -> Option<Self> {
        let (f, n) = fields::<4>(line)?;
        match (f[0], n) {
            ("HELLO", 1) => Some(HostMsg::Hello),
            ("CANCEL", 1) => Some(HostMsg::Cancel),
            ("INFO", 1) => Some(HostMsg::Info),
            ("PROFILE", 2) => Some(HostMsg::SetProfile(Profile::parse(f[1])?)),
            ("WATCH", 2) => parse_ssid(f[1]).map(|(ssid, len)| HostMsg::Watch { ssid, len }),
            ("DECOY", 2) => parse_ssid(f[1]).map(|(ssid, len)| HostMsg::Decoy { ssid, len }),
            ("HB", 1) => Some(HostMsg::Heartbeat),
            ("CONSOLE", 1) => Some(HostMsg::Console),
            ("WATCHDOG", 2) => Some(HostMsg::Watchdog { seconds: f[1].parse().ok()? }),
            ("TAIL", 2) => Some(HostMsg::Tail { n: f[1].parse().ok()? }),
            ("ASK", 4) => {
                Some(HostMsg::Ask { id: unhex(f[1])?, digest: unhex(f[2])?, nonce: unhex(f[3])? })
            }
            _ => None,
        }
    }
}

impl fmt::Display for KeyMsg<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyMsg::Key { public_key, version } => write!(f, "KEY {} {version}", Hex(public_key)),
            KeyMsg::Decide { id, approve, signature } => write!(
                f,
                "DECIDE {} {} {}",
                Hex(id),
                if *approve { 'A' } else { 'D' },
                Hex(signature)
            ),
            KeyMsg::Timeout { id } => write!(f, "TIMEOUT {}", Hex(id)),
            KeyMsg::Ok => f.write_str("OK"),
            KeyMsg::Err(e) => write!(f, "ERR {e}"),
            KeyMsg::Log { level, text } => {
                // One line, printable ASCII, bounded.
                write!(f, "LOG {} ", level.as_str())?;
                text.chars()
                    .take(MAX_LOG_TEXT)
                    .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
                    .try_for_each(|c| f.write_char(c))
            }
            KeyMsg::Info { chip, profile, version, supported } => {
                write!(f, "INFO {chip} {} {version} {supported}", profile.as_str())
            }
        }
    }
}

impl<'a> KeyMsg<'a> {
    pub fn parse(line: &'a str) -> Option<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(e) = line.strip_prefix("ERR ") {
            return Some(KeyMsg::Err(e));
        }
        if let Some(rest) = line.strip_prefix("LOG ") {
            let (level, text) = rest.split_once(' ').unwrap_or((rest, ""));
            return Some(KeyMsg::Log { level: Level::parse(level)?, text });
        }
        let (f, n) = fields::<5>(line)?;
        match (f[0], n) {
            ("OK", 1) => Some(KeyMsg::Ok),
            ("INFO", 5) if valid_version(f[1]) && valid_version(f[3]) => Some(KeyMsg::Info {
                chip: f[1],
                profile: Profile::parse(f[2])?,
                version: f[3],
                supported: Profiles::parse(f[4])?,
            }),
            ("KEY", 3) if valid_version(f[2]) => {
                Some(KeyMsg::Key { public_key: unhex(f[1])?, version: f[2] })
            }
            ("TIMEOUT", 2) => Some(KeyMsg::Timeout { id: unhex(f[1])? }),
            ("DECIDE", 4) => Some(KeyMsg::Decide {
                id: unhex(f[1])?,
                approve: match f[2] {
                    "A" => true,
                    "D" => false,
                    _ => return None,
                },
                signature: unhex(f[3])?,
            }),
            _ => None,
        }
    }
}

fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn host_messages_round_trip() {
        let ask = HostMsg::Ask { id: [0xab; 6], digest: [1; 32], nonce: [0xfe; 16] };
        let set = HostMsg::SetProfile(Profile::Oob);
        let watch = HostMsg::watch(b"home-iot").unwrap();
        assert_eq!(watch.to_string(), "WATCH 686f6d652d696f74");
        assert!(HostMsg::watch(&[b'x'; 33]).is_none());
        let more = [
            HostMsg::Heartbeat,
            HostMsg::Console,
            HostMsg::Watchdog { seconds: 180 },
            HostMsg::Tail { n: 50 },
            HostMsg::decoy(b"guest").unwrap(),
        ];
        for m in more {
            assert_eq!(HostMsg::parse(&m.to_string()), Some(m));
        }
        assert!(HostMsg::parse("WATCHDOG -1").is_none() && HostMsg::parse("TAIL 999").is_none());
        for m in [HostMsg::Hello, HostMsg::Cancel, HostMsg::Info, set, watch, ask] {
            assert_eq!(HostMsg::parse(&m.to_string()), Some(m));
        }
        assert!(ask.to_string().len() <= MAX_LINE);
    }

    #[test]
    fn key_messages_round_trip() {
        let msgs = [
            KeyMsg::Key { public_key: [7; 32], version: "0.1.0" },
            KeyMsg::Decide { id: [1; 6], approve: true, signature: [9; 64] },
            KeyMsg::Decide { id: [1; 6], approve: false, signature: [0; 64] },
            KeyMsg::Timeout { id: [2; 6] },
            KeyMsg::Ok,
            KeyMsg::Err("no key"),
            KeyMsg::Log { level: Level::Warn, text: "flash write failed at 0xa000" },
            KeyMsg::Info {
                chip: "esp32s3",
                profile: Profile::Sentry,
                version: "0.2.0",
                supported: Profiles::empty().with(Profile::Approver).with(Profile::Sentry),
            },
        ];
        for m in msgs {
            let s = m.to_string();
            assert!(s.len() <= MAX_LINE, "{s}");
            assert_eq!(KeyMsg::parse(&s), Some(m));
            assert_eq!(KeyMsg::parse(&(s + "\r\n")), Some(m), "line endings are ignored");
        }
    }

    #[test]
    fn rejects_malformed_lines() {
        for bad in [
            "",
            "ASK",
            "ASK abababababab",
            "ASK ABABABABABAB 00 00",
            "HELLO extra",
            "DECIDE 010101010101 X 00",
            "KEY 00 1.0",
            "KEY 0707070707070707070707070707070707070707070707070707070707070707 a;b",
            "PROFILE",
            "PROFILE root",
            "INFO esp32 approver 1.0",
            "INFO esp32 approver 1.0 approver,nope",
            "INFO esp32 nope 1.0 approver",
            "LOG fatal boom",
        ] {
            assert!(HostMsg::parse(bad).is_none() && KeyMsg::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn decision_and_nonce_change_the_message() {
        let a = signing_message(&[1; 6], &[2; 32], &[3; 16], true);
        assert_ne!(a, signing_message(&[1; 6], &[2; 32], &[3; 16], false));
        assert_ne!(a, signing_message(&[1; 6], &[2; 32], &[4; 16], true));
        assert_eq!(&a[..DOMAIN.len()], DOMAIN);
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    fn profile_codes_and_names_round_trip() {
        for p in Profile::ALL {
            assert_eq!(Profile::from_code(p.code()), Some(p));
            assert_eq!(Profile::parse(p.as_str()), Some(p));
        }
        assert_eq!(Profile::from_code(0), None, "erased flash (0x00) is no profile");
        assert_eq!(Profile::from_code(0xff), None, "erased flash (0xff) is no profile");
    }
}

#[cfg(test)]
mod log_tests {
    extern crate std;
    use super::*;
    use std::string::ToString;

    #[test]
    fn log_text_is_one_bounded_printable_line() {
        let long = "x".repeat(500);
        let s = KeyMsg::Log { level: Level::Error, text: &long }.to_string();
        assert_eq!(s.len(), "LOG error ".len() + MAX_LOG_TEXT);
        let s = KeyMsg::Log { level: Level::Info, text: "a\nb\u{7}c" }.to_string();
        assert_eq!(s, "LOG info a?b?c");
    }
}
