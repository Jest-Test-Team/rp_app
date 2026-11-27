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
//!
//! The key signs [`signing_message`]: a domain tag, the action id, the digest
//! of the action (computed by the gateway), a fresh gateway nonce and the
//! decision. The nonce makes every signature single-use.

#![no_std]

use core::fmt;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostMsg {
    Hello,
    Ask { id: [u8; ID_LEN], digest: [u8; DIGEST_LEN], nonce: [u8; NONCE_LEN] },
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMsg<'a> {
    Key { public_key: [u8; 32], version: &'a str },
    Decide { id: [u8; ID_LEN], approve: bool, signature: [u8; 64] },
    Timeout { id: [u8; ID_LEN] },
    Ok,
    Err(&'a str),
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
        }
    }
}

impl<'a> KeyMsg<'a> {
    pub fn parse(line: &'a str) -> Option<Self> {
        let line = line.trim_end_matches(['\r', '\n']);
        if let Some(e) = line.strip_prefix("ERR ") {
            return Some(KeyMsg::Err(e));
        }
        let (f, n) = fields::<4>(line)?;
        match (f[0], n) {
            ("OK", 1) => Some(KeyMsg::Ok),
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
        for m in [HostMsg::Hello, HostMsg::Cancel, ask] {
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
