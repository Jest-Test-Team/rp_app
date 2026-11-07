//! Pairing a console admin with a one-time secret.
//!
//! The device has no screen, so there is no "open pairing window". A 32-byte
//! secret reaches the app out of band — written to the SD card by the app
//! itself, or shown as a QR code by `sudo rpctl pairing new` — and both sides
//! prove they hold it with HMAC-SHA256:
//!
//! * client proof = HMAC(secret, "rp-pair-v1|client|<device>|<pubkey>|<nonce>")
//! * server proof = HMAC(secret, "rp-pair-v1|server|<device>|<pubkey>|<nonce>|<cert sha256>|<admin id>")
//!
//! The server proof covers the TLS certificate fingerprint, so the app can
//! pin the certificate it actually talks to. A secret works once; five wrong
//! proofs lock pairing for ten minutes.

use std::fs;
use std::path::Path;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub const MAX_FAILURES: u32 = 5;
pub const LOCK_SECS: i64 = 600;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PairingFile {
    /// 64 hex characters.
    #[serde(default)]
    pub secret: String,
    #[serde(default)]
    pub created_at: i64,
    /// 0 = no expiry (a secret written to a fresh SD card).
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub locked_until: i64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PairError {
    #[error("pairing is not open on this device (run: sudo rpctl pairing new)")]
    NotOpen,
    #[error("too many failed attempts; try again later")]
    Locked,
    #[error("wrong pairing code")]
    BadProof,
    #[error("malformed pairing request: {0}")]
    Malformed(&'static str),
    #[error("pairing store error: {0}")]
    Store(String),
}

pub fn client_message(device_id: &str, public_key: &str, nonce: &str) -> String {
    format!("rp-pair-v1|client|{device_id}|{public_key}|{nonce}")
}

pub fn server_message(
    device_id: &str,
    public_key: &str,
    nonce: &str,
    cert: &str,
    admin: &str,
) -> String {
    format!("rp-pair-v1|server|{device_id}|{public_key}|{nonce}|{cert}|{admin}")
}

pub fn hmac_hex(secret: &[u8], msg: &str) -> String {
    let mut m = HmacSha256::new_from_slice(secret).expect("any key length");
    m.update(msg.as_bytes());
    hex::encode(m.finalize().into_bytes())
}

fn hmac_ok(secret: &[u8], msg: &str, proof_hex: &str) -> bool {
    let Ok(proof) = hex::decode(proof_hex) else { return false };
    let mut m = HmacSha256::new_from_slice(secret).expect("any key length");
    m.update(msg.as_bytes());
    m.verify_slice(&proof).is_ok()
}

/// A fresh random secret, hex encoded.
pub fn new_secret() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

pub fn load(path: &Path) -> Option<PairingFile> {
    let t = fs::read_to_string(path).ok()?;
    toml::from_str(&t).ok()
}

pub fn open(path: &Path, now: i64, valid_secs: Option<i64>) -> std::io::Result<String> {
    let secret = new_secret();
    let f = PairingFile {
        secret: secret.clone(),
        created_at: now,
        expires_at: valid_secs.map(|s| now + s).unwrap_or(0),
        failures: 0,
        locked_until: 0,
    };
    crate::admin::write_private(path, &toml::to_string(&f).unwrap())?;
    Ok(secret)
}

/// Verify a client proof. On success the secret is destroyed and returned
/// (to compute the server proof); on failure the attempt is counted.
pub fn redeem(
    path: &Path,
    device_id: &str,
    public_key: &str,
    nonce: &str,
    proof: &str,
    now: i64,
) -> Result<Vec<u8>, PairError> {
    if !(16..=64).contains(&nonce.len()) || !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PairError::Malformed("client_nonce"));
    }
    let store = |e: std::io::Error| PairError::Store(e.to_string());
    let mut f = load(path).ok_or(PairError::NotOpen)?;
    if f.expires_at != 0 && now >= f.expires_at {
        let _ = fs::remove_file(path);
        return Err(PairError::NotOpen);
    }
    if f.locked_until > now {
        return Err(PairError::Locked);
    }
    let secret = hex::decode(&f.secret).map_err(|_| PairError::NotOpen)?;
    if secret.len() != 32 {
        return Err(PairError::NotOpen);
    }
    if !hmac_ok(&secret, &client_message(device_id, public_key, nonce), proof) {
        f.failures += 1;
        if f.failures >= MAX_FAILURES {
            f.failures = 0;
            f.locked_until = now + LOCK_SECS;
        }
        crate::admin::write_private(path, &toml::to_string(&f).unwrap()).map_err(store)?;
        return Err(if f.locked_until > now { PairError::Locked } else { PairError::BadProof });
    }
    fs::remove_file(path).map_err(store)?;
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "dev0dev0dev0dev0";
    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rp-pair-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d.join("pairing.toml")
    }

    #[test]
    fn right_secret_pairs_once() {
        let p = tmp("ok");
        let s = open(&p, 100, Some(600)).unwrap();
        let proof = hmac_hex(&hex::decode(&s).unwrap(), &client_message(DEV, "PK", NONCE));
        let got = redeem(&p, DEV, "PK", NONCE, &proof, 101).unwrap();
        assert_eq!(hex::encode(got), s);
        assert_eq!(redeem(&p, DEV, "PK", NONCE, &proof, 102), Err(PairError::NotOpen));
    }

    #[test]
    fn proof_binds_device_key_and_nonce() {
        let p = tmp("bind");
        let s = hex::decode(open(&p, 100, None).unwrap()).unwrap();
        let proof = hmac_hex(&s, &client_message(DEV, "PK", NONCE));
        assert_eq!(
            redeem(&p, "otherdevice00000", "PK", NONCE, &proof, 101),
            Err(PairError::BadProof)
        );
        assert_eq!(redeem(&p, DEV, "OTHER", NONCE, &proof, 101), Err(PairError::BadProof));
        assert!(redeem(&p, DEV, "PK", NONCE, &proof, 101).is_ok());
    }

    #[test]
    fn repeated_failures_lock_and_expiry_closes() {
        let p = tmp("lock");
        let s = hex::decode(open(&p, 100, Some(1000)).unwrap()).unwrap();
        for i in 0..MAX_FAILURES - 1 {
            assert_eq!(
                redeem(&p, DEV, "PK", NONCE, "00", 101 + i as i64),
                Err(PairError::BadProof)
            );
        }
        assert_eq!(redeem(&p, DEV, "PK", NONCE, "00", 110), Err(PairError::Locked));
        let good = hmac_hex(&s, &client_message(DEV, "PK", NONCE));
        assert_eq!(redeem(&p, DEV, "PK", NONCE, &good, 111), Err(PairError::Locked));
        assert!(redeem(&p, DEV, "PK", NONCE, &good, 110 + LOCK_SECS).is_ok());

        let p = tmp("expire");
        let s = hex::decode(open(&p, 100, Some(60)).unwrap()).unwrap();
        let good = hmac_hex(&s, &client_message(DEV, "PK", NONCE));
        assert_eq!(redeem(&p, DEV, "PK", NONCE, &good, 161), Err(PairError::NotOpen));
        assert!(!p.exists());
    }

    #[test]
    fn malformed_nonce_is_rejected_without_counting() {
        let p = tmp("nonce");
        open(&p, 100, None).unwrap();
        assert_eq!(
            redeem(&p, DEV, "PK", "x", "00", 101),
            Err(PairError::Malformed("client_nonce"))
        );
        assert_eq!(load(&p).unwrap().failures, 0);
    }

    #[test]
    fn server_proof_covers_the_certificate() {
        let s = [7u8; 32];
        let a = hmac_hex(&s, &server_message(DEV, "PK", NONCE, "certA", "id"));
        let b = hmac_hex(&s, &server_message(DEV, "PK", NONCE, "certB", "id"));
        assert_ne!(a, b);
    }
}
