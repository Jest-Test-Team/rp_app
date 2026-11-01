//! Console admins and signed requests.
//!
//! An admin is an Ed25519 public key registered at pairing. Every change the
//! console makes is a *signed envelope*: the payload (a JSON string) plus a
//! single-use nonce and an expiry, signed together with this device's id.
//! The verifier is rp-privd, so a compromised rp-api cannot forge a change.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Requests may be valid for at most this long.
pub const MAX_VALIDITY_SECS: i64 = 300;
pub const DOMAIN: &str = "rp-admin-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admin {
    pub id: String,
    pub name: String,
    /// Base64 (standard) of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub added_at: i64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Admins {
    #[serde(default, rename = "admin")]
    pub admins: Vec<Admin>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    #[error("unknown or revoked admin")]
    UnknownAdmin,
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("request expired or not yet valid")]
    Expired,
    #[error("bad signature")]
    BadSignature,
    #[error("request was already used")]
    Replay,
    #[error("nonce store error: {0}")]
    Store(String),
}

pub fn decode_key(b64: &str) -> Option<VerifyingKey> {
    let raw = base64::engine::general_purpose::STANDARD.decode(b64.trim()).ok()?;
    VerifyingKey::from_bytes(&raw.try_into().ok()?).ok()
}

/// Admin id: first 8 bytes of SHA-256 of the public key, hex.
pub fn admin_id(public_key_b64: &str) -> String {
    hex::encode(&Sha256::digest(public_key_b64.trim().as_bytes())[..8])
}

impl Admins {
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read_to_string(path) {
            Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_private(path, &toml::to_string(self).expect("serializable"))
    }

    pub fn active(&self) -> impl Iterator<Item = &Admin> {
        self.admins.iter().filter(|a| !a.revoked)
    }

    pub fn get(&self, id: &str) -> Option<&Admin> {
        self.active().find(|a| a.id == id)
    }

    /// Register a key. Re-adding a known key un-revokes it and keeps its id.
    pub fn add(&mut self, name: &str, public_key_b64: &str, now: i64) -> Result<Admin, String> {
        if decode_key(public_key_b64).is_none() {
            return Err("public_key is not a base64 Ed25519 key".into());
        }
        crate::validate::plain_text("name", name, 64).map_err(|e| e.0)?;
        let id = admin_id(public_key_b64);
        if let Some(a) = self.admins.iter_mut().find(|a| a.id == id) {
            a.revoked = false;
            a.name = name.into();
            return Ok(a.clone());
        }
        let a = Admin {
            id,
            name: name.into(),
            public_key: public_key_b64.trim().into(),
            added_at: now,
            revoked: false,
        };
        self.admins.push(a.clone());
        Ok(a)
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        match self.admins.iter_mut().find(|a| a.id == id && !a.revoked) {
            Some(a) => {
                a.revoked = true;
                true
            }
            None => false,
        }
    }
}

/// A signed console request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub admin_id: String,
    /// 16-64 hex characters, never reused.
    pub nonce: String,
    /// Unix seconds; at most MAX_VALIDITY_SECS in the future.
    pub expires_at: i64,
    /// The operation as a JSON string (signed byte for byte).
    pub payload: String,
    /// Base64 Ed25519 signature over `signing_bytes`.
    pub signature: String,
}

/// Exactly what is signed. The device id binds a request to one device.
pub fn signing_bytes(
    device_id: &str,
    admin_id: &str,
    nonce: &str,
    expires_at: i64,
    payload: &str,
) -> Vec<u8> {
    format!("{DOMAIN}\n{device_id}\n{admin_id}\n{nonce}\n{expires_at}\n{payload}").into_bytes()
}

/// Check a signed request. On success the nonce is consumed and the admin returned.
pub fn verify(
    admins: &Admins,
    device_id: &str,
    req: &Signed,
    now: i64,
    nonces: &NonceStore,
) -> Result<Admin, AuthError> {
    let admin = admins.get(&req.admin_id).ok_or(AuthError::UnknownAdmin)?;
    if !(16..=64).contains(&req.nonce.len()) || !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AuthError::Malformed("nonce"));
    }
    if req.expires_at <= now || req.expires_at > now + MAX_VALIDITY_SECS {
        return Err(AuthError::Expired);
    }
    if req.payload.len() > 128 * 1024 {
        return Err(AuthError::Malformed("payload too large"));
    }
    let key = decode_key(&admin.public_key).ok_or(AuthError::UnknownAdmin)?;
    let sig_raw = base64::engine::general_purpose::STANDARD
        .decode(req.signature.trim())
        .map_err(|_| AuthError::Malformed("signature"))?;
    let sig = Signature::from_slice(&sig_raw).map_err(|_| AuthError::Malformed("signature"))?;
    let msg = signing_bytes(device_id, &req.admin_id, &req.nonce, req.expires_at, &req.payload);
    key.verify_strict(&msg, &sig).map_err(|_| AuthError::BadSignature)?;
    // Only a valid signature may consume a nonce (no griefing with garbage).
    nonces.consume(&req.nonce, req.expires_at, now)?;
    Ok(admin.clone())
}

/// Used nonces, kept until they expire. A file because rp-privd exits when idle.
pub struct NonceStore {
    path: std::path::PathBuf,
}

impl NonceStore {
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_path_buf() }
    }

    pub fn consume(&self, nonce: &str, expires_at: i64, now: i64) -> Result<(), AuthError> {
        let err = |e: std::io::Error| AuthError::Store(e.to_string());
        if let Some(d) = self.path.parent() {
            fs::create_dir_all(d).map_err(err)?;
        }
        let lock_path = self.path.with_extension("lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(err)?;
        lock.lock().map_err(err)?;
        let mut seen: BTreeMap<String, i64> = fs::read_to_string(&self.path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        seen.retain(|_, exp| *exp > now);
        if seen.contains_key(nonce) {
            return Err(AuthError::Replay);
        }
        seen.insert(nonce.to_string(), expires_at);
        write_private(&self.path, &serde_json::to_string(&seen).unwrap()).map_err(err)?;
        Ok(())
    }
}

/// Write a root-only file atomically.
pub fn write_private(path: &Path, content: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("rp-tmp");
    {
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(&tmp)?.write_all(content.as_bytes())?;
    }
    fs::rename(&tmp, path)
}

/// Sign a request (used by tests, rp-probe and the fake API server; the app
/// does the same in Dart).
pub fn sign(
    key: &ed25519_dalek::SigningKey,
    device_id: &str,
    nonce: &str,
    expires_at: i64,
    payload: &str,
) -> Signed {
    use ed25519_dalek::Signer;
    let pk = base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes());
    let id = admin_id(&pk);
    let sig = key.sign(&signing_bytes(device_id, &id, nonce, expires_at, payload));
    Signed {
        admin_id: id,
        nonce: nonce.into(),
        expires_at,
        payload: payload.into(),
        signature: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
    }
}

pub fn public_key_b64(key: &ed25519_dalek::SigningKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.verifying_key().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rp-admin-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn setup(tag: &str) -> (Admins, NonceStore, std::path::PathBuf) {
        let mut a = Admins::default();
        a.add("phone", &public_key_b64(&key(1)), 1).unwrap();
        let d = tmp(tag);
        (a, NonceStore::new(&d.join("nonces.json")), d)
    }

    const DEV: &str = "dev0dev0dev0dev0";
    const NOW: i64 = 1_800_000_000;

    #[test]
    fn valid_request_verifies_once() {
        let (a, n, d) = setup("ok");
        let req = sign(&key(1), DEV, "00112233445566778899aabbccddeeff", NOW + 60, r#"{"op":"x"}"#);
        assert_eq!(verify(&a, DEV, &req, NOW, &n).unwrap().name, "phone");
        assert_eq!(verify(&a, DEV, &req, NOW, &n), Err(AuthError::Replay));
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn tampering_wrong_device_or_key_fails() {
        let (a, n, d) = setup("tamper");
        let nonce = "00112233445566778899aabbccddeef0";
        let mut req = sign(&key(1), DEV, nonce, NOW + 60, r#"{"op":"confirm","id":"a"}"#);
        req.payload = r#"{"op":"confirm","id":"b"}"#.into();
        assert_eq!(verify(&a, DEV, &req, NOW, &n), Err(AuthError::BadSignature));
        let req = sign(&key(1), "other-device-id0", nonce, NOW + 60, "{}");
        assert_eq!(verify(&a, DEV, &req, NOW, &n), Err(AuthError::BadSignature));
        // A different key claiming the registered admin's id.
        let mut forged = sign(&key(2), DEV, nonce, NOW + 60, "{}");
        forged.admin_id = admin_id(&public_key_b64(&key(1)));
        assert_eq!(verify(&a, DEV, &forged, NOW, &n), Err(AuthError::BadSignature));
        // An unregistered key.
        let other = sign(&key(2), DEV, nonce, NOW + 60, "{}");
        assert_eq!(verify(&a, DEV, &other, NOW, &n), Err(AuthError::UnknownAdmin));
        // None of the failures consumed the nonce.
        let good = sign(&key(1), DEV, nonce, NOW + 60, "{}");
        assert!(verify(&a, DEV, &good, NOW, &n).is_ok());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn expiry_window_is_enforced() {
        let (a, n, d) = setup("exp");
        let nonce = "00112233445566778899aabbccddee01";
        for exp in [NOW, NOW - 1, NOW + MAX_VALIDITY_SECS + 1] {
            let req = sign(&key(1), DEV, nonce, exp, "{}");
            assert_eq!(verify(&a, DEV, &req, NOW, &n), Err(AuthError::Expired));
        }
        let req = sign(&key(1), DEV, "zz", NOW + 10, "{}");
        assert_eq!(verify(&a, DEV, &req, NOW, &n), Err(AuthError::Malformed("nonce")));
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn revoked_admin_is_refused_and_nonces_expire() {
        let (mut a, n, d) = setup("revoke");
        let id = admin_id(&public_key_b64(&key(1)));
        let r1 = sign(&key(1), DEV, "00112233445566778899aabbccddee02", NOW + 30, "{}");
        verify(&a, DEV, &r1, NOW, &n).unwrap();
        // After expiry the nonce is pruned (it can't verify again anyway: expired).
        let r1b = sign(&key(1), DEV, "00112233445566778899aabbccddee02", NOW + 100, "{}");
        assert!(verify(&a, DEV, &r1b, NOW + 40, &n).is_ok());
        assert!(a.revoke(&id));
        assert!(!a.revoke(&id));
        let r2 = sign(&key(1), DEV, "00112233445566778899aabbccddee03", NOW + 30, "{}");
        assert_eq!(verify(&a, DEV, &r2, NOW, &n), Err(AuthError::UnknownAdmin));
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn admins_file_round_trips_and_rejects_bad_keys() {
        let d = tmp("file");
        let p = d.join("admins.toml");
        let mut a = Admins::load(&p).unwrap();
        assert!(a.add("x", "not-a-key", 1).is_err());
        assert!(a.add("bad\nname", &public_key_b64(&key(3)), 1).is_err());
        let ad = a.add("laptop", &public_key_b64(&key(3)), 5).unwrap();
        a.save(&p).unwrap();
        let b = Admins::load(&p).unwrap();
        assert_eq!(b.get(&ad.id).unwrap().name, "laptop");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let _ = fs::remove_dir_all(d);
    }
}
