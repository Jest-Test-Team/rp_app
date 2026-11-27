//! Hardware approval keys.
//!
//! With `[approver]` in the config, approving a privileged action also needs a
//! signature from an enrolled hardware key (an ESP32-S3 running
//! `firmware/approver-s3`), produced only when someone presses its button. The
//! wire format lives in `rp-wire`; this module is the pure part: the key list,
//! the digest of an action, signature checks, and the local bypass window used
//! when every key is lost or broken.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::approvals::Action;

/// Longest bypass a local administrator can open at once.
pub const MAX_BYPASS_MINUTES: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HwKey {
    pub id: String,
    pub name: String,
    /// Hex of the 32-byte Ed25519 public key.
    pub public_key: String,
    pub added_at: i64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HwKeys {
    #[serde(default, rename = "key")]
    pub keys: Vec<HwKey>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum HwError {
    #[error("no hardware key is enrolled (rpctl approver enroll)")]
    NoKeys,
    #[error("signature does not match any enrolled hardware key")]
    BadSignature,
    #[error("the hardware key answered for action {0}, not this one")]
    WrongAction(String),
}

/// Key id: first 8 bytes of SHA-256 of the raw public key, hex.
pub fn key_id(public_key: &[u8; 32]) -> String {
    hex::encode(&Sha256::digest(public_key)[..8])
}

impl HwKeys {
    pub fn load(path: &Path) -> Result<Self, String> {
        match fs::read_to_string(path) {
            Ok(t) => toml::from_str(&t).map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        crate::admin::write_private(path, &toml::to_string(self).expect("serializable"))
    }

    pub fn active(&self) -> impl Iterator<Item = &HwKey> {
        self.keys.iter().filter(|k| !k.revoked)
    }

    /// Enroll a key. Re-enrolling a known key un-revokes it and renames it.
    pub fn add(&mut self, name: &str, public_key: &[u8; 32], now: i64) -> Result<HwKey, String> {
        VerifyingKey::from_bytes(public_key).map_err(|_| "not a valid Ed25519 public key")?;
        crate::validate::plain_text("name", name, 64).map_err(|e| e.0)?;
        let id = key_id(public_key);
        if let Some(k) = self.keys.iter_mut().find(|k| k.id == id) {
            k.revoked = false;
            k.name = name.into();
            return Ok(k.clone());
        }
        let k = HwKey {
            id,
            name: name.into(),
            public_key: hex::encode(public_key),
            added_at: now,
            revoked: false,
        };
        self.keys.push(k.clone());
        Ok(k)
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        match self.keys.iter_mut().find(|k| k.id == id && !k.revoked) {
            Some(k) => {
                k.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Check a key's decision for `action`. Returns the key that signed it.
    pub fn verify(
        &self,
        action: &Action,
        nonce: &[u8; rp_wire::NONCE_LEN],
        answered_id: &[u8; rp_wire::ID_LEN],
        approve: bool,
        signature: &[u8; 64],
    ) -> Result<&HwKey, HwError> {
        if hex::encode(answered_id) != action.id {
            return Err(HwError::WrongAction(hex::encode(answered_id)));
        }
        let mut any = false;
        let msg = rp_wire::signing_message(answered_id, &action_digest(action), nonce, approve);
        let sig = Signature::from_bytes(signature);
        for k in self.active() {
            any = true;
            let Some(vk) = hex::decode(&k.public_key)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            else {
                continue;
            };
            if vk.verify_strict(&msg, &sig).is_ok() {
                return Ok(k);
            }
        }
        Err(if any { HwError::BadSignature } else { HwError::NoKeys })
    }
}

/// Action ids are 12 hex characters (see `approvals`); the key gets the bytes.
pub fn id_bytes(action: &Action) -> Option<[u8; rp_wire::ID_LEN]> {
    hex::decode(&action.id).ok()?.try_into().ok()
}

/// What the key's signature is bound to: every field that decides what
/// approval will do, so a signature for one request cannot approve another.
pub fn action_digest(a: &Action) -> [u8; 32] {
    let body = serde_json::json!({
        "id": a.id,
        "principal": a.principal,
        "tool": a.tool,
        "args": a.args,
        "summary": a.summary,
        "ttl_minutes": a.ttl_minutes,
        "created": a.created,
        "expires": a.expires,
    });
    let mut h = Sha256::new();
    h.update(b"rp-action-v1\0");
    h.update(serde_json::to_vec(&body).expect("serializable"));
    h.finalize().into()
}

/// Open a window during which approvals do not need a hardware key. Only a
/// root user on the device can write this file; every use is audited.
pub fn open_bypass(path: &Path, minutes: i64, now: i64) -> Result<i64, String> {
    if !(1..=MAX_BYPASS_MINUTES).contains(&minutes) {
        return Err(format!("bypass must be 1-{MAX_BYPASS_MINUTES} minutes"));
    }
    let until = now + minutes * 60;
    crate::admin::write_private(path, &until.to_string()).map_err(|e| e.to_string())?;
    Ok(until)
}

pub fn close_bypass(path: &Path) {
    let _ = fs::remove_file(path);
}

/// End of the bypass window, if one is open. A bypass longer than the maximum
/// (a hand-edited file) is ignored.
pub fn bypass_until(path: &Path, now: i64) -> Option<i64> {
    let until: i64 = fs::read_to_string(path).ok()?.trim().parse().ok()?;
    (until > now && until - now <= MAX_BYPASS_MINUTES * 60).then_some(until)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approvals::Status;
    use ed25519_dalek::{Signer, SigningKey};

    fn action() -> Action {
        Action {
            id: "0123456789ab".into(),
            created: 1,
            expires: 1000,
            principal: "claude".into(),
            tool: "block_device".into(),
            args: serde_json::json!({"ip": "10.77.0.5"}),
            summary: "block 10.77.0.5".into(),
            ttl_minutes: 60,
            status: Status::Pending,
            decided_by: None,
            result: None,
            executed_at: None,
        }
    }

    fn sign(sk: &SigningKey, a: &Action, nonce: &[u8; 16], approve: bool) -> [u8; 64] {
        let id = id_bytes(a).unwrap();
        sk.sign(&rp_wire::signing_message(&id, &action_digest(a), nonce, approve)).to_bytes()
    }

    #[test]
    fn accepts_only_the_enrolled_key_for_this_action_and_nonce() {
        let main = SigningKey::from_bytes(&[1; 32]);
        let backup = SigningKey::from_bytes(&[2; 32]);
        let stranger = SigningKey::from_bytes(&[3; 32]);
        let mut keys = HwKeys::default();
        let a = action();
        let id = id_bytes(&a).unwrap();
        let n = [5u8; 16];

        assert_eq!(
            keys.verify(&a, &n, &id, true, &sign(&main, &a, &n, true)),
            Err(HwError::NoKeys)
        );
        keys.add("main", main.verifying_key().as_bytes(), 0).unwrap();
        keys.add("backup", backup.verifying_key().as_bytes(), 0).unwrap();

        assert_eq!(
            keys.verify(&a, &n, &id, true, &sign(&main, &a, &n, true)).unwrap().name,
            "main"
        );
        assert_eq!(
            keys.verify(&a, &n, &id, true, &sign(&backup, &a, &n, true)).unwrap().name,
            "backup"
        );
        let bad = |sig| keys.verify(&a, &n, &id, true, &sig).unwrap_err();
        assert_eq!(bad(sign(&stranger, &a, &n, true)), HwError::BadSignature);
        assert_eq!(bad(sign(&main, &a, &[6; 16], true)), HwError::BadSignature, "old nonce");
        assert_eq!(bad(sign(&main, &a, &n, false)), HwError::BadSignature, "a denial");

        let mut other = action();
        other.args = serde_json::json!({"ip": "10.77.0.6"});
        assert_eq!(bad(sign(&main, &other, &n, true)), HwError::BadSignature, "other args");
        assert!(matches!(
            keys.verify(&a, &n, &[0; 6], true, &sign(&main, &a, &n, true)),
            Err(HwError::WrongAction(_))
        ));

        let main_id = key_id(main.verifying_key().as_bytes());
        assert!(keys.revoke(&main_id));
        assert_eq!(
            keys.verify(&a, &n, &id, true, &sign(&main, &a, &n, true)),
            Err(HwError::BadSignature),
            "revoked"
        );
    }

    #[test]
    fn keys_file_round_trip_and_reenroll() {
        let p = std::env::temp_dir().join(format!("rp-hwkeys-{}.toml", std::process::id()));
        let mut keys = HwKeys::default();
        let pk = *SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes();
        let k = keys.add("main", &pk, 7).unwrap();
        assert!(keys.revoke(&k.id));
        assert_eq!(keys.add("renamed", &pk, 9).unwrap().id, k.id, "same key, same id");
        assert!(keys.add("bad name\n", &[1; 32], 0).is_err());
        keys.save(&p).unwrap();
        let back = HwKeys::load(&p).unwrap();
        assert_eq!(back.keys, keys.keys);
        assert_eq!(back.active().next().unwrap().name, "renamed");
        let _ = fs::remove_file(p);
    }

    #[test]
    fn bypass_window_is_bounded() {
        let p = std::env::temp_dir().join(format!("rp-hwbypass-{}", std::process::id()));
        assert_eq!(bypass_until(&p, 0), None);
        assert!(open_bypass(&p, 0, 0).is_err());
        assert!(open_bypass(&p, MAX_BYPASS_MINUTES + 1, 0).is_err());
        let until = open_bypass(&p, 10, 100).unwrap();
        assert_eq!(bypass_until(&p, 100), Some(until));
        assert_eq!(bypass_until(&p, until), None, "closed at the end");
        fs::write(&p, (100 + 24 * 3600).to_string()).unwrap();
        assert_eq!(bypass_until(&p, 100), None, "hand-edited long bypass is ignored");
        close_bypass(&p);
        assert!(!p.exists());
    }
}
