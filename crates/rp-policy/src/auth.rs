//! Bearer-token authentication. Only SHA-256 hashes of tokens are stored.

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Capability;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub name: String,
    /// hex SHA-256 of the token.
    pub sha256: String,
    pub capabilities: BTreeSet<Capability>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Clients {
    #[serde(default, rename = "client")]
    pub clients: Vec<Client>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub name: String,
    pub capabilities: BTreeSet<Capability>,
}

impl Principal {
    pub fn can(&self, c: Capability) -> bool {
        self.capabilities.contains(&c)
    }
}

pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Constant-time comparison so token checks don't leak timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A new random token: 32 bytes from the OS RNG, hex encoded, with a prefix
/// that makes accidental leaks easy to grep for.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    format!("rpt_{}", hex::encode(b))
}

impl Clients {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let c: Clients = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        for cl in &c.clients {
            if cl.sha256.len() != 64 || !cl.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(format!("client '{}' has an invalid sha256", cl.name));
            }
        }
        Ok(c)
    }

    pub fn authenticate(&self, token: &str) -> Option<Principal> {
        let h = hash_token(token);
        // Check every entry (no early exit) to keep timing independent of position.
        let mut found = None;
        for c in &self.clients {
            if ct_eq(c.sha256.as_bytes(), h.as_bytes()) && found.is_none() {
                found =
                    Some(Principal { name: c.name.clone(), capabilities: c.capabilities.clone() });
            }
        }
        found
    }

    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_authenticate_by_hash_only() {
        let t = new_token();
        assert!(t.starts_with("rpt_") && t.len() == 68);
        let clients = Clients {
            clients: vec![Client {
                name: "claude".into(),
                sha256: hash_token(&t),
                capabilities: [Capability::Read].into(),
            }],
        };
        let p = clients.authenticate(&t).unwrap();
        assert_eq!(p.name, "claude");
        assert!(p.can(Capability::Read) && !p.can(Capability::Privileged));
        assert!(clients.authenticate("rpt_wrong").is_none());
        assert!(clients.authenticate("").is_none());
        assert!(!clients.to_toml().contains(&t), "token itself is never serialized");
    }

    #[test]
    fn round_trips_and_rejects_bad_hashes() {
        let dir = std::env::temp_dir().join(format!("rp-policy-auth-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("clients.toml");
        std::fs::write(
            &p,
            "[[client]]\nname = \"x\"\nsha256 = \"abc\"\ncapabilities = [\"read\"]\n",
        )
        .unwrap();
        assert!(Clients::load(&p).unwrap_err().contains("invalid sha256"));
        let good = Clients {
            clients: vec![Client {
                name: "y".into(),
                sha256: hash_token("t"),
                capabilities: [Capability::Active].into(),
            }],
        };
        std::fs::write(&p, good.to_toml()).unwrap();
        assert_eq!(Clients::load(&p).unwrap(), good);
    }
}
