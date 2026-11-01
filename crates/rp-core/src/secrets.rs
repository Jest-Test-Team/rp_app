//! Named secrets the console can set. Values are validated, written root-only
//! (0600) and never echoed back: callers get a fingerprint at most.

use std::fs;
use std::path::Path;

use rp_schema::Config;
use sha2::{Digest, Sha256};

use crate::files::under_root;

pub const TAILSCALE_KEY_PATH: &str = "/etc/rp/tailscale.key";
pub const AP_PSK_DEFAULT: &str = "/etc/rp/ap.psk";
pub const NAMES: &[&str] = &["ap_passphrase", "tailscale_auth_key"];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretError {
    #[error("unknown secret '{0}'")]
    Unknown(String),
    #[error("{0}")]
    Invalid(&'static str),
    #[error("could not store the secret: {0}")]
    Io(String),
}

/// Path a secret lives at (with the current config).
pub fn path(name: &str, cfg: Option<&Config>) -> Result<String, SecretError> {
    match name {
        "ap_passphrase" => Ok(cfg
            .and_then(|c| c.ap.as_ref())
            .map(|a| a.passphrase_file.clone())
            .unwrap_or_else(|| AP_PSK_DEFAULT.into())),
        "tailscale_auth_key" => Ok(TAILSCALE_KEY_PATH.into()),
        other => Err(SecretError::Unknown(other.into())),
    }
}

/// File content for a secret, after validation.
pub fn content(name: &str, value: &str) -> Result<String, SecretError> {
    match name {
        "ap_passphrase" => {
            if !crate::ap::valid_passphrase(value) {
                return Err(SecretError::Invalid(
                    "passphrase must be 8-63 printable ASCII characters",
                ));
            }
            Ok(crate::ap::psk_file_content(value))
        }
        "tailscale_auth_key" => {
            let ok = value.starts_with("tskey-")
                && value.len() <= 200
                && value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
            if !ok {
                return Err(SecretError::Invalid("not a Tailscale auth key (tskey-...)"));
            }
            Ok(format!("{value}\n"))
        }
        other => Err(SecretError::Unknown(other.into())),
    }
}

/// Short fingerprint for confirming which value is set, without revealing it.
pub fn fingerprint(value: &str) -> String {
    hex::encode(&Sha256::digest(value.as_bytes())[..6])
}

/// Validate and store a secret under `root`. Returns its fingerprint.
pub fn set(
    root: &Path,
    cfg: Option<&Config>,
    name: &str,
    value: &str,
) -> Result<String, SecretError> {
    let text = content(name, value)?;
    let p = under_root(root, &path(name, cfg)?);
    let io = |e: std::io::Error| SecretError::Io(e.to_string());
    if let Some(d) = p.parent() {
        fs::create_dir_all(d).map_err(io)?;
    }
    let tmp = p.with_extension("rp-tmp");
    {
        use std::io::Write;
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(io)?;
        f.write_all(text.as_bytes()).map_err(io)?;
    }
    fs::rename(&tmp, &p).map_err(io)?;
    Ok(fingerprint(value))
}

/// Whether a secret is set (file exists and is non-empty).
pub fn is_set(root: &Path, cfg: Option<&Config>, name: &str) -> bool {
    path(name, cfg)
        .map(|p| fs::metadata(under_root(root, &p)).map(|m| m.len() > 0).unwrap_or(false))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_stores_root_only() {
        let root = std::env::temp_dir().join(format!("rp-secrets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        assert_eq!(set(&root, None, "nope", "x"), Err(SecretError::Unknown("nope".into())));
        assert!(matches!(set(&root, None, "ap_passphrase", "short"), Err(SecretError::Invalid(_))));
        assert!(matches!(
            set(&root, None, "tailscale_auth_key", "tskey-a b"),
            Err(SecretError::Invalid(_))
        ));
        let fp = set(&root, None, "ap_passphrase", "correct horse").unwrap();
        assert_eq!(fp.len(), 12);
        let p = under_root(&root, AP_PSK_DEFAULT);
        assert!(fs::read_to_string(&p).unwrap().ends_with(" correct horse\n"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert!(is_set(&root, None, "ap_passphrase"));
        assert!(!is_set(&root, None, "tailscale_auth_key"));
        set(&root, None, "tailscale_auth_key", "tskey-auth-abc123").unwrap();
        assert!(is_set(&root, None, "tailscale_auth_key"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn fingerprint_does_not_contain_the_value() {
        let f = fingerprint("correct horse");
        assert!(!f.contains("horse"));
        assert_eq!(f, fingerprint("correct horse"));
        assert_ne!(f, fingerprint("correct horsf"));
    }
}
