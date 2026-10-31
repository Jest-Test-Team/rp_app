//! Append-only, hash-chained audit log (JSON Lines).
//!
//! Each entry carries the hash of the previous one, so editing or deleting a
//! line breaks the chain and `verify` reports where.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub ts: i64,
    pub principal: String,
    pub tool: String,
    /// SHA-256 of the canonical JSON arguments (the arguments themselves may be sensitive).
    pub args_sha256: String,
    /// allowed | denied | pending | approved | executed | expired | error
    pub decision: String,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn entry_hash(e: &Entry) -> String {
    let material = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        e.ts, e.principal, e.tool, e.args_sha256, e.decision, e.detail, e.prev
    );
    hex::encode(Sha256::digest(material.as_bytes()))
}

pub fn args_digest(args: &serde_json::Value) -> String {
    // serde_json maps are sorted (BTreeMap) unless preserve_order is enabled,
    // so this serialisation is canonical.
    hex::encode(Sha256::digest(serde_json::to_vec(args).unwrap_or_default()))
}

/// Last entry's hash, read from the end of the file.
fn last_hash(f: &mut std::fs::File) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let len = f.metadata()?.len();
    let start = len.saturating_sub(8192);
    f.seek(SeekFrom::Start(start))?;
    let mut tail = String::new();
    f.read_to_string(&mut tail)?;
    Ok(tail
        .lines()
        .rev()
        .find_map(|l| serde_json::from_str::<Entry>(l).ok())
        .map(|e| e.hash)
        .unwrap_or_else(|| GENESIS.to_string()))
}

/// Writers in different processes (rp-agent, rpctl approve) share one log, so
/// every append takes an exclusive file lock and re-reads the chain head —
/// nothing is cached between appends.
pub struct Audit {
    path: PathBuf,
    local: Mutex<()>,
}

impl Audit {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        Ok(Self { path: path.to_path_buf(), local: Mutex::new(()) })
    }

    pub fn record(
        &self,
        principal: &str,
        tool: &str,
        args: &serde_json::Value,
        decision: &str,
        detail: &str,
    ) -> std::io::Result<Entry> {
        let _guard = self.local.lock().unwrap();
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.lock()?;
        let prev = last_hash(&mut f)?;
        let mut e = Entry {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            principal: principal.into(),
            tool: tool.into(),
            args_sha256: args_digest(args),
            decision: decision.into(),
            detail: detail.chars().take(500).collect(),
            prev,
            hash: String::new(),
        };
        e.hash = entry_hash(&e);
        writeln!(f, "{}", serde_json::to_string(&e).unwrap())?;
        f.sync_data()?;
        f.unlock()?;
        Ok(e)
    }
}

/// Verify the chain. Ok(entries) or Err((line number, reason)).
pub fn verify(path: &Path) -> Result<usize, (usize, String)> {
    let text = std::fs::read_to_string(path).map_err(|e| (0, e.to_string()))?;
    let mut prev = GENESIS.to_string();
    let mut n = 0;
    for (i, line) in text.lines().enumerate() {
        let e: Entry =
            serde_json::from_str(line).map_err(|e| (i + 1, format!("unparseable: {e}")))?;
        if e.prev != prev {
            return Err((i + 1, "chain broken (entry removed or reordered)".into()));
        }
        if entry_hash(&e) != e.hash {
            return Err((i + 1, "entry modified".into()));
        }
        prev = e.hash;
        n += 1;
    }
    Ok(n)
}

pub fn read_recent(path: &Path, limit: usize) -> Vec<Entry> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut v: Vec<Entry> = text.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let skip = v.len().saturating_sub(limit);
    v.drain(..skip);
    v.reverse();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("rp-audit-{tag}-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn chain_verifies_and_survives_reopen() {
        let p = tmp("ok");
        let a = Audit::open(&p).unwrap();
        a.record("claude", "get_system_health", &json!({}), "allowed", "").unwrap();
        a.record("claude", "block_device", &json!({"ip": "x"}), "pending", "id=1").unwrap();
        drop(a);
        let a = Audit::open(&p).unwrap();
        a.record("admin", "block_device", &json!({"ip": "x"}), "approved", "id=1").unwrap();
        assert_eq!(verify(&p), Ok(3));
        let recent = read_recent(&p, 2);
        assert_eq!(recent[0].decision, "approved");
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn tampering_is_detected() {
        let p = tmp("tamper");
        let a = Audit::open(&p).unwrap();
        for i in 0..3 {
            a.record("p", "t", &json!({ "i": i }), "allowed", "").unwrap();
        }
        let text = std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p, text.replacen("\"allowed\"", "\"denied\"", 1)).unwrap();
        assert_eq!(verify(&p).unwrap_err().0, 1);

        let p2 = tmp("delete");
        let a = Audit::open(&p2).unwrap();
        for i in 0..3 {
            a.record("p", "t", &json!({ "i": i }), "allowed", "").unwrap();
        }
        let lines: Vec<String> =
            std::fs::read_to_string(&p2).unwrap().lines().map(String::from).collect();
        std::fs::write(&p2, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert_eq!(verify(&p2).unwrap_err().0, 2);
    }

    #[test]
    fn two_writers_on_one_file_keep_the_chain_intact() {
        let p = tmp("two");
        let a = Audit::open(&p).unwrap();
        let b = Audit::open(&p).unwrap();
        a.record("agent", "t", &json!({}), "pending", "").unwrap();
        b.record("admin", "t", &json!({}), "approved", "").unwrap();
        a.record("agent", "t", &json!({}), "allowed", "").unwrap();
        assert_eq!(verify(&p), Ok(3));
    }

    #[test]
    fn arguments_are_stored_as_digest_only() {
        let p = tmp("digest");
        let a = Audit::open(&p).unwrap();
        a.record("p", "t", &json!({"secret": "hunter2"}), "allowed", "").unwrap();
        assert!(!std::fs::read_to_string(&p).unwrap().contains("hunter2"));
    }
}
