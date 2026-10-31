//! Privileged actions wait for a human.
//!
//! A tool call can only *request* a privileged action. The request is stored
//! as `pending` and expires on its own. Approval happens out-of-band, by a
//! person running `rpctl approve <id>` on the device — there is deliberately no
//! API through which the requesting agent could approve its own request.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pending,
    Approved,
    Denied,
    Expired,
    Executed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub created: i64,
    /// Pending requests expire at this time if nobody approves them.
    pub expires: i64,
    pub principal: String,
    pub tool: String,
    pub args: serde_json::Value,
    /// Human-readable description of exactly what approval will do.
    pub summary: String,
    /// How long the change lasts once executed.
    pub ttl_minutes: i64,
    pub status: Status,
    pub decided_by: Option<String>,
    pub result: Option<String>,
    /// When the change was applied (for expiry and restore after reloads).
    #[serde(default)]
    pub executed_at: Option<i64>,
}

impl Action {
    /// Minutes left on an executed change, if it is still in force.
    pub fn remaining_minutes(&self, now: i64) -> Option<i64> {
        let at = self.executed_at?;
        let left = at + self.ttl_minutes * 60 - now;
        (self.status == Status::Executed && left > 0).then(|| (left + 59) / 60)
    }
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn new_id() -> String {
    let mut b = [0u8; 6];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    hex::encode(b)
}

pub struct Store {
    dir: PathBuf,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("no action with id '{0}'")]
    NotFound(String),
    #[error("action '{0}' is {1:?}, not pending")]
    NotPending(String, Status),
    #[error("action '{0}' expired")]
    Expired(String),
    #[error("io: {0}")]
    Io(String),
}

fn valid_id(id: &str) -> bool {
    id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit())
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        Self { dir: dir.to_path_buf() }
    }

    fn path(&self, id: &str) -> Result<PathBuf, StoreError> {
        if !valid_id(id) {
            return Err(StoreError::NotFound(id.into()));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    fn save(&self, a: &Action) -> Result<(), StoreError> {
        std::fs::create_dir_all(&self.dir).map_err(|e| StoreError::Io(e.to_string()))?;
        let p = self.path(&a.id)?;
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(a).unwrap())
            .map_err(|e| StoreError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &p).map_err(|e| StoreError::Io(e.to_string()))
    }

    pub fn request(
        &self,
        principal: &str,
        tool: &str,
        args: serde_json::Value,
        summary: String,
        ttl_minutes: i64,
        pending_minutes: i64,
    ) -> Result<Action, StoreError> {
        let created = now();
        let a = Action {
            id: new_id(),
            created,
            expires: created + pending_minutes * 60,
            principal: principal.into(),
            tool: tool.into(),
            args,
            summary,
            ttl_minutes,
            status: Status::Pending,
            decided_by: None,
            result: None,
            executed_at: None,
        };
        self.save(&a)?;
        Ok(a)
    }

    pub fn get(&self, id: &str) -> Result<Action, StoreError> {
        let text =
            std::fs::read_to_string(self.path(id)?).map_err(|_| StoreError::NotFound(id.into()))?;
        let mut a: Action =
            serde_json::from_str(&text).map_err(|e| StoreError::Io(e.to_string()))?;
        if a.status == Status::Pending && now() > a.expires {
            a.status = Status::Expired;
            self.save(&a)?;
        }
        Ok(a)
    }

    pub fn list(&self) -> Vec<Action> {
        let mut v: Vec<Action> = std::fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let id = name.strip_suffix(".json")?.to_string();
                self.get(&id).ok()
            })
            .collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.created));
        v
    }

    /// Human decision. Only valid for a pending, unexpired action.
    pub fn decide(&self, id: &str, approve: bool, by: &str) -> Result<Action, StoreError> {
        let mut a = self.get(id)?;
        match a.status {
            Status::Pending => {}
            Status::Expired => return Err(StoreError::Expired(id.into())),
            s => return Err(StoreError::NotPending(id.into(), s)),
        }
        a.status = if approve { Status::Approved } else { Status::Denied };
        a.decided_by = Some(by.into());
        self.save(&a)?;
        Ok(a)
    }

    pub fn finish(&self, id: &str, ok: bool, result: &str) -> Result<Action, StoreError> {
        let mut a = self.get(id)?;
        if a.status != Status::Approved {
            return Err(StoreError::NotPending(id.into(), a.status));
        }
        a.status = if ok { Status::Executed } else { Status::Failed };
        a.result = Some(result.into());
        if ok {
            a.executed_at = Some(now());
        }
        self.save(&a)?;
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store(tag: &str) -> Store {
        let d = std::env::temp_dir().join(format!("rp-approvals-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        Store::new(&d)
    }

    #[test]
    fn lifecycle_pending_approved_executed() {
        let s = store("life");
        let a = s
            .request("claude", "block_device", json!({"ip": "x"}), "block x".into(), 60, 15)
            .unwrap();
        assert_eq!(a.status, Status::Pending);
        assert_eq!(s.list().len(), 1);
        let d = s.decide(&a.id, true, "admin").unwrap();
        assert_eq!(d.status, Status::Approved);
        assert_eq!(
            s.decide(&a.id, true, "admin").unwrap_err(),
            StoreError::NotPending(a.id.clone(), Status::Approved)
        );
        let done = s.finish(&a.id, true, "ok").unwrap();
        assert_eq!(done.status, Status::Executed);
        assert_eq!(done.remaining_minutes(now()), Some(60));
        assert_eq!(done.remaining_minutes(now() + 3600), None, "expired after the TTL");
    }

    #[test]
    fn denial_and_expiry() {
        let s = store("exp");
        let a = s.request("p", "t", json!({}), "x".into(), 60, 15).unwrap();
        assert_eq!(s.decide(&a.id, false, "admin").unwrap().status, Status::Denied);
        assert!(s.finish(&a.id, true, "").is_err(), "denied actions never execute");

        let b = s.request("p", "t", json!({}), "x".into(), 60, -1).unwrap();
        assert_eq!(s.get(&b.id).unwrap().status, Status::Expired);
        assert_eq!(s.decide(&b.id, true, "admin").unwrap_err(), StoreError::Expired(b.id.clone()));
    }

    #[test]
    fn ids_cannot_escape_the_store() {
        let s = store("ids");
        assert!(matches!(s.get("../../etc/passwd"), Err(StoreError::NotFound(_))));
        assert!(matches!(s.decide("zzzzzzzzzzzz", true, "a"), Err(StoreError::NotFound(_))));
    }
}
