//! Admin decisions shared by `rpctl` (a human on the device) and `rp-privd`
//! (a human in the console app, proven by an admin signature): approving or
//! denying privileged requests, and managing MCP clients.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rp_core::files::under_root;
use rp_core::runner::Runner;
use rp_policy::approvals::{Action, Store};
use rp_policy::audit::Audit;
use rp_policy::auth::{hash_token, new_token, Client, Clients};
use rp_policy::Capability;
use rp_schema::Config;

pub fn agent_state(cfg: &Config, root: &Path) -> PathBuf {
    under_root(root, &cfg.agent.clone().unwrap_or_default().state_dir)
}

pub fn action_store(cfg: &Config, root: &Path) -> Store {
    Store::new(&agent_state(cfg, root).join("actions"))
}

pub fn audit(cfg: &Config, root: &Path) -> std::io::Result<Audit> {
    Audit::open(&agent_state(cfg, root).join("audit.jsonl"))
}

/// Approve (validate again, run, audit) or deny a pending request. With
/// `[approver]` configured, an approval also needs the hardware key.
pub fn decide(
    cfg: &Config,
    root: &Path,
    id: &str,
    approve: bool,
    admin: &str,
    runner: &dyn Runner,
) -> Result<Action, String> {
    decide_with(cfg, root, id, approve, admin, runner, &crate::approver::Serial::opener)
}

pub fn decide_with(
    cfg: &Config,
    root: &Path,
    id: &str,
    approve: bool,
    admin: &str,
    runner: &dyn Runner,
    open_key: crate::approver::Opener<'_>,
) -> Result<Action, String> {
    use crate::approver::{Outcome, Proof};

    let store = action_store(cfg, root);
    let audit = audit(cfg, root).map_err(|e| e.to_string())?;
    let pending = store.get(id).map_err(|e| e.to_string())?;
    let deny = |by: &str, detail: String| -> Result<Action, String> {
        let a = store.decide(id, false, by).map_err(|e| e.to_string())?;
        audit
            .record(by, &pending.tool, &pending.args, "denied", &detail)
            .map_err(|e| e.to_string())?;
        Ok(a)
    };
    if !approve {
        return deny(admin, format!("id={id}"));
    }
    // The stored request is data: validate it again and build the exact command.
    let argv = crate::actions::command(cfg, &pending.tool, &pending.args)
        .map_err(|e| format!("request no longer valid: {e}"))?;
    let (by, detail) = match &cfg.approver {
        None => (admin.to_string(), format!("id={id}")),
        Some(h) => match crate::approver::confirm(cfg, h, root, &pending, open_key) {
            Ok(Outcome::Approved(Proof::Key { id: key, name })) => {
                (format!("{admin}+key:{name}"), format!("id={id} hwkey={key}"))
            }
            Ok(Outcome::Approved(Proof::Bypass { until })) => {
                (format!("{admin}+bypass"), format!("id={id} hwkey=bypass until={until}"))
            }
            Ok(Outcome::DeniedOnKey { id: key, name }) => {
                return deny(&format!("{admin}+key:{name}"), format!("id={id} hwkey={key}"));
            }
            Err(e) => {
                audit
                    .record(
                        admin,
                        &pending.tool,
                        &pending.args,
                        "hwkey-failed",
                        &format!("id={id}"),
                    )
                    .map_err(|e| e.to_string())?;
                return Err(e);
            }
        },
    };
    let a = store.decide(id, true, &by).map_err(|e| e.to_string())?;
    audit.record(&by, &a.tool, &a.args, "approved", &detail).map_err(|e| e.to_string())?;
    let out = runner.run(&argv).map_err(|e| e.to_string())?;
    let ok = out.ok();
    let done = store
        .finish(id, ok, if ok { "applied" } else { out.stderr.trim() })
        .map_err(|e| e.to_string())?;
    audit
        .record(&by, &a.tool, &a.args, if ok { "executed" } else { "error" }, &format!("id={id}"))
        .map_err(|e| e.to_string())?;
    if !ok {
        return Err(format!("applying {id} failed: {}", out.stderr.trim()));
    }
    Ok(done)
}

fn clients_path(cfg: &Config, root: &Path) -> Result<PathBuf, String> {
    let m = cfg.mcp.as_ref().ok_or("no [mcp] section in the config")?;
    Ok(under_root(root, &m.clients_file))
}

pub fn load_clients(cfg: &Config, root: &Path) -> Result<Clients, String> {
    let path = clients_path(cfg, root)?;
    if path.exists() && std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) > 0 {
        Clients::load(&path)
    } else {
        Ok(Clients::default())
    }
}

pub fn parse_caps(list: &[String]) -> Result<BTreeSet<Capability>, String> {
    list.iter()
        .map(|c| match c.trim() {
            "read" => Ok(Capability::Read),
            "active" => Ok(Capability::Active),
            "privileged" => Ok(Capability::Privileged),
            other => Err(format!("unknown capability '{other}'")),
        })
        .collect()
}

pub fn valid_client_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Create an MCP client. Returns its token (shown once; only the hash is stored).
pub fn mcp_add_client(
    cfg: &Config,
    root: &Path,
    name: &str,
    caps: &[String],
) -> Result<String, String> {
    if !valid_client_name(name) {
        return Err("client name must be 1-32 letters, digits, '-' or '_'".into());
    }
    let caps = parse_caps(caps)?;
    if caps.is_empty() {
        return Err("give at least one capability".into());
    }
    let mut clients = load_clients(cfg, root)?;
    if clients.clients.iter().any(|c| c.name == name) {
        return Err(format!("client '{name}' exists"));
    }
    let token = new_token();
    clients.clients.push(Client {
        name: name.into(),
        sha256: hash_token(&token),
        capabilities: caps,
    });
    rp_policy::admin::write_private(&clients_path(cfg, root)?, &clients.to_toml())
        .map_err(|e| e.to_string())?;
    Ok(token)
}

pub fn mcp_remove_client(cfg: &Config, root: &Path, name: &str) -> Result<(), String> {
    let mut clients = load_clients(cfg, root)?;
    let before = clients.clients.len();
    clients.clients.retain(|c| c.name != name);
    if clients.clients.len() == before {
        return Err(format!("no client named '{name}'"));
    }
    rp_policy::admin::write_private(&clients_path(cfg, root)?, &clients.to_toml())
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approver::testkey::{Press, SoftKey};
    use crate::approver::KeyLink;
    use rp_core::runner::RecordingRunner;
    use rp_policy::approvals::Status;
    use rp_policy::hwkey::HwKeys;
    use rp_schema::Approver;
    use serde_json::json;

    const BASE: &str = "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n\
        [ap]\nssid = \"x-iot\"\ncountry = \"TW\"\nsubnet = \"198.51.100.128/25\"\n[agent]\n";

    struct Fixture {
        root: PathBuf,
        cfg: Config,
    }

    fn fixture(tag: &str, approver: bool) -> Fixture {
        let root = std::env::temp_dir().join(format!("rp-hwdecide-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let t = format!("{BASE}{}", if approver { "[approver]\n" } else { "" });
        Fixture { root, cfg: rp_core::config::parse(&t).unwrap() }
    }

    impl Fixture {
        fn enroll(&self, seed: u8) {
            let h = self.cfg.approver.clone().unwrap();
            let path = crate::approver::keys_path(&h, &self.root);
            let mut keys = HwKeys::load(&path).unwrap();
            let pk = SoftKey::new(seed, Press::Nothing).sk.verifying_key().to_bytes();
            keys.add(&format!("key{seed}"), &pk, 0).unwrap();
            keys.save(&path).unwrap();
        }

        fn request(&self) -> String {
            action_store(&self.cfg, &self.root)
                .request(
                    "claude",
                    "block_device",
                    json!({"ip": "198.51.100.140", "ttl_minutes": 30, "reason": "test"}),
                    "block".into(),
                    30,
                    15,
                )
                .unwrap()
                .id
        }

        fn decide(&self, id: &str, seed: u8, press: Press) -> (Result<Action, String>, usize) {
            let runner = RecordingRunner::default();
            let open = move |_: &Approver, _: &Path| -> std::io::Result<Box<dyn KeyLink>> {
                Ok(Box::new(SoftKey::new(seed, press)))
            };
            let r = decide_with(&self.cfg, &self.root, id, true, "admin:test", &runner, &open);
            (r, runner.calls().len())
        }

        fn status(&self, id: &str) -> Status {
            action_store(&self.cfg, &self.root).get(id).unwrap().status
        }
    }

    #[test]
    fn without_approver_section_nothing_changes() {
        let f = fixture("none", false);
        let id = f.request();
        let unreachable = |_: &Approver, _: &Path| -> std::io::Result<Box<dyn KeyLink>> {
            panic!("the key must not be contacted")
        };
        let runner = RecordingRunner::default();
        let a = decide_with(&f.cfg, &f.root, &id, true, "admin:t", &runner, &unreachable).unwrap();
        assert_eq!(a.status, Status::Executed);
    }

    #[test]
    fn key_press_approves_and_is_recorded() {
        let f = fixture("ok", true);
        f.enroll(1);
        let id = f.request();
        let (r, calls) = f.decide(&id, 1, Press::Approve);
        let a = r.unwrap();
        assert_eq!(a.status, Status::Executed);
        assert_eq!(a.decided_by.as_deref(), Some("admin:test+key:key1"));
        assert_eq!(calls, 1, "the change ran once");
    }

    #[test]
    fn backup_key_works_too() {
        let f = fixture("backup", true);
        f.enroll(1);
        f.enroll(2);
        let id = f.request();
        assert_eq!(f.decide(&id, 2, Press::Approve).0.unwrap().status, Status::Executed);
    }

    #[test]
    fn refusals_leave_nothing_applied() {
        let f = fixture("refuse", true);
        // No key enrolled yet.
        let id = f.request();
        let (r, calls) = f.decide(&id, 1, Press::Approve);
        assert!(r.unwrap_err().contains("no hardware key"));
        assert_eq!((calls, f.status(&id)), (0, Status::Pending));

        f.enroll(1);
        for press in [Press::Nothing, Press::Replay] {
            let (r, calls) = f.decide(&id, 1, press);
            assert!(r.is_err());
            assert_eq!((calls, f.status(&id)), (0, Status::Pending));
        }
        // A key that is not enrolled.
        let (r, calls) = f.decide(&id, 9, Press::Approve);
        assert!(r.unwrap_err().contains("not an enrolled key"));
        assert_eq!((calls, f.status(&id)), (0, Status::Pending));

        // A short press on the key denies the request for good.
        let (r, calls) = f.decide(&id, 1, Press::Deny);
        assert_eq!((r.unwrap().status, calls), (Status::Denied, 0));
    }

    #[test]
    fn a_board_in_another_profile_cannot_approve() {
        let f = fixture("profile", true);
        f.enroll(1);
        let id = f.request();
        let runner = RecordingRunner::default();
        let open = |_: &Approver, _: &Path| -> std::io::Result<Box<dyn KeyLink>> {
            let mut k = SoftKey::new(1, Press::Approve);
            k.profile = rp_wire::Profile::Sentry;
            Ok(Box::new(k))
        };
        let e = decide_with(&f.cfg, &f.root, &id, true, "admin:t", &runner, &open).unwrap_err();
        assert!(e.contains("sentry profile"), "{e}");
        assert_eq!((runner.calls().len(), f.status(&id)), (0, Status::Pending));
    }

    #[test]
    fn bypass_window_replaces_the_key() {
        let f = fixture("bypass", true);
        let id = f.request();
        let path = crate::approver::bypass_path(&f.cfg, &f.root);
        rp_policy::hwkey::open_bypass(&path, 5, rp_policy::approvals::now()).unwrap();
        let unreachable = |_: &Approver, _: &Path| -> std::io::Result<Box<dyn KeyLink>> {
            Err(std::io::Error::other("unplugged"))
        };
        let runner = RecordingRunner::default();
        let a = decide_with(&f.cfg, &f.root, &id, true, "admin:t", &runner, &unreachable).unwrap();
        assert_eq!(a.decided_by.as_deref(), Some("admin:t+bypass"));

        rp_policy::hwkey::close_bypass(&path);
        let id = f.request();
        let e = decide_with(&f.cfg, &f.root, &id, true, "admin:t", &runner, &unreachable);
        assert!(e.is_err());
    }
}
