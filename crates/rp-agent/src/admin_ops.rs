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

/// Approve (validate again, run, audit) or deny a pending request.
pub fn decide(
    cfg: &Config,
    root: &Path,
    id: &str,
    approve: bool,
    admin: &str,
    runner: &dyn Runner,
) -> Result<Action, String> {
    let store = action_store(cfg, root);
    let audit = audit(cfg, root).map_err(|e| e.to_string())?;
    let pending = store.get(id).map_err(|e| e.to_string())?;
    if !approve {
        let a = store.decide(id, false, admin).map_err(|e| e.to_string())?;
        audit
            .record(admin, &pending.tool, &pending.args, "denied", &format!("id={id}"))
            .map_err(|e| e.to_string())?;
        return Ok(a);
    }
    // The stored request is data: validate it again and build the exact command.
    let argv = crate::actions::command(cfg, &pending.tool, &pending.args)
        .map_err(|e| format!("request no longer valid: {e}"))?;
    let a = store.decide(id, true, admin).map_err(|e| e.to_string())?;
    audit
        .record(admin, &a.tool, &a.args, "approved", &format!("id={id}"))
        .map_err(|e| e.to_string())?;
    let out = runner.run(&argv).map_err(|e| e.to_string())?;
    let ok = out.ok();
    let done = store
        .finish(id, ok, if ok { "applied" } else { out.stderr.trim() })
        .map_err(|e| e.to_string())?;
    audit
        .record(admin, &a.tool, &a.args, if ok { "executed" } else { "error" }, &format!("id={id}"))
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
