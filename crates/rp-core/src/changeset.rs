//! Change sets: typed, revision-checked edits of `rp.toml` that are applied
//! with a device-local rollback timer and kept only once confirmed.
//!
//! Life cycle:
//! `created` → `preflighted` → (`apply`) → `awaiting_confirm` → `confirmed`
//! or → `rolled_back` (timer, or by hand) / `failed`. A change set whose base
//! revision is no longer current is reported as `superseded`.
//!
//! Every mutation — change sets and the classic `rpctl apply/rollback/confirm`
//! — holds one exclusive lock, so the CLI and the app cannot interleave.
//!
//! Only whitelisted keys can be patched (`editable_keys`); device facts and
//! file paths are never editable, and secrets never live in `rp.toml`.

use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rp_schema::Config;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::apply::{self, ApplyOptions, Target, STATE_DIR};
use crate::files::under_root;
use crate::module::{lookup, Module, Step};
use crate::preflight::{self, Check, Status};

pub const CHANGESET_DIR: &str = "/var/lib/rp/changesets";
pub const CONFIG_BACKUP_DIR: &str = "/var/lib/rp/config-backups";
pub const LOCK_PATH: &str = "/var/lib/rp/lock";
/// Seconds the app has to confirm a change before the device undoes it.
pub const DEFAULT_CONFIRM_SECS: u32 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsStatus {
    Created,
    Preflighted,
    Applying,
    AwaitingConfirm,
    Confirmed,
    RolledBack,
    Failed,
    Superseded,
}

impl CsStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Confirmed | Self::RolledBack | Self::Failed | Self::Superseded)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiff {
    pub path: String,
    pub diff: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeSet {
    pub id: String,
    pub module: String,
    pub base_revision: u64,
    pub patch: Map<String, Value>,
    pub status: CsStatus,
    pub created_by: String,
    pub created_at: i64,
    pub updated_at: i64,
    /// Unified diff of rp.toml.
    pub config_diff: String,
    /// Managed files the module would change.
    pub files: Vec<FileDiff>,
    /// Commands apply runs (filled by preflight).
    #[serde(default)]
    pub steps: Vec<String>,
    #[serde(default)]
    pub checks: Vec<Check>,
    /// Post-apply checks on the device.
    #[serde(default)]
    pub verification: Vec<Check>,
    /// Unix time the device rolls back at unless confirmed.
    #[serde(default)]
    pub deadline: Option<i64>,
    #[serde(default)]
    pub applied_revision: Option<u64>,
    #[serde(default)]
    pub backup_id: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    /// The complete new rp.toml (no secrets: rp.toml never holds any).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub new_config: String,
}

impl ChangeSet {
    /// The view handed to API clients (no full config text).
    pub fn public(&self) -> Self {
        Self { new_config: String::new(), ..self.clone() }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CsError {
    #[error("another change is in progress; try again shortly")]
    Busy,
    #[error("the configuration changed (revision {current}); reload and retry")]
    Conflict { current: u64 },
    #[error("unknown change set {0}")]
    NotFound(String),
    #[error("unknown module '{0}'")]
    UnknownModule(String),
    #[error("{0}")]
    Patch(String),
    #[error("invalid configuration: {}", .0.join("; "))]
    Invalid(Vec<String>),
    #[error("change set is {0:?}, expected {1}")]
    State(CsStatus, &'static str),
    #[error("preflight failed: {0}")]
    Preflight(String),
    #[error("{0}")]
    Apply(String),
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for CsError {
    fn from(e: std::io::Error) -> Self {
        CsError::Io(e.to_string())
    }
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn new_id() -> String {
    use rand_core::RngCore;
    let mut b = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn valid_id(id: &str) -> bool {
    id.len() == 16 && id.chars().all(|c| c.is_ascii_hexdigit())
}

// ---------------------------------------------------------------- lock ----

/// Exclusive lock for every configuration change. Released on drop.
pub struct Lock(#[allow(dead_code)] fs::File);

impl Lock {
    pub fn acquire(t: &Target) -> Result<Lock, CsError> {
        let p = t_path(t, LOCK_PATH);
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
        let f = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&p)?;
        match f.try_lock() {
            Ok(()) => Ok(Lock(f)),
            Err(fs::TryLockError::WouldBlock) => Err(CsError::Busy),
            Err(fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }
}

fn t_path(t: &Target, p: &str) -> PathBuf {
    under_root(&t.root, p)
}

// ------------------------------------------------------------ revision ----

#[derive(Debug, Default, Serialize, Deserialize)]
struct RevState {
    revision: u64,
    sha256: String,
}

fn rev_path(t: &Target) -> PathBuf {
    t_path(t, &format!("{STATE_DIR}/revision.json"))
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// The configuration revision. It increases whenever rp.toml's content
/// changes — through a change set or a hand edit.
pub fn revision(t: &Target, config: &Path) -> Result<u64, CsError> {
    let text = fs::read(config).unwrap_or_default();
    let sha = sha_hex(&text);
    let p = rev_path(t);
    let mut st: RevState =
        fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    if st.sha256 != sha {
        st.revision += 1;
        st.sha256 = sha;
        write_file(&p, serde_json::to_string(&st).unwrap().as_bytes(), 0o600)?;
    }
    Ok(st.revision)
}

/// Revision without recording a hand edit (for read-only callers).
pub fn peek_revision(t: &Target, config: &Path) -> u64 {
    let sha = sha_hex(&fs::read(config).unwrap_or_default());
    let st: RevState = fs::read_to_string(rev_path(t))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if st.sha256 == sha {
        st.revision
    } else {
        st.revision + 1
    }
}

fn write_file(p: &Path, content: &[u8], mode: u32) -> Result<(), CsError> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    let tmp = p.with_extension("rp-tmp");
    fs::write(&tmp, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    fs::rename(&tmp, p)?;
    Ok(())
}

// --------------------------------------------------------------- patch ----

/// Kind of value an editable key takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Int,
    Str,
    StrList,
    /// Array of tables (validated by the schema).
    Tables,
    /// Only this exact string (or null).
    Fixed(&'static str),
}

/// Keys the app may change, per module, as dotted paths from the root.
pub fn editable_keys(module: &str) -> &'static [(&'static str, Kind)] {
    use Kind::*;
    match module {
        "base" => &[
            ("base.allow_mdns", Bool),
            ("base.unattended_upgrades", Bool),
            ("base.journal_max_mb", Int),
            ("base.confirm_timeout_secs", Int),
            ("ssh.password_auth", Bool),
            ("ssh.allow_from", StrList),
        ],
        "dns" => &[
            ("dns.upstreams", StrList),
            ("dns.block", StrList),
            ("dns.allow", StrList),
            ("dns.block_response", Str),
            ("dns.block_suspicious", Bool),
            ("dns.suspicious_threshold", Int),
            ("dns.events_retention_days", Int),
            ("dns.rate_limit_qps", Int),
            ("dns.upstream_timeout_ms", Int),
        ],
        "ap" => &[
            ("ap.interface", Str),
            ("ap.ssid", Str),
            ("ap.country", Str),
            ("ap.channel", Int),
            ("ap.subnet", Str),
            ("ap.lease_time", Str),
            ("ap.dns_servers", StrList),
            ("ap.lan_can_reach_clients", Bool),
            ("ap.allow_lan", StrList),
            ("ap.block_dot", Bool),
        ],
        "vpn" => &[
            ("vpn.mode", Str),
            ("vpn.allow_lan", StrList),
            ("vpn.tailscale.hostname", Str),
            ("vpn.tailscale.auth_key_file", Fixed(crate::secrets::TAILSCALE_KEY_PATH)),
            ("vpn.wireguard.endpoint", Str),
            ("vpn.wireguard.listen_port", Int),
            ("vpn.wireguard.subnet", Str),
            ("vpn.wireguard.client_dns", Str),
        ],
        "agent" => &[
            ("agent.scan_allow", StrList),
            ("agent.scan_max_hosts", Int),
            ("agent.pending_minutes", Int),
            ("agent.max_ttl_minutes", Int),
            ("mcp.rate_limit_per_minute", Int),
            ("mcp.stdio_capabilities", StrList),
        ],
        "firewall" => &[("firewall.rules", Tables)],
        "api" => &[("api.allow_tailnet", Bool), ("api.session_minutes", Int)],
        _ => &[],
    }
}

fn to_item(key: &str, kind: Kind, v: &Value) -> Result<toml_edit::Item, String> {
    use toml_edit::{value, Array, ArrayOfTables, Item, Table};
    let bad = || format!("{key}: expected {kind:?}, got {v}");
    Ok(match kind {
        Kind::Bool => value(v.as_bool().ok_or_else(bad)?),
        Kind::Int => value(v.as_i64().ok_or_else(bad)?),
        Kind::Str => value(v.as_str().ok_or_else(bad)?),
        Kind::Fixed(s) => {
            if v.as_str() != Some(s) {
                return Err(format!("{key}: only \"{s}\" is allowed"));
            }
            value(s)
        }
        Kind::StrList => {
            let mut a = Array::new();
            for e in v.as_array().ok_or_else(bad)? {
                a.push(e.as_str().ok_or_else(bad)?);
            }
            value(a)
        }
        Kind::Tables => {
            let mut aot = ArrayOfTables::new();
            for e in v.as_array().ok_or_else(bad)? {
                let obj = e.as_object().ok_or_else(bad)?;
                let mut t = Table::new();
                for (k, x) in obj {
                    let item = match x {
                        Value::Bool(b) => value(*b),
                        Value::Number(n) if n.is_i64() => value(n.as_i64().unwrap()),
                        Value::String(s) => value(s.as_str()),
                        Value::Array(xs) => {
                            let mut a = Array::new();
                            for y in xs {
                                match y {
                                    Value::String(s) => a.push(s.as_str()),
                                    Value::Number(n) if n.is_i64() => a.push(n.as_i64().unwrap()),
                                    _ => return Err(format!("{key}.{k}: unsupported list item")),
                                }
                            }
                            value(a)
                        }
                        _ => return Err(format!("{key}.{k}: unsupported value {x}")),
                    };
                    t.insert(k, item);
                }
                aot.push(t);
            }
            Item::ArrayOfTables(aot)
        }
    })
}

/// Apply `patch` (dotted key → JSON value, null = remove) to config text and
/// validate the result. Returns the new text.
pub fn patch_config(
    text: &str,
    module: &str,
    patch: &Map<String, Value>,
) -> Result<String, CsError> {
    let allowed = editable_keys(module);
    if allowed.is_empty() {
        return Err(CsError::UnknownModule(module.into()));
    }
    if patch.is_empty() {
        return Err(CsError::Patch("empty patch".into()));
    }
    let mut doc: toml_edit::DocumentMut =
        text.parse().map_err(|e| CsError::Patch(format!("rp.toml does not parse: {e}")))?;
    for (key, v) in patch {
        let Some((_, kind)) = allowed.iter().find(|(k, _)| k == key) else {
            return Err(CsError::Patch(format!(
                "'{key}' cannot be changed from the {module} module"
            )));
        };
        let parts: Vec<&str> = key.split('.').collect();
        let (last, tables) = parts.split_last().unwrap();
        let mut table = doc.as_table_mut();
        for p in tables {
            if !table.contains_key(p) {
                if v.is_null() {
                    break;
                }
                let mut t = toml_edit::Table::new();
                t.set_implicit(true);
                table.insert(p, toml_edit::Item::Table(t));
            }
            table = table
                .get_mut(p)
                .and_then(|i| i.as_table_mut())
                .ok_or_else(|| CsError::Patch(format!("{key}: '{p}' is not a table")))?;
        }
        if v.is_null() {
            table.remove(last);
        } else {
            let item = to_item(key, *kind, v).map_err(CsError::Patch)?;
            table.insert(last, item);
        }
    }
    let out = doc.to_string();
    crate::config::parse(&out).map_err(|e| match e {
        crate::config::ConfigError::Invalid(v) => CsError::Invalid(v),
        other => CsError::Invalid(vec![other.to_string()]),
    })?;
    Ok(out)
}

// --------------------------------------------------------------- store ----

fn cs_path(t: &Target, id: &str) -> PathBuf {
    t_path(t, &format!("{CHANGESET_DIR}/{id}.json"))
}

fn save(t: &Target, cs: &ChangeSet) -> Result<(), CsError> {
    write_file(&cs_path(t, &cs.id), serde_json::to_string_pretty(cs).unwrap().as_bytes(), 0o600)
}

pub fn get(t: &Target, config: &Path, id: &str) -> Result<ChangeSet, CsError> {
    if !valid_id(id) {
        return Err(CsError::NotFound(id.into()));
    }
    let text = fs::read_to_string(cs_path(t, id)).map_err(|_| CsError::NotFound(id.into()))?;
    let mut cs: ChangeSet =
        serde_json::from_str(&text).map_err(|e| CsError::Io(format!("corrupt change set: {e}")))?;
    if matches!(cs.status, CsStatus::Created | CsStatus::Preflighted)
        && cs.base_revision != peek_revision(t, config)
    {
        cs.status = CsStatus::Superseded;
    }
    Ok(cs)
}

pub fn list(t: &Target, config: &Path) -> Vec<ChangeSet> {
    let mut out: Vec<ChangeSet> = fs::read_dir(t_path(t, CHANGESET_DIR))
        .map(|rd| {
            rd.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter_map(|n| n.strip_suffix(".json").map(str::to_string))
                .filter_map(|id| get(t, config, &id).ok())
                .collect()
        })
        .unwrap_or_default();
    out.sort_by_key(|c| std::cmp::Reverse(c.created_at));
    out
}

fn module_for(name: &str) -> Result<Box<dyn Module>, CsError> {
    lookup(name).ok_or_else(|| CsError::UnknownModule(name.into()))
}

fn diff(path: &str, old: &str, new: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(2)
        .header(&format!("a{path}"), &format!("b{path}"))
        .to_string()
}

/// Create a change set: validate the patch against the current revision.
pub fn create(
    t: &Target,
    config: &Path,
    module: &str,
    expected_revision: u64,
    patch: Map<String, Value>,
    by: &str,
) -> Result<ChangeSet, CsError> {
    let _lock = Lock::acquire(t)?;
    let m = module_for(module)?;
    let current = revision(t, config)?;
    if expected_revision != current {
        return Err(CsError::Conflict { current });
    }
    let old = fs::read_to_string(config)?;
    let new = patch_config(&old, module, &patch)?;
    let cfg = crate::config::parse(&new).map_err(|e| CsError::Invalid(vec![e.to_string()]))?;
    m.enabled(&cfg).map_err(|e| CsError::Invalid(vec![e]))?;
    let files = apply::plan(m.as_ref(), &cfg, t)
        .into_iter()
        .map(|c| FileDiff { path: c.path, diff: c.diff })
        .collect();
    let ts = now();
    let cs = ChangeSet {
        id: new_id(),
        module: module.into(),
        base_revision: current,
        patch,
        status: CsStatus::Created,
        created_by: by.into(),
        created_at: ts,
        updated_at: ts,
        config_diff: diff(&config.display().to_string(), &old, &new),
        files,
        steps: vec![],
        checks: vec![],
        verification: vec![],
        deadline: None,
        applied_revision: None,
        backup_id: None,
        error: None,
        new_config: new,
    };
    save(t, &cs)?;
    Ok(cs)
}

/// Networks the management API (and so the app) is reachable from.
pub fn mgmt_networks(cfg: &Config) -> Vec<ipnet::IpNet> {
    let mut n = cfg.device.lan_cidrs.clone();
    if cfg.api.as_ref().is_some_and(|a| a.allow_tailnet) {
        n.push(crate::vpn::TS_V4.parse().unwrap());
        n.push(crate::vpn::TS_V6.parse().unwrap());
    }
    n
}

/// Checks the new config must pass on this device. `peer` is the management
/// client; the change must not cut it off.
pub fn preflight(
    t: &Target,
    config: &Path,
    id: &str,
    peer: Option<IpAddr>,
) -> Result<ChangeSet, CsError> {
    let _lock = Lock::acquire(t)?;
    let mut cs = get(t, config, id)?;
    if cs.status == CsStatus::Superseded {
        return Err(CsError::Conflict { current: peek_revision(t, config) });
    }
    if !matches!(cs.status, CsStatus::Created | CsStatus::Preflighted) {
        return Err(CsError::State(cs.status, "created"));
    }
    let cfg =
        crate::config::parse(&cs.new_config).map_err(|e| CsError::Invalid(vec![e.to_string()]))?;
    let m = module_for(&cs.module)?;
    let facts = preflight::gather(&cfg, t);
    let mut checks = preflight::evaluate(&cfg, &cs.module, &facts, false);

    let hw = crate::capabilities::gather(t, Some(&cfg), peer);
    let caps = crate::capabilities::evaluate(&hw);
    if let Some(c) = caps.modules.get(&cs.module) {
        checks.push(if c.available {
            Check::new("capability", Status::Pass, "hardware supports this module")
        } else {
            let r: Vec<String> = c
                .reasons
                .iter()
                .map(|r| serde_json::to_value(r).unwrap().as_str().unwrap_or("").to_string())
                .collect();
            Check::new("capability", Status::Fail, format!("not supported here: {}", r.join(", ")))
        });
    }
    if let Some(p) = peer {
        let ok = mgmt_networks(&cfg).iter().any(|n| n.contains(&p));
        checks.push(if ok {
            Check::new("api_lockout", Status::Pass, "the app stays inside the allowed networks")
        } else {
            Check::new(
                "api_lockout",
                Status::Fail,
                "the app's address is outside the networks allowed to manage this device",
            )
        });
    }
    let dry = apply::apply(
        m.as_ref(),
        &cfg,
        t,
        &ApplyOptions { dry_run: true, install_packages: true, ..ApplyOptions::default() },
    )
    .map_err(|e| CsError::Apply(e.to_string()))?;
    cs.steps = dry.steps;
    cs.checks = checks;
    cs.updated_at = now();
    cs.status =
        if preflight::passed(&cs.checks) { CsStatus::Preflighted } else { CsStatus::Created };
    save(t, &cs)?;
    Ok(cs)
}

/// On-device checks run right after apply. Failure rolls back immediately.
pub fn verify_steps(module: &str, cfg: &Config) -> Vec<(&'static str, Step)> {
    let active = |unit: &str| Step::cmd(&["systemctl", "is-active", "--quiet", unit]);
    let mut v = vec![("firewall_loaded", Step::cmd(&["nft", "list", "table", "inet", "rp"]))];
    match module {
        "dns" => v.push(("rp_dns_active", active("rp-dns.service"))),
        "ap" => {
            v.push(("hostapd_active", active("rp-ap-hostapd.service")));
            v.push(("dnsmasq_active", active("rp-ap-dnsmasq.service")));
        }
        "vpn" => match cfg.vpn.as_ref().map(|v| v.mode) {
            Some(rp_schema::VpnMode::Wireguard) => {
                let i = cfg.vpn.as_ref().unwrap().wireguard.interface.clone();
                v.push(("wireguard_up", Step::cmd(&["ip", "link", "show", "dev", &i])));
            }
            _ => v.push(("tailscaled_active", active("tailscaled.service"))),
        },
        "agent" => v.push(("rp_agent_active", active("rp-agent.service"))),
        "api" => v.push(("rp_api_active", active("rp-api.socket"))),
        _ => {}
    }
    v
}

fn verify(t: &Target, module: &str, cfg: &Config) -> Vec<Check> {
    let mut out = Vec::new();
    let mgmt = cfg.device.mgmt_if();
    let carrier = fs::read_to_string(t_path(t, &format!("/sys/class/net/{mgmt}/carrier")))
        .map(|c| c.trim() == "1")
        .unwrap_or(false);
    out.push(if carrier {
        Check::new("mgmt_carrier", Status::Pass, format!("{mgmt} still has carrier"))
    } else {
        Check::new("mgmt_carrier", Status::Fail, format!("{mgmt} lost carrier"))
    });
    for (name, step) in verify_steps(module, cfg) {
        let ok = t.runner.run(&step.argv).map(|o| o.ok()).unwrap_or(false);
        out.push(Check::new(name, if ok { Status::Pass } else { Status::Fail }, step.display()));
    }
    out
}

fn restore_config(t: &Target, config: &Path, id: &str) -> Result<(), CsError> {
    let b = t_path(t, &format!("{CONFIG_BACKUP_DIR}/{id}.toml"));
    let old = fs::read(&b)?;
    write_file(config, &old, config_mode(config))
}

fn config_mode(config: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(config).map(|m| m.permissions().mode() & 0o7777).unwrap_or(0o644)
    }
    #[cfg(not(unix))]
    {
        let _ = config;
        0o644
    }
}

#[derive(Debug, Clone)]
pub struct CsApplyOptions {
    /// Seconds before the device rolls back by itself.
    pub confirm_secs: u32,
    /// argv prefix the rollback timer uses to call rpctl back.
    pub rpctl_argv: Vec<String>,
    pub install_packages: bool,
}

impl Default for CsApplyOptions {
    fn default() -> Self {
        Self {
            confirm_secs: DEFAULT_CONFIRM_SECS,
            rpctl_argv: vec!["/usr/local/bin/rpctl".into()],
            install_packages: true,
        }
    }
}

fn timer_unit(id: &str) -> String {
    format!("rp-changeset-{id}")
}

/// Apply a preflighted change set and arm the rollback timer.
pub fn apply_cs(
    t: &Target,
    config: &Path,
    id: &str,
    opts: &CsApplyOptions,
) -> Result<ChangeSet, CsError> {
    let _lock = Lock::acquire(t)?;
    let mut cs = get(t, config, id)?;
    if cs.status == CsStatus::Superseded {
        return Err(CsError::Conflict { current: peek_revision(t, config) });
    }
    if cs.status != CsStatus::Preflighted {
        return Err(CsError::State(cs.status, "preflighted"));
    }
    if list(t, config).iter().any(|o| {
        o.id != cs.id && matches!(o.status, CsStatus::Applying | CsStatus::AwaitingConfirm)
    }) {
        return Err(CsError::Busy);
    }
    let current = revision(t, config)?;
    if current != cs.base_revision {
        return Err(CsError::Conflict { current });
    }
    let cfg =
        crate::config::parse(&cs.new_config).map_err(|e| CsError::Invalid(vec![e.to_string()]))?;
    let m = module_for(&cs.module)?;

    let old = fs::read(config)?;
    write_file(&t_path(t, &format!("{CONFIG_BACKUP_DIR}/{}.toml", cs.id)), &old, 0o600)?;
    write_file(config, cs.new_config.as_bytes(), config_mode(config))?;
    cs.status = CsStatus::Applying;
    cs.updated_at = now();
    save(t, &cs)?;

    let res = apply::apply(
        m.as_ref(),
        &cfg,
        t,
        &ApplyOptions {
            dry_run: false,
            install_packages: opts.install_packages,
            dead_man_secs: None,
            rpctl_argv: vec![],
        },
    );
    let report = match res {
        Ok(r) => r,
        Err(e) => {
            let _ = restore_config(t, config, &cs.id);
            cs.status = CsStatus::Failed;
            cs.error = Some(e.to_string());
            cs.updated_at = now();
            revision(t, config)?;
            save(t, &cs)?;
            return Err(CsError::Apply(e.to_string()));
        }
    };
    cs.backup_id = report.backup_id.clone();
    cs.verification = verify(t, &cs.module, &cfg);
    if !preflight::passed(&cs.verification) {
        let detail = undo(t, config, &cs, m.as_ref());
        cs.status = CsStatus::Failed;
        cs.error = Some(format!("post-apply checks failed; rolled back{detail}"));
        cs.updated_at = now();
        revision(t, config)?;
        save(t, &cs)?;
        return Ok(cs);
    }

    let unit = timer_unit(&cs.id);
    let mut argv: Vec<String> = vec![
        "systemd-run".into(),
        format!("--unit={unit}"),
        format!("--on-active={}", opts.confirm_secs),
        "--timer-property=AccuracySec=1s".into(),
    ];
    argv.extend(opts.rpctl_argv.iter().cloned());
    argv.extend(["changeset".into(), "expire".into(), cs.id.clone()]);
    let timer_ok = t.runner.run(&argv).map(|o| o.ok()).unwrap_or(false);
    if !timer_ok {
        // Without a safety net the change must not stay.
        let detail = undo(t, config, &cs, m.as_ref());
        cs.status = CsStatus::Failed;
        cs.error = Some(format!("could not arm the rollback timer; rolled back{detail}"));
        cs.updated_at = now();
        revision(t, config)?;
        save(t, &cs)?;
        return Ok(cs);
    }
    cs.applied_revision = Some(revision(t, config)?);
    cs.deadline = Some(now() + i64::from(opts.confirm_secs));
    cs.status = CsStatus::AwaitingConfirm;
    cs.updated_at = now();
    save(t, &cs)?;
    Ok(cs)
}

/// Undo an applied change set's files and config. Returns a note on failure.
fn undo(t: &Target, config: &Path, cs: &ChangeSet, m: &dyn Module) -> String {
    let mut note = String::new();
    if let Some(b) = &cs.backup_id {
        if let Err(e) = apply::rollback(m, t, Some(b)) {
            note = format!(" (file rollback error: {e})");
        }
    }
    if let Err(e) = restore_config(t, config, &cs.id) {
        note.push_str(&format!(" (config restore error: {e})"));
    }
    note
}

/// Keep an applied change: cancel the timer.
pub fn confirm(t: &Target, config: &Path, id: &str) -> Result<ChangeSet, CsError> {
    let _lock = Lock::acquire(t)?;
    let mut cs = get(t, config, id)?;
    if cs.status != CsStatus::AwaitingConfirm {
        return Err(CsError::State(cs.status, "awaiting_confirm"));
    }
    let unit = format!("{}.timer", timer_unit(&cs.id));
    let _ = t.runner.run(&["systemctl".into(), "stop".into(), unit]);
    cs.status = CsStatus::Confirmed;
    cs.deadline = None;
    cs.updated_at = now();
    save(t, &cs)?;
    Ok(cs)
}

/// The timer fired: undo the change if it is still unconfirmed.
pub fn expire(t: &Target, config: &Path, id: &str) -> Result<ChangeSet, CsError> {
    let _lock = Lock::acquire(t)?;
    let mut cs = get(t, config, id)?;
    if cs.status != CsStatus::AwaitingConfirm {
        return Ok(cs);
    }
    let m = module_for(&cs.module)?;
    let note = undo(t, config, &cs, m.as_ref());
    cs.status = CsStatus::RolledBack;
    cs.error = Some(format!("not confirmed in time; rolled back automatically{note}"));
    cs.deadline = None;
    cs.updated_at = now();
    revision(t, config)?;
    save(t, &cs)?;
    Ok(cs)
}

/// Undo an applied change by hand. Only the latest change can be undone.
pub fn rollback(t: &Target, config: &Path, id: &str) -> Result<ChangeSet, CsError> {
    let _lock = Lock::acquire(t)?;
    let mut cs = get(t, config, id)?;
    if !matches!(cs.status, CsStatus::AwaitingConfirm | CsStatus::Confirmed) {
        return Err(CsError::State(cs.status, "awaiting_confirm or confirmed"));
    }
    let current = revision(t, config)?;
    if cs.applied_revision != Some(current) {
        return Err(CsError::Conflict { current });
    }
    let unit = format!("{}.timer", timer_unit(&cs.id));
    let _ = t.runner.run(&["systemctl".into(), "stop".into(), unit]);
    let m = module_for(&cs.module)?;
    let note = undo(t, config, &cs, m.as_ref());
    cs.status = CsStatus::RolledBack;
    cs.error = Some(format!("rolled back by an admin{note}"));
    cs.deadline = None;
    cs.updated_at = now();
    revision(t, config)?;
    save(t, &cs)?;
    Ok(cs)
}
