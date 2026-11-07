//! rp-privd: the only privileged half of the console API.
//!
//! rp-api (unprivileged) forwards requests over a unix socket. Read requests
//! are answered directly; every change must be a [`Signed`] envelope from a
//! registered admin, verified here — rp-api cannot produce one. Operations are
//! a closed enum: there is no way to pass a command, a path or nftables text.
//!
//! Wire format: 4-byte big-endian length, then JSON. One request per connection.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rp_core::apply::Target;
use rp_core::changeset::{self as cs, CsError, CsStatus};
use rp_core::files::under_root;
use rp_core::runner::Runner;
use rp_policy::admin::{self, Admins, AuthError, NonceStore, Signed};
use rp_policy::pairing::{self, PairError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const SOCKET: &str = "/run/rp/privd.sock";
pub const ADMINS: &str = "/etc/rp/admins.toml";
pub const DEVICE_ID: &str = "/etc/rp/device-id";
pub const PAIRING: &str = "/etc/rp/pairing.toml";
pub const NONCES: &str = "/var/lib/rp/privd/nonces.json";
pub const AUDIT: &str = "/var/lib/rp/privd/audit.jsonl";
/// rp-api's TLS certificate (DER), written by rp-api in its state directory.
pub const API_CERT: &str = "/var/lib/rp-api/tls/cert.der";
pub const MAX_FRAME: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    // Variants are structs (not unit variants) so serde enforces
    // deny_unknown_fields on every operation.
    Info {},
    Capabilities {
        #[serde(default)]
        peer: Option<IpAddr>,
    },
    Status {},
    Config {},
    ListChangesets {},
    GetChangeset {
        id: String,
    },
    ListAdmins {},
    /// Installed release, previous release and update history.
    UpdateStatus {},
    /// MCP client names and capabilities (never token hashes).
    McpClients {},
    Pair {
        name: String,
        public_key: String,
        client_nonce: String,
        proof: String,
    },
    Signed {
        req: Signed,
        /// The client address rp-api saw (only used for lockout checks).
        #[serde(default)]
        peer: Option<IpAddr>,
    },
}

/// What an admin can sign. The payload of a [`Signed`] envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SignedOp {
    Session {},
    CreateChangeset {
        module: String,
        expected_revision: u64,
        patch: Map<String, Value>,
    },
    Preflight {
        id: String,
    },
    Apply {
        id: String,
        #[serde(default)]
        confirm_secs: Option<u32>,
    },
    Confirm {
        id: String,
    },
    Rollback {
        id: String,
    },
    SetSecret {
        name: String,
        value: String,
    },
    Approve {
        action_id: String,
    },
    Deny {
        action_id: String,
    },
    RevokeAdmin {
        admin_id: String,
    },
    OpenPairing {
        valid_minutes: u32,
    },
    McpAddClient {
        name: String,
        capabilities: Vec<String>,
    },
    McpRemoveClient {
        name: String,
    },
    /// Install a signed release (all binaries at once, automatic switch-back).
    InstallUpdate {
        tag: String,
    },
    RollbackUpdate {},
    /// Remove every module (api last) and forget all admins.
    /// `confirm_device_id` must repeat this device's id.
    Uninstall {
        confirm_device_id: String,
    },
}

impl SignedOp {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Session {} => "session",
            Self::CreateChangeset { .. } => "create_changeset",
            Self::Preflight { .. } => "preflight",
            Self::Apply { .. } => "apply",
            Self::Confirm { .. } => "confirm",
            Self::Rollback { .. } => "rollback",
            Self::SetSecret { .. } => "set_secret",
            Self::Approve { .. } => "approve",
            Self::Deny { .. } => "deny",
            Self::RevokeAdmin { .. } => "revoke_admin",
            Self::OpenPairing { .. } => "open_pairing",
            Self::McpAddClient { .. } => "mcp_add_client",
            Self::McpRemoveClient { .. } => "mcp_remove_client",
            Self::InstallUpdate { .. } => "install_update",
            Self::RollbackUpdate {} => "rollback_update",
            Self::Uninstall { .. } => "uninstall",
        }
    }

    /// Arguments recorded in the audit log (secret values never are).
    fn audit_args(&self) -> Value {
        match self {
            Self::SetSecret { name, .. } => json!({ "name": name }),
            other => {
                let mut v = serde_json::to_value(other).unwrap_or(Value::Null);
                if let Some(o) = v.as_object_mut() {
                    o.remove("op");
                }
                v
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn ok(result: Value) -> Self {
        Self { ok: true, result, error: None }
    }
    pub fn err(code: &str, message: impl Into<String>) -> Self {
        Self::err_with(code, message, Value::Null)
    }
    pub fn err_with(code: &str, message: impl Into<String>, details: Value) -> Self {
        Self {
            ok: false,
            result: Value::Null,
            error: Some(ErrorBody { code: code.into(), message: message.into(), details }),
        }
    }
}

fn cs_err(e: CsError) -> Response {
    match e {
        CsError::Busy => Response::err("busy", e.to_string()),
        CsError::Conflict { current } => {
            Response::err_with("conflict", e.to_string(), json!({ "current_revision": current }))
        }
        CsError::NotFound(_) => Response::err("not_found", e.to_string()),
        CsError::UnknownModule(_) | CsError::Patch(_) => Response::err("invalid", e.to_string()),
        CsError::Invalid(ref v) => {
            Response::err_with("invalid", e.to_string(), json!({ "errors": v.clone() }))
        }
        CsError::State(..) => Response::err("state", e.to_string()),
        CsError::Preflight(_) => Response::err("preflight_failed", e.to_string()),
        CsError::Apply(_) | CsError::Io(_) => Response::err("internal", e.to_string()),
    }
}

/// Everything a request needs. `root` is `/` in production, a temp dir in tests.
pub struct Ctx<'a> {
    pub root: PathBuf,
    pub config: PathBuf,
    pub runner: &'a dyn Runner,
    /// argv prefix the rollback timer uses to call rpctl back.
    pub rpctl_argv: Vec<String>,
    pub now: i64,
}

impl Ctx<'_> {
    fn p(&self, path: &str) -> PathBuf {
        under_root(&self.root, path)
    }
    fn target(&self) -> Target<'_> {
        Target { root: self.root.clone(), runner: self.runner }
    }
}

/// This device's id; created (16 random bytes, hex) on first use.
pub fn device_id(root: &Path) -> std::io::Result<String> {
    let p = under_root(root, DEVICE_ID);
    if let Ok(s) = std::fs::read_to_string(&p) {
        let s = s.trim().to_string();
        if s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(s);
        }
    }
    let id = pairing::new_secret()[..32].to_string();
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&p, format!("{id}\n"))?;
    Ok(id)
}

pub fn cert_sha256(root: &Path) -> Option<String> {
    std::fs::read(under_root(root, API_CERT)).ok().map(|d| hex::encode(Sha256::digest(d)))
}

fn audit(ctx: &Ctx, who: &str, op: &str, args: &Value, outcome: &str) {
    if let Ok(a) = rp_policy::audit::Audit::open(&ctx.p(AUDIT)) {
        let _ = a.record(who, op, args, outcome, "console");
    }
}

/// Handle one request.
pub fn handle(ctx: &Ctx, req: Request) -> Response {
    let dev = match device_id(&ctx.root) {
        Ok(d) => d,
        Err(e) => return Response::err("internal", format!("device id: {e}")),
    };
    let t = ctx.target();
    match req {
        Request::Info {} => {
            let admins = Admins::load(&ctx.p(ADMINS)).unwrap_or_default();
            Response::ok(json!({
                "device_id": dev,
                "version": env!("CARGO_PKG_VERSION"),
                "paired": admins.active().next().is_some(),
                "pairing_open": ctx.p(PAIRING).exists(),
                "cert_sha256": cert_sha256(&ctx.root),
            }))
        }
        Request::Capabilities { peer } => {
            let cfg = rp_core::config::load(&ctx.config).ok();
            let hw = rp_core::capabilities::gather(&t, cfg.as_ref(), peer);
            Response::ok(serde_json::to_value(rp_core::capabilities::evaluate(&hw)).unwrap())
        }
        Request::Status {} => {
            let cfg = rp_core::config::load(&ctx.config).ok();
            let state = t.load_state();
            let modules: Map<String, Value> = rp_core::module::MODULES
                .iter()
                .map(|m| {
                    let st = state.modules.get(*m);
                    let configured = rp_core::module::lookup(m)
                        .zip(cfg.as_ref())
                        .is_some_and(|(md, c)| md.enabled(c).is_ok());
                    (
                        m.to_string(),
                        json!({
                            "configured": configured,
                            "applied": st.is_some_and(|s| !s.rolled_back),
                            "confirmed": st.is_some_and(|s| s.confirmed && !s.rolled_back),
                        }),
                    )
                })
                .collect();
            let secrets: Map<String, Value> = rp_core::secrets::NAMES
                .iter()
                .map(|n| {
                    (n.to_string(), json!(rp_core::secrets::is_set(&ctx.root, cfg.as_ref(), n)))
                })
                .collect();
            // The WireGuard server's public key (clients need it in their config).
            let wg_public = std::fs::read_to_string(ctx.p(rp_core::wg::SERVER_KEY_PATH))
                .ok()
                .and_then(|k| rp_core::wg::public_from_private(k.trim()).ok());
            Response::ok(json!({
                "device_id": dev,
                "revision": cs::peek_revision(&t, &ctx.config),
                "config_valid": cfg.is_some(),
                "modules": modules,
                "secrets": secrets,
                "wireguard_public_key": wg_public,
            }))
        }
        Request::Config {} => match rp_core::config::load(&ctx.config) {
            Ok(c) => Response::ok(json!({
                "revision": cs::peek_revision(&t, &ctx.config),
                "config": serde_json::to_value(c).unwrap(),
            })),
            Err(e) => Response::err("invalid", e.to_string()),
        },
        Request::ListChangesets {} => {
            let v: Vec<Value> = cs::list(&t, &ctx.config)
                .into_iter()
                .map(|c| serde_json::to_value(c.public()).unwrap())
                .collect();
            Response::ok(Value::Array(v))
        }
        Request::GetChangeset { id } => match cs::get(&t, &ctx.config, &id) {
            Ok(c) => Response::ok(serde_json::to_value(c.public()).unwrap()),
            Err(e) => cs_err(e),
        },
        Request::ListAdmins {} => {
            let admins = Admins::load(&ctx.p(ADMINS)).unwrap_or_default();
            let v: Vec<Value> = admins
                .active()
                .map(|a| json!({"id": a.id, "name": a.name, "added_at": a.added_at}))
                .collect();
            Response::ok(Value::Array(v))
        }
        Request::UpdateStatus {} => {
            let mut v = serde_json::to_value(rp_core::update::load_state(&t)).unwrap();
            v["live"] = json!(rp_core::update::live_tag(&t));
            v["running_version"] = json!(env!("CARGO_PKG_VERSION"));
            v["signing_key"] = json!(ctx.p(rp_core::update::PUBKEY).exists());
            Response::ok(v)
        }
        Request::McpClients {} => {
            let Ok(c) = rp_core::config::load(&ctx.config) else {
                return Response::err("invalid", "config does not load");
            };
            if c.mcp.is_none() {
                return Response::ok(json!({"configured": false, "clients": []}));
            }
            match rp_agent::admin_ops::load_clients(&c, &ctx.root) {
                Ok(cl) => Response::ok(json!({
                    "configured": true,
                    "clients": cl.clients.iter().map(|x| json!({
                        "name": x.name,
                        "capabilities": x.capabilities.iter().map(|c| c.as_str()).collect::<Vec<_>>(),
                    })).collect::<Vec<_>>(),
                })),
                Err(e) => Response::err("internal", e),
            }
        }
        Request::Pair { name, public_key, client_nonce, proof } => {
            pair(ctx, &dev, &name, &public_key, &client_nonce, &proof)
        }
        Request::Signed { req, peer } => signed(ctx, &dev, &req, peer),
    }
}

fn pair(ctx: &Ctx, dev: &str, name: &str, pk: &str, nonce: &str, proof: &str) -> Response {
    if admin::decode_key(pk).is_none() {
        return Response::err("invalid", "public_key is not a base64 Ed25519 key");
    }
    if rp_policy::validate::plain_text("name", name, 64).is_err() {
        return Response::err("invalid", "name must be plain text up to 64 characters");
    }
    // Check the certificate first so a missing one does not burn the secret.
    let Some(cert) = cert_sha256(&ctx.root) else {
        return Response::err("internal", "rp-api has no TLS certificate yet");
    };
    let secret = match pairing::redeem(&ctx.p(PAIRING), dev, pk, nonce, proof, ctx.now) {
        Ok(s) => s,
        Err(e) => {
            audit(ctx, "pairing", "pair", &json!({"name": name}), "refused");
            let code = match e {
                PairError::NotOpen => "pairing_closed",
                PairError::Locked => "locked",
                PairError::BadProof => "unauthorized",
                PairError::Malformed(_) => "invalid",
                PairError::Store(_) => "internal",
            };
            return Response::err(code, e.to_string());
        }
    };
    let mut admins = Admins::load(&ctx.p(ADMINS)).unwrap_or_default();
    let a = match admins.add(name, pk, ctx.now) {
        Ok(a) => a,
        Err(e) => return Response::err("invalid", e),
    };
    if let Err(e) = admins.save(&ctx.p(ADMINS)) {
        return Response::err("internal", e.to_string());
    }
    audit(ctx, &format!("admin:{}", a.id), "pair", &json!({"name": name}), "paired");
    let server_proof =
        pairing::hmac_hex(&secret, &pairing::server_message(dev, pk, nonce, &cert, &a.id));
    Response::ok(json!({
        "admin_id": a.id,
        "device_id": dev,
        "cert_sha256": cert,
        "server_proof": server_proof,
    }))
}

fn auth_err(e: AuthError) -> Response {
    let code = match e {
        AuthError::Store(_) => "internal",
        _ => "unauthorized",
    };
    Response::err(code, e.to_string())
}

fn signed(ctx: &Ctx, dev: &str, req: &Signed, peer: Option<IpAddr>) -> Response {
    let admins = match Admins::load(&ctx.p(ADMINS)) {
        Ok(a) => a,
        Err(e) => return Response::err("internal", e),
    };
    let nonces = NonceStore::new(&ctx.p(NONCES));
    let who = match admin::verify(&admins, dev, req, ctx.now, &nonces) {
        Ok(a) => a,
        Err(e) => {
            audit(ctx, &format!("admin:{}", req.admin_id), "signed", &Value::Null, "unauthorized");
            return auth_err(e);
        }
    };
    let op: SignedOp = match serde_json::from_str(&req.payload) {
        Ok(o) => o,
        Err(e) => return Response::err("bad_request", format!("unknown operation: {e}")),
    };
    let principal = format!("admin:{}", who.id);
    let by = format!("admin:{}", who.name);
    let res = run_op(ctx, &op, &who, &by, peer);
    let outcome =
        if res.ok { "ok" } else { res.error.as_ref().map(|e| e.code.as_str()).unwrap_or("error") };
    if !matches!(op, SignedOp::Session {}) {
        audit(ctx, &principal, op.name(), &op.audit_args(), outcome);
    }
    res
}

fn cs_ok(r: Result<cs::ChangeSet, CsError>) -> Response {
    match r {
        Ok(c) => {
            let failed = c.status == CsStatus::Failed;
            let v = serde_json::to_value(c.public()).unwrap();
            if failed {
                Response::err_with("apply_failed", c.error.clone().unwrap_or_default(), v)
            } else {
                Response::ok(v)
            }
        }
        Err(e) => cs_err(e),
    }
}

fn run_op(
    ctx: &Ctx,
    op: &SignedOp,
    who: &admin::Admin,
    by: &str,
    peer: Option<IpAddr>,
) -> Response {
    let t = ctx.target();
    let cfg =
        || rp_core::config::load(&ctx.config).map_err(|e| Response::err("invalid", e.to_string()));
    match op {
        SignedOp::Session {} => Response::ok(json!({"admin_id": who.id, "name": who.name})),
        SignedOp::CreateChangeset { module, expected_revision, patch } => {
            cs_ok(cs::create(&t, &ctx.config, module, *expected_revision, patch.clone(), by))
        }
        SignedOp::Preflight { id } => match cs::preflight(&t, &ctx.config, id, peer) {
            Ok(c) if c.status != CsStatus::Preflighted => Response::err_with(
                "preflight_failed",
                "preflight checks failed",
                serde_json::to_value(c.public()).unwrap(),
            ),
            other => cs_ok(other),
        },
        SignedOp::Apply { id, confirm_secs } => {
            let secs = confirm_secs.unwrap_or(cs::DEFAULT_CONFIRM_SECS).clamp(30, 600);
            cs_ok(cs::apply_cs(
                &t,
                &ctx.config,
                id,
                &cs::CsApplyOptions {
                    confirm_secs: secs,
                    rpctl_argv: ctx.rpctl_argv.clone(),
                    install_packages: true,
                },
            ))
        }
        SignedOp::Confirm { id } => cs_ok(cs::confirm(&t, &ctx.config, id)),
        SignedOp::Rollback { id } => cs_ok(cs::rollback(&t, &ctx.config, id)),
        SignedOp::SetSecret { name, value } => {
            let c = rp_core::config::load(&ctx.config).ok();
            match rp_core::secrets::set(&ctx.root, c.as_ref(), name, value) {
                Ok(fp) => Response::ok(json!({"name": name, "set": true, "fingerprint": fp})),
                Err(e) => Response::err("invalid", e.to_string()),
            }
        }
        SignedOp::Approve { action_id } | SignedOp::Deny { action_id } => {
            let approve = matches!(op, SignedOp::Approve { .. });
            let c = match cfg() {
                Ok(c) => c,
                Err(r) => return r,
            };
            match rp_agent::admin_ops::decide(&c, &ctx.root, action_id, approve, by, ctx.runner) {
                Ok(a) => Response::ok(serde_json::to_value(a).unwrap()),
                Err(e) => Response::err("invalid", e),
            }
        }
        SignedOp::RevokeAdmin { admin_id } => {
            let mut admins = Admins::load(&ctx.p(ADMINS)).unwrap_or_default();
            if !admins.revoke(admin_id) {
                return Response::err("not_found", "no such admin");
            }
            match admins.save(&ctx.p(ADMINS)) {
                Ok(()) => Response::ok(json!({"revoked": admin_id})),
                Err(e) => Response::err("internal", e.to_string()),
            }
        }
        SignedOp::OpenPairing { valid_minutes } => {
            let mins = (*valid_minutes).clamp(1, 60);
            match pairing::open(&ctx.p(PAIRING), ctx.now, Some(i64::from(mins) * 60)) {
                Ok(secret) => Response::ok(json!({
                    "secret": secret,
                    "device_id": device_id(&ctx.root).unwrap_or_default(),
                    "cert_sha256": cert_sha256(&ctx.root),
                    "expires_at": ctx.now + i64::from(mins) * 60,
                })),
                Err(e) => Response::err("internal", e.to_string()),
            }
        }
        SignedOp::McpAddClient { name, capabilities } => {
            let c = match cfg() {
                Ok(c) => c,
                Err(r) => return r,
            };
            match rp_agent::admin_ops::mcp_add_client(&c, &ctx.root, name, capabilities) {
                Ok(token) => {
                    let _ = ctx.runner.run(&[
                        "systemctl".into(),
                        "try-restart".into(),
                        "rp-mcp.service".into(),
                    ]);
                    Response::ok(json!({"name": name, "token": token}))
                }
                Err(e) => Response::err("invalid", e),
            }
        }
        SignedOp::InstallUpdate { tag } => {
            let _lock = match cs::Lock::acquire(&t) {
                Ok(l) => l,
                Err(e) => return cs_err(e),
            };
            let o = rp_core::update::Options {
                tag: tag.clone(),
                base_url: rp_core::update::DEFAULT_BASE.into(),
                target: None,
                config: ctx.config.clone(),
                settle: std::time::Duration::from_secs(if ctx.root == Path::new("/") {
                    5
                } else {
                    0
                }),
                dry_run: false,
            };
            update_result(rp_core::update::install(&t, &o))
        }
        SignedOp::RollbackUpdate {} => {
            let _lock = match cs::Lock::acquire(&t) {
                Ok(l) => l,
                Err(e) => return cs_err(e),
            };
            let settle =
                std::time::Duration::from_secs(if ctx.root == Path::new("/") { 5 } else { 0 });
            update_result(rp_core::update::rollback(&t, settle))
        }
        SignedOp::Uninstall { confirm_device_id } => {
            let dev = device_id(&ctx.root).unwrap_or_default();
            if confirm_device_id != &dev {
                return Response::err("invalid", "confirm_device_id must repeat this device's id");
            }
            let _lock = match cs::Lock::acquire(&t) {
                Ok(l) => l,
                Err(e) => return cs_err(e),
            };
            let state = t.load_state();
            let mut removed = vec![];
            // Everything else first, the console API (our own access) last.
            for m in ["firewall", "ap", "vpn", "dns", "agent", "base", "api"] {
                if state.modules.get(m).is_some_and(|s| !s.rolled_back) {
                    if let Some(module) = rp_core::module::lookup(m) {
                        if rp_core::apply::rollback(module.as_ref(), &t, None).is_ok() {
                            removed.push(m);
                        }
                    }
                }
            }
            let _ = std::fs::remove_file(ctx.p(ADMINS));
            let _ = std::fs::remove_file(ctx.p(PAIRING));
            Response::ok(json!({"removed": removed, "admins_removed": true}))
        }
        SignedOp::McpRemoveClient { name } => {
            let c = match cfg() {
                Ok(c) => c,
                Err(r) => return r,
            };
            match rp_agent::admin_ops::mcp_remove_client(&c, &ctx.root, name) {
                Ok(()) => {
                    let _ = ctx.runner.run(&[
                        "systemctl".into(),
                        "try-restart".into(),
                        "rp-mcp.service".into(),
                    ]);
                    Response::ok(json!({"removed": name}))
                }
                Err(e) => Response::err("not_found", e),
            }
        }
    }
}

fn update_result(r: Result<rp_core::update::Report, rp_core::update::UpdateError>) -> Response {
    use rp_core::update::UpdateError as E;
    match r {
        Ok(rep) => Response::ok(serde_json::to_value(rep).unwrap()),
        Err(e) => {
            let code = match &e {
                E::BadTag(_) => "invalid",
                E::NoKey | E::Signature(_) | E::Checksum(_) | E::Archive(_) => {
                    "verification_failed"
                }
                E::SmokeTest(_) | E::RolledBack(..) => "update_failed",
                E::NoPrevious => "state",
                E::Download(_) => "unavailable",
                E::Io(_) => "internal",
            };
            Response::err(code, e.to_string())
        }
    }
}

// ------------------------------------------------------------- framing ----

pub fn write_frame(w: &mut impl Write, v: &impl Serialize) -> std::io::Result<()> {
    let body = serde_json::to_vec(v)?;
    if body.len() > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    w.write_all(&(body.len() as u32).to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

pub fn read_frame(r: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(body)
}

/// Client side: send one request and read the response (blocking).
#[cfg(unix)]
pub fn call(socket: &Path, req: &Request) -> std::io::Result<Response> {
    let mut s = std::os::unix::net::UnixStream::connect(socket)?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(600)))?;
    write_frame(&mut s, req)?;
    let body = read_frame(&mut s)?;
    serde_json::from_slice(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests;
