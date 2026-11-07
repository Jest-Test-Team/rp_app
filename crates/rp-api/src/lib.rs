//! rp-api: the console app's HTTPS API. Unprivileged.
//!
//! * Reads need a session (`Authorization: Bearer rps_…`), created by
//!   `POST /v1/session` with an admin-signed envelope.
//! * Changes *are* admin-signed envelopes, forwarded to rp-privd, which
//!   verifies them. rp-api only checks that the signed operation matches the
//!   URL (so a signature for one change set cannot be replayed at another).
//! * Observation data comes from rp-agent (loopback, agent token).
//! * Clients outside the management networks are refused (the firewall
//!   already drops them; this is a second line).

pub mod fake;
pub mod tls;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response as AxResponse};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use rp_policy::admin::Signed;
use rp_policy::ratelimit::Limiter;
use rp_privd::{Request as PReq, Response as PResp};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use utoipa::{OpenApi, ToSchema};

pub const API_VERSION: u32 = 1;
pub const MAX_BODY: usize = 256 * 1024;

/// Talks to rp-privd (the real socket, or an in-process fake device).
pub trait Backend: Send + Sync + 'static {
    fn privd(&self, req: PReq) -> PResp;
}

/// Reads observation data from rp-agent (`/v1/health`, ...).
pub trait Observer: Send + Sync + 'static {
    fn get(&self, path_and_query: &str) -> Result<Value, String>;
}

pub struct SocketBackend(pub std::path::PathBuf);

impl Backend for SocketBackend {
    fn privd(&self, req: PReq) -> PResp {
        rp_privd::call(&self.0, &req)
            .unwrap_or_else(|e| PResp::err("unavailable", format!("rp-privd: {e}")))
    }
}

/// rp-agent over loopback HTTP with its bearer token.
pub struct AgentObserver {
    pub addr: String,
    pub token_file: std::path::PathBuf,
    pub rt: tokio::runtime::Handle,
}

impl Observer for AgentObserver {
    fn get(&self, path: &str) -> Result<Value, String> {
        let token =
            std::fs::read_to_string(&self.token_file).map_err(|e| format!("agent token: {e}"))?;
        let (status, body) = self.rt.block_on(rp_http::request(
            &self.addr,
            "GET",
            path,
            Some(token.trim()),
            None,
        ))?;
        if status == 200 {
            Ok(body)
        } else {
            Err(format!("agent returned {status}"))
        }
    }
}

struct Session {
    admin_id: String,
    name: String,
    expires: Instant,
}

pub struct AppState {
    pub backend: Arc<dyn Backend>,
    pub observer: Arc<dyn Observer>,
    /// Empty = any address (tests).
    pub allowed: Vec<ipnet::IpNet>,
    pub session_minutes: u32,
    sessions: Mutex<HashMap<String, Session>>,
    general: Mutex<Limiter>,
    pairing: Mutex<Limiter>,
    signed: Mutex<Limiter>,
}

impl AppState {
    pub fn new(
        backend: Arc<dyn Backend>,
        observer: Arc<dyn Observer>,
        allowed: Vec<ipnet::IpNet>,
        session_minutes: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            backend,
            observer,
            allowed,
            session_minutes: session_minutes.clamp(1, 1440),
            sessions: Mutex::new(HashMap::new()),
            general: Mutex::new(Limiter::new(600)),
            pairing: Mutex::new(Limiter::new(10)),
            signed: Mutex::new(Limiter::new(120)),
        })
    }
}

type St = State<Arc<AppState>>;

// --------------------------------------------------------------- errors ----

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,
    /// Stable machine-readable code (unauthorized, conflict, preflight_failed, ...).
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Value::is_null")]
    #[schema(value_type = Object)]
    pub details: Value,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &str, message: impl Into<String>) -> Self {
        Self { status, code: code.into(), message: message.into(), details: Value::Null }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> AxResponse {
        let status = self.status;
        let mut r = (status, Json(json!({"error": self}))).into_response();
        r.headers_mut().insert("cache-control", HeaderValue::from_static("no-store"));
        r
    }
}

pub fn status_for(code: &str) -> StatusCode {
    match code {
        "unauthorized" => StatusCode::UNAUTHORIZED,
        "forbidden" | "pairing_closed" => StatusCode::FORBIDDEN,
        "not_found" => StatusCode::NOT_FOUND,
        "conflict" | "busy" | "state" => StatusCode::CONFLICT,
        "invalid" | "bad_request" => StatusCode::BAD_REQUEST,
        "preflight_failed" | "apply_failed" | "verification_failed" | "update_failed" => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        "locked" | "rate_limited" => StatusCode::TOO_MANY_REQUESTS,
        "unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn from_privd(r: PResp) -> ApiResult {
    if r.ok {
        return Ok(Json(r.result));
    }
    let e = r.error.unwrap_or(rp_privd::ErrorBody {
        code: "internal".into(),
        message: "unknown error".into(),
        details: Value::Null,
    });
    Err(ApiError {
        status: status_for(&e.code),
        code: e.code,
        message: e.message,
        details: e.details,
    })
}

async fn privd(st: &AppState, req: PReq) -> PResp {
    let b = st.backend.clone();
    tokio::task::spawn_blocking(move || b.privd(req))
        .await
        .unwrap_or_else(|_| PResp::err("internal", "backend task failed"))
}

async fn observe(st: &AppState, path: String) -> ApiResult {
    let o = st.observer.clone();
    match tokio::task::spawn_blocking(move || o.get(&path)).await {
        Ok(Ok(v)) => Ok(Json(v)),
        Ok(Err(e)) => Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "unavailable", e)),
        Err(_) => Err(ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "task failed")),
    }
}

// ---------------------------------------------------------------- guard ----

fn allowed(st: &AppState, ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    };
    st.allowed.is_empty() || ip.is_loopback() || st.allowed.iter().any(|n| n.contains(&ip))
}

async fn guard(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> AxResponse {
    if !allowed(&st, peer.ip()) {
        return ApiError::new(StatusCode::FORBIDDEN, "forbidden", "not allowed from this network")
            .into_response();
    }
    if !st.general.lock().unwrap().allow(&peer.ip().to_string(), Instant::now()) {
        return ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many requests")
            .into_response();
    }
    let mut r = next.run(req).await;
    let h = r.headers_mut();
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    r
}

fn limit(l: &Mutex<Limiter>, peer: &SocketAddr) -> Result<(), ApiError> {
    if l.lock().unwrap().allow(&peer.ip().to_string(), Instant::now()) {
        Ok(())
    } else {
        Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", "too many requests"))
    }
}

// -------------------------------------------------------------- session ----

/// An authenticated admin session (for reads).
pub struct Authed {
    pub admin_id: String,
    pub name: String,
}

fn token_key(t: &str) -> String {
    hex::encode(Sha256::digest(t.as_bytes()))
}

impl FromRequestParts<Arc<AppState>> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, st: &Arc<AppState>) -> Result<Self, ApiError> {
        let unauth = || {
            ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized", "a valid session is required")
        };
        let tok = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim)
            .ok_or_else(unauth)?;
        let mut s = st.sessions.lock().unwrap();
        let now = Instant::now();
        s.retain(|_, v| v.expires > now);
        let x = s.get(&token_key(tok)).ok_or_else(unauth)?;
        Ok(Authed { admin_id: x.admin_id.clone(), name: x.name.clone() })
    }
}

/// `Json` whose rejections use the API's error format.
pub struct Body<T>(pub T);

impl<T, S> axum::extract::FromRequest<S> for Body<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, st: &S) -> Result<Self, ApiError> {
        match Json::<T>::from_request(req, st).await {
            Ok(Json(v)) => Ok(Body(v)),
            Err(e) => {
                let status = e.status();
                let code = if status == StatusCode::PAYLOAD_TOO_LARGE {
                    "too_large"
                } else {
                    "bad_request"
                };
                Err(ApiError::new(status, code, e.body_text()))
            }
        }
    }
}

// --------------------------------------------------------------- schemas ---

/// An admin-signed request (see the pairing and signing docs).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub admin_id: String,
    /// 16-64 hex characters, never reused.
    pub nonce: String,
    /// Unix seconds, at most 300 s ahead.
    pub expires_at: i64,
    /// The operation, as a JSON string, e.g. `{"op":"confirm","id":"…"}`.
    pub payload: String,
    /// Base64 Ed25519 signature over `rp-admin-v1\n<device>\n<admin>\n<nonce>\n<expires>\n<payload>`.
    pub signature: String,
}

impl From<SignedEnvelope> for Signed {
    fn from(e: SignedEnvelope) -> Self {
        Signed {
            admin_id: e.admin_id,
            nonce: e.nonce,
            expires_at: e.expires_at,
            payload: e.payload,
            signature: e.signature,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PairRequest {
    /// Shown in the admin list, e.g. "Pixel 9".
    pub name: String,
    /// Base64 Ed25519 public key.
    pub public_key: String,
    /// 16-64 hex characters.
    pub client_nonce: String,
    /// Hex HMAC-SHA256(secret, `rp-pair-v1|client|<device>|<public_key>|<client_nonce>`).
    pub proof: String,
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub struct EventsQuery {
    pub since_mins: Option<i64>,
    pub limit: Option<u32>,
    pub action: Option<String>,
}

/// Check the signed operation names what the URL says.
fn expect_op(env: &SignedEnvelope, op: &str, fields: &[(&str, &str)]) -> Result<(), ApiError> {
    let bad = |m: &str| ApiError::new(StatusCode::BAD_REQUEST, "bad_request", m.to_string());
    let v: Value = serde_json::from_str(&env.payload).map_err(|_| bad("payload is not JSON"))?;
    if v.get("op").and_then(Value::as_str) != Some(op) {
        return Err(bad(&format!("signed operation must be '{op}' for this endpoint")));
    }
    for (k, want) in fields {
        if v.get(*k).and_then(Value::as_str) != Some(*want) {
            return Err(bad(&format!("signed '{k}' does not match the URL")));
        }
    }
    Ok(())
}

async fn signed(st: &AppState, peer: SocketAddr, env: SignedEnvelope) -> ApiResult {
    limit(&st.signed, &peer)?;
    from_privd(privd(st, PReq::Signed { req: env.into(), peer: Some(peer.ip()) }).await)
}

// ------------------------------------------------------------- handlers ----

/// Device identity and pairing state. No authentication.
#[utoipa::path(get, path = "/v1/info", tag = "device", responses((status = 200, body = Object)))]
async fn info(State(st): St) -> ApiResult {
    let Json(v) = from_privd(privd(&st, PReq::Info {}).await)?;
    Ok(Json(json!({
        "device_id": v["device_id"],
        "version": v["version"],
        "api_version": API_VERSION,
        "paired": v["paired"],
        "pairing_open": v["pairing_open"],
        "cert_sha256": v["cert_sha256"],
    })))
}

/// Pair this app with a one-time pairing code.
#[utoipa::path(post, path = "/v1/pairing", tag = "pairing", request_body = PairRequest,
    responses((status = 200, body = Object), (status = 401, body = ApiError), (status = 403, body = ApiError), (status = 429, body = ApiError)))]
async fn pair(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(b): Body<PairRequest>,
) -> ApiResult {
    limit(&st.pairing, &peer)?;
    from_privd(
        privd(
            &st,
            PReq::Pair {
                name: b.name,
                public_key: b.public_key,
                client_nonce: b.client_nonce,
                proof: b.proof,
            },
        )
        .await,
    )
}

/// Open a pairing code for another app installation (signed `open_pairing`).
#[utoipa::path(post, path = "/v1/pairing/open", tag = "pairing", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 401, body = ApiError)))]
async fn pairing_open(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "open_pairing", &[])?;
    signed(&st, peer, env).await
}

/// Create a read session from a signed `session` operation.
#[utoipa::path(post, path = "/v1/session", tag = "session", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 401, body = ApiError)))]
async fn session(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "session", &[])?;
    let Json(v) = signed(&st, peer, env).await?;
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    let token = format!("rps_{}", hex::encode(b));
    let mins = st.session_minutes;
    st.sessions.lock().unwrap().insert(
        token_key(&token),
        Session {
            admin_id: v["admin_id"].as_str().unwrap_or_default().into(),
            name: v["name"].as_str().unwrap_or_default().into(),
            expires: Instant::now() + std::time::Duration::from_secs(u64::from(mins) * 60),
        },
    );
    Ok(Json(json!({
        "token": token,
        "expires_in": mins * 60,
        "admin_id": v["admin_id"],
        "name": v["name"],
    })))
}

/// End the current session.
#[utoipa::path(delete, path = "/v1/session", tag = "session", responses((status = 200, body = Object)), security(("session" = [])))]
async fn logout(State(st): St, _a: Authed, parts: axum::http::HeaderMap) -> ApiResult {
    if let Some(t) = parts
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        st.sessions.lock().unwrap().remove(&token_key(t.trim()));
    }
    Ok(Json(json!({"ok": true})))
}

/// Who the session belongs to.
#[utoipa::path(get, path = "/v1/me", tag = "session", responses((status = 200, body = Object)), security(("session" = [])))]
async fn me(a: Authed) -> ApiResult {
    Ok(Json(json!({"admin_id": a.admin_id, "name": a.name})))
}

/// What this hardware can run, per module.
#[utoipa::path(get, path = "/v1/capabilities", tag = "device", responses((status = 200, body = Object)), security(("session" = [])))]
async fn capabilities(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    _a: Authed,
) -> ApiResult {
    from_privd(privd(&st, PReq::Capabilities { peer: Some(peer.ip()) }).await)
}

/// Revision, module state and which secrets are set.
#[utoipa::path(get, path = "/v1/status", tag = "device", responses((status = 200, body = Object)), security(("session" = [])))]
async fn status(State(st): St, _a: Authed) -> ApiResult {
    from_privd(privd(&st, PReq::Status {}).await)
}

/// Module states.
#[utoipa::path(get, path = "/v1/modules", tag = "modules", responses((status = 200, body = Object)), security(("session" = [])))]
async fn modules(State(st): St, _a: Authed) -> ApiResult {
    let Json(v) = from_privd(privd(&st, PReq::Status {}).await)?;
    Ok(Json(json!({"revision": v["revision"], "modules": v["modules"]})))
}

/// The whole configuration (rp.toml holds no secrets).
#[utoipa::path(get, path = "/v1/config", tag = "modules", responses((status = 200, body = Object)), security(("session" = [])))]
async fn config(State(st): St, _a: Authed) -> ApiResult {
    from_privd(privd(&st, PReq::Config {}).await)
}

/// One module's configuration section(s).
#[utoipa::path(get, path = "/v1/modules/{id}/config", tag = "modules", params(("id" = String, Path)),
    responses((status = 200, body = Object), (status = 404, body = ApiError)), security(("session" = [])))]
async fn module_config(State(st): St, _a: Authed, Path(id): Path<String>) -> ApiResult {
    let Json(v) = from_privd(privd(&st, PReq::Config {}).await)?;
    let c = &v["config"];
    let sections: &[&str] = match id.as_str() {
        "base" => &["base", "ssh"],
        "agent" => &["agent", "mcp"],
        "vpn" | "dns" | "ap" | "firewall" | "api" => &[],
        _ => return Err(ApiError::new(StatusCode::NOT_FOUND, "not_found", "unknown module")),
    };
    let mut out = serde_json::Map::new();
    if sections.is_empty() {
        out.insert(id.clone(), c[&id].clone());
    }
    for s in sections {
        out.insert(s.to_string(), c[*s].clone());
    }
    Ok(Json(json!({"module": id, "revision": v["revision"], "config": out})))
}

/// Change sets, newest first.
#[utoipa::path(get, path = "/v1/changesets", tag = "changesets", responses((status = 200, body = Object)), security(("session" = [])))]
async fn list_changesets(State(st): St, _a: Authed) -> ApiResult {
    let Json(v) = from_privd(privd(&st, PReq::ListChangesets {}).await)?;
    Ok(Json(json!({"changesets": v})))
}

/// One change set.
#[utoipa::path(get, path = "/v1/changesets/{id}", tag = "changesets", params(("id" = String, Path)),
    responses((status = 200, body = Object), (status = 404, body = ApiError)), security(("session" = [])))]
async fn get_changeset(State(st): St, _a: Authed, Path(id): Path<String>) -> ApiResult {
    from_privd(privd(&st, PReq::GetChangeset { id }).await)
}

/// Create a change set (signed `create_changeset`).
#[utoipa::path(post, path = "/v1/changesets", tag = "changesets", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 400, body = ApiError), (status = 401, body = ApiError), (status = 409, body = ApiError)))]
async fn create_changeset(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "create_changeset", &[])?;
    signed(&st, peer, env).await
}

/// Run a change set's preflight checks (signed `preflight`).
#[utoipa::path(post, path = "/v1/changesets/{id}/preflight", tag = "changesets", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 422, body = ApiError)))]
async fn cs_preflight(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "preflight", &[("id", &id)])?;
    signed(&st, peer, env).await
}

/// Apply a preflighted change set; the device rolls back unless confirmed (signed `apply`).
#[utoipa::path(post, path = "/v1/changesets/{id}/apply", tag = "changesets", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 409, body = ApiError), (status = 422, body = ApiError)))]
async fn cs_apply(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "apply", &[("id", &id)])?;
    signed(&st, peer, env).await
}

/// Keep an applied change set (signed `confirm`).
#[utoipa::path(post, path = "/v1/changesets/{id}/confirm", tag = "changesets", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 409, body = ApiError)))]
async fn cs_confirm(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "confirm", &[("id", &id)])?;
    signed(&st, peer, env).await
}

/// Undo the latest applied change set (signed `rollback`).
#[utoipa::path(post, path = "/v1/changesets/{id}/rollback", tag = "changesets", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 409, body = ApiError)))]
async fn cs_rollback(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "rollback", &[("id", &id)])?;
    signed(&st, peer, env).await
}

/// Set a secret (signed `set_secret`). The value is never returned.
#[utoipa::path(put, path = "/v1/secrets/{name}", tag = "secrets", params(("name" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 400, body = ApiError)))]
async fn set_secret(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "set_secret", &[("name", &name)])?;
    signed(&st, peer, env).await
}

/// Paired admins.
#[utoipa::path(get, path = "/v1/admins", tag = "admins", responses((status = 200, body = Object)), security(("session" = [])))]
async fn admins(State(st): St, _a: Authed) -> ApiResult {
    let Json(v) = from_privd(privd(&st, PReq::ListAdmins {}).await)?;
    Ok(Json(json!({"admins": v})))
}

/// Revoke an admin (signed `revoke_admin`).
#[utoipa::path(delete, path = "/v1/admins/{id}", tag = "admins", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 404, body = ApiError)))]
async fn revoke_admin(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "revoke_admin", &[("admin_id", &id)])?;
    signed(&st, peer, env).await
}

/// Pending and past privileged action requests (from MCP clients).
#[utoipa::path(get, path = "/v1/actions/pending", tag = "mcp", responses((status = 200, body = Object)), security(("session" = [])))]
async fn actions(State(st): St, _a: Authed) -> ApiResult {
    observe(&st, "/v1/actions".into()).await
}

/// Approve a privileged request (signed `approve`).
#[utoipa::path(post, path = "/v1/actions/{id}/approve", tag = "mcp", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 400, body = ApiError)))]
async fn approve(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "approve", &[("action_id", &id)])?;
    signed(&st, peer, env).await
}

/// Deny a privileged request (signed `deny`).
#[utoipa::path(post, path = "/v1/actions/{id}/deny", tag = "mcp", params(("id" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 400, body = ApiError)))]
async fn deny(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(id): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "deny", &[("action_id", &id)])?;
    signed(&st, peer, env).await
}

/// MCP tools with their capability tier and input schema.
#[utoipa::path(get, path = "/v1/mcp/tools", tag = "mcp", responses((status = 200, body = Object)), security(("session" = [])))]
async fn mcp_tools(_a: Authed) -> ApiResult {
    let tools: Vec<Value> = rp_mcp::tools::TOOLS
        .iter()
        .map(|t| json!({"name": t.name, "tier": t.capability.as_str(), "description": t.description, "input_schema": (t.schema)()}))
        .collect();
    Ok(Json(json!({"tools": tools})))
}

/// MCP clients (names and capabilities).
#[utoipa::path(get, path = "/v1/mcp/clients", tag = "mcp", responses((status = 200, body = Object)), security(("session" = [])))]
async fn mcp_clients(State(st): St, _a: Authed) -> ApiResult {
    from_privd(privd(&st, PReq::McpClients {}).await)
}

/// Create an MCP client; the token is returned once (signed `mcp_add_client`).
#[utoipa::path(post, path = "/v1/mcp/clients", tag = "mcp", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 400, body = ApiError)))]
async fn mcp_add(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "mcp_add_client", &[])?;
    signed(&st, peer, env).await
}

/// Revoke an MCP client (signed `mcp_remove_client`).
#[utoipa::path(delete, path = "/v1/mcp/clients/{name}", tag = "mcp", params(("name" = String, Path)), request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 404, body = ApiError)))]
async fn mcp_remove(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "mcp_remove_client", &[("name", &name)])?;
    signed(&st, peer, env).await
}

/// System health (CPU, memory, temperature, power, disk, clock).
#[utoipa::path(get, path = "/v1/health", tag = "observe", responses((status = 200, body = Object)), security(("session" = [])))]
async fn health(State(st): St, _a: Authed) -> ApiResult {
    observe(&st, "/v1/health".into()).await
}

/// Devices seen on the networks.
#[utoipa::path(get, path = "/v1/inventory", tag = "observe", responses((status = 200, body = Object)), security(("session" = [])))]
async fn inventory(State(st): St, _a: Authed) -> ApiResult {
    observe(&st, "/v1/inventory".into()).await
}

/// Devices connected to the IoT access point.
#[utoipa::path(get, path = "/v1/ap/clients", tag = "observe", responses((status = 200, body = Object)), security(("session" = [])))]
async fn ap_clients(State(st): St, _a: Authed) -> ApiResult {
    let Json(cfg) = from_privd(privd(&st, PReq::Config {}).await)?;
    let Some(iface) = cfg["config"]["ap"]["interface"].as_str().map(str::to_string) else {
        return Ok(Json(json!({"configured": false, "clients": []})));
    };
    let Json(inv) = observe(&st, "/v1/inventory".into()).await?;
    let clients: Vec<Value> = inv["devices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| d["iface"].as_str() == Some(iface.as_str()))
        .cloned()
        .collect();
    Ok(Json(json!({"configured": true, "interface": iface, "clients": clients})))
}

/// VPN state (Tailscale / WireGuard).
#[utoipa::path(get, path = "/v1/vpn/status", tag = "observe", responses((status = 200, body = Object)), security(("session" = [])))]
async fn vpn_status(State(st): St, _a: Authed) -> ApiResult {
    observe(&st, "/v1/vpn".into()).await
}

/// DNS firewall events, newest first.
#[utoipa::path(get, path = "/v1/dns/events", tag = "observe", params(EventsQuery), responses((status = 200, body = Object)), security(("session" = [])))]
async fn dns_events(State(st): St, _a: Authed, Query(q): Query<EventsQuery>) -> ApiResult {
    let since = q.since_mins.unwrap_or(60).clamp(1, 10_080);
    let lim = q.limit.unwrap_or(100).min(1000);
    let mut p = format!("/v1/dns/events?since_mins={since}&limit={lim}");
    if let Some(a) = q.action.filter(|a| a == "blocked" || a == "suspicious") {
        p.push_str(&format!("&action={a}"));
    }
    observe(&st, p).await
}

/// DNS dashboard numbers.
#[utoipa::path(get, path = "/v1/dns/stats", tag = "observe", params(EventsQuery), responses((status = 200, body = Object)), security(("session" = [])))]
async fn dns_stats(State(st): St, _a: Authed, Query(q): Query<EventsQuery>) -> ApiResult {
    let since = q.since_mins.unwrap_or(1440).clamp(1, 10_080);
    observe(&st, format!("/v1/dns/stats?since_mins={since}")).await
}

/// Recent connections (conntrack).
#[utoipa::path(get, path = "/v1/flows", tag = "observe", responses((status = 200, body = Object)), security(("session" = [])))]
async fn flows(State(st): St, _a: Authed) -> ApiResult {
    observe(&st, "/v1/flows?limit=200".into()).await
}

/// Firewall rules managed by the firewall module.
#[utoipa::path(get, path = "/v1/firewall/rules", tag = "modules", responses((status = 200, body = Object)), security(("session" = [])))]
async fn firewall_rules(State(st): St, _a: Authed) -> ApiResult {
    let Json(v) = from_privd(privd(&st, PReq::Config {}).await)?;
    let rules = v["config"]["firewall"]["rules"].clone();
    Ok(Json(json!({
        "revision": v["revision"],
        "configured": !v["config"]["firewall"].is_null(),
        "rules": if rules.is_null() { json!([]) } else { rules },
    })))
}

/// The hash-chained audit logs (agent/MCP actions).
#[utoipa::path(get, path = "/v1/audit/events", tag = "observe", responses((status = 200, body = Object)), security(("session" = [])))]
async fn audit(State(st): St, _a: Authed) -> ApiResult {
    observe(&st, "/v1/audit?limit=100".into()).await
}

/// Installed release, previous release, history, and whether a signing key is set.
#[utoipa::path(get, path = "/v1/update", tag = "update", responses((status = 200, body = Object)), security(("session" = [])))]
async fn update_status(State(st): St, _a: Authed) -> ApiResult {
    from_privd(privd(&st, PReq::UpdateStatus {}).await)
}

/// Install a signed release (signed `install_update`). Long-running.
#[utoipa::path(post, path = "/v1/update", tag = "update", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 422, body = ApiError)))]
async fn update_install(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "install_update", &[])?;
    signed(&st, peer, env).await
}

/// Switch back to the previous release (signed `rollback_update`).
#[utoipa::path(post, path = "/v1/update/rollback", tag = "update", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 409, body = ApiError)))]
async fn update_rollback(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "rollback_update", &[])?;
    signed(&st, peer, env).await
}

/// Remove every module and forget all admins (signed `uninstall`).
#[utoipa::path(post, path = "/v1/uninstall", tag = "update", request_body = SignedEnvelope,
    responses((status = 200, body = Object), (status = 400, body = ApiError)))]
async fn uninstall(
    State(st): St,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Body(env): Body<SignedEnvelope>,
) -> ApiResult {
    expect_op(&env, "uninstall", &[])?;
    signed(&st, peer, env).await
}

/// This API's OpenAPI document.
#[utoipa::path(get, path = "/v1/openapi.json", tag = "device", responses((status = 200, body = Object)))]
async fn openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ApiDoc::openapi())
}

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let c = api.components.get_or_insert_with(Default::default);
        c.add_security_scheme(
            "session",
            SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    info(title = "RP Security console API", version = "1",
         description = "Local-first management API of an RP Security device. Reads need a session; every change is an admin-signed envelope verified on the device by rp-privd."),
    paths(info, pair, pairing_open, session, logout, me, capabilities, status, modules, config, module_config,
          list_changesets, get_changeset, create_changeset, cs_preflight, cs_apply, cs_confirm, cs_rollback,
          set_secret, admins, revoke_admin, actions, approve, deny, mcp_tools, mcp_clients, mcp_add, mcp_remove,
          health, inventory, ap_clients, vpn_status, dns_events, dns_stats, flows, firewall_rules, audit,
          update_status, update_install, update_rollback, uninstall, openapi_json),
    components(schemas(SignedEnvelope, PairRequest, ApiError)),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

pub fn router(st: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/openapi.json", get(openapi_json))
        .route("/v1/pairing", post(pair))
        .route("/v1/pairing/open", post(pairing_open))
        .route("/v1/session", post(session).delete(logout))
        .route("/v1/me", get(me))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/status", get(status))
        .route("/v1/modules", get(modules))
        .route("/v1/config", get(config))
        .route("/v1/modules/{id}/config", get(module_config))
        .route("/v1/changesets", get(list_changesets).post(create_changeset))
        .route("/v1/changesets/{id}", get(get_changeset))
        .route("/v1/changesets/{id}/preflight", post(cs_preflight))
        .route("/v1/changesets/{id}/apply", post(cs_apply))
        .route("/v1/changesets/{id}/confirm", post(cs_confirm))
        .route("/v1/changesets/{id}/rollback", post(cs_rollback))
        .route("/v1/secrets/{name}", put(set_secret))
        .route("/v1/admins", get(admins))
        .route("/v1/admins/{id}", delete(revoke_admin))
        .route("/v1/actions/pending", get(actions))
        .route("/v1/actions/{id}/approve", post(approve))
        .route("/v1/actions/{id}/deny", post(deny))
        .route("/v1/mcp/tools", get(mcp_tools))
        .route("/v1/mcp/clients", get(mcp_clients).post(mcp_add))
        .route("/v1/mcp/clients/{name}", delete(mcp_remove))
        .route("/v1/health", get(health))
        .route("/v1/inventory", get(inventory))
        .route("/v1/ap/clients", get(ap_clients))
        .route("/v1/vpn/status", get(vpn_status))
        .route("/v1/dns/events", get(dns_events))
        .route("/v1/dns/stats", get(dns_stats))
        .route("/v1/flows", get(flows))
        .route("/v1/firewall/rules", get(firewall_rules))
        .route("/v1/audit/events", get(audit))
        .route("/v1/update", get(update_status).post(update_install))
        .route("/v1/update/rollback", post(update_rollback))
        .route("/v1/uninstall", post(uninstall))
        .fallback(|| async {
            ApiError::new(StatusCode::NOT_FOUND, "not_found", "no such endpoint")
        })
        .layer(axum::middleware::from_fn_with_state(st.clone(), guard))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(st)
}

/// Serve `app` over TLS on `listener` until the process ends.
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    tls: tokio_rustls::TlsAcceptor,
    app: Router,
) {
    use hyper_util::rt::{TokioIo, TokioTimer};
    use tower::ServiceExt;
    let conns = Arc::new(tokio::sync::Semaphore::new(64));
    loop {
        let Ok((tcp, peer)) = listener.accept().await else { continue };
        let Ok(permit) = conns.clone().try_acquire_owned() else { continue };
        let (tls, app) = (tls.clone(), app.clone());
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok(stream)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), tls.accept(tcp)).await
            else {
                return;
            };
            let svc = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(peer));
                    app.clone().oneshot(req.map(axum::body::Body::new))
                },
            );
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(TokioTimer::new()).header_read_timeout(std::time::Duration::from_secs(10));
            let conn = b.serve_connection(TokioIo::new(stream), svc);
            let _ = tokio::time::timeout(std::time::Duration::from_secs(300), conn).await;
        });
    }
}

#[cfg(test)]
mod tests;
