//! The HTTP layer over the fake device (real rp-privd logic, recorded commands).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body as AxBody;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request as HttpReq, StatusCode};
use ed25519_dalek::SigningKey;
use rp_policy::admin::{public_key_b64, sign};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::fake::{FakeBackend, FakeDevice};
use super::*;

const SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct T {
    app: Router,
    dev: Arc<FakeDevice>,
    device_id: String,
    n: std::sync::atomic::AtomicU32,
}

impl T {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rp-api-t-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dev = Arc::new(FakeDevice::create(&dir, Some(SECRET)).unwrap());
        let tls = rp_core::files::under_root(&dir, "/var/lib/rp-api/tls");
        crate::tls::load_or_create(&tls, &["localhost".into()]).unwrap();
        let be = Arc::new(FakeBackend(dev.clone()));
        let app = router(AppState::new(be.clone(), be, vec![], 15));
        let device_id = rp_privd::device_id(&dir).unwrap();
        T { app, dev, device_id, n: 0.into() }
    }

    async fn req(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        self.req_from(method, path, bearer, body, "192.0.2.10:5000").await
    }

    async fn req_from(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Value>,
        peer: &str,
    ) -> (StatusCode, Value) {
        let mut b = HttpReq::builder().method(method).uri(path);
        if let Some(t) = bearer {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let mut r = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(AxBody::from(v.to_string()))
                .unwrap(),
            None => b.body(AxBody::empty()).unwrap(),
        };
        let peer: SocketAddr = peer.parse().unwrap();
        r.extensions_mut().insert(ConnectInfo(peer));
        let resp = self.app.clone().oneshot(r).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn env(&self, key: &SigningKey, op: Value) -> Value {
        let n = self.n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let s = sign(
            key,
            &self.device_id,
            &format!("{n:032x}"),
            rp_core::changeset::now() + 60,
            &op.to_string(),
        );
        serde_json::to_value(s).unwrap()
    }

    async fn pair(&self, key: &SigningKey) -> (StatusCode, Value) {
        let pk = public_key_b64(key);
        let nonce = "00112233445566778899aabbccddeeff";
        let proof = rp_policy::pairing::hmac_hex(
            &hex::decode(SECRET).unwrap(),
            &rp_policy::pairing::client_message(&self.device_id, &pk, nonce),
        );
        self.req(
            Method::POST,
            "/v1/pairing",
            None,
            Some(json!({"name": "pixel", "public_key": pk, "client_nonce": nonce, "proof": proof})),
        )
        .await
    }

    async fn session(&self, key: &SigningKey) -> String {
        let (s, v) = self
            .req(Method::POST, "/v1/session", None, Some(self.env(key, json!({"op": "session"}))))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        v["token"].as_str().unwrap().to_string()
    }
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn code(v: &Value) -> &str {
    v["error"]["code"].as_str().unwrap_or("")
}

#[tokio::test]
async fn info_is_public_and_reads_need_a_session() {
    let t = T::new("info");
    let (s, v) = t.req(Method::GET, "/v1/info", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["api_version"], 1);
    assert_eq!(v["pairing_open"], true);
    for p in [
        "/v1/status",
        "/v1/capabilities",
        "/v1/health",
        "/v1/changesets",
        "/v1/mcp/tools",
        "/v1/me",
    ] {
        let (s, v) = t.req(Method::GET, p, None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{p}");
        assert_eq!(code(&v), "unauthorized");
        let (s, _) = t.req(Method::GET, p, Some("rps_forged"), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{p} with a made-up token");
    }
}

#[tokio::test]
async fn pairing_then_session_then_reads() {
    let t = T::new("pair");
    let (s, v) = t.pair(&key(1)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let cert = std::fs::read(rp_core::files::under_root(&t.dev.root, rp_privd::API_CERT)).unwrap();
    assert_eq!(v["cert_sha256"], hex::encode(sha2::Sha256::digest(cert)));
    let (s, v) = t.pair(&key(1)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "single use: {v}");
    assert_eq!(code(&v), "pairing_closed");

    let tok = t.session(&key(1)).await;
    assert!(tok.starts_with("rps_"));
    let (s, v) = t.req(Method::GET, "/v1/me", Some(&tok), None).await;
    assert_eq!((s, v["name"].as_str()), (StatusCode::OK, Some("pixel")));
    let (s, v) = t.req(Method::GET, "/v1/capabilities", Some(&tok), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["modules"]["ap"]["available"], true, "{v}");
    for p in [
        "/v1/status",
        "/v1/modules",
        "/v1/config",
        "/v1/modules/ap/config",
        "/v1/health",
        "/v1/inventory",
        "/v1/ap/clients",
        "/v1/vpn/status",
        "/v1/dns/events?limit=5",
        "/v1/dns/stats",
        "/v1/flows",
        "/v1/firewall/rules",
        "/v1/audit/events",
        "/v1/admins",
        "/v1/mcp/tools",
        "/v1/mcp/clients",
        "/v1/actions/pending",
        "/v1/changesets",
    ] {
        let (s, v) = t.req(Method::GET, p, Some(&tok), None).await;
        assert_eq!(s, StatusCode::OK, "{p}: {v}");
    }
    let (_, v) = t.req(Method::GET, "/v1/ap/clients", Some(&tok), None).await;
    assert_eq!(v["clients"].as_array().unwrap().len(), 2, "only wlan0 clients: {v}");
    let (s, _) = t.req(Method::GET, "/v1/modules/nope/config", Some(&tok), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, _) = t.req(Method::DELETE, "/v1/session", Some(&tok), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = t.req(Method::GET, "/v1/status", Some(&tok), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "logged out");
}

#[tokio::test]
async fn signed_operation_must_match_the_url() {
    let t = T::new("match");
    t.pair(&key(1)).await;
    // A session signature can't be used to confirm, and vice versa.
    let (s, v) = t
        .req(
            Method::POST,
            "/v1/session",
            None,
            Some(t.env(&key(1), json!({"op": "confirm", "id": "a"}))),
        )
        .await;
    assert_eq!((s, code(&v)), (StatusCode::BAD_REQUEST, "bad_request"));
    let env = t.env(&key(1), json!({"op": "confirm", "id": "aaaaaaaaaaaaaaaa"}));
    let (s, v) =
        t.req(Method::POST, "/v1/changesets/bbbbbbbbbbbbbbbb/confirm", None, Some(env)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"]["message"].as_str().unwrap().contains("does not match"));
    let env = t.env(
        &key(1),
        json!({"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}),
    );
    let (s, _) = t.req(Method::PUT, "/v1/secrets/tailscale_auth_key", None, Some(env)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_set_life_cycle_over_http_and_expiry() {
    let t = T::new("cs");
    t.pair(&key(1)).await;
    let tok = t.session(&key(1)).await;
    let (_, st) = t.req(Method::GET, "/v1/status", Some(&tok), None).await;
    let rev = st["revision"].as_u64().unwrap();

    // Stale revision → 409 with the current one.
    let (s, v) = t.req(Method::POST, "/v1/changesets", None, Some(t.env(&key(1),
        json!({"op": "create_changeset", "module": "ap", "expected_revision": rev + 5, "patch": {"ap.block_dot": true}})))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["error"]["details"]["current_revision"], rev);

    // Invalid value → 400 with the validation errors.
    let (s, v) = t.req(Method::POST, "/v1/changesets", None, Some(t.env(&key(1),
        json!({"op": "create_changeset", "module": "ap", "expected_revision": rev, "patch": {"ap.channel": 99}})))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    let (s, v) = t.req(Method::POST, "/v1/changesets", None, Some(t.env(&key(1),
        json!({"op": "create_changeset", "module": "ap", "expected_revision": rev, "patch": {"ap.block_dot": true}})))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_string();
    assert!(v["config_diff"].as_str().unwrap().contains("+block_dot = true"));

    let path = |a: &str| format!("/v1/changesets/{id}/{a}");
    // Preflight needs the AP passphrase secret first.
    let (s, v) = t
        .req(
            Method::POST,
            &path("preflight"),
            None,
            Some(t.env(&key(1), json!({"op": "preflight", "id": id}))),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["error"]["details"]["checks"].to_string().contains("ap_passphrase"));
    let (s, v) = t
        .req(
            Method::PUT,
            "/v1/secrets/ap_passphrase",
            None,
            Some(t.env(
                &key(1),
                json!({"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}),
            )),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!v.to_string().contains("horse"));
    let (s, v) = t
        .req(
            Method::POST,
            &path("preflight"),
            None,
            Some(t.env(&key(1), json!({"op": "preflight", "id": id}))),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, v) = t
        .req(
            Method::POST,
            &path("apply"),
            None,
            Some(t.env(&key(1), json!({"op": "apply", "id": id, "confirm_secs": 30}))),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "awaiting_confirm");

    // Nobody confirms: the device rolls back by itself after the deadline.
    *t.dev.clock_offset.lock().unwrap() += 31;
    let expired = t.dev.expire_due();
    assert_eq!(expired, vec![id.clone()]);
    let (_, v) = t.req(Method::GET, &format!("/v1/changesets/{id}"), Some(&tok), None).await;
    assert_eq!(v["status"], "rolled_back");
    let (s, v) = t
        .req(
            Method::POST,
            &path("confirm"),
            None,
            Some(t.env(&key(1), json!({"op": "confirm", "id": id}))),
        )
        .await;
    assert_eq!((s, code(&v)), (StatusCode::CONFLICT, "state"), "too late to confirm");
}

#[tokio::test]
async fn confirmed_change_and_manual_rollback() {
    let t = T::new("confirm");
    t.pair(&key(1)).await;
    let tok = t.session(&key(1)).await;
    let (_, st) = t.req(Method::GET, "/v1/status", Some(&tok), None).await;
    let (_, v) = t.req(Method::POST, "/v1/changesets", None, Some(t.env(&key(1),
        json!({"op": "create_changeset", "module": "dns", "expected_revision": st["revision"], "patch": {"dns.block": ["ads.example"]}})))).await;
    let id = v["id"].as_str().unwrap().to_string();
    let path = |a: &str| format!("/v1/changesets/{id}/{a}");
    for op in ["preflight", "apply", "confirm"] {
        let (s, v) = t
            .req(Method::POST, &path(op), None, Some(t.env(&key(1), json!({"op": op, "id": id}))))
            .await;
        assert_eq!(s, StatusCode::OK, "{op}: {v}");
    }
    let (_, v) = t.req(Method::GET, "/v1/modules/dns/config", Some(&tok), None).await;
    assert_eq!(v["config"]["dns"]["block"], json!(["ads.example"]));
    let (s, v) = t
        .req(
            Method::POST,
            &path("rollback"),
            None,
            Some(t.env(&key(1), json!({"op": "rollback", "id": id}))),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, v) = t.req(Method::GET, "/v1/modules/dns/config", Some(&tok), None).await;
    assert_eq!(v["config"]["dns"]["block"], json!([]));
}

#[tokio::test]
async fn approval_queue_and_mcp_clients() {
    let t = T::new("approve");
    t.pair(&key(1)).await;
    let tok = t.session(&key(1)).await;
    let id = t
        .dev
        .request_action("block_device", json!({"ip": "198.51.100.150", "ttl_minutes": 30}))
        .unwrap();
    let (_, v) = t.req(Method::GET, "/v1/actions/pending", Some(&tok), None).await;
    assert_eq!(v["actions"][0]["id"], id.as_str());
    assert_eq!(v["actions"][0]["status"], "pending");
    let (s, v) = t
        .req(
            Method::POST,
            &format!("/v1/actions/{id}/approve"),
            None,
            Some(t.env(&key(1), json!({"op": "approve", "action_id": id}))),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["status"], "executed");
    let cmds = std::fs::read_to_string(t.dev.root.join("commands.log")).unwrap();
    assert!(cmds.contains("nft add element inet rp ap_quarantine4"), "{cmds}");

    let (s, v) = t.req(Method::POST, "/v1/mcp/clients", None, Some(t.env(&key(1),
        json!({"op": "mcp_add_client", "name": "claude", "capabilities": ["read", "active"]})))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let token = v["token"].as_str().unwrap().to_string();
    let (_, v) = t.req(Method::GET, "/v1/mcp/clients", Some(&tok), None).await;
    assert_eq!(v["clients"][0]["capabilities"], json!(["read", "active"]));
    assert!(!v.to_string().contains(&token));
    // An MCP token is not a console session.
    let (s, _) = t.req(Method::GET, "/v1/status", Some(&token), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = t
        .req(
            Method::DELETE,
            "/v1/mcp/clients/claude",
            None,
            Some(t.env(&key(1), json!({"op": "mcp_remove_client", "name": "claude"}))),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn errors_are_structured_and_limits_hold() {
    let t = T::new("errors");
    let (s, v) = t.req(Method::GET, "/v1/nope", None, None).await;
    assert_eq!((s, code(&v)), (StatusCode::NOT_FOUND, "not_found"));
    let (s, v) = t.req(Method::POST, "/v1/session", None, Some(json!({"unknown": 1}))).await;
    assert_eq!((s.is_client_error(), code(&v)), (true, "bad_request"));
    let huge = json!({"name": "x".repeat(MAX_BODY + 10), "public_key": "", "client_nonce": "", "proof": ""});
    let (s, v) = t.req(Method::POST, "/v1/pairing", None, Some(huge)).await;
    assert_eq!((s, code(&v)), (StatusCode::PAYLOAD_TOO_LARGE, "too_large"));
    // Pairing attempts are rate limited per address.
    let mut last = StatusCode::OK;
    for _ in 0..12 {
        let (s, _) = t
            .req_from(
                Method::POST,
                "/v1/pairing",
                None,
                Some(json!({"name": "x", "public_key": "x", "client_nonce": "00", "proof": "00"})),
                "192.0.2.99:1",
            )
            .await;
        last = s;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn outside_networks_are_refused() {
    let dir = std::env::temp_dir().join(format!("rp-api-t-nets-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let dev = Arc::new(FakeDevice::create(&dir, None).unwrap());
    let be = Arc::new(FakeBackend(dev));
    let st = AppState::new(be.clone(), be, vec!["192.0.2.0/24".parse().unwrap()], 15);
    assert!(allowed(&st, "192.0.2.7".parse().unwrap()));
    assert!(allowed(&st, "::ffff:192.0.2.7".parse().unwrap()), "v4-mapped v6");
    assert!(allowed(&st, "127.0.0.1".parse().unwrap()));
    assert!(!allowed(&st, "198.51.100.7".parse().unwrap()));
    let app = router(st);
    let mut r = HttpReq::builder().uri("/v1/info").body(AxBody::empty()).unwrap();
    r.extensions_mut().insert(ConnectInfo("198.51.100.7:1".parse::<SocketAddr>().unwrap()));
    assert_eq!(app.oneshot(r).await.unwrap().status(), StatusCode::FORBIDDEN);
}

#[test]
fn openapi_documents_every_route() {
    let doc = serde_json::to_value(ApiDoc::openapi()).unwrap();
    let mut got: Vec<String> = vec![];
    for (p, item) in doc["paths"].as_object().unwrap() {
        for m in item.as_object().unwrap().keys() {
            got.push(format!("{} {p}", m.to_uppercase()));
        }
    }
    got.sort();
    let mut want: Vec<String> = [
        "GET /v1/info",
        "GET /v1/openapi.json",
        "POST /v1/pairing",
        "POST /v1/pairing/open",
        "POST /v1/session",
        "DELETE /v1/session",
        "GET /v1/me",
        "GET /v1/capabilities",
        "GET /v1/status",
        "GET /v1/modules",
        "GET /v1/config",
        "GET /v1/modules/{id}/config",
        "GET /v1/changesets",
        "POST /v1/changesets",
        "GET /v1/changesets/{id}",
        "POST /v1/changesets/{id}/preflight",
        "POST /v1/changesets/{id}/apply",
        "POST /v1/changesets/{id}/confirm",
        "POST /v1/changesets/{id}/rollback",
        "PUT /v1/secrets/{name}",
        "GET /v1/admins",
        "DELETE /v1/admins/{id}",
        "GET /v1/actions/pending",
        "POST /v1/actions/{id}/approve",
        "POST /v1/actions/{id}/deny",
        "GET /v1/mcp/tools",
        "GET /v1/mcp/clients",
        "POST /v1/mcp/clients",
        "DELETE /v1/mcp/clients/{name}",
        "GET /v1/health",
        "GET /v1/inventory",
        "GET /v1/ap/clients",
        "GET /v1/vpn/status",
        "GET /v1/dns/events",
        "GET /v1/dns/stats",
        "GET /v1/flows",
        "GET /v1/firewall/rules",
        "GET /v1/audit/events",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    want.sort();
    assert_eq!(got, want, "router and OpenAPI document must list the same endpoints");
    assert!(doc["components"]["securitySchemes"]["session"].is_object());
}
