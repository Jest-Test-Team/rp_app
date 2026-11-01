use std::fs;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rp_core::runner::RecordingRunner;
use rp_policy::admin::{public_key_b64, sign};
use serde_json::json;

use super::*;

const CFG: &str =
    "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n\n[agent]\n\n[mcp]\n";
const NOW: i64 = 1_800_000_000;

struct Dev {
    root: PathBuf,
    config: PathBuf,
    runner: RecordingRunner,
}

impl Dev {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("rp-privd-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let w = |p: &str, c: &[u8]| {
            let f = under_root(&root, p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, c).unwrap();
        };
        for b in rp_core::preflight::REQUIRED_BINARIES {
            w(&format!("/usr/sbin/{b}"), b"");
        }
        w("/sys/class/net/eth0/carrier", b"1\n");
        w("/sys/class/net/eth0/device/vendor", b"x");
        w("/etc/os-release", b"ID=debian\n");
        w(API_CERT, b"fake certificate der");
        let config = root.join("rp.toml");
        fs::write(&config, CFG).unwrap();
        let runner = RecordingRunner::default()
            .with_response("id -u", "0\n")
            .with_response("dpkg-query", "install ok installed")
            .with_response("uname -m", "armv7l\n");
        Dev { root, config, runner }
    }

    fn ctx(&self, now: i64) -> Ctx<'_> {
        Ctx {
            root: self.root.clone(),
            config: self.config.clone(),
            runner: &self.runner,
            rpctl_argv: vec!["/usr/local/bin/rpctl".into()],
            now,
        }
    }

    fn call(&self, req: Request) -> Response {
        handle(&self.ctx(NOW), req)
    }

    fn dev_id(&self) -> String {
        device_id(&self.root).unwrap()
    }

    /// Pair `key` using a freshly opened pairing secret.
    fn pair(&self, key: &SigningKey) -> Response {
        let secret = pairing::open(&under_root(&self.root, PAIRING), NOW, Some(600)).unwrap();
        let pk = public_key_b64(key);
        let nonce = "00112233445566778899aabbccddeeff";
        let proof = pairing::hmac_hex(
            &hex::decode(&secret).unwrap(),
            &pairing::client_message(&self.dev_id(), &pk, nonce),
        );
        let r = self.call(Request::Pair {
            name: "phone".into(),
            public_key: pk.clone(),
            client_nonce: nonce.into(),
            proof,
        });
        if r.ok {
            let expect = pairing::hmac_hex(
                &hex::decode(&secret).unwrap(),
                &pairing::server_message(
                    &self.dev_id(),
                    &pk,
                    nonce,
                    r.result["cert_sha256"].as_str().unwrap(),
                    r.result["admin_id"].as_str().unwrap(),
                ),
            );
            assert_eq!(r.result["server_proof"], expect, "server proves the secret too");
        }
        r
    }

    fn signed(&self, key: &SigningKey, n: u32, op: Value) -> Response {
        let req = sign(key, &self.dev_id(), &format!("{n:032x}"), NOW + 60, &op.to_string());
        self.call(Request::Signed { req, peer: Some("192.0.2.10".parse().unwrap()) })
    }

    fn audit_text(&self) -> String {
        fs::read_to_string(under_root(&self.root, AUDIT)).unwrap_or_default()
    }
}

impl Drop for Dev {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn code(r: &Response) -> &str {
    r.error.as_ref().map(|e| e.code.as_str()).unwrap_or("ok")
}

#[test]
fn info_reports_pairing_state_without_secrets() {
    let d = Dev::new("info");
    let r = d.call(Request::Info {});
    assert!(r.ok);
    assert_eq!(r.result["paired"], false);
    assert_eq!(r.result["device_id"].as_str().unwrap().len(), 32);
    assert_eq!(r.result["device_id"], d.call(Request::Info {}).result["device_id"], "stable id");
    d.pair(&key(1));
    let r = d.call(Request::Info {});
    assert_eq!(r.result["paired"], true);
    assert_eq!(r.result["pairing_open"], false, "secret is single use");
}

#[test]
fn pairing_needs_the_secret_and_works_once() {
    let d = Dev::new("pair");
    // Not open at all.
    let r = d.call(Request::Pair {
        name: "x".into(),
        public_key: public_key_b64(&key(9)),
        client_nonce: "00112233445566778899aabbccddeeff".into(),
        proof: "00".into(),
    });
    assert_eq!(code(&r), "pairing_closed");
    // Open, wrong proof.
    pairing::open(&under_root(&d.root, PAIRING), NOW, None).unwrap();
    let r = d.call(Request::Pair {
        name: "x".into(),
        public_key: public_key_b64(&key(9)),
        client_nonce: "00112233445566778899aabbccddeeff".into(),
        proof: "ab".repeat(32),
    });
    assert_eq!(code(&r), "unauthorized");
    // Right proof (fresh secret).
    let r = d.pair(&key(1));
    assert!(r.ok, "{r:?}");
    assert_eq!(
        r.result["cert_sha256"],
        hex::encode(Sha256::digest(b"fake certificate der")),
        "server proof covers the real certificate"
    );
    assert!(d.audit_text().contains("\"paired\""));
}

#[test]
fn missing_certificate_does_not_burn_the_secret() {
    let d = Dev::new("nocert");
    fs::remove_file(under_root(&d.root, API_CERT)).unwrap();
    let r = d.pair(&key(1));
    assert_eq!(code(&r), "internal");
    assert!(under_root(&d.root, PAIRING).exists());
}

#[test]
fn unsigned_or_forged_changes_are_refused() {
    let d = Dev::new("forged");
    d.pair(&key(1));
    let op = json!({"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"});
    // Unknown key.
    assert_eq!(code(&d.signed(&key(2), 1, op.clone())), "unauthorized");
    // Tampered payload.
    let mut req = sign(&key(1), &d.dev_id(), &format!("{:032x}", 2), NOW + 60, &op.to_string());
    req.payload = req.payload.replace("correct horse", "attacker pass");
    assert_eq!(code(&d.call(Request::Signed { req, peer: None })), "unauthorized");
    // Signed for another device.
    let req = sign(
        &key(1),
        "ffffffffffffffffffffffffffffffff",
        &format!("{:032x}", 3),
        NOW + 60,
        &op.to_string(),
    );
    assert_eq!(code(&d.call(Request::Signed { req, peer: None })), "unauthorized");
    // Expired.
    let req = sign(&key(1), &d.dev_id(), &format!("{:032x}", 4), NOW - 1, &op.to_string());
    assert_eq!(code(&d.call(Request::Signed { req, peer: None })), "unauthorized");
    assert!(!rp_core::secrets::is_set(&d.root, None, "ap_passphrase"));
    assert!(d.audit_text().contains("unauthorized"));
}

#[test]
fn replayed_requests_are_refused() {
    let d = Dev::new("replay");
    d.pair(&key(1));
    let op = json!({"op": "session"});
    let req = sign(&key(1), &d.dev_id(), &format!("{:032x}", 7), NOW + 60, &op.to_string());
    assert!(d.call(Request::Signed { req: req.clone(), peer: None }).ok);
    let r = d.call(Request::Signed { req, peer: None });
    assert_eq!(code(&r), "unauthorized");
    assert!(r.error.unwrap().message.contains("already used"));
}

#[test]
fn unknown_operations_are_rejected() {
    let d = Dev::new("unknown");
    d.pair(&key(1));
    let r = d.signed(&key(1), 1, json!({"op": "run_command", "argv": ["sh", "-c", "id"]}));
    assert_eq!(code(&r), "bad_request");
    let r = d.signed(&key(1), 2, json!({"op": "confirm", "id": "x", "extra": 1}));
    assert_eq!(code(&r), "bad_request", "unknown fields are refused too");
    let r = d.signed(&key(1), 3, json!({"op": "session", "as": "root"}));
    assert_eq!(code(&r), "bad_request", "also on operations without arguments");
    let r: Result<Request, _> = serde_json::from_str(r#"{"op":"info","shell":"id"}"#);
    assert!(r.is_err());
}

#[test]
fn signed_change_set_life_cycle() {
    let d = Dev::new("cs");
    d.pair(&key(1));
    let st = d.call(Request::Status {});
    let rev = st.result["revision"].as_u64().unwrap();
    let r = d.signed(
        &key(1),
        1,
        json!({"op": "create_changeset", "module": "base", "expected_revision": rev,
               "patch": {"base.allow_mdns": false}}),
    );
    assert!(r.ok, "{r:?}");
    assert!(r.result.get("new_config").is_none(), "full config never leaves privd");
    let id = r.result["id"].as_str().unwrap().to_string();
    assert_eq!(r.result["created_by"], "admin:phone");

    let r = d.signed(&key(1), 2, json!({"op": "preflight", "id": id}));
    assert!(r.ok, "{r:?}");
    let r = d.signed(&key(1), 3, json!({"op": "apply", "id": id, "confirm_secs": 5}));
    assert!(r.ok, "{r:?}");
    assert_eq!(r.result["status"], "awaiting_confirm");
    let timer = d.runner.calls().into_iter().find(|c| c.starts_with("systemd-run")).unwrap();
    assert!(timer.contains("--on-active=30"), "confirm window is clamped to >= 30 s: {timer}");
    let r = d.signed(&key(1), 4, json!({"op": "confirm", "id": id}));
    assert_eq!(r.result["status"], "confirmed");

    let got = d.call(Request::GetChangeset { id: id.clone() });
    assert_eq!(got.result["status"], "confirmed");
    assert_eq!(d.call(Request::ListChangesets {}).result.as_array().unwrap().len(), 1);
    let audit = d.audit_text();
    for op in ["create_changeset", "preflight", "apply", "confirm"] {
        assert!(audit.contains(&format!("\"{op}\"")), "{op} audited");
    }
}

#[test]
fn stale_revision_is_a_conflict_with_the_current_revision() {
    let d = Dev::new("conflict");
    d.pair(&key(1));
    let r = d.signed(
        &key(1),
        1,
        json!({"op": "create_changeset", "module": "base", "expected_revision": 999,
               "patch": {"base.allow_mdns": false}}),
    );
    assert_eq!(code(&r), "conflict");
    assert!(r.error.unwrap().details["current_revision"].is_u64());
}

#[test]
fn preflight_failure_is_reported_with_checks() {
    let d = Dev::new("pfail");
    d.pair(&key(1));
    let rev = d.call(Request::Status {}).result["revision"].as_u64().unwrap();
    let r = d.signed(
        &key(1),
        1,
        json!({"op": "create_changeset", "module": "base", "expected_revision": rev,
               "patch": {"base.allow_mdns": false}}),
    );
    let id = r.result["id"].as_str().unwrap().to_string();
    let req = sign(
        &key(1),
        &d.dev_id(),
        &format!("{:032x}", 2),
        NOW + 60,
        &json!({"op": "preflight", "id": id}).to_string(),
    );
    let r = d.call(Request::Signed { req, peer: Some("198.51.100.1".parse().unwrap()) });
    assert_eq!(code(&r), "preflight_failed");
    assert!(r.error.unwrap().details["checks"].to_string().contains("api_lockout"));
}

#[test]
fn secrets_are_set_but_never_logged_or_returned() {
    let d = Dev::new("secret");
    d.pair(&key(1));
    let r = d.signed(
        &key(1),
        1,
        json!({"op": "set_secret", "name": "ap_passphrase", "value": "correct horse"}),
    );
    assert!(r.ok);
    assert!(!r.result.to_string().contains("horse"));
    assert!(rp_core::secrets::is_set(&d.root, None, "ap_passphrase"));
    assert!(!d.audit_text().contains("horse"), "secret values never reach the audit log");
    assert_eq!(d.call(Request::Status {}).result["secrets"]["ap_passphrase"], true);
    let r = d.signed(
        &key(1),
        2,
        json!({"op": "set_secret", "name": "ap_passphrase", "value": "short"}),
    );
    assert_eq!(code(&r), "invalid");
    assert!(!r.error.unwrap().message.contains("short"));
}

#[test]
fn revoked_admin_loses_access_and_new_device_can_pair() {
    let d = Dev::new("revoke");
    d.pair(&key(1));
    let r = d.signed(&key(1), 1, json!({"op": "open_pairing", "valid_minutes": 10}));
    assert!(r.ok);
    let secret = r.result["secret"].as_str().unwrap().to_string();
    let pk2 = public_key_b64(&key(2));
    let nonce = "ffeeddccbbaa99887766554433221100";
    let proof = pairing::hmac_hex(
        &hex::decode(&secret).unwrap(),
        &pairing::client_message(&d.dev_id(), &pk2, nonce),
    );
    let r = d.call(Request::Pair {
        name: "laptop".into(),
        public_key: pk2,
        client_nonce: nonce.into(),
        proof,
    });
    assert!(r.ok, "{r:?}");
    assert_eq!(d.call(Request::ListAdmins {}).result.as_array().unwrap().len(), 2);

    let first = rp_policy::admin::admin_id(&public_key_b64(&key(1)));
    // Nonces are per device, not per admin: a second admin uses fresh ones.
    let r = d.signed(&key(2), 11, json!({"op": "revoke_admin", "admin_id": first}));
    assert!(r.ok);
    assert_eq!(code(&d.signed(&key(1), 2, json!({"op": "session"}))), "unauthorized");
    assert_eq!(d.call(Request::ListAdmins {}).result.as_array().unwrap().len(), 1);
}

#[test]
fn mcp_clients_get_a_token_once() {
    let d = Dev::new("mcp");
    d.pair(&key(1));
    let r = d.signed(
        &key(1),
        1,
        json!({"op": "mcp_add_client", "name": "claude", "capabilities": ["read"]}),
    );
    assert!(r.ok, "{r:?}");
    let token = r.result["token"].as_str().unwrap().to_string();
    let file = fs::read_to_string(under_root(&d.root, "/etc/rp/mcp-clients.toml")).unwrap();
    assert!(!file.contains(&token), "only the hash is stored");
    assert!(!d.audit_text().contains(&token));
    let r = d.signed(
        &key(1),
        2,
        json!({"op": "mcp_add_client", "name": "x; rm -rf /", "capabilities": ["read"]}),
    );
    assert_eq!(code(&r), "invalid");
    let r = d.signed(
        &key(1),
        3,
        json!({"op": "mcp_add_client", "name": "y", "capabilities": ["root"]}),
    );
    assert_eq!(code(&r), "invalid");
    assert!(d.signed(&key(1), 4, json!({"op": "mcp_remove_client", "name": "claude"})).ok);
    assert_eq!(
        code(&d.signed(&key(1), 5, json!({"op": "mcp_remove_client", "name": "claude"}))),
        "not_found"
    );
}

#[test]
fn approve_without_pending_request_is_an_error() {
    let d = Dev::new("approve");
    d.pair(&key(1));
    let r = d.signed(&key(1), 1, json!({"op": "approve", "action_id": "nope"}));
    assert_eq!(code(&r), "invalid");
}

#[test]
fn frames_round_trip_and_oversize_is_refused() {
    let mut buf = Vec::new();
    write_frame(&mut buf, &Request::Info {}).unwrap();
    let body = read_frame(&mut buf.as_slice()).unwrap();
    assert!(matches!(serde_json::from_slice(&body).unwrap(), Request::Info {}));
    let mut huge = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
    huge.extend([0u8; 8]);
    assert!(read_frame(&mut huge.as_slice()).is_err());
}
