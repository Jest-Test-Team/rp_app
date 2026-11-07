//! HTTP API. Every endpoint requires the agent bearer token. The agent only
//! observes and records requests; it never executes privileged changes.

use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use rp_http::{Request, Response};
use rp_policy::approvals::Store;
use rp_policy::audit::Audit;
use rp_policy::validate;
use serde_json::{json, Value};

use crate::actions;
use crate::collect::{self, Ctx};

pub struct State {
    pub ctx: Ctx,
    pub token: Option<String>,
    pub store: Store,
    pub audit: Audit,
    pub last_scan: Mutex<Option<Instant>>,
}

const SCAN_COOLDOWN: Duration = Duration::from_secs(10);

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn principal(req: &Request) -> String {
    req.header("x-rp-principal")
        .filter(|p| {
            p.len() <= 64 && p.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
        })
        .unwrap_or("unknown")
        .to_string()
}

impl State {
    pub fn scan_allow(&self) -> Vec<IpNet> {
        let a = self.ctx.cfg.agent.clone().unwrap_or_default();
        if !a.scan_allow.is_empty() {
            return a.scan_allow;
        }
        let mut v = self.ctx.cfg.device.lan_cidrs.clone();
        if let Some(ap) = &self.ctx.cfg.ap {
            v.push(IpNet::V4(ap.subnet));
        }
        v
    }
}

pub async fn handle(st: Arc<State>, req: Request) -> Response {
    let Some(expected) = st.token.as_deref() else {
        return Response::error(503, "agent token not configured");
    };
    if !req.bearer().is_some_and(|t| ct_eq(t, expected)) {
        return Response::error(401, "unauthorized");
    }
    let st2 = st.clone();
    // Collectors read files / run short commands: keep them off the I/O threads.
    tokio::task::spawn_blocking(move || route(&st2, &req))
        .await
        .unwrap_or_else(|_| Response::error(500, "internal error"))
}

fn route(st: &State, req: &Request) -> Response {
    let ctx = &st.ctx;
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/v1/health") => Response::json(200, &collect::health(ctx)),
        ("GET", "/v1/inventory") => Response::json(200, &collect::inventory(ctx)),
        ("GET", "/v1/arp") => Response::json(200, &json!({"neighbors": collect::neighbors(ctx)})),
        ("GET", "/v1/usb") => Response::json(200, &json!({"devices": collect::usb(ctx)})),
        ("GET", "/v1/vpn") => Response::json(200, &collect::vpn(ctx)),
        ("GET", "/v1/flows") => {
            let limit =
                req.query_param("limit").and_then(|l| l.parse().ok()).unwrap_or(200usize).min(2000);
            Response::json(200, &collect::flows(ctx, limit))
        }
        ("GET", "/v1/dns/events") => {
            let since = req
                .query_param("since_mins")
                .and_then(|v| v.parse().ok())
                .unwrap_or(60i64)
                .clamp(1, 10_080);
            let limit =
                req.query_param("limit").and_then(|v| v.parse().ok()).unwrap_or(100u32).min(1000);
            let action = req.query_param("action").filter(|a| a == "blocked" || a == "suspicious");
            Response::json(200, &collect::dns_events(ctx, since, action.as_deref(), limit))
        }
        ("GET", "/v1/dns/stats") => {
            let since = req
                .query_param("since_mins")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1440i64)
                .clamp(1, 10_080);
            Response::json(200, &collect::dns_stats(ctx, since))
        }
        ("GET", "/v1/actions") => {
            let list: Vec<Value> =
                st.store.list().iter().map(|a| serde_json::to_value(a).unwrap()).collect();
            Response::json(200, &json!({"actions": list}))
        }
        ("GET", "/v1/audit") => {
            let limit =
                req.query_param("limit").and_then(|v| v.parse().ok()).unwrap_or(50usize).min(500);
            let path = ctx.state_dir().join("audit.jsonl");
            let entries: Vec<Value> = rp_policy::audit::read_recent(&path, limit)
                .iter()
                .map(|e| serde_json::to_value(e).unwrap())
                .collect();
            let chain = match rp_policy::audit::verify(&path) {
                Ok(n) => json!({"ok": true, "entries": n}),
                Err((line, why)) => json!({"ok": false, "line": line, "reason": why}),
            };
            Response::json(200, &json!({"chain": chain, "entries": entries}))
        }
        ("POST", "/v1/scan") => scan(st, req),
        ("POST", "/v1/actions") => request_action(st, req),
        (_, p) if p.starts_with("/v1/") => Response::error(405, "method not allowed"),
        _ => Response::error(404, "not found"),
    }
}

fn scan(st: &State, req: &Request) -> Response {
    let who = principal(req);
    let body = match req.json() {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e),
    };
    let target = body.get("target").and_then(Value::as_str).unwrap_or("");
    let max = st.ctx.cfg.agent.clone().unwrap_or_default().scan_max_hosts;
    let net = match validate::scan_target(target, &st.scan_allow(), max) {
        Ok(n) => n,
        Err(e) => {
            let _ = st.audit.record(&who, "scan_network", &body, "denied", &e.0);
            return Response::error(403, &e.0);
        }
    };
    {
        let mut last = st.last_scan.lock().unwrap();
        if last.is_some_and(|t| t.elapsed() < SCAN_COOLDOWN) {
            return Response::error(429, "a scan ran in the last 10 seconds");
        }
        *last = Some(Instant::now());
    }
    let _ = st.audit.record(&who, "scan_network", &body, "allowed", &net.to_string());
    // A datagram to the discard port makes the kernel resolve each address via
    // ARP; no raw sockets or extra privileges needed.
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        for h in net.hosts() {
            let _ = sock.send_to(b"", (h, 9));
        }
    }
    std::thread::sleep(Duration::from_millis(1500));
    let found: Vec<Value> = collect::neighbors(&st.ctx)
        .into_iter()
        .filter(|n| n["state"] == "reachable")
        .filter(|n| {
            n["ip"]
                .as_str()
                .and_then(|i| i.parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| net.contains(&ip))
        })
        .collect();
    Response::json(200, &json!({"target": net.to_string(), "hosts": found}))
}

fn request_action(st: &State, req: &Request) -> Response {
    let who = principal(req);
    let body = match req.json() {
        Ok(v) => v,
        Err(e) => return Response::error(400, &e),
    };
    let tool = body.get("tool").and_then(Value::as_str).unwrap_or("");
    let args = body.get("args").cloned().unwrap_or(json!({}));
    match actions::plan(&st.ctx.cfg, tool, &args) {
        Ok(p) => {
            let pending = st.ctx.cfg.agent.clone().unwrap_or_default().pending_minutes;
            match st.store.request(
                &who,
                p.tool,
                p.args.clone(),
                p.summary.clone(),
                p.ttl_minutes,
                pending,
            ) {
                Ok(a) => {
                    let _ =
                        st.audit.record(&who, p.tool, &p.args, "pending", &format!("id={}", a.id));
                    Response::json(
                        202,
                        &json!({
                            "status": "pending_approval",
                            "id": a.id,
                            "summary": a.summary,
                            "expires": a.expires,
                            "how_to_approve": format!("A person must run on the device: sudo rpctl approve {}", a.id),
                        }),
                    )
                }
                Err(e) => Response::error(500, &e.to_string()),
            }
        }
        Err(e) => {
            let _ = st.audit.record(&who, tool, &args, "denied", &e.0);
            Response::error(403, &e.0)
        }
    }
}
