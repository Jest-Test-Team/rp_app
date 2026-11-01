//! rp-api server.
//!
//!   rp-api [--config /etc/rp/rp.toml]          production (behind rp-privd)
//!   rp-api --fake [--fake-root DIR] ...        simulated device for app tests
//!   rp-api openapi                             print the OpenAPI document

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Json, State};
use axum::routing::post;
use clap::{Parser, Subcommand};
use rp_api::fake::{FakeBackend, FakeDevice};
use rp_api::{AgentObserver, AppState, SocketBackend};
use serde_json::{json, Value};
use utoipa::OpenApi;

#[derive(Parser)]
#[command(name = "rp-api", version, about = "RP Security console API (HTTPS)")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    #[arg(long, default_value = "/etc/rp/rp.toml")]
    config: PathBuf,
    /// Override api.listen.
    #[arg(long)]
    listen: Option<SocketAddr>,
    #[arg(long, default_value = "/var/lib/rp-api")]
    state_dir: PathBuf,
    #[arg(long, default_value = rp_privd::SOCKET)]
    privd_socket: PathBuf,
    /// Serve a simulated device (no root, nothing on this machine changes).
    #[arg(long)]
    fake: bool,
    /// Fake device root (default: a new temp dir).
    #[arg(long)]
    fake_root: Option<PathBuf>,
    /// Open pairing on the fake device with this 64-hex secret.
    #[arg(long)]
    fake_pairing_secret: Option<String>,
    /// Write {"port", "cert_sha256", "device_id", "root"} here once listening.
    #[arg(long)]
    ready_file: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print the OpenAPI document (JSON).
    Openapi,
}

fn hostnames(root: &std::path::Path) -> Vec<String> {
    let h = std::fs::read_to_string(rp_core::files::under_root(root, "/etc/hostname"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let mut v = vec!["rp-security.local".to_string(), "localhost".into()];
    if !h.is_empty() {
        v.push(format!("{h}.local"));
    }
    v
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(Cmd::Openapi) = cli.cmd {
        println!("{}", rp_api::ApiDoc::openapi().to_pretty_json()?);
        return Ok(());
    }

    let (state, listen, tls_dir, extra, root) = if cli.fake {
        let root = match &cli.fake_root {
            Some(r) => r.clone(),
            None => {
                let d = std::env::temp_dir().join(format!("rp-api-fake-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&d);
                d
            }
        };
        let dev = Arc::new(FakeDevice::create(&root, cli.fake_pairing_secret.as_deref())?);
        let be = Arc::new(FakeBackend(dev.clone()));
        let st = AppState::new(be.clone(), be, vec![], 15);
        // The device's rollback timers.
        let d2 = dev.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                iv.tick().await;
                let d3 = d2.clone();
                let _ = tokio::task::spawn_blocking(move || d3.expire_due()).await;
            }
        });
        let listen = cli.listen.unwrap_or_else(|| "127.0.0.1:8443".parse().unwrap());
        let tls = rp_core::files::under_root(&root, "/var/lib/rp-api/tls");
        (st, listen, tls, Some(fake_routes(dev)), root)
    } else {
        let cfg = rp_core::config::load(&cli.config).context("loading config")?;
        let api = cfg.api.clone().context("no [api] section in the config")?;
        let agent = cfg.agent.clone().unwrap_or_default();
        let observer = Arc::new(AgentObserver {
            addr: agent.listen.to_string(),
            token_file: agent.token_file.clone().into(),
            rt: tokio::runtime::Handle::current(),
        });
        let st = AppState::new(
            Arc::new(SocketBackend(cli.privd_socket.clone())),
            observer,
            rp_core::changeset::mgmt_networks(&cfg),
            api.session_minutes,
        );
        (st, cli.listen.unwrap_or(api.listen), cli.state_dir.join("tls"), None, PathBuf::from("/"))
    };

    let id = rp_api::tls::load_or_create(&tls_dir, &hostnames(&root))?;
    let acceptor = rp_api::tls::acceptor(&id)?;
    let mut app = rp_api::router(state.clone());
    if let Some(x) = extra {
        app = app.merge(x);
    }
    let listener =
        tokio::net::TcpListener::bind(listen).await.with_context(|| format!("bind {listen}"))?;
    let port = listener.local_addr()?.port();
    let device_id = rp_privd::device_id(&root).unwrap_or_default();
    eprintln!("rp-api: https://{} cert_sha256={}", listener.local_addr()?, id.sha256());
    if let Some(f) = &cli.ready_file {
        let v = json!({"port": port, "cert_sha256": id.sha256(), "device_id": device_id,
                       "root": root.display().to_string()});
        std::fs::write(f, v.to_string())?;
    }
    rp_api::serve_tls(listener, acceptor, app).await;
    Ok(())
}

/// Test-only endpoints of the fake device (never in a real build's router).
fn fake_routes(dev: Arc<FakeDevice>) -> axum::Router {
    async fn action(State(d): State<Arc<FakeDevice>>, Json(b): Json<Value>) -> Json<Value> {
        let tool = b["tool"].as_str().unwrap_or("").to_string();
        match d.request_action(&tool, b["args"].clone()) {
            Ok(id) => Json(json!({"id": id})),
            Err(e) => Json(json!({"error": e})),
        }
    }
    async fn clock(State(d): State<Arc<FakeDevice>>, Json(b): Json<Value>) -> Json<Value> {
        let add = b["advance_secs"].as_i64().unwrap_or(0).clamp(0, 86_400);
        *d.clock_offset.lock().unwrap() += add;
        let d2 = d.clone();
        let expired =
            tokio::task::spawn_blocking(move || d2.expire_due()).await.unwrap_or_default();
        Json(json!({"now": d.now(), "expired": expired}))
    }
    async fn pairing(State(d): State<Arc<FakeDevice>>, Json(b): Json<Value>) -> Json<Value> {
        let secret = b["secret"].as_str().unwrap_or("").to_string();
        let f =
            rp_policy::pairing::PairingFile { secret, created_at: d.now(), ..Default::default() };
        let p = rp_core::files::under_root(&d.root, rp_privd::PAIRING);
        let body = format!("secret = \"{}\"\ncreated_at = {}\n", f.secret, f.created_at);
        Json(json!({"ok": rp_policy::admin::write_private(&p, &body).is_ok()}))
    }
    async fn commands(State(d): State<Arc<FakeDevice>>) -> Json<Value> {
        let t = std::fs::read_to_string(d.root.join("commands.log")).unwrap_or_default();
        Json(json!({"commands": t.lines().collect::<Vec<_>>()}))
    }
    axum::Router::new()
        .route("/_fake/actions", post(action))
        .route("/_fake/clock", post(clock))
        .route("/_fake/pairing", post(pairing))
        .route("/_fake/commands", axum::routing::get(commands))
        .with_state(dev)
}
