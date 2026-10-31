//! rp-agent — edge agent for the rp gateway.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rp_agent::api::{self, State};
use rp_agent::collect::{self, Ctx};
use rp_core::files::under_root;
use rp_policy::approvals::Store;
use rp_policy::audit::Audit;

#[derive(Parser)]
#[command(name = "rp-agent", version, about = "rp edge agent")]
struct Cli {
    #[arg(long, env = "RP_CONFIG", default_value = "/etc/rp/rp.toml", global = true)]
    config: PathBuf,
    /// Read system files under this root (testing).
    #[arg(long, default_value = "/", global = true)]
    root: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the HTTP API (default).
    Run,
    /// Print one collector's output as JSON: health | inventory | arp | usb | vpn | flows | dns
    Snapshot { what: String },
}

fn ctx(cli: &Cli) -> Result<Ctx> {
    let cfg = rp_core::config::load(&cli.config)?;
    Ok(Ctx { root: cli.root.clone(), cfg })
}

async fn run(cli: Cli) -> Result<()> {
    let ctx = ctx(&cli)?;
    let a = ctx.cfg.agent.clone().context("no [agent] section in the config")?;
    let token = std::fs::read_to_string(under_root(&cli.root, &a.token_file))
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| t.len() >= 32);
    if token.is_none() {
        eprintln!(
            "rp-agent: warning: {} missing or too short; all requests will be refused",
            a.token_file
        );
    }
    let state_dir = ctx.state_dir();
    std::fs::create_dir_all(&state_dir).ok();
    let audit = Audit::open(&state_dir.join("audit.jsonl"))?;
    let store = Store::new(&state_dir.join("actions"));
    let st = Arc::new(State { ctx, token, store, audit, last_scan: Mutex::new(None) });
    let listener = tokio::net::TcpListener::bind(a.listen)
        .await
        .with_context(|| format!("bind {}", a.listen))?;
    eprintln!("rp-agent: listening on {}", a.listen);
    let server = rp_http::serve(listener, move |req| api::handle(st.clone(), req));
    tokio::select! {
        _ = server => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate() => {}
    }
    Ok(())
}

async fn terminate() {
    #[cfg(unix)]
    {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    }
    #[cfg(not(unix))]
    std::future::pending::<()>().await;
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.cmd {
        Some(Cmd::Snapshot { what }) => (|| -> Result<()> {
            let c = ctx(&cli)?;
            let v = match what.as_str() {
                "health" => collect::health(&c),
                "inventory" => collect::inventory(&c),
                "arp" => serde_json::json!(collect::neighbors(&c)),
                "usb" => serde_json::json!(collect::usb(&c)),
                "vpn" => collect::vpn(&c),
                "flows" => collect::flows(&c, 200),
                "dns" => collect::dns_events(&c, 60, None, 100),
                other => anyhow::bail!("unknown snapshot '{other}'"),
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        })(),
        _ => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(anyhow::Error::from)
            .and_then(|rt| rt.block_on(run(cli))),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rp-agent: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
