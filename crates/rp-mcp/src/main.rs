//! rp-mcp — MCP server (stdio or Streamable HTTP) for the rp gateway.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use rp_http::{Request, Response};
use rp_mcp::protocol;
use rp_mcp::tools::Dispatcher;
use rp_policy::audit::Audit;
use rp_policy::auth::{Clients, Principal};
use rp_policy::ratelimit::Limiter;
use rp_policy::Capability;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Parser)]
#[command(name = "rp-mcp", version, about = "MCP server for the rp edge gateway")]
struct Cli {
    #[arg(long, env = "RP_CONFIG", default_value = "/etc/rp/rp.toml")]
    config: PathBuf,
    /// Speak MCP over stdin/stdout (e.g. `ssh device rp-mcp --stdio`).
    #[arg(long)]
    stdio: bool,
    /// Override file locations (systemd LoadCredential= puts them in $CREDENTIALS_DIRECTORY).
    #[arg(long, env = "RP_MCP_AGENT_TOKEN_FILE")]
    agent_token_file: Option<PathBuf>,
    #[arg(long, env = "RP_MCP_CLIENTS_FILE")]
    clients_file: Option<PathBuf>,
    /// Resolve configured file paths under this root (testing).
    #[arg(long, default_value = "/")]
    root: PathBuf,
}

fn caps(list: &[String]) -> BTreeSet<Capability> {
    list.iter()
        .filter_map(|c| match c.as_str() {
            "read" => Some(Capability::Read),
            "active" => Some(Capability::Active),
            "privileged" => Some(Capability::Privileged),
            _ => None,
        })
        .collect()
}

async fn run(cli: Cli) -> Result<()> {
    let cfg = rp_core::config::load(&cli.config)?;
    let m = cfg.mcp.clone().context("no [mcp] section in the config")?;
    let at = |p: &str| rp_core::files::under_root(&cli.root, p);
    let token_path = cli.agent_token_file.clone().unwrap_or_else(|| at(&m.agent_token_file));
    let agent_token = std::fs::read_to_string(&token_path)
        .with_context(|| format!("cannot read agent token {}", token_path.display()))?
        .trim()
        .to_string();
    let audit = Audit::open(&at(&m.audit_log))
        .map_err(|e| eprintln!("rp-mcp: warning: audit log disabled: {e}"))
        .ok();
    let d = Arc::new(Dispatcher {
        agent: m.agent,
        agent_token,
        limiter: Mutex::new(Limiter::new(m.rate_limit_per_minute)),
        audit,
    });

    if cli.stdio {
        let who = Principal { name: "stdio".into(), capabilities: caps(&m.stdio_capabilities) };
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut out = tokio::io::stdout();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            if line.len() > rp_http::MAX_BODY_BYTES {
                continue;
            }
            if let Some(reply) = protocol::handle_raw(&d, &who, &line).await {
                out.write_all(serde_json::to_string(&reply)?.as_bytes()).await?;
                out.write_all(b"\n").await?;
                out.flush().await?;
            }
        }
        return Ok(());
    }

    let clients_path = cli.clients_file.clone().unwrap_or_else(|| at(&m.clients_file));
    let clients = Arc::new(Clients::load(&clients_path).map_err(anyhow::Error::msg)?);
    let listener = tokio::net::TcpListener::bind(m.listen)
        .await
        .with_context(|| format!("bind {}", m.listen))?;
    eprintln!(
        "rp-mcp: Streamable HTTP on http://{}/mcp ({} client(s))",
        m.listen,
        clients.clients.len()
    );
    let server = rp_http::serve(listener, move |req| {
        let (d, clients) = (d.clone(), clients.clone());
        async move { http(&d, &clients, req).await }
    });
    tokio::select! {
        _ = server => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    Ok(())
}

async fn http(d: &Dispatcher, clients: &Clients, req: Request) -> Response {
    if req.path != "/mcp" {
        return Response::error(404, "not found");
    }
    // Browsers send Origin; MCP clients don't. Refusing it blocks DNS-rebinding
    // and drive-by pages from reaching this local service.
    if req.header("origin").is_some() {
        return Response::error(403, "cross-origin requests are not allowed");
    }
    if req.method != "POST" {
        return Response::error(405, "only POST is supported (no SSE stream)");
    }
    let Some(who) = req.bearer().and_then(|t| clients.authenticate(t)) else {
        return Response::error(401, "unauthorized");
    };
    let raw = String::from_utf8_lossy(&req.body);
    match protocol::handle_raw(d, &who, &raw).await {
        Some(v) => Response::json(200, &v),
        None => Response::empty(202),
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt =
        match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("rp-mcp: error: {e}");
                return ExitCode::FAILURE;
            }
        };
    match rt.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rp-mcp: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
