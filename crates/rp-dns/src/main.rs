//! rp-dns — filtering, logging DNS forwarder for the rp edge gateway.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rp_dns::engine::{Engine, Lists};
use rp_dns::{events, score, server};
use rp_schema::Dns;

#[derive(Parser)]
#[command(name = "rp-dns", version, about = "Filtering, logging DNS forwarder")]
struct Cli {
    #[arg(long, env = "RP_CONFIG", default_value = "/etc/rp/rp.toml", global = true)]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the server (default).
    Run,
    /// Validate the [dns] config and load the lists.
    Check,
    /// Show how a name would score; with --file, score every line and summarise as JSON.
    Score {
        name: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        /// Threshold for the summary (default: from config, else 60).
        #[arg(long)]
        threshold: Option<u8>,
    },
    /// Print recent security events from the database.
    Events {
        /// Only events from the last N minutes.
        #[arg(long, default_value_t = 60)]
        since_mins: i64,
        /// blocked | suspicious
        #[arg(long)]
        action: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long)]
        json: bool,
    },
}

fn dns_config(path: &Path) -> Result<Dns> {
    let cfg = rp_core::config::load(path)?;
    cfg.dns.context("no [dns] section in the config")
}

async fn run(cfg: Dns, config_path: PathBuf) -> Result<()> {
    let (lists, warnings) = Lists::load(&cfg);
    for w in &warnings {
        eprintln!("rp-dns: warning: {w}");
    }
    eprintln!(
        "rp-dns: {} blocked, {} allowed domains; upstreams {:?}",
        lists.block.len(),
        lists.allow.len(),
        cfg.upstreams
    );
    let sink = events::start(PathBuf::from(&cfg.events_db), cfg.events_retention_days);
    let engine = Arc::new(Engine::new(cfg.clone(), lists, sink));

    let mut bound = 0;
    for addr in &cfg.listen {
        match (server::bind_udp(*addr), server::bind_tcp(*addr)) {
            (Ok(u), Ok(t)) => {
                tokio::spawn(server::serve_udp(u, engine.clone()));
                tokio::spawn(server::serve_tcp(t, engine.clone()));
                eprintln!("rp-dns: listening on {addr} (udp+tcp)");
                bound += 1;
            }
            (Err(e), _) | (_, Err(e)) => eprintln!("rp-dns: warning: cannot listen on {addr}: {e}"),
        }
    }
    anyhow::ensure!(bound > 0, "could not bind any listen address");

    #[cfg(unix)]
    {
        let engine = engine.clone();
        tokio::spawn(async move {
            let Ok(mut hup) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
            else {
                return;
            };
            while hup.recv().await.is_some() {
                match dns_config(&config_path) {
                    Ok(c) => {
                        let (lists, warnings) = Lists::load(&c);
                        for w in &warnings {
                            eprintln!("rp-dns: warning: {w}");
                        }
                        eprintln!("rp-dns: reloaded lists ({} blocked)", lists.block.len());
                        *engine.lists.write().unwrap() = Arc::new(lists);
                    }
                    Err(e) => eprintln!("rp-dns: reload failed, keeping old lists: {e:#}"),
                }
            }
        });
    }

    shutdown_signal().await;
    let s = &engine.stats;
    eprintln!(
        "rp-dns: stopping: queries={} blocked={} suspicious={} refused={} malformed={} upstream_failures={} events_dropped={}",
        s.queries.load(Ordering::Relaxed),
        s.blocked.load(Ordering::Relaxed),
        s.suspicious.load(Ordering::Relaxed),
        s.refused.load(Ordering::Relaxed),
        s.malformed.load(Ordering::Relaxed),
        s.upstream_failures.load(Ordering::Relaxed),
        engine.events.dropped.load(Ordering::Relaxed),
    );
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("signal handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = (|| -> Result<()> {
        match cli.cmd.unwrap_or(Cmd::Run) {
            Cmd::Run => {
                let cfg = dns_config(&cli.config)?;
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?
                    .block_on(run(cfg, cli.config.clone()))
            }
            Cmd::Check => {
                let cfg = dns_config(&cli.config)?;
                let (lists, warnings) = Lists::load(&cfg);
                for w in &warnings {
                    println!("warning: {w}");
                }
                println!(
                    "dns config OK: {} blocked, {} allowed, {} upstream(s)",
                    lists.block.len(),
                    lists.allow.len(),
                    cfg.upstreams.len()
                );
                Ok(())
            }
            Cmd::Score { name, file, threshold } => {
                let threshold = threshold
                    .or_else(|| dns_config(&cli.config).ok().map(|d| d.suspicious_threshold))
                    .unwrap_or(60);
                if let Some(f) = file {
                    let text = std::fs::read_to_string(&f)?;
                    let names: Vec<String> = text
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .filter_map(rp_dns::lists::normalize)
                        .collect();
                    let flagged: Vec<&String> =
                        names.iter().filter(|n| score::score(n).value >= threshold).collect();
                    let rate = if names.is_empty() {
                        0.0
                    } else {
                        flagged.len() as f64 / names.len() as f64
                    };
                    println!(
                        "{}",
                        serde_json::json!({
                            "names": names.len(), "flagged": flagged.len(), "rate": rate,
                            "threshold": threshold, "examples": flagged.iter().take(10).collect::<Vec<_>>(),
                        })
                    );
                    return Ok(());
                }
                let name = name.context("give a NAME or --file")?;
                let n = rp_dns::lists::normalize(&name).context("not a valid DNS name")?;
                let s = score::score(&n);
                println!("{n}: score {} {:?}", s.value, s.reasons);
                Ok(())
            }
            Cmd::Events { since_mins, action, limit, json } => {
                let cfg = dns_config(&cli.config)?;
                let since = events::now_secs() - since_mins * 60;
                let rows =
                    events::query(Path::new(&cfg.events_db), since, action.as_deref(), limit)?;
                if json {
                    let v: Vec<_> = rows.iter().map(|e| e.json()).collect();
                    println!("{}", serde_json::to_string_pretty(&v)?);
                } else {
                    for e in rows {
                        println!(
                            "{} {:<10} {:<15} {:<6} {} ({}, score {})",
                            e.ts, e.action, e.client, e.qtype, e.qname, e.reason, e.score
                        );
                    }
                }
                Ok(())
            }
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rp-dns: error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
