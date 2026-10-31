//! rp-probe — audit and test helper invoked by the Robot Framework suites.
//!
//! Exit codes: 0 clean · 1 findings or error.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod secrets;
mod tput;

#[derive(Parser)]
#[command(name = "rp-probe", version, about = "Audit and test helper for rp")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Accept one TCP connection and report received throughput as JSON.
    TputServer {
        #[arg(long)]
        bind: std::net::SocketAddr,
    },
    /// Send data for --seconds and report throughput as JSON.
    TputClient {
        #[arg(long)]
        connect: std::net::SocketAddr,
        #[arg(long, default_value_t = 5.0)]
        seconds: f64,
    },
    /// Scan files/directories for leaked secrets and real network identifiers.
    SecretScan {
        /// Env file whose sensitive values must never appear (e.g. local.env).
        #[arg(long)]
        env_file: Option<PathBuf>,
        /// Print findings as JSON.
        #[arg(long)]
        json: bool,
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::TputServer { bind } => match tput::serve_once(bind) {
            Ok(r) => {
                println!("{}", r.json("server"));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::TputClient { connect, seconds } => match tput::send(connect, seconds) {
            Ok(r) => {
                println!("{}", r.json("client"));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::SecretScan { env_file, json, paths } => {
            let values = env_file
                .and_then(|p| std::fs::read_to_string(p).ok())
                .map(|t| secrets::sensitive_values(&t))
                .unwrap_or_default();
            let findings = secrets::scan_paths(&paths, &values);
            if json {
                let v: Vec<_> = findings
                    .iter()
                    .map(|f| serde_json::json!({"file": f.file, "line": f.line, "kind": f.kind}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                // Never echo the matched text itself — only where and what kind.
                for f in &findings {
                    println!("{}:{}: {}", f.file, f.line, f.kind);
                }
                println!(
                    "checked {} sensitive value(s); findings: {}",
                    values.len(),
                    findings.len()
                );
            }
            if findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
