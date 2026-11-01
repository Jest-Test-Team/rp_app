//! rp-probe — audit and test helper invoked by the Robot Framework suites.
//!
//! Exit codes: 0 clean · 1 findings or error.

use std::path::PathBuf;
use std::process::ExitCode;

use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, Subcommand};

mod console;
mod dnsprobe;
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
    /// Console API helpers (signing, pairing proofs, rp-privd requests).
    #[command(subcommand)]
    Console(console::ConsoleCmd),
    /// Send one DNS query and print {rcode, answers, ms} as JSON.
    DnsQuery {
        #[arg(long)]
        server: std::net::SocketAddr,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "A")]
        r#type: String,
        #[arg(long)]
        tcp: bool,
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
    },
    /// Send N queries and print latency percentiles as JSON.
    DnsBench {
        #[arg(long)]
        server: std::net::SocketAddr,
        #[arg(long, default_value = "www.example.")]
        name: String,
        #[arg(long, default_value_t = 200)]
        count: u32,
    },
    /// Send raw bytes (hex) over UDP and report whether anything came back.
    DnsRaw {
        #[arg(long)]
        server: std::net::SocketAddr,
        #[arg(long)]
        hex: String,
    },
    /// Run a fake upstream resolver (answers 203.0.113.99), or a dead one with --silent.
    DnsFakeUpstream {
        #[arg(long)]
        bind: std::net::SocketAddr,
        #[arg(long)]
        silent: bool,
    },
    /// Send one JSON-RPC message to an MCP HTTP endpoint and print the reply as JSON:
    /// {"status": <http>, "body": <reply>}. The token is read from an env var so it
    /// never appears in process listings.
    Mcp {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "/mcp")]
        path: String,
        /// Environment variable holding the bearer token (omit for none).
        #[arg(long)]
        token_env: Option<String>,
        #[arg(long)]
        method: String,
        #[arg(long, default_value = "{}")]
        params: String,
        /// Send as a notification (no id).
        #[arg(long)]
        notify: bool,
        /// Extra header NAME:VALUE (repeatable), e.g. Origin:http://evil.example
        #[arg(long)]
        header: Vec<String>,
        /// Send this raw body instead of a JSON-RPC message.
        #[arg(long)]
        raw: Option<String>,
    },
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
        Cmd::Console(c) => match console::run(c) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Cmd::Mcp { addr, path, token_env, method, params, notify, header, raw } => {
            let token = token_env.and_then(|v| std::env::var(v).ok());
            let params: serde_json::Value = match serde_json::from_str(&params) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: --params is not JSON: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let mut msg = serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params});
            if !notify {
                msg["id"] = serde_json::json!(1);
            }
            let headers: Vec<(String, String)> = header
                .iter()
                .filter_map(|h| {
                    h.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            let hdr_refs: Vec<(&str, &str)> =
                headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            let r = rt.block_on(async {
                match raw {
                    Some(body) => raw_post(&addr, &path, token.as_deref(), &body).await,
                    None => {
                        rp_http::request_with_headers(
                            &addr,
                            "POST",
                            &path,
                            token.as_deref(),
                            &hdr_refs,
                            Some(&msg),
                        )
                        .await
                    }
                }
            });
            match r {
                Ok((status, body)) => {
                    println!("{}", serde_json::json!({"status": status, "body": body}));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("{}", serde_json::json!({"status": 0, "error": e}));
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::DnsQuery { server, name, r#type, tcp, timeout_ms } => {
            let qtype = match hickory_proto::rr::RecordType::from_str(&r#type.to_uppercase()) {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("error: bad type: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match dnsprobe::query(server, &name, qtype, tcp, Duration::from_millis(timeout_ms)) {
                Ok(a) => {
                    println!("{}", a.json());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    println!("{}", serde_json::json!({"rcode": "Timeout", "error": e.to_string()}));
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::DnsBench { server, name, count } => {
            let mut ms = Vec::new();
            let mut failures = 0;
            let mut rcodes = std::collections::BTreeMap::<String, u32>::new();
            for _ in 0..count {
                match dnsprobe::query(
                    server,
                    &name,
                    hickory_proto::rr::RecordType::A,
                    false,
                    Duration::from_secs(2),
                ) {
                    Ok(a) => {
                        ms.push(a.millis);
                        *rcodes.entry(a.rcode).or_default() += 1;
                    }
                    Err(_) => failures += 1,
                }
            }
            ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let pct = |p: f64| {
                ms.get(((ms.len() as f64 - 1.0) * p).round() as usize).copied().unwrap_or(0.0)
            };
            println!(
                "{}",
                serde_json::json!({"count": count, "failures": failures, "rcodes": rcodes, "p50_ms": pct(0.5), "p95_ms": pct(0.95), "p99_ms": pct(0.99)})
            );
            if failures == count {
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }
        Cmd::DnsRaw { server, hex } => {
            let bytes: Result<Vec<u8>, _> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(hex.get(i..i + 2).unwrap_or("zz"), 16))
                .collect();
            match bytes {
                Ok(b) => match dnsprobe::send_raw(server, &b, Duration::from_millis(800)) {
                    Ok(got) => {
                        println!("{}", serde_json::json!({"reply": got}));
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        ExitCode::FAILURE
                    }
                },
                Err(_) => {
                    eprintln!("error: --hex must be hex bytes");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::DnsFakeUpstream { bind, silent } => match dnsprobe::fake_upstream(bind, silent) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },
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

/// POST an arbitrary body (for malformed-input tests).
async fn raw_post(
    addr: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> Result<(u16, serde_json::Value), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let auth = token.map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n{auth}Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    let mut out = String::new();
    s.read_to_string(&mut out).await.map_err(|e| e.to_string())?;
    let (head, rest) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let status = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((status, serde_json::from_str(rest).unwrap_or(serde_json::Value::Null)))
}
