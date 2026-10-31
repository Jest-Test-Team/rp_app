//! rpctl — configure, apply and roll back the rp edge security gateway.
//!
//! Exit codes: 0 ok · 1 error · 2 preflight failed · 3 invalid config.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rp_core::apply::{self, ApplyOptions, Target};
use rp_core::files::under_root;
use rp_core::module::{lookup, Module, MODULES};
use rp_core::preflight::{self, Status};
use rp_core::runner::{RecordingRunner, Runner, SystemRunner};
use rp_schema::Config;

const EXIT_PREFLIGHT: u8 = 2;
const EXIT_CONFIG: u8 = 3;

#[derive(Parser)]
#[command(name = "rpctl", version, about = "Raspberry Pi edge security gateway control")]
struct Cli {
    /// Config file.
    #[arg(long, env = "RP_CONFIG", default_value = "/etc/rp/rp.toml", global = true)]
    config: PathBuf,
    /// Alternate filesystem root (testing / image preparation).
    #[arg(long, default_value = "/", global = true)]
    root: PathBuf,
    /// Machine-readable output.
    #[arg(long, global = true)]
    json: bool,
    /// Record commands to FILE instead of running them (testing).
    #[arg(long, hide = true, global = true)]
    record_commands: Option<PathBuf>,
    /// With --record-commands: comma-separated command prefixes that fail.
    #[arg(long, hide = true, global = true)]
    fail_commands: Option<String>,
    /// With --record-commands: canned stdout, `PREFIX=STDOUT` (repeatable).
    #[arg(long, hide = true, global = true)]
    fake_output: Vec<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List modules.
    Modules,
    /// Validate the config file.
    Check,
    /// Check that the system is safe to apply a module to.
    Preflight { module: String },
    /// Print (or write to --out) the files a module manages.
    Render {
        module: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Apply a module.
    Apply {
        module: String,
        /// Show the diff and commands without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Do not apt-get install missing packages.
        #[arg(long)]
        no_packages: bool,
        /// Do not arm the automatic-rollback timer for firewall changes.
        #[arg(long)]
        no_confirm_timer: bool,
    },
    /// Keep the last firewall change (cancels the automatic rollback).
    Confirm,
    /// Restore files from the last (or a given) backup.
    Rollback {
        module: String,
        #[arg(long)]
        backup: Option<String>,
        /// Invoked by the automatic-rollback timer.
        #[arg(long, hide = true)]
        auto: bool,
    },
    /// Show module state and drift.
    Status,
    /// VPN helpers.
    #[command(subcommand)]
    Vpn(VpnCmd),
}

#[derive(Subcommand)]
enum VpnCmd {
    /// Create a WireGuard client: prints its config and QR code once, plus the
    /// TOML to add to rp.toml. The client's private key is never stored.
    AddPeer {
        name: String,
        /// Host number inside the tunnel subnet (default: next free).
        #[arg(long)]
        host: Option<u32>,
        /// Do not print the QR code.
        #[arg(long)]
        no_qr: bool,
    },
}

fn module(name: &str) -> Result<Box<dyn Module>> {
    lookup(name).with_context(|| format!("unknown module '{name}' (known: {})", MODULES.join(", ")))
}

/// A module that is configured, or an error explaining why not.
fn enabled_module(name: &str, cfg: &Config) -> Result<Box<dyn Module>> {
    let m = module(name)?;
    m.enabled(cfg).map_err(|e| anyhow::anyhow!("module '{name}' is not configured: {e}"))?;
    Ok(m)
}

fn load_config(path: &Path) -> std::result::Result<Config, ExitCode> {
    rp_core::config::load(path).map_err(|e| {
        eprintln!("error: {e}");
        ExitCode::from(EXIT_CONFIG)
    })
}

fn print_checks(checks: &[preflight::Check], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(checks).unwrap());
        return;
    }
    for c in checks {
        let mark = match c.status {
            Status::Pass => "PASS",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        };
        println!("[{mark}] {:<16} {}", c.name, c.detail);
    }
}

fn run(cli: &Cli, runner: &dyn Runner) -> Result<ExitCode> {
    let target = Target { root: cli.root.clone(), runner };
    match &cli.cmd {
        Cmd::Modules => {
            for m in MODULES {
                println!("{m}");
            }
        }
        Cmd::Check => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&cfg)?);
            } else {
                println!("config OK: {}", cli.config.display());
            }
        }
        Cmd::Preflight { module: name } => {
            module(name)?;
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let facts = preflight::gather(&cfg, &target);
            let checks = preflight::evaluate(&cfg, name, &facts, false);
            print_checks(&checks, cli.json);
            if !preflight::passed(&checks) {
                return Ok(ExitCode::from(EXIT_PREFLIGHT));
            }
        }
        Cmd::Render { module: name, out } => {
            module(name)?;
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let m = enabled_module(name, &cfg)?;
            for f in m.render(&cfg) {
                match out {
                    Some(dir) => {
                        let p = under_root(dir, &f.path);
                        std::fs::create_dir_all(p.parent().unwrap())?;
                        std::fs::write(&p, &f.content)?;
                        println!("{}", p.display());
                    }
                    None => println!("==> {} (mode {:o})\n{}", f.path, f.mode, f.content),
                }
            }
        }
        Cmd::Apply { module: name, dry_run, no_packages, no_confirm_timer } => {
            module(name)?;
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let m = enabled_module(name, &cfg)?;
            let facts = preflight::gather(&cfg, &target);
            let checks = preflight::evaluate(&cfg, name, &facts, *dry_run);
            if !preflight::passed(&checks) {
                print_checks(&checks, false);
                eprintln!("preflight failed; nothing was changed");
                return Ok(ExitCode::from(EXIT_PREFLIGHT));
            }
            let opts = ApplyOptions {
                dry_run: *dry_run,
                install_packages: !no_packages,
                dead_man_secs: (!no_confirm_timer).then_some(cfg.base.confirm_timeout_secs),
                rpctl_argv: self_argv(cli)?,
            };
            let report = apply::apply(m.as_ref(), &cfg, &target, &opts)?;
            if report.changes.is_empty() {
                println!("{name}: already up to date");
                return Ok(ExitCode::SUCCESS);
            }
            for c in &report.changes {
                print!("{}", c.diff);
            }
            let verb = if *dry_run { "would run" } else { "ran" };
            for s in &report.steps {
                println!("{verb}: {s}");
            }
            if *dry_run {
                println!("dry run: {} file(s) would change", report.changes.len());
            } else {
                println!("{name}: applied {} file(s)", report.changes.len());
                for n in m.next_steps(&cfg) {
                    println!("next: {n}");
                }
                if report.needs_confirm {
                    println!(
                        "IMPORTANT: run `rpctl confirm` within {}s or the change is rolled back automatically",
                        cfg.base.confirm_timeout_secs
                    );
                }
            }
        }
        Cmd::Confirm => {
            let done = apply::confirm(&target)?;
            if done.is_empty() {
                println!("nothing to confirm");
            } else {
                println!("confirmed: {}", done.join(", "));
            }
        }
        Cmd::Rollback { module: name, backup, auto } => {
            let m = module(name)?;
            let rep = apply::rollback(m.as_ref(), &target, backup.as_deref())?;
            let why = if *auto { " (automatic: change was not confirmed)" } else { "" };
            println!(
                "{name}: rolled back {} file(s) from backup {}{why}",
                rep.changes.len(),
                rep.backup_id.unwrap_or_default()
            );
        }
        Cmd::Vpn(VpnCmd::AddPeer { name, host, no_qr }) => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            return add_peer(&cfg, &cli.root, name, *host, !no_qr);
        }
        Cmd::Status => {
            let cfg = load_config(&cli.config).ok();
            let state = target.load_state();
            let mut rows = Vec::new();
            for name in MODULES {
                let m = module(name)?;
                let st = state.modules.get(*name);
                let drift = cfg.as_ref().map(|c| apply::plan(m.as_ref(), c, &target).len());
                rows.push(serde_json::json!({
                    "module": name,
                    "applied": st.map(|s| !s.rolled_back).unwrap_or(false),
                    "confirmed": st.map(|s| s.confirmed).unwrap_or(false),
                    "backup_id": st.map(|s| s.backup_id.clone()),
                    "pending_changes": drift,
                }));
            }
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for r in rows {
                    println!(
                        "{:<6} applied={} confirmed={} pending_changes={}",
                        r["module"].as_str().unwrap_or(""),
                        r["applied"],
                        r["confirmed"],
                        r["pending_changes"]
                    );
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn add_peer(
    cfg: &Config,
    root: &Path,
    name: &str,
    host: Option<u32>,
    qr: bool,
) -> Result<ExitCode> {
    use rp_core::wg;
    let Some(v) = cfg.vpn.as_ref().filter(|v| v.mode == rp_schema::VpnMode::Wireguard) else {
        anyhow::bail!("vpn.mode must be \"wireguard\" to add peers");
    };
    if v.wireguard.endpoint.is_none() {
        anyhow::bail!("set vpn.wireguard.endpoint (public host:port) first");
    }
    if v.wireguard.peers.iter().any(|p| p.name == name) {
        anyhow::bail!("a peer named '{name}' already exists");
    }
    let host = match host {
        Some(h) => h,
        None => wg::next_free_host(cfg).context("tunnel subnet is full")?,
    };
    let key_path = under_root(root, wg::SERVER_KEY_PATH);
    let server_private = std::fs::read_to_string(&key_path).with_context(|| {
        format!("cannot read {} (run `sudo rpctl apply vpn` first, as root)", key_path.display())
    })?;
    let server_public = wg::public_from_private(&server_private).map_err(anyhow::Error::msg)?;

    let kp = wg::generate();
    let mut candidate = cfg.clone();
    candidate.vpn.as_mut().unwrap().wireguard.peers.push(rp_schema::WgPeer {
        name: name.to_string(),
        public_key: kp.public.clone(),
        host,
    });
    rp_core::config::validate(&candidate)?;

    let client = wg::client_config(cfg, host, &kp.private, &server_public);
    println!("# ---- client config for '{name}' (shown ONCE; the private key is not stored) ----");
    print!("{client}");
    if qr {
        let code = qrcode::QrCode::new(client.as_bytes())?;
        let art = code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build();
        println!("\n{art}");
    }
    println!("# ---- add this to /etc/rp/rp.toml, then run: sudo rpctl apply vpn ----");
    print!("{}", wg::peer_toml(name, &kp.public, host));
    Ok(ExitCode::SUCCESS)
}

/// argv the dead-man timer uses to call this binary back with the same config.
fn self_argv(cli: &Cli) -> Result<Vec<String>> {
    let exe = std::env::current_exe().context("cannot locate rpctl binary")?;
    let config = std::path::absolute(&cli.config)?;
    let mut v = vec![exe.display().to_string(), "--config".into(), config.display().to_string()];
    if cli.root != Path::new("/") {
        v.extend(["--root".into(), std::path::absolute(&cli.root)?.display().to_string()]);
    }
    Ok(v)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match &cli.record_commands {
        Some(path) => {
            let fails: Vec<&str> = cli
                .fail_commands
                .as_deref()
                .map(|s| s.split(',').filter(|p| !p.is_empty()).collect())
                .unwrap_or_default();
            let mut rec = RecordingRunner::failing(&fails);
            for spec in &cli.fake_output {
                let (prefix, out) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
                rec = rec.with_response(prefix, &out.replace("\\n", "\n"));
            }
            let r = run(&cli, &rec);
            let mut log = std::fs::read_to_string(path).unwrap_or_default();
            for c in rec.calls() {
                log.push_str(&c);
                log.push('\n');
            }
            if let Err(e) = std::fs::write(path, log) {
                eprintln!("error: cannot write {}: {e}", path.display());
            }
            r
        }
        None => run(&cli, &SystemRunner),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn unknown_module_is_an_error() {
        assert!(module("nope").is_err());
        assert!(module("base").is_ok());
    }
}
