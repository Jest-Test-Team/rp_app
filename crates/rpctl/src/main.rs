//! rpctl — configure, apply and roll back the rp edge security gateway.
//!
//! Exit codes: 0 ok · 1 error · 2 preflight failed · 3 invalid config ·
//! 4 revision conflict or another change in progress.

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
    /// What this hardware can run (per module, with reasons). Always JSON.
    Capabilities {
        /// Management client address: its route decides the management link.
        #[arg(long)]
        peer: Option<std::net::IpAddr>,
        /// Evaluate a hardware-facts JSON file instead of this system (testing).
        #[arg(long)]
        facts: Option<PathBuf>,
    },
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
    /// Remove a module: restore the files from before it was first applied
    /// (or from a given backup).
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
    /// Access point helpers.
    #[command(subcommand)]
    Ap(ApCmd),
    /// MCP client management.
    #[command(subcommand)]
    Mcp(McpCmd),
    /// Manage the DNS blocklist file (the first entry of dns.blocklists).
    #[command(subcommand)]
    Dns(DnsCmd),
    /// List privileged action requests.
    Actions,
    /// Approve a pending privileged request and apply it (human decision).
    Approve { id: String },
    /// Deny a pending privileged request.
    Deny { id: String },
    /// Re-add unexpired approved quarantines after a firewall reload.
    #[command(hide = true)]
    QuarantineRestore,
    /// Audit log tools.
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Revision-checked configuration changes with automatic rollback (what
    /// the console app uses).
    #[command(subcommand)]
    Changeset(ChangesetCmd),
    /// Store a named secret (ap_passphrase, tailscale_auth_key) root-only, from stdin.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Pair the console app: open a one-time pairing code (QR).
    #[command(subcommand)]
    Pairing(PairingCmd),
    /// Console admins (paired app installations).
    #[command(subcommand)]
    Admins(AdminsCmd),
    /// Write a first config for the network this device is on.
    Init {
        /// Detect the uplink and LAN (required: say you mean it).
        #[arg(long)]
        auto: bool,
        /// Replace an existing config (a backup is kept).
        #[arg(long)]
        force: bool,
        /// Print instead of writing.
        #[arg(long)]
        print: bool,
    },
    /// Prepare a freshly flashed SD card (boot partition).
    #[command(subcommand)]
    Bootfs(BootfsCmd),
    /// Get this device ready for the console app (idempotent): write a config
    /// if there is none, enable [agent] and [api], apply base, agent and api,
    /// and open pairing when no app is paired yet.
    Setup {
        /// Minutes the pairing code stays valid.
        #[arg(long, default_value_t = 30)]
        pairing_minutes: u32,
        /// Do not open pairing (a secret was placed on the SD card).
        #[arg(long)]
        no_pairing: bool,
        /// Do not apt-get install missing packages.
        #[arg(long)]
        no_packages: bool,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)] // parsed once per process
enum BootfsCmd {
    /// Print the files for a provisioning spec (JSON) as {"name": "content"} —
    /// deterministic, for golden tests shared with the app.
    #[command(hide = true)]
    Render {
        #[arg(long)]
        spec: PathBuf,
    },
    /// Write first-boot files: the device installs rp and waits to be paired.
    Write {
        /// Mounted boot partition (contains cmdline.txt and meta-data).
        #[arg(long)]
        dir: PathBuf,
        /// Release to install, e.g. v0.2.0.
        #[arg(long)]
        tag: String,
        /// SHA-256 of that release's install.sh (see its SHA256SUMS).
        #[arg(long)]
        install_sha256: String,
        #[arg(long, default_value = "rp-security")]
        hostname: String,
        #[arg(long, default_value = rp_core::provision::DEFAULT_REPO)]
        repo: String,
        /// Create this admin user (key login only).
        #[arg(long, requires = "ssh_key_file")]
        admin_user: Option<String>,
        #[arg(long, requires = "admin_user")]
        ssh_key_file: Option<PathBuf>,
        /// Join this Wi-Fi network (password read from stdin).
        #[arg(long, requires = "wifi_country")]
        wifi_ssid: Option<String>,
        #[arg(long)]
        wifi_country: Option<String>,
        #[arg(long)]
        timezone: Option<String>,
        #[arg(long)]
        no_qr: bool,
    },
}

#[derive(Subcommand)]
enum PairingCmd {
    /// Create a one-time pairing secret and show it as a QR code for the app.
    New {
        /// Minutes the code stays valid.
        #[arg(long, default_value_t = 15)]
        minutes: u32,
        /// Host name or address the app should connect to (default: <hostname>.local).
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        no_qr: bool,
    },
    /// Close an open pairing code.
    Close,
}

#[derive(Subcommand)]
enum AdminsCmd {
    List,
    /// Revoke an admin (e.g. a lost phone).
    Revoke {
        id: String,
    },
}

#[derive(Subcommand)]
enum ChangesetCmd {
    /// Current configuration revision.
    Revision,
    /// Create a change set from a JSON patch of dotted keys.
    Create {
        module: String,
        #[arg(long)]
        expected_revision: u64,
        /// JSON object, e.g. '{"ap.block_dot": true}'.
        #[arg(long)]
        patch: String,
    },
    /// Run preflight checks for a change set.
    Preflight {
        id: String,
        /// Management client address (must stay allowed).
        #[arg(long)]
        peer: Option<std::net::IpAddr>,
    },
    /// Apply a preflighted change set and arm the rollback timer.
    Apply {
        id: String,
        /// Seconds to confirm before the device rolls back by itself.
        #[arg(long, default_value_t = rp_core::changeset::DEFAULT_CONFIRM_SECS)]
        confirm_secs: u32,
        #[arg(long)]
        no_packages: bool,
    },
    /// Keep an applied change set.
    Confirm {
        id: String,
    },
    /// Undo the latest applied change set.
    Rollback {
        id: String,
    },
    /// Called by the rollback timer.
    #[command(hide = true)]
    Expire {
        id: String,
    },
    Show {
        id: String,
    },
    List,
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Read the value from stdin (one line) and store it with mode 600.
    Set { name: String },
    /// Show which secrets are set (never their values).
    Status,
}

#[derive(Subcommand)]
enum McpCmd {
    /// Create a client token (printed once; only its hash is stored).
    AddClient {
        name: String,
        /// Comma-separated: read, active, privileged
        #[arg(long, default_value = "read")]
        cap: String,
    },
    /// Revoke a client.
    RemoveClient { name: String },
    /// List clients and their capabilities.
    Clients,
}

#[derive(Subcommand)]
enum DnsCmd {
    /// Show blocked domains in the list file.
    List {
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Block domains (subdomains included). Creates the file if needed.
    Block {
        #[arg(required = true)]
        domains: Vec<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        no_reload: bool,
    },
    /// Unblock domains.
    Unblock {
        #[arg(required = true)]
        domains: Vec<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        no_reload: bool,
    },
    /// Merge a hosts-format or one-domain-per-line list (file or https URL).
    Import {
        /// Local file to import.
        source: Option<PathBuf>,
        /// Download from an https URL instead.
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long)]
        no_reload: bool,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the hash chains of the agent and MCP audit logs.
    Verify,
}

#[derive(Subcommand)]
enum ApCmd {
    /// Set the WPA2 passphrase (8-63 chars). Prompted without echo, or read
    /// from stdin with --stdin. Stored root-only, never printed or logged.
    SetPassphrase {
        #[arg(long)]
        stdin: bool,
    },
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
        /// Also add the peer to the config file (a backup is kept).
        #[arg(long)]
        write: bool,
    },
    /// Revoke a WireGuard client: remove it from the config file (a backup is
    /// kept). Run `rpctl apply vpn` afterwards to drop it from the tunnel.
    RemovePeer { name: String },
    /// List WireGuard clients.
    Peers,
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
    // Real changes share one lock with change sets (the app) so they can't interleave.
    // The dead-man timer's rollback waits for the lock instead of giving up.
    use rp_core::changeset::Lock;
    let _lock = match &cli.cmd {
        Cmd::Rollback { auto: true, .. } => Some(Lock::wait(&target)),
        Cmd::Apply { dry_run: false, .. } | Cmd::Confirm | Cmd::Rollback { .. } => {
            Some(Lock::acquire(&target))
        }
        _ => None,
    }
    .transpose()
    .map_err(|e| anyhow::anyhow!("{e}"))?;
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
        Cmd::Capabilities { peer, facts } => {
            let hw = match facts {
                Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)
                    .with_context(|| format!("invalid facts file {}", p.display()))?,
                None => {
                    let cfg = rp_core::config::load(&cli.config).ok();
                    rp_core::capabilities::gather(&target, cfg.as_ref(), *peer)
                }
            };
            println!("{}", serde_json::to_string_pretty(&rp_core::capabilities::evaluate(&hw))?);
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
            let rep = if *auto {
                apply::rollback_last(m.as_ref(), &target)?
            } else {
                apply::rollback(m.as_ref(), &target, backup.as_deref())?
            };
            let why = if *auto { " (automatic: change was not confirmed)" } else { "" };
            println!(
                "{name}: rolled back {} file(s) from backup {}{why}",
                rep.changes.len(),
                rep.backup_id.unwrap_or_default()
            );
        }
        Cmd::Vpn(VpnCmd::AddPeer { name, host, no_qr, write }) => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let peer = add_peer(&cfg, &cli.root, name, *host, !no_qr)?;
            if *write {
                edit_config(&cli.config, |doc| {
                    let peers = peers_array(doc)?;
                    let mut t = toml_edit::Table::new();
                    t["name"] = toml_edit::value(peer.name.clone());
                    t["public_key"] = toml_edit::value(peer.public_key.clone());
                    t["host"] = toml_edit::value(i64::from(peer.host));
                    peers.push(t);
                    Ok(())
                })?;
                println!(
                    "added '{name}' to {} — now run: sudo rpctl apply vpn",
                    cli.config.display()
                );
            }
        }
        Cmd::Vpn(VpnCmd::RemovePeer { name }) => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let known = cfg.vpn.as_ref().map(|v| v.wireguard.peers.iter().any(|p| &p.name == name));
            if known != Some(true) {
                anyhow::bail!("no WireGuard peer named '{name}'");
            }
            edit_config(&cli.config, |doc| {
                let peers = peers_array(doc)?;
                peers.retain(|t| t.get("name").and_then(|v| v.as_str()) != Some(name.as_str()));
                Ok(())
            })?;
            println!(
                "revoked '{name}' in {} — now run: sudo rpctl apply vpn",
                cli.config.display()
            );
        }
        Cmd::Vpn(VpnCmd::Peers) => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            for p in cfg.vpn.iter().flat_map(|v| v.wireguard.peers.iter()) {
                println!(
                    "{:<20} host={:<4} {}",
                    p.name,
                    p.host,
                    rp_core::vpn::wg_peer_addr(&cfg, p.host)
                );
            }
        }
        Cmd::Ap(ApCmd::SetPassphrase { stdin }) => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let a = cfg.ap.as_ref().context("no [ap] section in the config")?;
            let pass = if *stdin {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                line.trim_end_matches(['\r', '\n']).to_string()
            } else {
                let p = rpassword::prompt_password("New Wi-Fi passphrase: ")?;
                let again = rpassword::prompt_password("Repeat: ")?;
                anyhow::ensure!(p == again, "passphrases do not match");
                p
            };
            anyhow::ensure!(
                rp_core::ap::valid_passphrase(&pass),
                "passphrase must be 8-63 printable ASCII characters"
            );
            let path = under_root(&cli.root, &a.passphrase_file);
            write_secret(&path, &rp_core::ap::psk_file_content(&pass))?;
            println!("passphrase saved to {} (mode 600)", a.passphrase_file);
            println!("apply or re-apply: sudo rpctl apply ap   (hostapd re-reads it on restart)");
        }
        Cmd::Changeset(c) => return changeset_cmd(cli, c, &target),
        Cmd::Secret(SecretCmd::Set { name }) => {
            let cfg = rp_core::config::load(&cli.config).ok();
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            let value = line.trim_end_matches(['\r', '\n']);
            let fp = rp_core::secrets::set(&cli.root, cfg.as_ref(), name, value)?;
            println!("{name} stored (fingerprint {fp})");
        }
        Cmd::Secret(SecretCmd::Status) => {
            let cfg = rp_core::config::load(&cli.config).ok();
            for n in rp_core::secrets::NAMES {
                let set = rp_core::secrets::is_set(&cli.root, cfg.as_ref(), n);
                println!("{n:<20} {}", if set { "set" } else { "not set" });
            }
        }
        Cmd::Pairing(PairingCmd::New { minutes, host, no_qr }) => {
            anyhow::ensure!((1..=1440).contains(minutes), "--minutes must be 1-1440");
            let dev = rp_privd::device_id(&cli.root)?;
            let cert = rp_privd::cert_sha256(&cli.root)
                .context("rp-api has no TLS certificate yet: apply the api module first (sudo rpctl apply api)")?;
            let secret = rp_policy::pairing::open(
                &under_root(&cli.root, rp_privd::PAIRING),
                rp_core::changeset::now(),
                Some(i64::from(*minutes) * 60),
            )?;
            let cfg = rp_core::config::load(&cli.config).ok();
            let port = cfg.and_then(|c| c.api).map(|a| a.listen.port()).unwrap_or(8443);
            let host = host.clone().unwrap_or_else(|| {
                let h = std::fs::read_to_string(under_root(&cli.root, "/etc/hostname"))
                    .unwrap_or_default();
                format!("{}.local", h.trim())
            });
            let payload = serde_json::json!({
                "v": 1, "host": host, "port": port, "device": dev, "secret": secret, "cert": cert,
            })
            .to_string();
            if !no_qr {
                let code = qrcode::QrCode::new(payload.as_bytes())?;
                println!(
                    "{}",
                    code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build()
                );
            }
            println!("Scan with the RP Security app (Add device > Pair with code), or enter:");
            println!("  host   {host}:{port}");
            println!("  code   {secret}");
            println!("  device {dev}");
            println!(
                "Valid for {minutes} minute(s), one use. Close early: sudo rpctl pairing close"
            );
        }
        Cmd::Init { auto, force, print } => {
            anyhow::ensure!(*auto, "pass --auto to detect the network and write a config");
            let path = &cli.config;
            if path.exists() && !force && !print {
                println!("{} exists; nothing to do (use --force to replace it)", path.display());
                return Ok(ExitCode::SUCCESS);
            }
            let d = rp_core::init::detect(&target).map_err(anyhow::Error::msg)?;
            let text = rp_core::init::render(&d);
            rp_core::config::parse(&text)?;
            if *print {
                print!("{text}");
                return Ok(ExitCode::SUCCESS);
            }
            if path.exists() {
                std::fs::copy(path, path.with_extension("toml.bak-init"))?;
            }
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, &text)?;
            println!(
                "wrote {} (uplink {}, LAN {})",
                path.display(),
                d.wan_if,
                d.lan_cidrs.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")
            );
        }
        Cmd::Bootfs(BootfsCmd::Render { spec }) => {
            let s: rp_core::provision::Spec =
                serde_json::from_str(&std::fs::read_to_string(spec)?)?;
            let files =
                rp_core::provision::files(&s).map_err(|e| anyhow::anyhow!("{}", e.join("; ")))?;
            let m: serde_json::Map<String, serde_json::Value> =
                files.into_iter().map(|(k, v)| (k, serde_json::Value::String(v))).collect();
            println!("{}", serde_json::to_string_pretty(&m)?);
        }
        Cmd::Bootfs(BootfsCmd::Write {
            dir,
            tag,
            install_sha256,
            hostname,
            repo,
            admin_user,
            ssh_key_file,
            wifi_ssid,
            wifi_country,
            timezone,
            no_qr,
        }) => {
            use rp_core::provision as pv;
            anyhow::ensure!(
                dir.join("cmdline.txt").exists() && dir.join("meta-data").exists(),
                "{} is not a freshly flashed Raspberry Pi OS boot partition (no cmdline.txt / meta-data)",
                dir.display()
            );
            let admin = match (admin_user, ssh_key_file) {
                (Some(u), Some(f)) => {
                    Some((u.clone(), std::fs::read_to_string(f)?.trim().to_string()))
                }
                _ => None,
            };
            let wifi = match wifi_ssid {
                Some(ssid) => {
                    let mut pw = String::new();
                    std::io::stdin().read_line(&mut pw)?;
                    Some(pv::Wifi {
                        ssid: ssid.clone(),
                        password: pw.trim_end_matches(['\r', '\n']).to_string(),
                        country: wifi_country.clone().unwrap_or_default(),
                    })
                }
                None => None,
            };
            let spec = pv::Spec {
                hostname: hostname.clone(),
                tag: tag.clone(),
                install_sha256: install_sha256.to_lowercase(),
                repo: repo.clone(),
                pairing_secret: rp_policy::pairing::new_secret(),
                instance_id: format!("rp-{}", rp_core::changeset::now()),
                admin,
                wifi,
                timezone: timezone.clone(),
            };
            let files = pv::files(&spec).map_err(|e| anyhow::anyhow!("{}", e.join("; ")))?;
            for (name, content) in &files {
                let p = dir.join(name);
                std::fs::write(&p, content)?;
            }
            let meta = std::fs::read_to_string(dir.join("meta-data")).unwrap_or_default();
            std::fs::write(dir.join("meta-data"), pv::meta_data(&meta, &spec.instance_id))?;
            let qr = pv::pairing_qr(&spec, 8443);
            if cli.json {
                println!("{qr}");
            } else {
                if !no_qr {
                    let code = qrcode::QrCode::new(qr.as_bytes())?;
                    println!(
                        "{}",
                        code.render::<qrcode::render::unicode::Dense1x2>().quiet_zone(true).build()
                    );
                }
                println!("Card ready: {} file(s) written to {}", files.len() + 1, dir.display());
                println!("Boot the device on your network, then pair in the app with this code:");
                println!("  host {}.local:8443", spec.hostname);
                println!("  code {}", spec.pairing_secret);
            }
        }
        Cmd::Setup { pairing_minutes, no_pairing, no_packages } => {
            return setup(cli, &target, *pairing_minutes, *no_pairing, *no_packages);
        }
        Cmd::Pairing(PairingCmd::Close) => {
            let p = under_root(&cli.root, rp_privd::PAIRING);
            if p.exists() {
                std::fs::remove_file(&p)?;
                println!("pairing closed");
            } else {
                println!("pairing was not open");
            }
        }
        Cmd::Admins(c) => {
            let p = under_root(&cli.root, rp_privd::ADMINS);
            let mut admins = rp_policy::admin::Admins::load(&p).map_err(anyhow::Error::msg)?;
            match c {
                AdminsCmd::List => {
                    for a in admins.active() {
                        println!("{}  {:<24} added {}", a.id, a.name, a.added_at);
                    }
                }
                AdminsCmd::Revoke { id } => {
                    anyhow::ensure!(admins.revoke(id), "no active admin '{id}'");
                    admins.save(&p)?;
                    println!("revoked {id}");
                }
            }
        }
        Cmd::Mcp(c) => return mcp_cmd(cli, c),
        Cmd::Dns(c) => return dns_cmd(cli, c, runner),
        Cmd::Actions => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let store = action_store(&cfg, &cli.root);
            let list = store.list();
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("no action requests");
            } else {
                for a in list {
                    println!(
                        "{}  {:<9} {:<15} by {:<12} {}",
                        a.id,
                        format!("{:?}", a.status).to_lowercase(),
                        a.tool,
                        a.principal,
                        a.summary
                    );
                }
            }
        }
        Cmd::Approve { id } | Cmd::Deny { id } => {
            let approve = matches!(cli.cmd, Cmd::Approve { .. });
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let admin =
                format!("admin:{}", std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into()));
            let a = rp_agent::admin_ops::decide(&cfg, &cli.root, id, approve, &admin, runner)
                .map_err(anyhow::Error::msg)?;
            if approve {
                println!("approved and applied {id}: {} (expires automatically)", a.summary);
            } else {
                println!("denied {id}: {}", a.summary);
            }
        }
        Cmd::QuarantineRestore => {
            let Ok(cfg) = rp_core::config::load(&cli.config) else { return Ok(ExitCode::SUCCESS) };
            if cfg.agent.is_none() || cfg.ap.is_none() {
                return Ok(ExitCode::SUCCESS);
            }
            let now = rp_policy::approvals::now();
            let mut restored = 0;
            for a in action_store(&cfg, &cli.root).list() {
                let Some(left) = a.remaining_minutes(now) else { continue };
                let mut args = a.args.clone();
                args["ttl_minutes"] = serde_json::json!(left);
                if let Ok(argv) = rp_agent::actions::command(&cfg, &a.tool, &args) {
                    if runner.run(&argv).map(|o| o.ok()).unwrap_or(false) {
                        restored += 1;
                    }
                }
            }
            println!("restored {restored} active quarantine(s)");
        }
        Cmd::Audit(AuditCmd::Verify) => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return Ok(code),
            };
            let mut logs = vec![agent_state(&cfg, &cli.root).join("audit.jsonl")];
            if let Some(m) = &cfg.mcp {
                logs.push(under_root(&cli.root, &m.audit_log));
            }
            logs.push(under_root(&cli.root, rp_privd::AUDIT));
            let mut bad = false;
            for l in logs {
                if !l.exists() {
                    println!("{}: (no log yet)", l.display());
                    continue;
                }
                match rp_policy::audit::verify(&l) {
                    Ok(n) => println!("{}: OK ({n} entries)", l.display()),
                    Err((line, why)) => {
                        bad = true;
                        println!("{}: BROKEN at line {line}: {why}", l.display());
                    }
                }
            }
            if bad {
                return Ok(ExitCode::FAILURE);
            }
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
) -> Result<rp_schema::WgPeer> {
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
    let peer = rp_schema::WgPeer { name: name.to_string(), public_key: kp.public.clone(), host };
    let mut candidate = cfg.clone();
    candidate.vpn.as_mut().unwrap().wireguard.peers.push(peer.clone());
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
    Ok(peer)
}

/// `[[vpn.wireguard.peers]]` in a TOML document, created if missing.
fn peers_array(doc: &mut toml_edit::DocumentMut) -> Result<&mut toml_edit::ArrayOfTables> {
    let vpn =
        doc.get_mut("vpn").and_then(|v| v.as_table_mut()).context("config has no [vpn] table")?;
    let wg = vpn.entry("wireguard").or_insert_with(|| toml_edit::Item::Table(Default::default()));
    let wg = wg.as_table_mut().context("[vpn.wireguard] is not a table")?;
    let peers =
        wg.entry("peers").or_insert_with(|| toml_edit::Item::ArrayOfTables(Default::default()));
    peers.as_array_of_tables_mut().context("vpn.wireguard.peers must be [[vpn.wireguard.peers]]")
}

/// Edit the config preserving comments/formatting; keeps a timestamped backup
/// and refuses to write a result that fails validation.
fn setup(
    cli: &Cli,
    t: &Target,
    pairing_minutes: u32,
    no_pairing: bool,
    no_packages: bool,
) -> Result<ExitCode> {
    let mut report = serde_json::Map::new();
    let say = |m: &str| {
        if !cli.json {
            println!("{m}");
        }
    };
    // 1. A config.
    if !cli.config.exists() {
        let d = rp_core::init::detect(t).map_err(anyhow::Error::msg)?;
        let text = rp_core::init::render(&d);
        rp_core::config::parse(&text)?;
        if let Some(dir) = cli.config.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&cli.config, text)?;
        say(&format!("wrote {} for uplink {}", cli.config.display(), d.wan_if));
        report.insert("config_written".into(), true.into());
    } else {
        report.insert("config_written".into(), false.into());
    }
    // 2. The sections the console needs (an existing v0.1 config has neither).
    let cfg = rp_core::config::load(&cli.config)?;
    let mut added = vec![];
    if cfg.agent.is_none() {
        added.push("agent");
    }
    if cfg.api.is_none() {
        added.push("api");
    }
    if !added.is_empty() {
        edit_config(&cli.config, |doc| {
            for sect in &added {
                doc[*sect] = toml_edit::Item::Table(toml_edit::Table::new());
            }
            Ok(())
        })?;
        say(&format!("enabled [{}] in {}", added.join("], ["), cli.config.display()));
    }
    report.insert("sections_added".into(), serde_json::json!(added));
    // 3. Apply. Locally there is no session to lose; over SSH, preflight's
    // lockout check already proved the session stays allowed (these modules
    // only add allow rules), so no confirm timer is armed.
    let cfg = rp_core::config::load(&cli.config)?;
    let mut applied = serde_json::Map::new();
    for name in ["base", "agent", "api"] {
        let m = module(name)?;
        let facts = preflight::gather(&cfg, t);
        let checks = preflight::evaluate(&cfg, name, &facts, false);
        if !preflight::passed(&checks) {
            if !cli.json {
                print_checks(&checks, false);
            }
            let failed: Vec<_> = checks.iter().filter(|c| c.status == Status::Fail).collect();
            report.insert("failed_module".into(), name.into());
            report.insert("checks".into(), serde_json::to_value(failed)?);
            if cli.json {
                println!("{}", serde_json::Value::Object(report));
            }
            eprintln!("setup stopped: preflight for {name} failed; nothing else was changed");
            return Ok(ExitCode::from(EXIT_PREFLIGHT));
        }
        let _lock = rp_core::changeset::Lock::acquire(t).map_err(|e| anyhow::anyhow!("{e}"))?;
        let opts = ApplyOptions {
            dry_run: false,
            install_packages: !no_packages,
            dead_man_secs: None,
            rpctl_argv: self_argv(cli)?,
        };
        let rep = apply::apply(m.as_ref(), &cfg, t, &opts)?;
        applied.insert(name.into(), serde_json::json!(rep.changes.len()));
        say(&format!(
            "{name}: {}",
            if rep.changes.is_empty() {
                "up to date".into()
            } else {
                format!("applied {} file(s)", rep.changes.len())
            }
        ));
    }
    report.insert("applied".into(), serde_json::Value::Object(applied));
    // 4. Pairing.
    let admins = rp_policy::admin::Admins::load(&under_root(&cli.root, rp_privd::ADMINS))
        .unwrap_or_default();
    let paired = admins.active().next().is_some();
    report.insert("paired".into(), paired.into());
    let pairing_file = under_root(&cli.root, rp_privd::PAIRING);
    if !no_pairing && !paired && !pairing_file.exists() {
        anyhow::ensure!((1..=1440).contains(&pairing_minutes), "--pairing-minutes must be 1-1440");
        let dev = rp_privd::device_id(&cli.root)?;
        let secret = rp_policy::pairing::open(
            &pairing_file,
            rp_core::changeset::now(),
            Some(i64::from(pairing_minutes) * 60),
        )?;
        let host =
            std::fs::read_to_string(under_root(&cli.root, "/etc/hostname")).unwrap_or_default();
        let port = cfg.api.as_ref().map(|a| a.listen.port()).unwrap_or(8443);
        let p = serde_json::json!({"v": 1, "host": format!("{}.local", host.trim()), "port": port,
            "device": dev, "secret": secret, "cert": rp_privd::cert_sha256(&cli.root)});
        if !cli.json {
            println!("pairing open for {pairing_minutes} min; code {secret}");
        }
        report.insert("pairing".into(), p);
    } else {
        report.insert("pairing".into(), serde_json::Value::Null);
    }
    if cli.json {
        println!("{}", serde_json::Value::Object(report));
    }
    Ok(ExitCode::SUCCESS)
}

fn edit_config(
    path: &Path,
    f: impl FnOnce(&mut toml_edit::DocumentMut) -> Result<()>,
) -> Result<()> {
    let text = std::fs::read_to_string(path)?;
    let mut doc: toml_edit::DocumentMut = text.parse()?;
    f(&mut doc)?;
    let out = doc.to_string();
    rp_core::config::parse(&out).context("edited config would be invalid; not written")?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    let backup = path.with_extension(format!("toml.bak-{stamp}"));
    std::fs::copy(path, &backup)?;
    let tmp = path.with_extension("toml.rp-tmp");
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn agent_state(cfg: &Config, root: &Path) -> PathBuf {
    under_root(root, &cfg.agent.clone().unwrap_or_default().state_dir)
}

fn action_store(cfg: &Config, root: &Path) -> rp_policy::approvals::Store {
    rp_policy::approvals::Store::new(&agent_state(cfg, root).join("actions"))
}

/// Domain of a list line (plain or hosts format), normalised, or None.
fn list_line_domain(line: &str) -> Option<String> {
    let l = line.split('#').next()?.trim();
    let mut f = l.split_whitespace();
    let first = f.next()?;
    let d = if first.parse::<std::net::IpAddr>().is_ok() {
        f.next()?
    } else if f.next().is_some() {
        return None; // a plain list has one domain per line; anything else is malformed
    } else {
        first
    };
    rp_dns::lists::normalize(d)
}

fn dns_cmd(cli: &Cli, c: &DnsCmd, runner: &dyn Runner) -> Result<ExitCode> {
    let cfg = match load_config(&cli.config) {
        Ok(c) => c,
        Err(code) => return Ok(code),
    };
    let d = cfg.dns.as_ref().context("no [dns] section in the config")?;
    let file_arg = match c {
        DnsCmd::List { file } | DnsCmd::Block { file, .. } | DnsCmd::Unblock { file, .. } => file,
        DnsCmd::Import { file, .. } => file,
    };
    let path = match file_arg {
        Some(f) => under_root(&cli.root, &f.display().to_string()),
        None => under_root(
            &cli.root,
            d.blocklists.first().context("dns.blocklists is empty; add a file path to rp.toml")?,
        ),
    };
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        "# One domain per line, or hosts format (0.0.0.0 domain). Subdomains are included.\n\
         # Managed with: sudo rpctl dns block|unblock|import\n"
            .into()
    });
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut present: std::collections::BTreeSet<String> =
        lines.iter().filter_map(|l| list_line_domain(l)).collect();

    let normalize_all = |ds: &[String]| -> Result<Vec<String>> {
        ds.iter()
            .map(|x| {
                rp_dns::lists::normalize(x).with_context(|| format!("'{x}' is not a valid domain"))
            })
            .collect()
    };
    let (changed, reload, summary) = match c {
        DnsCmd::List { .. } => {
            for dom in &present {
                println!("{dom}");
            }
            eprintln!("{} domain(s) in {}", present.len(), path.display());
            return Ok(ExitCode::SUCCESS);
        }
        DnsCmd::Block { domains, no_reload, .. } => {
            let mut added = 0;
            for dom in normalize_all(domains)? {
                if present.insert(dom.clone()) {
                    lines.push(dom);
                    added += 1;
                }
            }
            (added > 0, !no_reload, format!("blocked {added} new domain(s)"))
        }
        DnsCmd::Unblock { domains, no_reload, .. } => {
            let gone: std::collections::BTreeSet<String> =
                normalize_all(domains)?.into_iter().collect();
            let before = lines.len();
            lines.retain(|l| list_line_domain(l).is_none_or(|dom| !gone.contains(&dom)));
            let removed = before - lines.len();
            (removed > 0, !no_reload, format!("unblocked {removed} line(s)"))
        }
        DnsCmd::Import { source, url, no_reload, .. } => {
            let incoming = match (source, url) {
                (Some(f), None) => std::fs::read_to_string(f)
                    .with_context(|| format!("cannot read {}", f.display()))?,
                (None, Some(u)) => {
                    anyhow::ensure!(
                        u.starts_with("https://") && !u.contains(char::is_whitespace),
                        "only https:// URLs are accepted"
                    );
                    let tmp =
                        std::env::temp_dir().join(format!("rp-dns-import-{}", std::process::id()));
                    let argv: Vec<String> =
                        ["curl", "-fsSL", "--proto", "=https", "--max-filesize", "50000000", "-o"]
                            .iter()
                            .map(|s| s.to_string())
                            .chain([tmp.display().to_string(), u.clone()])
                            .collect();
                    let out = runner.run(&argv)?;
                    anyhow::ensure!(out.ok(), "download failed: {}", out.stderr.trim());
                    let t = std::fs::read_to_string(&tmp).unwrap_or_default();
                    let _ = std::fs::remove_file(&tmp);
                    t
                }
                _ => anyhow::bail!("give a FILE or --url URL"),
            };
            let (mut added, mut skipped) = (0usize, 0usize);
            lines.push(format!(
                "# imported: {}",
                url.clone().unwrap_or_else(|| source.as_ref().unwrap().display().to_string())
            ));
            for l in incoming.lines() {
                let t = l.split('#').next().unwrap_or("").trim();
                if t.is_empty() {
                    continue;
                }
                match list_line_domain(t) {
                    Some(dom)
                        if !matches!(
                            dom.as_str(),
                            "localhost" | "localhost.localdomain" | "local" | "broadcasthost"
                        ) =>
                    {
                        if present.insert(dom.clone()) {
                            lines.push(dom);
                            added += 1;
                        }
                    }
                    _ => skipped += 1,
                }
            }
            (
                added > 0,
                !no_reload,
                format!("imported {added} new domain(s), skipped {skipped} invalid line(s)"),
            )
        }
    };
    if changed {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("rp-tmp");
        std::fs::write(&tmp, lines.join("\n") + "\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        }
        std::fs::rename(&tmp, &path)?;
    }
    println!("{summary} ({} total) in {}", present.len(), path.display());
    if changed && reload {
        let argv: Vec<String> =
            ["systemctl", "reload", "rp-dns.service"].iter().map(|s| s.to_string()).collect();
        match runner.run(&argv) {
            Ok(o) if o.ok() => println!("rp-dns reloaded"),
            _ => println!("note: could not reload rp-dns (run: sudo systemctl reload rp-dns)"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn mcp_cmd(cli: &Cli, c: &McpCmd) -> Result<ExitCode> {
    let cfg = match load_config(&cli.config) {
        Ok(c) => c,
        Err(code) => return Ok(code),
    };
    cfg.mcp.as_ref().context("no [mcp] section in the config")?;
    let clients = rp_agent::admin_ops::load_clients(&cfg, &cli.root).map_err(anyhow::Error::msg)?;
    match c {
        McpCmd::AddClient { name, cap } => {
            let caps: Vec<String> =
                cap.split(',').map(|c| c.trim().to_string()).filter(|c| !c.is_empty()).collect();
            let token = rp_agent::admin_ops::mcp_add_client(&cfg, &cli.root, name, &caps)
                .map_err(anyhow::Error::msg)?;
            println!("client '{name}' created. Token (shown ONCE, store it in your MCP client):");
            println!("{token}");
            println!("restart to load it: sudo systemctl restart rp-mcp");
        }
        McpCmd::RemoveClient { name } => {
            rp_agent::admin_ops::mcp_remove_client(&cfg, &cli.root, name)
                .map_err(anyhow::Error::msg)?;
            println!("revoked '{name}' — restart to apply: sudo systemctl restart rp-mcp");
        }
        McpCmd::Clients => {
            for c in &clients.clients {
                let caps: Vec<&str> = c.capabilities.iter().map(|c| c.as_str()).collect();
                println!("{:<20} {}", c.name, caps.join(","));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Write a secret atomically with mode 600 from the start (never world-readable).
fn changeset_cmd(cli: &Cli, c: &ChangesetCmd, t: &Target) -> Result<ExitCode> {
    use rp_core::changeset as cs;
    let by = format!("admin:{}", std::env::var("SUDO_USER").unwrap_or_else(|_| "root".into()));
    let show = |x: &cs::ChangeSet| -> Result<()> {
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&x.public())?);
        } else {
            println!("{} {:<8} {:?} (base revision {})", x.id, x.module, x.status, x.base_revision);
            for k in &x.checks {
                println!("  [{:?}] {:<16} {}", k.status, k.name, k.detail);
            }
            for k in &x.verification {
                println!("  verify [{:?}] {:<14} {}", k.status, k.name, k.detail);
            }
            if let Some(e) = &x.error {
                println!("  error: {e}");
            }
            if let Some(d) = x.deadline {
                println!("  confirm before unix time {d} (rpctl changeset confirm {})", x.id);
            }
        }
        Ok(())
    };
    let res = match c {
        ChangesetCmd::Revision => {
            println!("{}", cs::revision(t, &cli.config)?);
            return Ok(ExitCode::SUCCESS);
        }
        ChangesetCmd::Create { module, expected_revision, patch } => {
            let p: serde_json::Value =
                serde_json::from_str(patch).context("--patch is not JSON")?;
            let p = p.as_object().cloned().context("--patch must be a JSON object")?;
            cs::create(t, &cli.config, module, *expected_revision, p, &by).inspect(|x| {
                if !cli.json {
                    print!("{}", x.config_diff);
                }
            })
        }
        ChangesetCmd::Preflight { id, peer } => cs::preflight(t, &cli.config, id, *peer),
        ChangesetCmd::Apply { id, confirm_secs, no_packages } => cs::apply_cs(
            t,
            &cli.config,
            id,
            &cs::CsApplyOptions {
                confirm_secs: *confirm_secs,
                rpctl_argv: self_argv(cli)?,
                install_packages: !no_packages,
            },
        ),
        ChangesetCmd::Confirm { id } => cs::confirm(t, &cli.config, id),
        ChangesetCmd::Rollback { id } => cs::rollback(t, &cli.config, id),
        ChangesetCmd::Expire { id } => cs::expire(t, &cli.config, id),
        ChangesetCmd::Show { id } => cs::get(t, &cli.config, id),
        ChangesetCmd::List => {
            let all = cs::list(t, &cli.config);
            if cli.json {
                let v: Vec<_> = all.iter().map(|x| x.public()).collect();
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                for x in all {
                    println!("{} {:<8} {:?}", x.id, x.module, x.status);
                }
            }
            return Ok(ExitCode::SUCCESS);
        }
    };
    match res {
        Ok(x) => {
            show(&x)?;
            let bad = matches!(x.status, cs::CsStatus::Failed)
                || (matches!(c, ChangesetCmd::Preflight { .. })
                    && x.status != cs::CsStatus::Preflighted);
            Ok(if bad { ExitCode::from(EXIT_PREFLIGHT) } else { ExitCode::SUCCESS })
        }
        Err(e) => {
            eprintln!("error: {e}");
            Ok(ExitCode::from(match e {
                cs::CsError::Invalid(_) | cs::CsError::Patch(_) => EXIT_CONFIG,
                cs::CsError::Conflict { .. } | cs::CsError::Busy => 4,
                _ => 1,
            }))
        }
    }
}

fn write_secret(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("rp-tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(&tmp)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
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
