//! rp-privd server: a unix socket (systemd socket activation or `--socket`),
//! peer-uid check, one request per connection, exit when idle.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use rp_core::runner::{RecordingRunner, Runner, SystemRunner};
use rp_privd::{handle, write_frame, Ctx, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[derive(Parser, Clone)]
#[command(name = "rp-privd", version, about = "Privileged helper for the rp console API")]
struct Cli {
    #[arg(long, default_value = "/etc/rp/rp.toml")]
    config: PathBuf,
    /// Listen here instead of the systemd-provided socket.
    #[arg(long)]
    socket: Option<PathBuf>,
    /// User whose processes may connect (besides root).
    #[arg(long, default_value = "rp-api")]
    allow_user: String,
    /// Additional uid allowed to connect (testing).
    #[arg(long)]
    allow_uid: Vec<u32>,
    /// Exit after this many idle seconds (0 = never).
    #[arg(long, default_value_t = 60)]
    idle_secs: u64,
    #[arg(long, default_value = "/usr/local/bin/rpctl")]
    rpctl: String,
    #[arg(long, default_value = "/", hide = true)]
    root: PathBuf,
    /// Record commands to FILE instead of running them (testing).
    #[arg(long, hide = true)]
    record_commands: Option<PathBuf>,
    #[arg(long, hide = true)]
    fake_output: Vec<String>,
    #[arg(long, hide = true)]
    fail_commands: Option<String>,
    /// Pretend the clock is at this unix time (testing).
    #[arg(long, hide = true)]
    fake_now: Option<i64>,
}

fn uid_of(root: &std::path::Path, user: &str) -> Option<u32> {
    let passwd = std::fs::read_to_string(rp_core::files::under_root(root, "/etc/passwd")).ok()?;
    passwd.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 2 && f[0] == user).then(|| f[2].parse().ok()).flatten()
    })
}

fn listener(cli: &Cli) -> Result<UnixListener> {
    if let Some(p) = &cli.socket {
        let _ = std::fs::remove_file(p);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d)?;
        }
        let l = UnixListener::bind(p).with_context(|| format!("bind {}", p.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o660))?;
        }
        return Ok(l);
    }
    // systemd socket activation: fd 3.
    let pid_ok = std::env::var("LISTEN_PID").ok().and_then(|v| v.parse::<u32>().ok())
        == Some(std::process::id());
    let fds: u32 = std::env::var("LISTEN_FDS").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    anyhow::ensure!(
        pid_ok && fds >= 1,
        "no --socket given and not started by systemd socket activation"
    );
    use std::os::fd::FromRawFd;
    // SAFETY: systemd passes the listening socket as fd 3 and nothing else owns it.
    let std_l = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    std_l.set_nonblocking(true)?;
    Ok(UnixListener::from_std(std_l)?)
}

struct Shared {
    cli: Cli,
    allowed: Vec<u32>,
    record: Mutex<()>,
    active: AtomicUsize,
    last: Mutex<Instant>,
}

fn process(sh: &Shared, body: &[u8]) -> Response {
    let req: Request = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return Response::err("bad_request", format!("invalid request: {e}")),
    };
    let cli = &sh.cli;
    let mut rpctl_argv =
        vec![cli.rpctl.clone(), "--config".into(), cli.config.display().to_string()];
    if cli.root != std::path::Path::new("/") {
        rpctl_argv.extend(["--root".into(), cli.root.display().to_string()]);
    }
    let now = cli.fake_now.unwrap_or_else(rp_core::changeset::now);
    let run = |runner: &dyn Runner| {
        handle(
            &Ctx { root: cli.root.clone(), config: cli.config.clone(), runner, rpctl_argv, now },
            req,
        )
    };
    match &cli.record_commands {
        None => run(&SystemRunner),
        Some(path) => {
            let fails: Vec<&str> = cli
                .fail_commands
                .as_deref()
                .map(|s| s.split(',').filter(|p| !p.is_empty()).collect())
                .unwrap_or_default();
            let mut rec = RecordingRunner::failing(&fails);
            for spec in &cli.fake_output {
                let (p, o) = spec.split_once('=').unwrap_or((spec.as_str(), ""));
                rec = rec.with_response(p, &o.replace("\\n", "\n"));
            }
            let _g = sh.record.lock().unwrap();
            let r = run(&rec);
            let mut log = std::fs::read_to_string(path).unwrap_or_default();
            for c in rec.calls() {
                log.push_str(&c);
                log.push('\n');
            }
            let _ = std::fs::write(path, log);
            r
        }
    }
}

async fn serve(sh: Arc<Shared>, mut s: UnixStream) {
    let uid = match s.peer_cred() {
        Ok(c) => c.uid(),
        Err(_) => return,
    };
    if !sh.allowed.contains(&uid) {
        eprintln!("rp-privd: refused connection from uid {uid}");
        reply(&mut s, &Response::err("forbidden", "this user may not talk to rp-privd")).await;
        return;
    }
    let mut len = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_secs(10), async {
        s.read_exact(&mut len).await?;
        let n = u32::from_be_bytes(len) as usize;
        if n > rp_privd::MAX_FRAME {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"));
        }
        let mut body = vec![0u8; n];
        s.read_exact(&mut body).await?;
        Ok(body)
    })
    .await;
    let body = match read {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            reply(&mut s, &Response::err("bad_request", e.to_string())).await;
            return;
        }
        Err(_) => return,
    };
    let sh2 = sh.clone();
    let resp = tokio::task::spawn_blocking(move || process(&sh2, &body))
        .await
        .unwrap_or_else(|_| Response::err("internal", "request handler crashed"));
    reply(&mut s, &resp).await;
}

async fn reply(s: &mut UnixStream, r: &Response) {
    let mut out = Vec::new();
    if write_frame(&mut out, r).is_ok() {
        let _ = s.write_all(&out).await;
    }
    // Closing a Linux unix socket with unread input resets the connection and
    // the peer loses this reply (e.g. a refused or oversized request). Finish
    // our side, then discard what is left (bounded) before closing.
    let _ = s.shutdown().await;
    let mut sink = [0u8; 8192];
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let mut left = 4 * 1024 * 1024usize;
        while left > 0 {
            match s.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => left = left.saturating_sub(n),
            }
        }
    })
    .await;
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut allowed = vec![0];
    if let Some(u) = uid_of(&cli.root, &cli.allow_user) {
        allowed.push(u);
    }
    allowed.extend(&cli.allow_uid);
    let l = listener(&cli)?;
    let sh = Arc::new(Shared {
        cli: cli.clone(),
        allowed,
        record: Mutex::new(()),
        active: AtomicUsize::new(0),
        last: Mutex::new(Instant::now()),
    });
    loop {
        tokio::select! {
            acc = l.accept() => {
                let Ok((s, _)) = acc else { continue };
                sh.active.fetch_add(1, Ordering::SeqCst);
                let sh2 = sh.clone();
                tokio::spawn(async move {
                    serve(sh2.clone(), s).await;
                    *sh2.last.lock().unwrap() = Instant::now();
                    sh2.active.fetch_sub(1, Ordering::SeqCst);
                });
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                let idle = sh.last.lock().unwrap().elapsed();
                if cli.idle_secs > 0 && sh.active.load(Ordering::SeqCst) == 0
                    && idle > Duration::from_secs(cli.idle_secs) {
                    return Ok(());
                }
            }
        }
    }
}
