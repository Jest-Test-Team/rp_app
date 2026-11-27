//! rp-boards: keeps the serial ports of the rp ESP32 boards open.
//!
//! Without it a port is only opened for the few seconds of an approval, so
//! whatever a board says in between — boot reasons, panics, `LOG` lines — is
//! lost. This service (`rp-agent boards`, its own sandboxed unit with access
//! to the tty devices and no network) owns every configured port:
//!
//! * it reconnects when a board is plugged in, asks `HELLO`/`INFO`, and writes
//!   what it knows to `<state>/status.json`;
//! * it keeps everything a board logs in `<state>/<port name>.jsonl` (rotated
//!   at [`LOG_LINES`]), which rp-agent serves read-only to the console app and
//!   to MCP clients;
//! * it lends a port to one root client at a time over a unix socket
//!   (`ATTACH <port>`, then plain rp-wire lines both ways), which is how
//!   `rpctl` and rp-privd ask for approvals and switch profiles while it runs.

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use rp_core::files::under_root;
use rp_policy::hwkey;
use rp_schema::Config;
use rp_wire::{HostMsg, KeyMsg};
use serde::{Deserialize, Serialize};

use crate::approver::{KeyLink, Serial};

pub const SOCKET: &str = "/run/rp-boards/boards.sock";
pub const STATE_DIR: &str = "/var/lib/rp/boards";
/// Log lines kept per board (plus one rotated file of the same size).
pub const LOG_LINES: usize = 2000;
/// oob boards get a heartbeat this often.
pub const HEARTBEAT_S: u64 = 10;

/// What rp-boards tells boards about their profile.
#[derive(Debug, Clone, Default)]
pub struct Setup {
    /// sentry: the SSID to guard (the gateway's IoT access point).
    pub watch: Option<Vec<u8>>,
    /// oob: watchdog seconds (0 = off).
    pub watchdog_seconds: u16,
    /// honeypot: the decoy network's name.
    pub decoy: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BoardStatus {
    /// The configured port, e.g. `/dev/rp-approver`.
    pub port: String,
    pub connected: bool,
    pub chip: Option<String>,
    pub firmware: Option<String>,
    pub profile: Option<String>,
    #[serde(default)]
    pub supported: Vec<String>,
    pub key_id: Option<String>,
    /// The board's own account of its last start (`boot reason=...`).
    pub last_boot: Option<String>,
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub errors: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    pub ts: i64,
    pub port: String,
    /// error | warn | info | debug
    pub level: String,
    /// board (a `LOG` line), raw (other text the board printed), gateway
    pub source: String,
    pub text: String,
}

/// The ports rp-boards manages: `[boards] ports`, else the approver's two.
pub fn ports(cfg: &Config) -> Vec<String> {
    if let Some(b) = &cfg.boards {
        return b.ports.clone();
    }
    let a = cfg.approver.clone().unwrap_or_default();
    vec![a.port, a.backup_port]
}

pub fn state_dir(root: &Path) -> PathBuf {
    under_root(root, STATE_DIR)
}

fn log_name(port: &str) -> String {
    let base = Path::new(port).file_name().map(|n| n.to_string_lossy().into_owned());
    let base = base.unwrap_or_else(|| "board".into());
    base.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).collect()
}

pub fn log_path(root: &Path, port: &str) -> PathBuf {
    state_dir(root).join(format!("{}.jsonl", log_name(port)))
}

/// Recent entries for one port (newest first), from the current and the
/// rotated file.
pub fn read_logs(root: &Path, port: &str, limit: usize, min: Option<&str>) -> Vec<LogEntry> {
    let rank = |l: &str| match l {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        _ => 3,
    };
    let max = min.map(rank).unwrap_or(3);
    let cur = log_path(root, port);
    let old = cur.with_extension("1.jsonl");
    let mut out = Vec::new();
    for p in [cur, old] {
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        for l in text.lines().rev() {
            if out.len() >= limit {
                return out;
            }
            if let Ok(e) = serde_json::from_str::<LogEntry>(l) {
                if rank(&e.level) <= max {
                    out.push(e);
                }
            }
        }
    }
    out
}

pub fn read_status(root: &Path) -> Vec<BoardStatus> {
    std::fs::read_to_string(state_dir(root).join("status.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Appends to one port's log, rotating at [`LOG_LINES`].
struct LogFile {
    path: PathBuf,
    lines: usize,
}

impl LogFile {
    fn open(path: PathBuf) -> Self {
        let lines = std::fs::read_to_string(&path).map(|t| t.lines().count()).unwrap_or(0);
        Self { path, lines }
    }

    fn append(&mut self, e: &LogEntry) {
        if self.lines >= LOG_LINES {
            let _ = std::fs::rename(&self.path, self.path.with_extension("1.jsonl"));
            self.lines = 0;
        }
        let line = serde_json::to_string(e).expect("serializable") + "\n";
        let ok = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if ok.is_ok() {
            self.lines += 1;
        }
    }
}

struct Port {
    status: BoardStatus,
    log: LogFile,
    /// Lines to write to the board (set while the port is open).
    to_board: Option<mpsc::Sender<String>>,
    /// The attached client, with its id.
    client: Option<(u64, mpsc::Sender<String>)>,
    /// The board was given its profile's settings since it (re)started.
    setup_sent: bool,
    last_heartbeat: Option<Instant>,
}

/// Shared state of all ports.
pub struct Hub {
    root: PathBuf,
    setup: Setup,
    ports: Mutex<HashMap<String, Port>>,
    next_client: AtomicU64,
}

fn now() -> i64 {
    rp_policy::approvals::now()
}

/// Boot ROM and bootloader chatter: kept, but as debug.
fn is_chatter(l: &str) -> bool {
    [
        "I (",
        "W (",
        "load:",
        "entry ",
        "ESP-ROM",
        "Build:",
        "rst:",
        "ets ",
        "mode:",
        "SPIWP",
        "clk_drv",
        "configsip",
        "Saved PC",
    ]
    .iter()
    .any(|p| l.starts_with(p))
}

fn looks_fatal(l: &str) -> bool {
    let l = l.to_ascii_lowercase();
    ["panic", "abort", "guru meditation", "backtrace", "exception", "stack overflow"]
        .iter()
        .any(|w| l.contains(w))
}

/// Printable text only, bounded.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(300).collect()
}

impl Hub {
    pub fn new(root: &Path, ports: &[String]) -> Arc<Self> {
        Self::with_setup(root, ports, Setup::default())
    }

    pub fn with_setup(root: &Path, ports: &[String], setup: Setup) -> Arc<Self> {
        let dir = state_dir(root);
        let _ = std::fs::create_dir_all(&dir);
        let map = ports
            .iter()
            .map(|p| {
                let status = BoardStatus { port: p.clone(), ..Default::default() };
                let port = Port {
                    status,
                    log: LogFile::open(log_path(root, p)),
                    to_board: None,
                    client: None,
                    setup_sent: false,
                    last_heartbeat: None,
                };
                (p.clone(), port)
            })
            .collect();
        Arc::new(Self {
            root: root.to_path_buf(),
            setup,
            ports: Mutex::new(map),
            next_client: AtomicU64::new(1),
        })
    }

    fn with<R>(&self, port: &str, f: impl FnOnce(&mut Port) -> R) -> Option<R> {
        let mut m = self.ports.lock().unwrap_or_else(|e| e.into_inner());
        let r = m.get_mut(port).map(f);
        let all: Vec<BoardStatus> = {
            let mut v: Vec<_> = m.values().map(|p| p.status.clone()).collect();
            v.sort_by(|a, b| a.port.cmp(&b.port));
            v
        };
        drop(m);
        let path = state_dir(&self.root).join("status.json");
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, serde_json::to_vec_pretty(&all).unwrap()).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
        }
        r
    }

    pub fn log(&self, port: &str, level: &str, source: &str, text: &str) {
        let e = LogEntry {
            ts: now(),
            port: port.into(),
            level: level.into(),
            source: source.into(),
            text: clean(text),
        };
        self.with(port, |p| {
            if level == "error" {
                p.status.errors += 1;
            }
            p.log.append(&e);
        });
    }

    /// One line from a board: update the status, keep logs, forward protocol
    /// replies to the attached client.
    pub fn from_board(&self, port: &str, line: &str) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() || line.starts_with("# ") {
            return;
        }
        // A start can cut the bootloader's last line short, so the board's
        // first LOG line arrives glued to it: split them.
        if let Some(i) = line.find("LOG ").filter(|&i| i > 0) {
            self.from_board(port, &line[..i]);
            self.from_board(port, &line[i..]);
            return;
        }
        let forward = match KeyMsg::parse(line) {
            Some(KeyMsg::Log { level, text }) => {
                if text.starts_with("boot reason=") || text.starts_with("restarted after") {
                    let t = clean(text);
                    self.with(port, |p| p.status.last_boot = Some(t));
                }
                // "running profile=<p> firmware=<v>" right after every start.
                if let Some(rest) = text.strip_prefix("running profile=") {
                    let name = rest.split(' ').next().unwrap_or("");
                    if let Some(prof) = rp_wire::Profile::parse(name) {
                        self.with(port, |p| {
                            p.status.profile = Some(prof.as_str().into());
                            p.setup_sent = false; // it restarted
                        });
                    }
                }
                self.log(port, level.as_str(), "board", text);
                false
            }
            Some(KeyMsg::Key { public_key, version }) => {
                let (id, v) = (hwkey::key_id(&public_key), version.to_string());
                self.with(port, |p| {
                    p.status.key_id = Some(id);
                    p.status.firmware = Some(v);
                });
                true
            }
            Some(KeyMsg::Info { chip, profile, version, supported }) => {
                let (c, v) = (chip.to_string(), version.to_string());
                self.with(port, |p| {
                    p.status.chip = Some(c);
                    p.status.firmware = Some(v);
                    p.status.profile = Some(profile.as_str().into());
                    p.status.supported = supported.iter().map(|p| p.as_str().into()).collect();
                });
                true
            }
            Some(KeyMsg::Err(e)) => {
                self.log(port, "warn", "board", &format!("ERR {e}"));
                true
            }
            Some(_) => true,
            None if is_chatter(line) => {
                self.log(port, "debug", "raw", line);
                false
            }
            None => {
                self.log(port, if looks_fatal(line) { "error" } else { "info" }, "raw", line);
                false
            }
        };
        self.with(port, |p| {
            p.status.last_seen = Some(now());
            if forward {
                if let Some((_, c)) = &p.client {
                    if c.send(line.to_string()).is_err() {
                        p.client = None;
                    }
                }
            }
        });
    }

    fn set_connected(&self, port: &str, to_board: Option<mpsc::Sender<String>>) {
        let up = to_board.is_some();
        let changed = self
            .with(port, |p| {
                let was = p.status.connected;
                p.status.connected = up;
                p.to_board = to_board;
                p.setup_sent = false;
                if !up {
                    p.client = None;
                    p.status.profile = None;
                }
                was != up
            })
            .unwrap_or(false);
        if changed {
            let what = if up { "board connected" } else { "board disconnected" };
            self.log(port, if up { "info" } else { "warn" }, "gateway", what);
        }
    }

    /// Lines a board needs once per start for its profile: the SSID to
    /// guard (sentry), watchdog and the console lines kept across a crash
    /// (oob), the decoy name (honeypot). Plus the oob heartbeat.
    fn pending(&self, port: &str) -> Vec<String> {
        let s = &self.setup;
        self.with(port, |p| {
            let mut out = Vec::new();
            let profile = p.status.profile.clone().unwrap_or_default();
            if !p.setup_sent && !profile.is_empty() {
                p.setup_sent = true;
                match profile.as_str() {
                    "sentry" => out.extend(s.watch.as_deref().and_then(HostMsg::watch)),
                    "oob" => {
                        out.push(HostMsg::Watchdog { seconds: s.watchdog_seconds });
                        out.push(HostMsg::Tail { n: rp_board::oob::LINES as u8 });
                    }
                    "honeypot" => out.extend(s.decoy.as_deref().and_then(HostMsg::decoy)),
                    _ => {}
                }
            }
            if profile == "oob"
                && p.last_heartbeat.is_none_or(|t| t.elapsed() >= Duration::from_secs(HEARTBEAT_S))
            {
                p.last_heartbeat = Some(Instant::now());
                out.push(HostMsg::Heartbeat);
            }
            out.into_iter().map(|m| m.to_string()).collect()
        })
        .unwrap_or_default()
    }

    fn needs_info(&self, port: &str) -> bool {
        self.with(port, |p| {
            p.status.chip.is_none() || p.status.profile.is_none() || p.status.key_id.is_none()
        })
        .unwrap_or(false)
    }

    fn attached(&self, port: &str) -> bool {
        self.with(port, |p| p.client.is_some()).unwrap_or(false)
    }

    /// Lend `port` to a client. Returns its id, the sender towards the board
    /// and the receiver of the board's protocol replies.
    pub fn attach(
        &self,
        port: &str,
    ) -> Result<(u64, mpsc::Sender<String>, mpsc::Receiver<String>), String> {
        let id = self.next_client.fetch_add(1, Ordering::Relaxed);
        self.with(port, |p| {
            let Some(to_board) = p.to_board.clone() else {
                return Err("not connected".to_string());
            };
            if p.client.is_some() {
                return Err("busy".to_string());
            }
            let (tx, rx) = mpsc::channel();
            p.client = Some((id, tx));
            Ok((id, to_board, rx))
        })
        .unwrap_or_else(|| Err(format!("unknown port {port}")))
    }

    pub fn detach(&self, port: &str, id: u64) {
        self.with(port, |p| {
            if p.client.as_ref().is_some_and(|(c, _)| *c == id) {
                p.client = None;
            }
        });
    }
}

/// Keep one port open for good: reconnect, query, read, write.
fn port_worker(hub: Arc<Hub>, port: String) {
    let path = under_root(&hub.root, &port);
    loop {
        if !path.exists() {
            hub.set_connected(&port, None);
            std::thread::sleep(Duration::from_secs(2));
            continue;
        }
        let mut link = match Serial::open(&path) {
            Ok(l) => l,
            Err(e) => {
                hub.log(&port, "error", "gateway", &format!("cannot open {}: {e}", path.display()));
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };
        let (tx, rx) = mpsc::channel::<String>();
        hub.set_connected(&port, Some(tx));
        let mut next_query = Instant::now();
        let err = loop {
            if let Some(e) = rx.try_iter().find_map(|l| link.send(&l).err()) {
                break e;
            }
            // Ask who is there until we know, then once a minute — not while
            // a client is talking to the board.
            if Instant::now() >= next_query && !hub.attached(&port) {
                let missing = hub.needs_info(&port);
                for q in [HostMsg::Hello, HostMsg::Info] {
                    if let Err(e) = link.send(&q.to_string()) {
                        hub.log(&port, "warn", "gateway", &format!("write failed: {e}"));
                    }
                }
                next_query = Instant::now() + Duration::from_secs(if missing { 2 } else { 60 });
            }
            if !hub.attached(&port) {
                for w in hub.pending(&port) {
                    if let Err(e) = link.send(&w) {
                        hub.log(&port, "warn", "gateway", &format!("write failed: {e}"));
                    }
                }
            }
            match link.recv(Instant::now() + Duration::from_millis(100)) {
                Ok(Some(line)) => hub.from_board(&port, &line),
                Ok(None) => {}
                Err(e) => break e,
            }
        };
        hub.log(&port, "warn", "gateway", &format!("port closed: {err}"));
        hub.set_connected(&port, None);
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// One socket client: `ATTACH <port>`, then lines both ways.
fn serve_client(hub: Arc<Hub>, stream: UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut first = String::new();
    reader.by_ref().take(512).read_line(&mut first)?;
    let mut w = stream.try_clone()?;
    let Some(port) = first.trim().strip_prefix("ATTACH ").map(str::to_string) else {
        return w.write_all(b"ERR expected ATTACH <port>\n");
    };
    let (id, to_board, from_board) = match hub.attach(&port) {
        Ok(x) => x,
        Err(e) => return w.write_all(format!("ERR {e}\n").as_bytes()),
    };
    w.write_all(b"OK\n")?;
    hub.log(&port, "debug", "gateway", "client attached");
    let writer = std::thread::spawn(move || {
        for line in from_board {
            if w.write_all(format!("{line}\n").as_bytes()).is_err() {
                break;
            }
        }
    });
    stream.set_read_timeout(None)?;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.by_ref().take(rp_wire::MAX_LINE as u64 + 2).read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let l = line.trim_end();
                // Only rp-wire requests pass, so a client cannot type raw
                // text at the board.
                // Never CONSOLE: raw passthrough is for a laptop plugged
                // straight into the board, not for clients of this service.
                let ok = HostMsg::parse(l).is_some_and(|m| m != HostMsg::Console);
                if ok && to_board.send(l.to_string()).is_err() {
                    break;
                }
            }
        }
    }
    hub.detach(&port, id);
    hub.log(&port, "debug", "gateway", "client detached");
    drop(to_board);
    let _ = writer.join();
    Ok(())
}

pub fn serve(hub: Arc<Hub>, socket: &Path) -> io::Result<()> {
    if let Some(d) = socket.parent() {
        std::fs::create_dir_all(d)?;
    }
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    }
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let hub = hub.clone();
        std::thread::spawn(move || {
            let _ = serve_client(hub, stream);
        });
    }
    Ok(())
}

/// The decoy network's name: `[boards] decoy_ssid`, else "<IoT SSID>-guest"
/// (cut to 32 bytes on a character boundary).
pub fn decoy_name(cfg: &Config) -> Option<Vec<u8>> {
    if let Some(d) = cfg.boards.as_ref().and_then(|b| b.decoy_ssid.clone()) {
        return Some(d.into_bytes());
    }
    let ap = cfg.ap.as_ref()?;
    let mut name = ap.ssid.clone();
    while name.len() + "-guest".len() > 32 {
        name.pop();
    }
    Some(format!("{name}-guest").into_bytes())
}

/// `rp-agent boards`: run until killed.
pub fn run(cfg: &Config, root: &Path) -> io::Result<()> {
    let ports = ports(cfg);
    let b = cfg.boards.clone();
    let setup = Setup {
        watch: cfg.ap.as_ref().map(|a| a.ssid.as_bytes().to_vec()),
        watchdog_seconds: b.as_ref().map_or(0, |b| b.watchdog_seconds),
        decoy: decoy_name(cfg),
    };
    let hub = Hub::with_setup(root, &ports, setup);
    for p in ports {
        let hub = hub.clone();
        std::thread::spawn(move || port_worker(hub, p));
    }
    serve(hub, &under_root(root, SOCKET))
}

/// A port borrowed from rp-boards.
pub struct HubLink {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl HubLink {
    pub fn attach(socket: &Path, port: &str) -> io::Result<Self> {
        let stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(Duration::from_millis(200)))?;
        let mut link = Self { stream, buf: Vec::new() };
        link.send(&format!("ATTACH {port}"))?;
        match link.recv(Instant::now() + Duration::from_secs(3))? {
            Some(l) if l == "OK" => Ok(link),
            Some(l) => Err(io::Error::other(format!(
                "rp-boards: {}",
                l.strip_prefix("ERR ").unwrap_or(&l)
            ))),
            None => Err(io::Error::other("rp-boards: did not answer")),
        }
    }
}

impl KeyLink for HubLink {
    fn send(&mut self, line: &str) -> io::Result<()> {
        self.stream.write_all(format!("{line}\n").as_bytes())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<String>> {
        let mut chunk = [0u8; 256];
        loop {
            if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=nl).collect();
                return Ok(Some(String::from_utf8_lossy(&line).trim_end().to_string()));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(io::Error::other("rp-boards closed the connection")),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }
    }
}

/// Open a board port: through rp-boards when it runs and manages that port,
/// else directly (a port given as an existing path is used as is).
pub fn open_port(root: &Path, port: &str) -> io::Result<Box<dyn KeyLink>> {
    let socket = under_root(root, SOCKET);
    if socket.exists() {
        match HubLink::attach(&socket, port) {
            Ok(l) => return Ok(Box::new(l)),
            // rp-boards answered: the port is busy, not connected, ...
            Err(e)
                if e.to_string().starts_with("rp-boards:")
                    && !e.to_string().contains("unknown port") =>
            {
                return Err(e)
            }
            // A stale socket (service stopped) or a port it does not manage.
            Err(_) => {}
        }
    }
    let direct = Path::new(port);
    let path = if direct.exists() { direct.to_path_buf() } else { under_root(root, port) };
    if !path.exists() {
        return Err(io::Error::new(io::ErrorKind::NotFound, format!("{port}: no such device")));
    }
    Ok(Box::new(Serial::open(&path)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rp-boards-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    const P: &str = "/dev/rp-approver";

    #[test]
    fn board_lines_update_status_and_logs() {
        let r = root("lines");
        let hub = Hub::new(&r, &[P.to_string()]);
        hub.from_board(P, "LOG info boot reason=SysBrownOut");
        hub.from_board(P, "LOG error could not store the new profile in flash; not restarting");
        hub.from_board(P, "INFO esp32 approver 0.2.0 approver,oob");
        hub.from_board(P, "LOG info running profile=oob firmware=0.2.0");
        assert_eq!(read_status(&r)[0].profile.as_deref(), Some("oob"), "updated on restart");
        hub.from_board(P, "INFO esp32 approver 0.2.0 approver,oob");
        hub.from_board(P, "I (27) boot: chip revision: v3.1");
        hub.from_board(P, "====================== PANIC ======================");
        hub.from_board(P, "# button down");
        hub.from_board(P, "I (194) esp_image: segment 3: sizeLOG info boot reason=CoreUsbUart");
        assert_eq!(read_status(&r)[0].last_boot.as_deref(), Some("boot reason=CoreUsbUart"));
        hub.from_board(P, "ERR bad line");

        let st = read_status(&r);
        assert_eq!(st.len(), 1);
        assert_eq!(st[0].chip.as_deref(), Some("esp32"));
        assert_eq!(st[0].profile.as_deref(), Some("approver"));
        assert_eq!(st[0].supported, ["approver", "oob"]);
        assert_eq!(st[0].last_boot.as_deref(), Some("boot reason=CoreUsbUart"), "the latest");
        assert_eq!(st[0].errors, 2, "the LOG error and the panic line");

        let all = read_logs(&r, P, 100, None);
        assert_eq!(all.len(), 8, "everything but the # note and INFO: {all:?}");
        assert_eq!(all[0].text, "ERR bad line", "newest first");
        let errors = read_logs(&r, P, 100, Some("error"));
        assert_eq!(errors.len(), 2);
        assert!(errors.iter().any(|e| e.source == "raw" && e.text.contains("PANIC")));
        let infos = read_logs(&r, P, 100, Some("info"));
        assert!(infos.iter().all(|e| e.level != "debug"), "boot ROM chatter is debug");
    }

    #[test]
    fn logs_rotate_and_stay_readable() {
        let r = root("rotate");
        let hub = Hub::new(&r, &[P.to_string()]);
        for i in 0..LOG_LINES + 10 {
            hub.log(P, "info", "board", &format!("line {i}"));
        }
        let cur = std::fs::read_to_string(log_path(&r, P)).unwrap();
        assert_eq!(cur.lines().count(), 10);
        let recent = read_logs(&r, P, 20, None);
        assert_eq!(recent[0].text, format!("line {}", LOG_LINES + 9));
        assert_eq!(recent[19].text, format!("line {}", LOG_LINES - 10), "spans both files");
    }

    #[test]
    fn attach_lends_a_port_to_one_client_at_a_time() {
        let r = root("attach");
        let hub = Hub::new(&r, &[P.to_string()]);
        let socket = r.join("boards.sock");
        let h = hub.clone();
        let s = socket.clone();
        std::thread::spawn(move || serve(h, &s));
        while !socket.exists() {
            std::thread::sleep(Duration::from_millis(5));
        }

        let e = HubLink::attach(&socket, P).err().unwrap();
        assert!(e.to_string().contains("not connected"), "{e}");

        let (to_board_tx, to_board) = mpsc::channel();
        hub.set_connected(P, Some(to_board_tx));
        let mut link = HubLink::attach(&socket, P).unwrap();
        let busy = HubLink::attach(&socket, P).err().unwrap();
        assert!(busy.to_string().contains("busy"), "{busy}");

        link.send("HELLO").unwrap();
        link.send("rm -rf /").unwrap(); // not rp-wire: dropped
        link.send("INFO").unwrap();
        assert_eq!(to_board.recv_timeout(Duration::from_secs(2)).unwrap(), "HELLO");
        assert_eq!(to_board.recv_timeout(Duration::from_secs(2)).unwrap(), "INFO");

        hub.from_board(P, "LOG info hello"); // logged, not forwarded
        hub.from_board(P, "OK");
        let got = link.recv(Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(got.as_deref(), Some("OK"));

        drop(link);
        let deadline = Instant::now() + Duration::from_secs(2);
        while hub.attached(P) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!hub.attached(P), "detached when the client goes away");
        assert!(HubLink::attach(&socket, P).is_ok());
    }

    #[test]
    fn boards_get_their_profile_settings_once_per_start() {
        let r = root("setup");
        let setup = Setup {
            watch: Some(b"iot".to_vec()),
            watchdog_seconds: 120,
            decoy: Some(b"guest".to_vec()),
        };
        let hub = Hub::with_setup(&r, &[P.to_string()], setup);
        assert!(hub.pending(P).is_empty(), "profile unknown yet");
        hub.from_board(P, "LOG info running profile=sentry firmware=0.2.0");
        assert_eq!(hub.pending(P), ["WATCH 696f74"]);
        assert!(hub.pending(P).is_empty(), "once");
        hub.from_board(P, "LOG info running profile=sentry firmware=0.2.0");
        assert_eq!(hub.pending(P).len(), 1, "again after a restart");
        hub.from_board(P, "LOG info running profile=approver firmware=0.2.0");
        assert!(hub.pending(P).is_empty(), "nothing for an approval key");

        hub.from_board(P, "LOG info running profile=oob firmware=0.2.0");
        assert_eq!(hub.pending(P), ["WATCHDOG 120", "TAIL 64", "HB"]);
        assert!(hub.pending(P).is_empty(), "heartbeat every few seconds, not every loop");

        hub.from_board(P, "LOG info running profile=honeypot firmware=0.2.0");
        assert_eq!(hub.pending(P), ["DECOY 6775657374"]);
    }

    #[test]
    fn ports_default_to_the_approver_pair() {
        let cfg = rp_core::config::parse(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[agent]\n[approver]\n",
        )
        .unwrap();
        assert_eq!(ports(&cfg), ["/dev/rp-approver", "/dev/rp-approver-backup"]);
    }
}
