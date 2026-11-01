//! `rp-api --fake`: a simulated device for the app's tests and demos.
//!
//! It is not a mock of the API: requests go through the real rp-privd logic
//! (pairing, signatures, nonces, change sets, secrets, audit) against a
//! throw-away root, with system commands recorded instead of run. Change sets
//! that are not confirmed in time are rolled back like the device does.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rp_core::files::under_root;
use rp_core::runner::RecordingRunner;
use rp_privd::{Ctx, Request, Response};
use serde_json::{json, Value};

const FAKE_CONFIG: &str = r#"# Simulated device (documentation address ranges only).
[device]
wan_if = "eth0"
lan_cidrs = ["192.0.2.0/24", "127.0.0.0/8"]

[dns]
upstreams = ["198.51.100.53:53"]

[ap]
ssid = "RP-Demo-IoT"
country = "TW"
subnet = "198.51.100.128/25"

[agent]

[mcp]

[api]
"#;

const IW_LIST: &str =
    "Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n\tBand 1:\n";

pub struct FakeDevice {
    pub root: PathBuf,
    pub config: PathBuf,
    rpctl: String,
    lock: Mutex<()>,
    /// Pretend clock offset in seconds (tests move time forward).
    pub clock_offset: Mutex<i64>,
}

fn w(root: &Path, p: &str, c: &[u8]) -> std::io::Result<()> {
    let f = under_root(root, p);
    if let Some(d) = f.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(f, c)
}

impl FakeDevice {
    /// Prepare a fake root in `dir`. `pairing_secret` opens pairing with that
    /// 64-hex secret (like a freshly flashed SD card would).
    pub fn create(dir: &Path, pairing_secret: Option<&str>) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let root = dir.to_path_buf();
        for b in rp_core::preflight::REQUIRED_BINARIES {
            w(&root, &format!("/usr/sbin/{b}"), b"")?;
        }
        w(&root, "/sys/class/net/eth0/carrier", b"1\n")?;
        w(&root, "/sys/class/net/eth0/device/vendor", b"0x0424\n")?;
        w(&root, "/sys/class/net/wlan0/carrier", b"0\n")?;
        w(&root, "/sys/class/net/wlan0/phy80211/name", b"phy0\n")?;
        w(&root, "/proc/device-tree/model", b"Raspberry Pi 2 Model B Rev 1.1 (simulated)\0")?;
        w(&root, "/proc/meminfo", b"MemTotal:         942000 kB\n")?;
        w(&root, "/etc/os-release", b"PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n")?;
        w(&root, "/etc/hostname", b"rp-demo\n")?;
        let config = root.join("etc/rp/rp.toml");
        if !config.exists() {
            w(&root, "/etc/rp/rp.toml", FAKE_CONFIG.as_bytes())?;
        }
        if let Some(s) = pairing_secret {
            anyhow::ensure!(
                s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()),
                "pairing secret must be 64 hex characters"
            );
            let f = rp_policy::pairing::PairingFile {
                secret: s.to_lowercase(),
                created_at: rp_core::changeset::now(),
                ..Default::default()
            };
            rp_policy::admin::write_private(
                &under_root(&root, rp_privd::PAIRING),
                &toml_string(&f),
            )?;
        }
        let dev = Self {
            root,
            config,
            rpctl: "rpctl".into(),
            lock: Mutex::new(()),
            clock_offset: Mutex::new(0),
        };
        dev.install_base()?;
        Ok(dev)
    }

    /// A real install has the base firewall applied: do it once (recorded).
    fn install_base(&self) -> anyhow::Result<()> {
        let runner = Self::runner();
        let t = rp_core::apply::Target { root: self.root.clone(), runner: &runner };
        if t.load_state().modules.contains_key("base") {
            return Ok(());
        }
        let cfg = rp_core::config::load(&self.config)?;
        rp_core::apply::apply(
            &rp_core::base::Base,
            &cfg,
            &t,
            &rp_core::apply::ApplyOptions::default(),
        )
        .map_err(|e| anyhow::anyhow!("fake base install: {e}"))?;
        Ok(())
    }

    fn runner() -> RecordingRunner {
        RecordingRunner::default()
            .with_response("id -u", "0\n")
            .with_response("dpkg-query", "install ok installed")
            .with_response("uname -m", "armv7l\n")
            .with_response("uname -r", "6.18.0-fake\n")
            .with_response("iw list", IW_LIST)
            .with_response("ip -j route get", r#"[{"dev":"eth0"}]"#)
            .with_response("nmcli -g WIFI-PROPERTIES.AP", "yes")
    }

    pub fn now(&self) -> i64 {
        rp_core::changeset::now() + *self.clock_offset.lock().unwrap()
    }

    pub fn handle(&self, req: Request) -> Response {
        let _g = self.lock.lock().unwrap();
        let runner = Self::runner();
        let ctx = Ctx {
            root: self.root.clone(),
            config: self.config.clone(),
            runner: &runner,
            rpctl_argv: vec![self.rpctl.clone()],
            now: self.now(),
        };
        let r = rp_privd::handle(&ctx, req);
        let log = self.root.join("commands.log");
        let mut text = std::fs::read_to_string(&log).unwrap_or_default();
        for c in runner.calls() {
            text.push_str(&c);
            text.push('\n');
        }
        let _ = std::fs::write(log, text);
        r
    }

    /// Roll back change sets whose confirm deadline passed (the device's timer).
    pub fn expire_due(&self) -> Vec<String> {
        let _g = self.lock.lock().unwrap();
        let runner = Self::runner();
        let t = rp_core::apply::Target { root: self.root.clone(), runner: &runner };
        let now = self.now();
        let mut done = vec![];
        for c in rp_core::changeset::list(&t, &self.config) {
            if c.status == rp_core::changeset::CsStatus::AwaitingConfirm
                && c.deadline.is_some_and(|d| d <= now)
                && rp_core::changeset::expire(&t, &self.config, &c.id).is_ok()
            {
                done.push(c.id);
            }
        }
        done
    }

    /// Canned observation data, shaped like rp-agent's.
    pub fn observe(&self, path: &str) -> Result<Value, String> {
        let p = path.split('?').next().unwrap_or("");
        let now = self.now();
        Ok(match p {
            "/v1/health" => json!({
                "status": "ok", "alerts": [],
                "cpu": {"load1": 0.21, "cores": 4}, "memory": {"total_mb": 920, "available_mb": 610},
                "temperature_c": 47.2, "under_voltage": false, "throttled": false,
                "disk": {"root_used_pct": 31}, "clock_synced": true, "uptime_secs": 86_400,
                "services": {"rp-dns": "active", "rp-agent": "active", "rp-api": "active"},
            }),
            "/v1/inventory" => json!({"devices": [
                {"ip": "192.0.2.20", "mac": "02:00:00:00:00:20", "iface": "eth0", "state": "REACHABLE", "hostname": "laptop", "first_seen": now - 900_000, "new": false},
                {"ip": "198.51.100.150", "mac": "02:00:00:00:00:23", "iface": "wlan0", "state": "REACHABLE", "hostname": "smart-plug", "first_seen": now - 3_600, "new": true},
                {"ip": "198.51.100.151", "mac": "02:00:00:00:00:31", "iface": "wlan0", "state": "STALE", "hostname": null, "first_seen": now - 200_000, "new": false},
            ], "count": 3, "new_in_last_24h": 1}),
            "/v1/vpn" => {
                json!({"mode": "tailscale", "running": true, "exit_node": true, "peers": 4})
            }
            "/v1/flows" => {
                json!({"flows": [{"proto": "tcp", "src": "198.51.100.150", "dst": "203.0.113.80", "dport": 443}]})
            }
            "/v1/dns/events" => json!({"configured": true, "events": [
                {"ts": now - 30, "client": "198.51.100.150", "qname": "telemetry.example", "qtype": "A", "action": "blocked", "reason": "blocklist", "score": 0},
                {"ts": now - 90, "client": "192.0.2.20", "qname": "q7x9k2m4.example", "qtype": "A", "action": "suspicious", "reason": "dga", "score": 72},
            ]}),
            "/v1/dns/stats" => {
                json!({"configured": true, "total": 1520, "blocked": 212, "block_rate": 0.1395,
                "by_action": {"allowed": 1290, "blocked": 212, "suspicious": 18},
                "top_domains": [{"domain": "www.example", "count": 300}],
                "top_blocked": [{"domain": "telemetry.example", "count": 120}],
                "top_clients": [{"client": "198.51.100.150", "count": 700, "blocked": 150}]})
            }
            "/v1/actions" => {
                let store = rp_policy::approvals::Store::new(&under_root(
                    &self.root,
                    "/var/lib/rp/agent/actions",
                ));
                json!({"actions": store.list()})
            }
            "/v1/audit" => {
                let path = under_root(&self.root, rp_privd::AUDIT);
                json!({"chain": {"ok": rp_policy::audit::verify(&path).is_ok()},
                       "entries": rp_policy::audit::read_recent(&path, 100)})
            }
            other => return Err(format!("fake device has no {other}")),
        })
    }

    /// Create a pending privileged request, as an MCP client would (validated
    /// by the same rules rp-agent applies).
    pub fn request_action(&self, tool: &str, args: Value) -> Result<String, String> {
        let cfg = rp_core::config::load(&self.config).map_err(|e| e.to_string())?;
        let plan = rp_agent::actions::plan(&cfg, tool, &args).map_err(|e| e.0)?;
        let store =
            rp_policy::approvals::Store::new(&under_root(&self.root, "/var/lib/rp/agent/actions"));
        let a = store
            .request("mcp:claude", plan.tool, plan.args, plan.summary, plan.ttl_minutes, 15)
            .map_err(|e| e.to_string())?;
        Ok(a.id)
    }
}

fn toml_string(f: &rp_policy::pairing::PairingFile) -> String {
    format!(
        "secret = \"{}\"\ncreated_at = {}\nexpires_at = {}\nfailures = 0\nlocked_until = 0\n",
        f.secret, f.created_at, f.expires_at
    )
}

pub struct FakeBackend(pub std::sync::Arc<FakeDevice>);

impl crate::Backend for FakeBackend {
    fn privd(&self, req: Request) -> Response {
        self.0.handle(req)
    }
}

impl crate::Observer for FakeBackend {
    fn get(&self, path: &str) -> Result<Value, String> {
        self.0.observe(path)
    }
}
