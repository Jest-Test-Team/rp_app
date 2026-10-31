//! Read-only collectors. Every path is resolved under `root` so tests can use
//! fixture trees; nothing here changes system state except the agent's own
//! "first seen" bookkeeping.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rp_core::files::under_root;
use rp_schema::{Config, VpnMode};
use serde_json::{json, Value};

pub struct Ctx {
    pub root: PathBuf,
    pub cfg: Config,
}

impl Ctx {
    pub fn path(&self, p: &str) -> PathBuf {
        under_root(&self.root, p)
    }
    fn read(&self, p: &str) -> Option<String> {
        std::fs::read_to_string(self.path(p)).ok()
    }
    pub fn state_dir(&self) -> PathBuf {
        let d = self.cfg.agent.clone().unwrap_or_default().state_dir;
        self.path(&d)
    }
}

pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// IPv4 neighbour table from /proc/net/arp.
pub fn neighbors(ctx: &Ctx) -> Vec<Value> {
    let Some(text) = ctx.read("/proc/net/arp") else { return vec![] };
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 6 {
                return None;
            }
            let flags = u32::from_str_radix(f[2].trim_start_matches("0x"), 16).unwrap_or(0);
            let state = if flags & 0x2 != 0 { "reachable" } else { "incomplete" };
            Some(json!({"ip": f[0], "mac": f[3].to_ascii_lowercase(), "iface": f[5], "state": state}))
        })
        .collect()
}

/// dnsmasq leases: "<expiry> <mac> <ip> <hostname> <client-id>".
pub fn leases(ctx: &Ctx) -> Vec<Value> {
    let Some(text) = ctx.read("/var/lib/rp/ap/dnsmasq.leases") else { return vec![] };
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() >= 4).then(|| {
                json!({
                    "expires": f[0].parse::<i64>().unwrap_or(0),
                    "mac": f[1].to_ascii_lowercase(),
                    "ip": f[2],
                    "hostname": if f[3] == "*" { Value::Null } else { json!(f[3]) },
                })
            })
        })
        .collect()
}

/// Devices seen on any interface, merged with DHCP leases, with "first seen"
/// tracking so devices that appeared recently can be flagged.
pub fn inventory(ctx: &Ctx) -> Value {
    let seen_path = ctx.state_dir().join("seen.json");
    let mut seen: BTreeMap<String, i64> = std::fs::read_to_string(&seen_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let now = now();
    let lease_by_mac: BTreeMap<String, Value> =
        leases(ctx).into_iter().map(|l| (l["mac"].as_str().unwrap_or("").to_string(), l)).collect();

    let mut devices = Vec::new();
    let mut changed = false;
    for n in neighbors(ctx) {
        let mac = n["mac"].as_str().unwrap_or("").to_string();
        if mac.is_empty() || mac == "00:00:00:00:00:00" {
            continue;
        }
        let first = *seen.entry(mac.clone()).or_insert_with(|| {
            changed = true;
            now
        });
        let lease = lease_by_mac.get(&mac);
        devices.push(json!({
            "ip": n["ip"], "mac": mac, "iface": n["iface"], "state": n["state"],
            "hostname": lease.map(|l| l["hostname"].clone()).unwrap_or(Value::Null),
            "first_seen": first,
            "new": now - first < 86_400,
        }));
    }
    if changed {
        let _ = std::fs::create_dir_all(ctx.state_dir());
        let _ = std::fs::write(&seen_path, serde_json::to_vec(&seen).unwrap_or_default());
    }
    let new_count = devices.iter().filter(|d| d["new"] == true).count();
    json!({"devices": devices, "count": devices.len(), "new_in_last_24h": new_count})
}

pub fn usb(ctx: &Ctx) -> Vec<Value> {
    let base = ctx.path("/sys/bus/usb/devices");
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(&base) else { return out };
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let d = e.path();
        let read = |f: &str| std::fs::read_to_string(d.join(f)).ok().map(|s| s.trim().to_string());
        let Some(vendor) = read("idVendor") else { continue };
        out.push(json!({
            "bus_path": e.file_name().to_string_lossy(),
            "vendor_id": vendor,
            "product_id": read("idProduct"),
            "manufacturer": read("manufacturer"),
            "product": read("product"),
            "speed_mbps": read("speed"),
        }));
    }
    out
}

fn meminfo(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
}

pub fn health(ctx: &Ctx) -> Value {
    let load: Vec<f64> = ctx
        .read("/proc/loadavg")
        .map(|t| t.split_whitespace().take(3).filter_map(|v| v.parse().ok()).collect())
        .unwrap_or_default();
    let mem = ctx.read("/proc/meminfo").unwrap_or_default();
    let temp = ctx
        .read("/sys/class/thermal/thermal_zone0/temp")
        .and_then(|t| t.trim().parse::<f64>().ok())
        .map(|m| m / 1000.0);
    let uptime =
        ctx.read("/proc/uptime").and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok());
    let modules: Value = ctx
        .read("/var/lib/rp/state.json")
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        .map(|v| v["modules"].clone())
        .unwrap_or(json!({}));
    json!({
        "load": load,
        "mem_total_kb": meminfo(&mem, "MemTotal:"),
        "mem_available_kb": meminfo(&mem, "MemAvailable:"),
        "temperature_c": temp,
        "uptime_s": uptime,
        "modules": modules,
    })
}

fn run_with_timeout(argv: &[&str]) -> Option<String> {
    let (prog, args) = argv.split_first()?;
    let mut child = Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) if s.success() => break,
            Ok(Some(_)) => return None,
            Ok(None) if start.elapsed() > Duration::from_secs(5) => {
                let _ = child.kill();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
    let mut out = String::new();
    std::io::Read::read_to_string(&mut child.stdout.take()?, &mut out).ok()?;
    Some(out)
}

pub fn vpn(ctx: &Ctx) -> Value {
    let Some(v) = &ctx.cfg.vpn else { return json!({"configured": false}) };
    match v.mode {
        VpnMode::Wireguard => {
            let names: BTreeMap<&str, &str> = v
                .wireguard
                .peers
                .iter()
                .map(|p| (p.public_key.as_str(), p.name.as_str()))
                .collect();
            let dump = run_with_timeout(&["wg", "show", &v.wireguard.interface, "dump"]);
            let peers: Vec<Value> = dump
                .as_deref()
                .unwrap_or("")
                .lines()
                .skip(1)
                .filter_map(|l| {
                    let f: Vec<&str> = l.split('\t').collect();
                    (f.len() >= 7).then(|| {
                        json!({
                            "name": names.get(f[0]).copied().unwrap_or("unknown"),
                            "latest_handshake": f[4].parse::<i64>().unwrap_or(0),
                            "rx_bytes": f[5].parse::<u64>().unwrap_or(0),
                            "tx_bytes": f[6].parse::<u64>().unwrap_or(0),
                        })
                    })
                })
                .collect();
            json!({"configured": true, "mode": "wireguard", "available": dump.is_some(), "peers": peers})
        }
        VpnMode::Tailscale => {
            let st = run_with_timeout(&["tailscale", "status", "--json"])
                .and_then(|t| serde_json::from_str::<Value>(&t).ok());
            match st {
                Some(s) => json!({
                    "configured": true, "mode": "tailscale", "available": true,
                    "backend_state": s["BackendState"],
                    "peers": s["Peer"].as_object().map(|p| p.len()).unwrap_or(0),
                }),
                None => json!({"configured": true, "mode": "tailscale", "available": false}),
            }
        }
    }
}

/// Connection-tracking flows (metadata only: addresses, ports, byte counts).
pub fn flows(ctx: &Ctx, limit: usize) -> Value {
    let text = ctx.read("/proc/net/nf_conntrack").unwrap_or_default();
    let mut flows = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let proto = f[2];
        let kv = |key: &str| f.iter().find_map(|t| t.strip_prefix(key)).map(str::to_string);
        let state =
            f.iter().find(|t| t.chars().all(|c| c.is_ascii_uppercase() || c == '_') && t.len() > 3);
        flows.push(json!({
            "proto": proto,
            "src": kv("src="), "dst": kv("dst="),
            "sport": kv("sport=").and_then(|p| p.parse::<u16>().ok()),
            "dport": kv("dport=").and_then(|p| p.parse::<u16>().ok()),
            "state": state,
            "packets": kv("packets=").and_then(|p| p.parse::<u64>().ok()),
            "bytes": kv("bytes=").and_then(|p| p.parse::<u64>().ok()),
        }));
        if flows.len() >= limit {
            break;
        }
    }
    let mut by_dst: BTreeMap<String, u64> = BTreeMap::new();
    for fl in &flows {
        if let (Some(d), Some(p)) = (fl["dst"].as_str(), fl["dport"].as_u64()) {
            *by_dst.entry(format!("{d}:{p}")).or_default() += 1;
        }
    }
    let mut top: Vec<(String, u64)> = by_dst.into_iter().collect();
    top.sort_by_key(|a| std::cmp::Reverse(a.1));
    top.truncate(10);
    json!({"flows": flows, "count": flows.len(), "top_destinations": top})
}

pub fn dns_events(ctx: &Ctx, since_mins: i64, action: Option<&str>, limit: u32) -> Value {
    let Some(d) = &ctx.cfg.dns else { return json!({"configured": false, "events": []}) };
    let db = ctx.path(&d.events_db);
    if !Path::new(&db).exists() {
        return json!({"configured": true, "events": []});
    }
    let since = now() - since_mins * 60;
    match rp_dns::events::query(&db, since, action, limit) {
        Ok(rows) => {
            json!({"configured": true, "events": rows.iter().map(|e| e.json()).collect::<Vec<_>>()})
        }
        Err(e) => json!({"configured": true, "error": e.to_string(), "events": []}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Ctx {
        let root = std::env::temp_dir().join(format!("rp-agent-fx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let w = |p: &str, c: &str| {
            let full = under_root(&root, p);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(full, c).unwrap();
        };
        w("/proc/net/arp", "IP address       HW type     Flags       HW address            Mask     Device\n192.0.2.50       0x1         0x2         02:aa:bb:cc:dd:01     *        eth0\n192.0.2.51       0x1         0x0         00:00:00:00:00:00     *        eth0\n198.51.100.140   0x1         0x2         02:aa:bb:cc:dd:02     *        wlan0\n"); // rp-probe:allow
        w(
            "/var/lib/rp/ap/dnsmasq.leases",
            "1893456000 02:aa:bb:cc:dd:02 198.51.100.140 plug-01 *\n",
        );
        w("/proc/loadavg", "0.10 0.20 0.30 1/100 123\n");
        w("/proc/meminfo", "MemTotal:  944000 kB\nMemAvailable:  800000 kB\n");
        w("/sys/class/thermal/thermal_zone0/temp", "46000\n");
        w("/sys/bus/usb/devices/1-1.2/idVendor", "7392\n");
        w("/sys/bus/usb/devices/1-1.2/idProduct", "7811\n");
        w("/sys/bus/usb/devices/1-1.2/product", "802.11n WLAN Adapter\n");
        w("/proc/net/nf_conntrack", "ipv4     2 tcp      6 299 ESTABLISHED src=198.51.100.140 dst=203.0.113.10 sport=40000 dport=443 packets=10 bytes=900 src=203.0.113.10 dst=192.0.2.10 sport=443 dport=40000 packets=8 bytes=4000 [ASSURED] mark=0 use=1\n");
        let cfg = rp_core::config::parse(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[agent]\n",
        )
        .unwrap();
        Ctx { root, cfg }
    }

    #[test]
    fn inventory_merges_leases_and_tracks_first_seen() {
        let c = fixture();
        let inv = inventory(&c);
        assert_eq!(inv["count"], 2, "incomplete all-zero entry is skipped");
        let plug =
            inv["devices"].as_array().unwrap().iter().find(|d| d["iface"] == "wlan0").unwrap();
        assert_eq!(plug["hostname"], "plug-01");
        assert_eq!(plug["new"], true);
        let first = plug["first_seen"].as_i64().unwrap();
        let again = inventory(&c);
        let plug2 =
            again["devices"].as_array().unwrap().iter().find(|d| d["iface"] == "wlan0").unwrap();
        assert_eq!(plug2["first_seen"].as_i64().unwrap(), first, "first_seen is stable");
    }

    #[test]
    fn health_usb_and_flows() {
        let c = fixture();
        let h = health(&c);
        assert_eq!(h["temperature_c"], 46.0);
        assert_eq!(h["mem_total_kb"], 944000);
        let u = usb(&c);
        assert_eq!(u[0]["vendor_id"], "7392");
        let f = flows(&c, 100);
        assert_eq!(f["count"], 1);
        assert_eq!(f["flows"][0]["dport"], 443);
        assert_eq!(f["flows"][0]["state"], "ESTABLISHED");
        assert_eq!(f["top_destinations"][0][0], "203.0.113.10:443");
    }

    #[test]
    fn missing_sources_degrade_gracefully() {
        let c = Ctx { root: PathBuf::from("/nonexistent-root"), cfg: fixture().cfg };
        assert!(neighbors(&c).is_empty());
        assert_eq!(flows(&c, 10)["count"], 0);
        assert_eq!(vpn(&c)["configured"], false);
        assert_eq!(dns_events(&c, 60, None, 10)["configured"], false);
    }
}
