//! Pre-apply checks. Gathering facts is separate from judging them so the
//! judgement logic is pure and unit-testable.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;

use rp_schema::Config;
use serde::Serialize;

use crate::apply::Target;
use crate::config::ssh_allow;
use crate::files::under_root;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub status: Status,
    pub detail: String,
}

impl Check {
    fn new(name: &str, status: Status, detail: impl Into<String>) -> Self {
        Self { name: name.into(), status, detail: detail.into() }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Iface {
    pub exists: bool,
    pub carrier: bool,
    pub addrs: Vec<IpAddr>,
}

/// Observed facts about the target system.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub is_root: bool,
    pub os_debian_like: bool,
    pub binaries: BTreeMap<String, bool>,
    pub ifaces: BTreeMap<String, Iface>,
    /// Source address of the SSH session running rpctl, if any.
    pub ssh_client: Option<IpAddr>,
    pub authorized_keys: bool,
    /// For the ap module: passphrase file present with a valid WPA2 passphrase.
    pub ap_psk_ok: bool,
    /// For the ap module: does the interface support AP mode (None = unknown).
    pub ap_capable: Option<bool>,
    pub ap_iface_exists: bool,
}

pub const REQUIRED_BINARIES: &[&str] = &["nft", "systemctl", "sshd", "sysctl", "ip"];

/// Collect facts from the live (or `--root`-prefixed) system.
pub fn gather(cfg: &Config, t: &Target) -> Facts {
    let mut f = Facts {
        is_root: run_stdout(t, &["id", "-u"]).map(|s| s.trim() == "0").unwrap_or(false),
        ..Facts::default()
    };

    if let Ok(os) = fs::read_to_string(under_root(&t.root, "/etc/os-release")) {
        f.os_debian_like = os.lines().any(|l| {
            let l = l.to_ascii_lowercase();
            (l.starts_with("id=") || l.starts_with("id_like=")) && l.contains("debian")
        });
    }

    for b in REQUIRED_BINARIES {
        let found = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .iter()
            .any(|d| under_root(&t.root, &format!("{d}/{b}")).exists());
        f.binaries.insert(b.to_string(), found);
    }

    let mut names = vec![cfg.device.wan_if.clone()];
    if cfg.device.mgmt_if() != cfg.device.wan_if {
        names.push(cfg.device.mgmt_if().to_string());
    }
    for name in names {
        let sys = under_root(&t.root, &format!("/sys/class/net/{name}"));
        let exists = sys.exists();
        let carrier =
            fs::read_to_string(sys.join("carrier")).map(|c| c.trim() == "1").unwrap_or(false);
        let addrs = run_stdout(t, &["ip", "-j", "addr", "show", "dev", &name])
            .map(|j| parse_ip_json(&j))
            .unwrap_or_default();
        f.ifaces.insert(name, Iface { exists, carrier, addrs });
    }

    f.ssh_client = std::env::var("SSH_CONNECTION")
        .ok()
        .and_then(|v| v.split_whitespace().next().and_then(|a| a.parse().ok()));

    let mut key_files = vec![under_root(&t.root, "/root/.ssh/authorized_keys")];
    if let Ok(rd) = fs::read_dir(under_root(&t.root, "/home")) {
        key_files.extend(rd.flatten().map(|e| e.path().join(".ssh/authorized_keys")));
    }
    if let Some(a) = &cfg.ap {
        f.ap_iface_exists =
            under_root(&t.root, &format!("/sys/class/net/{}", a.interface)).exists();
        f.ap_psk_ok = fs::read_to_string(under_root(&t.root, &a.passphrase_file))
            .ok()
            .and_then(|t| t.lines().next().map(str::to_string))
            .and_then(|l| l.strip_prefix("00:00:00:00:00:00 ").map(str::to_string)) // rp-probe:allow
            .is_some_and(|p| crate::ap::valid_passphrase(&p));
        f.ap_capable =
            run_stdout(t, &["nmcli", "-g", "WIFI-PROPERTIES.AP", "device", "show", &a.interface])
                .map(|o| o.trim() == "yes");
    }
    f.authorized_keys = key_files.iter().any(|p| {
        fs::read_to_string(p)
            .map(|t| {
                t.lines().any(|l| {
                    let l = l.trim_start();
                    l.starts_with("ssh-") || l.starts_with("ecdsa-") || l.starts_with("sk-")
                })
            })
            .unwrap_or(false)
    });
    f
}

fn run_stdout(t: &Target, argv: &[&str]) -> Option<String> {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    t.runner.run(&argv).ok().filter(|o| o.ok()).map(|o| o.stdout)
}

/// Extract addresses from `ip -j addr show` output.
pub fn parse_ip_json(json: &str) -> Vec<IpAddr> {
    let v: serde_json::Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    v.as_array()
        .into_iter()
        .flatten()
        .flat_map(|link| link["addr_info"].as_array().cloned().unwrap_or_default())
        .filter_map(|a| a["local"].as_str().and_then(|s| s.parse().ok()))
        .collect()
}

/// Judge facts for a module. `dry_run` downgrades root/binary checks.
pub fn evaluate(cfg: &Config, module: &str, facts: &Facts, dry_run: bool) -> Vec<Check> {
    use Status::*;
    let mut out = Vec::new();
    let soft = if dry_run { Warn } else { Fail };

    out.push(if facts.is_root {
        Check::new("root", Pass, "running as root")
    } else {
        Check::new("root", soft, "apply needs root (sudo rpctl ...)")
    });
    out.push(if facts.os_debian_like {
        Check::new("os", Pass, "Debian-based OS")
    } else {
        Check::new("os", soft, "not a Debian-based OS; only Raspberry Pi OS / Debian are supported")
    });
    for (b, found) in &facts.binaries {
        out.push(if *found {
            Check::new(&format!("binary:{b}"), Pass, "found")
        } else {
            Check::new(&format!("binary:{b}"), soft, "not installed")
        });
    }

    let mgmt = cfg.device.mgmt_if();
    match facts.ifaces.get(mgmt) {
        Some(i) if i.exists && i.carrier => {
            out.push(Check::new("mgmt_if", Pass, format!("{mgmt} is up with carrier")))
        }
        Some(i) if i.exists => out.push(Check::new(
            "mgmt_if",
            Fail,
            format!("{mgmt} has no carrier — plug it in before changing the firewall"),
        )),
        _ => out.push(Check::new("mgmt_if", Fail, format!("interface {mgmt} does not exist"))),
    }

    let allow = ssh_allow(cfg);
    if let Some(i) = facts.ifaces.get(mgmt) {
        let in_lan = i.addrs.iter().any(|a| cfg.device.lan_cidrs.iter().any(|n| n.contains(a)));
        if !i.addrs.is_empty() && !in_lan {
            out.push(Check::new(
                "mgmt_addr",
                Warn,
                format!("no address on {mgmt} is inside device.lan_cidrs — check the config"),
            ));
        }
    }

    match facts.ssh_client {
        Some(c) if allow.iter().any(|n| n.contains(&c)) => {
            out.push(Check::new("ssh_lockout", Pass, "current SSH session is inside ssh allow-list"))
        }
        Some(_) => out.push(Check::new(
            "ssh_lockout",
            Fail,
            "your current SSH source address is NOT in the ssh allow-list; applying would lock you out",
        )),
        None => out.push(Check::new("ssh_lockout", Pass, "not running over SSH")),
    }

    if module == "ap" {
        if let Some(a) = &cfg.ap {
            out.push(if facts.ap_iface_exists {
                Check::new("ap_iface", Pass, format!("{} exists", a.interface))
            } else {
                Check::new("ap_iface", Fail, format!("interface {} does not exist", a.interface))
            });
            out.push(if facts.ap_psk_ok {
                Check::new("ap_passphrase", Pass, "passphrase file is valid")
            } else {
                Check::new(
                    "ap_passphrase",
                    Fail,
                    format!(
                        "{} missing or invalid — run: sudo rpctl ap set-passphrase",
                        a.passphrase_file
                    ),
                )
            });
            out.push(match facts.ap_capable {
                Some(true) => Check::new("ap_mode", Pass, "adapter supports AP mode"),
                Some(false) => Check::new("ap_mode", Fail, "adapter does not support AP mode"),
                None => {
                    Check::new("ap_mode", Warn, "could not determine AP support (nmcli missing?)")
                }
            });
            if a.interface == cfg.device.mgmt_if() {
                out.push(Check::new(
                    "ap_lockout",
                    Fail,
                    "the AP interface is your management interface",
                ));
            }
        }
    }

    if module == "base" && !cfg.ssh.password_auth && !facts.authorized_keys {
        out.push(Check::new(
            "ssh_keys",
            Fail,
            "ssh.password_auth = false but no authorized_keys found; you would be locked out",
        ));
    }
    out
}

pub fn passed(checks: &[Check]) -> bool {
    checks.iter().all(|c| c.status != Status::Fail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(extra: &str) -> Config {
        parse(&format!("[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n{extra}"))
            .unwrap()
    }

    fn good() -> Facts {
        let mut f = Facts { is_root: true, os_debian_like: true, ..Facts::default() };
        for b in REQUIRED_BINARIES {
            f.binaries.insert(b.to_string(), true);
        }
        f.ifaces.insert(
            "eth0".into(),
            Iface { exists: true, carrier: true, addrs: vec!["192.0.2.10".parse().unwrap()] },
        );
        f
    }

    fn status(checks: &[Check], name: &str) -> Status {
        checks.iter().find(|c| c.name == name).unwrap().status
    }

    #[test]
    fn healthy_system_passes() {
        assert!(passed(&evaluate(&cfg(""), "base", &good(), false)));
    }

    #[test]
    fn ssh_session_outside_allow_list_fails() {
        let mut f = good();
        f.ssh_client = Some("198.51.100.7".parse().unwrap());
        let c = evaluate(&cfg(""), "base", &f, false);
        assert_eq!(status(&c, "ssh_lockout"), Status::Fail);
        f.ssh_client = Some("192.0.2.99".parse().unwrap());
        assert_eq!(status(&evaluate(&cfg(""), "base", &f, false), "ssh_lockout"), Status::Pass);
    }

    #[test]
    fn missing_carrier_fails() {
        let mut f = good();
        f.ifaces.get_mut("eth0").unwrap().carrier = false;
        assert_eq!(status(&evaluate(&cfg(""), "base", &f, false), "mgmt_if"), Status::Fail);
        f.ifaces.clear();
        assert_eq!(status(&evaluate(&cfg(""), "base", &f, false), "mgmt_if"), Status::Fail);
    }

    #[test]
    fn disabling_passwords_requires_keys() {
        let c = cfg("[ssh]\npassword_auth = false\n");
        assert_eq!(status(&evaluate(&c, "base", &good(), false), "ssh_keys"), Status::Fail);
        let mut f = good();
        f.authorized_keys = true;
        assert!(passed(&evaluate(&c, "base", &f, false)));
    }

    #[test]
    fn dry_run_softens_root_and_binaries() {
        let mut f = good();
        f.is_root = false;
        f.binaries.insert("nft".into(), false);
        let c = evaluate(&cfg(""), "base", &f, true);
        assert_eq!(status(&c, "root"), Status::Warn);
        assert_eq!(status(&c, "binary:nft"), Status::Warn);
        assert_eq!(status(&evaluate(&cfg(""), "base", &f, false), "root"), Status::Fail);
    }

    #[test]
    fn parses_ip_json() {
        let j = r#"[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10"},{"family":"inet6","local":"fe80::1"}]}]"#;
        assert_eq!(parse_ip_json(j).len(), 2);
        assert!(parse_ip_json("not json").is_empty());
    }
}
