//! `rpctl init`: write a first config for the network the device is on.
//!
//! The uplink is the interface of the default route; the LAN is that
//! interface's own prefixes (IPv4, and IPv6 ULA / global /64s). The agent and
//! the console API are enabled so the app can pair; everything else is added
//! from the app later.

use ipnet::IpNet;
use serde_json::Value;

use crate::apply::Target;

#[derive(Debug, Clone, PartialEq)]
pub struct Detected {
    pub wan_if: String,
    pub lan_cidrs: Vec<IpNet>,
}

fn run_stdout(t: &Target, argv: &[&str]) -> Option<String> {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    t.runner.run(&argv).ok().filter(|o| o.ok()).map(|o| o.stdout)
}

/// Networks from `ip -j addr show dev X` output.
pub fn networks(addr_json: &str) -> Vec<IpNet> {
    let v: Value = serde_json::from_str(addr_json).unwrap_or(Value::Null);
    let mut out = vec![];
    for link in v.as_array().into_iter().flatten() {
        for a in link["addr_info"].as_array().into_iter().flatten() {
            let (Some(local), Some(len)) = (a["local"].as_str(), a["prefixlen"].as_u64()) else {
                continue;
            };
            let Ok(ip) = local.parse::<std::net::IpAddr>() else { continue };
            let keep = match ip {
                std::net::IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && len >= 8,
                std::net::IpAddr::V6(v6) => {
                    let seg = v6.segments()[0];
                    // ULA (fc00::/7) or global unicast (2000::/3), and not a host route.
                    ((seg & 0xfe00) == 0xfc00 || (seg & 0xe000) == 0x2000)
                        && (48..=64).contains(&len)
                }
            };
            if !keep {
                continue;
            }
            if let Ok(n) = IpNet::new(ip, len as u8) {
                let n = n.trunc();
                if !out.contains(&n) {
                    out.push(n);
                }
            }
        }
    }
    out
}

pub fn detect(t: &Target) -> Result<Detected, String> {
    let routes =
        run_stdout(t, &["ip", "-j", "route", "show", "default"]).ok_or("cannot read routes")?;
    let v: Value = serde_json::from_str(&routes).map_err(|_| "cannot parse routes")?;
    let wan_if = v
        .get(0)
        .and_then(|r| r["dev"].as_str())
        .ok_or("no default route: connect the device to your network first")?
        .to_string();
    if !crate::config::valid_ifname(&wan_if) {
        return Err(format!("unexpected interface name {wan_if:?}"));
    }
    let addrs = run_stdout(t, &["ip", "-j", "addr", "show", "dev", &wan_if])
        .ok_or("cannot read addresses")?;
    let lan_cidrs = networks(&addrs);
    if lan_cidrs.is_empty() {
        return Err(format!("{wan_if} has no usable address yet"));
    }
    Ok(Detected { wan_if, lan_cidrs })
}

pub fn render(d: &Detected) -> String {
    let cidrs: Vec<String> = d.lan_cidrs.iter().map(|n| format!("\"{n}\"")).collect();
    format!(
        "# Written by `rpctl init` for the network this device was on.\n\
         # Change it from the RP Security app, or edit and run `sudo rpctl check`.\n\
         [device]\nwan_if = \"{}\"\nlan_cidrs = [{}]\n\n\
         # Observation data for the app and MCP tools.\n[agent]\n\n\
         # The console API (pair with the app).\n[api]\n",
        d.wan_if,
        cidrs.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    const ADDR: &str = r#"[{"ifname":"eth0","addr_info":[
        {"family":"inet","local":"192.0.2.10","prefixlen":24},
        {"family":"inet6","local":"fd00:1:2:3::10","prefixlen":64},
        {"family":"inet6","local":"2001:db8:1:2::10","prefixlen":64},
        {"family":"inet6","local":"fe80::1","prefixlen":64},
        {"family":"inet","local":"169.254.3.4","prefixlen":16}]}]"#;

    #[test]
    fn keeps_lan_prefixes_only() {
        let n: Vec<String> = networks(ADDR).iter().map(|n| n.to_string()).collect();
        assert_eq!(n, ["192.0.2.0/24", "fd00:1:2:3::/64", "2001:db8:1:2::/64"]);
        assert!(networks("garbage").is_empty());
    }

    #[test]
    fn detects_and_renders_a_valid_config() {
        let r = RecordingRunner::default()
            .with_response(
                "ip -j route show default",
                r#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"}]"#,
            )
            .with_response("ip -j addr show dev eth0", ADDR);
        let t = Target { root: "/".into(), runner: &r };
        let d = detect(&t).unwrap();
        assert_eq!(d.wan_if, "eth0");
        let cfg = crate::config::parse(&render(&d)).unwrap();
        assert!(cfg.api.is_some() && cfg.agent.is_some());
        assert_eq!(cfg.device.lan_cidrs.len(), 3);
    }

    #[test]
    fn no_route_is_a_clear_error() {
        let r = RecordingRunner::default().with_response("ip -j route show default", "[]");
        let t = Target { root: "/".into(), runner: &r };
        assert!(detect(&t).unwrap_err().contains("no default route"));
    }
}
