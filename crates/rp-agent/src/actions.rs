//! Privileged actions: validated plans and the exact command approval runs.
//!
//! Only clients behind this box's access point can be blocked — the box is
//! their gateway, so the block is real. On the main LAN the box is just
//! another host and could not enforce anything, so those targets are refused.

use rp_policy::validate::{self, Invalid};
use rp_schema::Config;
use serde_json::{json, Value};

pub const QUARANTINE_IP_SET: &str = "ap_quarantine4";
pub const QUARANTINE_MAC_SET: &str = "ap_quarantine_mac";

#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub tool: &'static str,
    pub args: Value,
    pub summary: String,
    pub ttl_minutes: i64,
}

fn ap_subnet(cfg: &Config) -> Result<ipnet::IpNet, Invalid> {
    cfg.ap.as_ref().map(|a| ipnet::IpNet::V4(a.subnet)).ok_or_else(|| {
        Invalid("privileged actions need the ap module: only clients behind this gateway can be blocked".into())
    })
}

fn ttl(cfg: &Config, args: &Value) -> Result<i64, Invalid> {
    let max = cfg.agent.clone().unwrap_or_default().max_ttl_minutes;
    let t = args.get("ttl_minutes").and_then(Value::as_i64).unwrap_or(60);
    validate::bounded("ttl_minutes", t, 1, max)
}

fn reason(args: &Value) -> Result<String, Invalid> {
    let r = args.get("reason").and_then(Value::as_str).unwrap_or("").to_string();
    validate::plain_text("reason", &r, 200)?;
    Ok(r)
}

fn only_keys(args: &Value, allowed: &[&str]) -> Result<(), Invalid> {
    let Some(obj) = args.as_object() else {
        return Err(Invalid("arguments must be an object".into()));
    };
    if let Some(k) = obj.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(Invalid(format!("unknown argument '{k}'")));
    }
    Ok(())
}

pub fn plan(cfg: &Config, tool: &str, args: &Value) -> Result<Plan, Invalid> {
    match tool {
        "block_device" => {
            only_keys(args, &["ip", "ttl_minutes", "reason"])?;
            let net = ap_subnet(cfg)?;
            let ip_s = args
                .get("ip")
                .and_then(Value::as_str)
                .ok_or_else(|| Invalid("ip is required".into()))?;
            let ip = validate::ip_in("ip", ip_s, &net)?;
            if Some(ip)
                == cfg.ap.as_ref().map(|a| std::net::IpAddr::V4(a.subnet.hosts().next().unwrap()))
            {
                return Err(Invalid("refusing to block the gateway address".into()));
            }
            let ttl = ttl(cfg, args)?;
            let reason = reason(args)?;
            Ok(Plan {
                tool: "block_device",
                args: json!({"ip": ip.to_string(), "ttl_minutes": ttl, "reason": reason}),
                summary: format!("Block all traffic to and from AP client {ip} for {ttl} minutes"),
                ttl_minutes: ttl,
            })
        }
        "isolate_client" => {
            only_keys(args, &["mac", "ttl_minutes", "reason"])?;
            ap_subnet(cfg)?;
            let mac_s = args
                .get("mac")
                .and_then(Value::as_str)
                .ok_or_else(|| Invalid("mac is required".into()))?;
            let mac = validate::mac(mac_s)?;
            let ttl = ttl(cfg, args)?;
            let reason = reason(args)?;
            Ok(Plan {
                tool: "isolate_client",
                args: json!({"mac": mac, "ttl_minutes": ttl, "reason": reason}),
                summary: format!("Cut AP client {mac} off from everything (even if it changes IP) for {ttl} minutes"),
                ttl_minutes: ttl,
            })
        }
        other => Err(Invalid(format!("'{other}' is not a privileged action"))),
    }
}

/// argv run by `rpctl approve` (no shell). The element times out by itself,
/// so the change rolls back automatically even if nothing else runs.
pub fn command(cfg: &Config, tool: &str, args: &Value) -> Result<Vec<String>, Invalid> {
    // Re-validate: the stored request is data, not trusted input.
    let p = plan(cfg, tool, args)?;
    let (set, value) = match tool {
        "block_device" => (QUARANTINE_IP_SET, p.args["ip"].as_str().unwrap().to_string()),
        _ => (QUARANTINE_MAC_SET, p.args["mac"].as_str().unwrap().to_string()),
    };
    Ok(vec![
        "nft".into(),
        "add".into(),
        "element".into(),
        "inet".into(),
        "rp".into(),
        set.into(),
        format!("{{ {value} timeout {}m }}", p.ttl_minutes),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(ap: bool) -> Config {
        let mut t = "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n".to_string();
        if ap {
            t.push_str(
                "[ap]\nssid = \"x-iot\"\ncountry = \"TW\"\nsubnet = \"198.51.100.128/25\"\n",
            );
        }
        rp_core::config::parse(&t).unwrap()
    }

    #[test]
    fn block_device_is_confined_to_ap_clients() {
        let c = cfg(true);
        let p =
            plan(&c, "block_device", &json!({"ip": "198.51.100.140", "ttl_minutes": 30})).unwrap();
        assert!(p.summary.contains("198.51.100.140") && p.summary.contains("30 minutes"));
        assert_eq!(
            command(&c, "block_device", &p.args).unwrap().last().unwrap(),
            "{ 198.51.100.140 timeout 30m }"
        );
        for bad in [
            json!({"ip": "192.0.2.50"}),
            json!({"ip": "198.51.100.129"}),
            json!({"ip": "198.51.100.140", "ttl_minutes": 99999}),
            json!({"ip": "198.51.100.140", "ttl_minutes": 0}),
            json!({"ip": "198.51.100.140; nft flush ruleset"}),
            json!({"ip": "198.51.100.140", "extra": 1}),
            json!({"ip": "198.51.100.140", "reason": "x\n$(reboot)"}),
            json!({}),
        ] {
            assert!(plan(&c, "block_device", &bad).is_err(), "{bad} should be rejected");
        }
        assert!(plan(&cfg(false), "block_device", &json!({"ip": "198.51.100.140"})).is_err());
    }

    #[test]
    fn isolate_client_validates_mac() {
        let c = cfg(true);
        let p = plan(&c, "isolate_client", &json!({"mac": "02-AA-BB-CC-DD-02"})).unwrap();
        assert_eq!(p.args["mac"], "02:aa:bb:cc:dd:02");
        assert!(command(&c, "isolate_client", &p.args)
            .unwrap()
            .contains(&QUARANTINE_MAC_SET.to_string()));
        assert!(plan(&c, "isolate_client", &json!({"mac": "ff:ff:ff:ff:ff:ff"})).is_err());
        assert!(plan(&c, "reboot", &json!({})).is_err());
    }
}
