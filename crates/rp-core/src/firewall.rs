//! The `firewall` module: typed rules from the console, rendered to
//! `/etc/rp/nft.d/05-firewall.nft` (loaded before every other module's
//! snippet, so a user drop wins over a module accept).
//!
//! There is no way to pass nftables text: zones, protocols, ports and an
//! action are rendered from validated values. Rules that could cut off the
//! management path — anything dropping traffic to this device's SSH, API,
//! DNS, DHCP or mDNS, or "everything to the device" — are refused.

use std::fmt::Write;

use ipnet::IpNet;
use rp_schema::{Config, FwAction, FwRule, Proto, Zone};

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};
use crate::nft::{self, split_families};

pub const SNIPPET_PATH: &str = "/etc/rp/nft.d/05-firewall.nft";
pub const CHECK_PATH: &str = "/etc/rp/.check/firewall.nft";
pub const MAX_RULES: usize = 64;

pub struct Firewall;

fn api_port(cfg: &Config) -> u16 {
    cfg.api.as_ref().map(|a| a.listen.port()).unwrap_or(8443)
}

/// Ports on this device that keep it manageable and the networks working.
pub fn protected_ports(cfg: &Config) -> Vec<u16> {
    let mut p = vec![cfg.ssh.port, api_port(cfg), 53, 67, 68, 5353];
    p.sort_unstable();
    p.dedup();
    p
}

pub fn validate_rules(cfg: &Config, rules: &[FwRule]) -> Vec<String> {
    let mut e = vec![];
    if rules.len() > MAX_RULES {
        e.push(format!("firewall: at most {MAX_RULES} rules"));
    }
    let protected = protected_ports(cfg);
    for (i, r) in rules.iter().enumerate() {
        let at = format!("firewall.rules[{i}] ({})", r.name);
        let name_ok = !r.name.trim().is_empty()
            && r.name.len() <= 40
            && r.name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_'));
        if !name_ok {
            e.push(format!("{at}: name must be 1-40 letters, digits, spaces, '-' or '_'"));
        }
        if r.from == Zone::Device {
            e.push(format!("{at}: 'from' cannot be the device (outgoing traffic is not filtered)"));
        }
        if r.from == r.to && r.to != Zone::Device {
            e.push(format!("{at}: from and to are the same zone"));
        }
        if !r.ports.is_empty() && !matches!(r.proto, Proto::Tcp | Proto::Udp) {
            e.push(format!("{at}: ports need proto tcp or udp"));
        }
        if r.ports.contains(&0) || r.ports.len() > 16 {
            e.push(format!("{at}: 1-16 ports, each 1-65535"));
        }
        for n in &r.dest {
            if n.prefix_len() == 0 {
                e.push(format!("{at}: dest {n} covers everything (leave dest empty instead)"));
            }
            if n.network() != n.addr() {
                e.push(format!("{at}: dest {n} has host bits set"));
            }
        }
        if r.to == Zone::Device && r.action != FwAction::Accept {
            if r.ports.is_empty() || !matches!(r.proto, Proto::Tcp | Proto::Udp) {
                e.push(format!(
                    "{at}: blocking traffic to the device needs tcp/udp and explicit ports"
                ));
            } else if let Some(p) = r.ports.iter().find(|p| protected.contains(p)) {
                e.push(format!("{at}: port {p} keeps the device manageable and cannot be blocked"));
            }
        }
        if r.to == Zone::Iot && cfg.ap.is_none() || r.from == Zone::Iot && cfg.ap.is_none() {
            e.push(format!("{at}: the iot zone needs the IoT access point ([ap])"));
        }
        if (r.to == Zone::Vpn || r.from == Zone::Vpn) && cfg.vpn.is_none() {
            e.push(format!("{at}: the vpn zone needs the VPN ([vpn])"));
        }
    }
    e
}

/// Interface / address matches for a zone. `dir` is "i" (from) or "o" (to).
fn zone_match(cfg: &Config, z: Zone, dir: char, fam: Option<u8>) -> Option<String> {
    let wan = &cfg.device.wan_if;
    let (sd, ifx) = if dir == 'i' { ("saddr", "iifname") } else { ("daddr", "oifname") };
    let fam_set = |set4: &str, set6: &str, neg: &str| match fam {
        Some(4) => format!("{ifx} \"{wan}\" ip {sd} {neg}@{set4}"),
        Some(6) => format!("{ifx} \"{wan}\" ip6 {sd} {neg}@{set6}"),
        _ => unreachable!(),
    };
    Some(match z {
        Zone::Lan => fam_set("lan4", "lan6", ""),
        Zone::Wan => fam_set("lan4", "lan6", "!= "),
        Zone::Iot => format!("{ifx} \"{}\"", cfg.ap.as_ref()?.interface),
        Zone::Vpn => format!("{ifx} \"{}\"", crate::vpn::vpn_if(cfg)),
        Zone::Device => String::new(),
    })
}

fn rule_lines(cfg: &Config, r: &FwRule) -> Vec<String> {
    // lan/wan matches are per address family; others are family-neutral.
    let fam_based = |z: Zone| matches!(z, Zone::Lan | Zone::Wan);
    let (d4, d6) = split_families(&r.dest);
    let families: Vec<Option<u8>> = if fam_based(r.from) || fam_based(r.to) || !r.dest.is_empty() {
        let mut f = vec![];
        if r.dest.is_empty() || !d4.is_empty() {
            f.push(Some(4));
        }
        if r.dest.is_empty() || !d6.is_empty() {
            f.push(Some(6));
        }
        f
    } else {
        vec![None]
    };
    let mut out = vec![];
    for fam in families {
        let mut m: Vec<String> = vec![];
        let f = fam.or(Some(4));
        if let Some(x) = zone_match(cfg, r.from, 'i', f).filter(|x| !x.is_empty()) {
            m.push(x);
        }
        if let Some(x) = zone_match(cfg, r.to, 'o', f).filter(|x| !x.is_empty()) {
            m.push(x);
        }
        let dests: &[IpNet] = match fam {
            Some(4) => &d4,
            Some(6) => &d6,
            _ => &[],
        };
        if !dests.is_empty() {
            let list: Vec<String> = dests.iter().map(|n| n.to_string()).collect();
            let k = if fam == Some(6) { "ip6" } else { "ip" };
            m.push(format!("{k} daddr {{ {} }}", list.join(", ")));
        }
        match (r.proto, fam) {
            (Proto::Tcp | Proto::Udp, _) => {
                let p = if r.proto == Proto::Tcp { "tcp" } else { "udp" };
                if r.ports.is_empty() {
                    m.push(format!("meta l4proto {p}"));
                } else {
                    let list: Vec<String> = r.ports.iter().map(|x| x.to_string()).collect();
                    m.push(format!("{p} dport {{ {} }}", list.join(", ")));
                }
            }
            (Proto::Icmp, Some(6)) => m.push("meta l4proto ipv6-icmp".into()),
            (Proto::Icmp, _) => m.push("meta l4proto icmp".into()),
            (Proto::Any, _) => {}
        }
        if r.log {
            // A rate-limited log rule before the verdict (same match).
            let tag: String =
                r.name.chars().filter(|c| c.is_ascii_alphanumeric()).take(12).collect();
            out.push(format!("{} limit rate 6/minute log prefix \"rp-fw-{tag} \"", m.join(" ")));
        }
        let verdict = match r.action {
            FwAction::Accept => "accept",
            FwAction::Drop => "drop",
            FwAction::Reject => {
                if matches!(r.proto, Proto::Tcp) {
                    "reject with tcp reset"
                } else {
                    "reject"
                }
            }
        };
        m.push(verdict.into());
        out.push(m.join(" "));
    }
    out
}

pub fn snippet(cfg: &Config) -> String {
    let rules = cfg.firewall.as_ref().map(|f| f.rules.as_slice()).unwrap_or(&[]);
    let mut s = format!("# {HEADER}\n# Console firewall rules, evaluated before every module's rules.\ntable inet rp {{\n");
    let (fwd, inp): (Vec<&FwRule>, Vec<&FwRule>) = rules.iter().partition(|r| r.to != Zone::Device);
    s.push_str("\tchain mod_forward {\n");
    for r in fwd {
        let _ = writeln!(s, "\t\t# {}", r.name);
        for l in rule_lines(cfg, r) {
            let _ = writeln!(s, "\t\t{l}");
        }
    }
    s.push_str("\t}\n\tchain mod_input {\n");
    for r in inp {
        let _ = writeln!(s, "\t\t# {}", r.name);
        for l in rule_lines(cfg, r) {
            let _ = writeln!(s, "\t\t{l}");
        }
    }
    s.push_str("\t}\n}\n");
    s
}

impl Module for Firewall {
    fn name(&self) -> &'static str {
        "firewall"
    }

    fn enabled(&self, cfg: &Config) -> Result<(), String> {
        cfg.firewall
            .as_ref()
            .map(|_| ())
            .ok_or_else(|| "no [firewall] section in the config".into())
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        if cfg.firewall.is_none() {
            return vec![];
        }
        let snip = snippet(cfg);
        vec![
            ManagedFile::new(SNIPPET_PATH, 0o600, snip.clone()),
            ManagedFile::check_only(CHECK_PATH, nft::combined(cfg, &snip)),
        ]
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![Step::cmd(&["nft", "-c", "-f", &format!("{{staged:{CHECK_PATH}}}")])]
    }

    fn post_apply(&self, _cfg: &Config) -> Vec<Step> {
        vec![Step::cmd(&["systemctl", "reload-or-restart", "rp-firewall.service"])]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![Step::best_effort(&["systemctl", "reload-or-restart", "rp-firewall.service"])]
    }

    fn arms_dead_man(&self) -> bool {
        true
    }

    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(rules: &str) -> Result<Config, String> {
        parse(&format!(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\", \"2001:db8:1::/64\"]\n\
             [ap]\nssid = \"x\"\ncountry = \"TW\"\nsubnet = \"198.51.100.128/25\"\n[api]\n[firewall]\n{rules}"
        ))
        .map_err(|e| e.to_string())
    }

    #[test]
    fn iot_to_lan_drop_renders_per_family() {
        let c = cfg("[[firewall.rules]]\nname = \"No IoT to NAS\"\nfrom = \"iot\"\nto = \"lan\"\nproto = \"tcp\"\nports = [445, 139]\naction = \"drop\"\n").unwrap();
        let s = snippet(&c);
        assert!(
            s.contains(
                "iifname \"wlan0\" oifname \"eth0\" ip daddr @lan4 tcp dport { 445, 139 } drop"
            ),
            "{s}"
        );
        assert!(s.contains(
            "iifname \"wlan0\" oifname \"eth0\" ip6 daddr @lan6 tcp dport { 445, 139 } drop"
        ));
        assert!(!s.contains("mod_input {\n\t\t#"), "no input rules");
    }

    #[test]
    fn wan_is_the_uplink_minus_the_lan_and_logging_is_separate() {
        let c = cfg("[[firewall.rules]]\nname = \"Telnet\"\nfrom = \"iot\"\nto = \"wan\"\nproto = \"tcp\"\nports = [23]\naction = \"reject\"\nlog = true\n").unwrap();
        let s = snippet(&c);
        assert!(s.contains("oifname \"eth0\" ip daddr != @lan4 tcp dport { 23 } limit rate 6/minute log prefix \"rp-fw-Telnet \""));
        assert!(
            s.contains("oifname \"eth0\" ip daddr != @lan4 tcp dport { 23 } reject with tcp reset")
        );
    }

    #[test]
    fn dest_networks_restrict_and_pick_the_family() {
        let c = cfg("[[firewall.rules]]\nname = \"Printer\"\nfrom = \"iot\"\nto = \"lan\"\ndest = [\"192.0.2.40/32\"]\nproto = \"tcp\"\nports = [631]\naction = \"accept\"\n").unwrap();
        let s = snippet(&c);
        assert!(s.contains("ip daddr { 192.0.2.40/32 } tcp dport { 631 } accept"));
        assert!(!s.contains("ip6 daddr"), "no IPv6 rule for an IPv4-only dest");
    }

    #[test]
    fn device_rules_go_to_input_and_management_cannot_be_blocked() {
        let ok = cfg("[[firewall.rules]]\nname = \"No SNMP\"\nfrom = \"iot\"\nto = \"device\"\nproto = \"udp\"\nports = [161]\naction = \"drop\"\n").unwrap();
        let s = snippet(&ok);
        let input = &s[s.find("chain mod_input").unwrap()..];
        assert!(input.contains("iifname \"wlan0\" udp dport { 161 } drop"));
        for bad in [
            "proto = \"tcp\"\nports = [22]",
            "proto = \"tcp\"\nports = [8443]",
            "proto = \"udp\"\nports = [53]",
            "proto = \"any\"",
        ] {
            let e = cfg(&format!("[[firewall.rules]]\nname = \"x\"\nfrom = \"lan\"\nto = \"device\"\n{bad}\naction = \"drop\"\n")).unwrap_err();
            assert!(e.contains("cannot be blocked") || e.contains("explicit ports"), "{bad}: {e}");
        }
    }

    #[test]
    fn invalid_rules_are_refused() {
        for (rule, want) in [
            ("name = \"x;flush ruleset\"\nfrom = \"lan\"\nto = \"wan\"\naction = \"drop\"", "name must"),
            ("name = \"x\"\nfrom = \"device\"\nto = \"wan\"\naction = \"drop\"", "cannot be the device"),
            ("name = \"x\"\nfrom = \"lan\"\nto = \"lan\"\naction = \"drop\"", "same zone"),
            ("name = \"x\"\nfrom = \"lan\"\nto = \"wan\"\nports = [80]\naction = \"drop\"", "need proto"),
            ("name = \"x\"\nfrom = \"lan\"\nto = \"wan\"\ndest = [\"0.0.0.0/0\"]\naction = \"drop\"", "covers everything"),
            ("name = \"x\"\nfrom = \"vpn\"\nto = \"wan\"\naction = \"drop\"", "needs the VPN"),
            ("name = \"x\"\nfrom = \"lan\"\nto = \"wan\"\naction = \"masquerade\"", "unknown variant"),
        ] {
            let e = cfg(&format!("[[firewall.rules]]\n{rule}\n")).unwrap_err();
            assert!(e.contains(want), "{rule}: {e}");
        }
    }

    #[test]
    fn empty_firewall_is_valid_and_arms_dead_man() {
        let c = cfg("").unwrap();
        assert!(snippet(&c).contains("chain mod_forward {\n\t}"));
        assert!(Firewall.arms_dead_man());
        assert_eq!(Firewall.render(&c).len(), 2);
    }
}
