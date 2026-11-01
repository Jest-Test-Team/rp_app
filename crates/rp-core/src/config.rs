//! Loading and semantic validation of `rp.toml`.

use std::path::Path;

use ipnet::IpNet;
use rp_schema::Config;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("invalid TOML in {path}: {source}")]
    Parse { path: String, source: toml::de::Error },
    #[error("invalid configuration:\n  - {}", .0.join("\n  - "))]
    Invalid(Vec<String>),
}

/// Read, parse and validate a config file.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|source| ConfigError::Read { path: path.display().to_string(), source })?;
    parse(&text).map_err(|e| match e {
        ConfigError::Parse { source, .. } => {
            ConfigError::Parse { path: path.display().to_string(), source }
        }
        other => other,
    })
}

/// Parse and validate config text.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let cfg: Config = toml::from_str(text)
        .map_err(|source| ConfigError::Parse { path: "<input>".into(), source })?;
    validate(&cfg)?;
    Ok(cfg)
}

/// Linux interface names: 1–15 chars, no '/', whitespace or ':' .
pub fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name != "."
        && name != ".."
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Networks that must never be used as an allow-list (would open everything).
fn is_catch_all(net: &IpNet) -> bool {
    net.prefix_len() == 0
}

/// Semantic checks that serde cannot express.
pub fn validate(cfg: &Config) -> Result<(), ConfigError> {
    let mut errs = Vec::new();
    let d = &cfg.device;

    if !valid_ifname(&d.wan_if) {
        errs.push(format!("device.wan_if '{}' is not a valid interface name", d.wan_if));
    }
    if let Some(m) = &d.mgmt_if {
        if !valid_ifname(m) {
            errs.push(format!("device.mgmt_if '{m}' is not a valid interface name"));
        }
    }
    if d.lan_cidrs.is_empty() {
        errs.push("device.lan_cidrs must list at least one network".into());
    }
    for n in &d.lan_cidrs {
        if is_catch_all(n) {
            errs.push(format!("device.lan_cidrs entry {n} covers the whole address space"));
        }
        if n.network() != n.addr() {
            errs.push(format!("device.lan_cidrs entry {n} has host bits set (use {})", n.trunc()));
        }
    }

    if cfg.ssh.port == 0 {
        errs.push("ssh.port must be 1-65535".into());
    }
    for n in &cfg.ssh.allow_from {
        if is_catch_all(n) {
            errs.push(format!("ssh.allow_from entry {n} would expose sshd to every address"));
        }
    }

    if let Some(v) = &cfg.vpn {
        validate_vpn(cfg, v, &mut errs);
    }
    if let Some(d) = &cfg.dns {
        validate_dns(d, &mut errs);
    }
    if let Some(a) = &cfg.ap {
        validate_ap(cfg, a, &mut errs);
    }
    if let Some(a) = &cfg.agent {
        if !(1..=1024).contains(&a.scan_max_hosts) {
            errs.push("agent.scan_max_hosts must be 1-1024".into());
        }
        if !(1..=1440).contains(&a.pending_minutes) {
            errs.push("agent.pending_minutes must be 1-1440".into());
        }
        if !(1..=10_080).contains(&a.max_ttl_minutes) {
            errs.push("agent.max_ttl_minutes must be 1-10080".into());
        }
        for n in &a.scan_allow {
            if n.prefix_len() < 16 {
                errs.push(format!("agent.scan_allow entry {n} is too broad (use /16 or smaller)"));
            }
        }
        for p in [&a.token_file, &a.state_dir] {
            if !p.starts_with('/') || p.contains(['\'', ' ']) {
                errs.push(format!("agent path '{p}' must be absolute without quotes or spaces"));
            }
        }
    }
    if let Some(m) = &cfg.mcp {
        if cfg.agent.is_none() {
            errs.push("[mcp] needs an [agent] section".into());
        }
        if !(1..=1000).contains(&m.rate_limit_per_minute) {
            errs.push("mcp.rate_limit_per_minute must be 1-1000".into());
        }
        for c in &m.stdio_capabilities {
            if !matches!(c.as_str(), "read" | "active" | "privileged") {
                errs.push(format!("mcp.stdio_capabilities: unknown capability '{c}'"));
            }
        }
        for p in [&m.clients_file, &m.agent_token_file, &m.audit_log] {
            if !p.starts_with('/') || p.contains(['\'', ' ']) {
                errs.push(format!("mcp path '{p}' must be absolute without quotes or spaces"));
            }
        }
    }

    if cfg.base.journal_max_mb > 4096 {
        errs.push("base.journal_max_mb must be 0-4096".into());
    }

    let t = cfg.base.confirm_timeout_secs;
    if !(30..=3600).contains(&t) {
        errs.push(format!("base.confirm_timeout_secs {t} must be between 30 and 3600"));
    }

    if errs.is_empty() {
        Ok(())
    } else {
        Err(ConfigError::Invalid(errs))
    }
}

fn safe_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

fn validate_vpn(cfg: &Config, v: &rp_schema::Vpn, errs: &mut Vec<String>) {
    use rp_schema::VpnMode;
    for n in &v.allow_lan {
        if is_catch_all(n) {
            errs.push(format!("vpn.allow_lan entry {n} would expose every network"));
        }
    }
    match v.mode {
        VpnMode::Tailscale => {
            let t = &v.tailscale;
            if let Some(p) = &t.auth_key_file {
                if !p.starts_with('/') || p.chars().any(|c| c.is_whitespace() || c == '\'') {
                    errs.push(
                        "vpn.tailscale.auth_key_file must be an absolute path without spaces"
                            .into(),
                    );
                }
            }
            if let Some(h) = &t.hostname {
                if !safe_token(h, 63) || h.contains('_') {
                    errs.push(format!(
                        "vpn.tailscale.hostname '{h}' must be letters, digits and '-'"
                    ));
                }
            }
            if !(3..=20).contains(&t.debian_codename.len())
                || !t.debian_codename.chars().all(|c| c.is_ascii_lowercase())
            {
                errs.push(format!(
                    "vpn.tailscale.debian_codename '{}' is not valid",
                    t.debian_codename
                ));
            }
        }
        VpnMode::Wireguard => {
            let w = &v.wireguard;
            if !valid_ifname(&w.interface) {
                errs.push(format!(
                    "vpn.wireguard.interface '{}' is not a valid interface name",
                    w.interface
                ));
            }
            if w.listen_port == 0 {
                errs.push("vpn.wireguard.listen_port must be 1-65535".into());
            }
            if w.subnet.prefix_len() > 30 {
                errs.push(format!(
                    "vpn.wireguard.subnet {} is too small (use /30 or larger)",
                    w.subnet
                ));
            }
            if w.subnet.network() != w.subnet.addr() {
                errs.push(format!("vpn.wireguard.subnet {} has host bits set", w.subnet));
            }
            let tunnel = IpNet::V4(w.subnet.trunc());
            for lan in &cfg.device.lan_cidrs {
                if lan.contains(&tunnel.network()) || tunnel.contains(&lan.network()) {
                    errs.push(format!(
                        "vpn.wireguard.subnet {} overlaps device.lan_cidrs {lan}",
                        w.subnet
                    ));
                }
            }
            if let Some(e) = &w.endpoint {
                let ok = e.rsplit_once(':').is_some_and(|(h, p)| {
                    !h.is_empty()
                        && h.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '[' | ']' | ':')
                        })
                        && p.parse::<u16>().is_ok_and(|p| p > 0)
                });
                if !ok {
                    errs.push(format!("vpn.wireguard.endpoint '{e}' must be host:port"));
                }
            }
            let max_host = (1u64 << (32 - w.subnet.prefix_len())) - 2;
            let mut names = std::collections::BTreeSet::new();
            let mut hosts = std::collections::BTreeSet::new();
            for p in &w.peers {
                if !safe_token(&p.name, 32) {
                    errs.push(format!(
                        "vpn.wireguard peer name '{}' must be letters, digits, '-' or '_'",
                        p.name
                    ));
                }
                if !names.insert(p.name.clone()) {
                    errs.push(format!("vpn.wireguard peer name '{}' is duplicated", p.name));
                }
                if !hosts.insert(p.host) {
                    errs.push(format!("vpn.wireguard peer host {} is used twice", p.host));
                }
                if p.host < 2 || u64::from(p.host) > max_host {
                    errs.push(format!(
                        "vpn.wireguard peer '{}' host {} must be 2..={max_host} (1 is the server)",
                        p.name, p.host
                    ));
                }
                if !valid_wg_key(&p.public_key) {
                    errs.push(format!(
                        "vpn.wireguard peer '{}' public_key is not a WireGuard key",
                        p.name
                    ));
                }
            }
        }
    }
}

/// A DNS name (optionally `*.`-prefixed) as used in allow/block lists.
pub fn valid_domain(d: &str) -> bool {
    let d = d.trim_end_matches('.');
    let d = d.strip_prefix("*.").unwrap_or(d);
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

fn validate_dns(d: &rp_schema::Dns, errs: &mut Vec<String>) {
    if d.upstreams.is_empty() {
        errs.push("dns.upstreams must list at least one resolver".into());
    }
    if d.listen.is_empty() {
        errs.push("dns.listen must list at least one address".into());
    }
    for l in &d.listen {
        if l.port() == 0 {
            errs.push(format!("dns.listen {l} needs a port"));
        }
    }
    for u in &d.upstreams {
        if u.port() == 0 || u.ip().is_unspecified() {
            errs.push(format!("dns.upstreams entry {u} is not a usable resolver address"));
        }
        // Forwarding to ourselves would loop every query forever.
        let loops = d.listen.iter().any(|l| {
            l.port() == u.port()
                && (l.ip() == u.ip() || (l.ip().is_unspecified() && u.ip().is_loopback()))
        });
        if loops {
            errs.push(format!("dns.upstreams entry {u} points back at rp-dns itself"));
        }
    }
    for (field, list) in [("dns.allow", &d.allow), ("dns.block", &d.block)] {
        for name in list {
            if !valid_domain(name) {
                errs.push(format!("{field} entry '{name}' is not a valid domain"));
            }
        }
    }
    for p in d.blocklists.iter().chain(std::iter::once(&d.events_db)) {
        if !p.starts_with('/') {
            errs.push(format!("dns path '{p}' must be absolute"));
        }
    }
    if d.suspicious_threshold > 100 {
        errs.push("dns.suspicious_threshold must be 0-100".into());
    }
    if d.rate_limit_qps == 0 {
        errs.push("dns.rate_limit_qps must be at least 1".into());
    }
    if !(100..=10_000).contains(&d.upstream_timeout_ms) {
        errs.push("dns.upstream_timeout_ms must be 100-10000".into());
    }
    if d.events_retention_days == 0 || d.events_retention_days > 365 {
        errs.push("dns.events_retention_days must be 1-365".into());
    }
}

fn validate_ap(cfg: &Config, a: &rp_schema::Ap, errs: &mut Vec<String>) {
    if !valid_ifname(&a.interface) {
        errs.push(format!("ap.interface '{}' is not a valid interface name", a.interface));
    }
    if a.interface == cfg.device.wan_if || a.interface == cfg.device.mgmt_if() {
        errs.push(format!(
            "ap.interface '{}' is your uplink/management interface; the AP would cut you off",
            a.interface
        ));
    }
    if a.ssid.is_empty() || a.ssid.len() > 32 || a.ssid.chars().any(|c| c.is_control()) {
        errs.push("ap.ssid must be 1-32 bytes without control characters".into());
    }
    if a.country.len() != 2 || !a.country.chars().all(|c| c.is_ascii_uppercase()) {
        errs.push(format!("ap.country '{}' must be a two-letter code like TW", a.country));
    }
    if !(1..=13).contains(&a.channel) {
        errs.push(format!("ap.channel {} must be a 2.4 GHz channel 1-13", a.channel));
    }
    if !(16..=29).contains(&a.subnet.prefix_len()) {
        errs.push(format!("ap.subnet {} must be between /16 and /29", a.subnet));
    }
    if a.subnet.network() != a.subnet.addr() {
        errs.push(format!("ap.subnet {} has host bits set", a.subnet));
    }
    let net = IpNet::V4(a.subnet.trunc());
    let mut others: Vec<IpNet> = cfg.device.lan_cidrs.clone();
    if let Some(v) = &cfg.vpn {
        others.push(IpNet::V4(v.wireguard.subnet));
    }
    for o in others {
        if o.contains(&net.network()) || net.contains(&o.network()) {
            errs.push(format!("ap.subnet {} overlaps {o}", a.subnet));
        }
    }
    if !a.passphrase_file.starts_with('/') {
        errs.push("ap.passphrase_file must be an absolute path".into());
    }
    let lease_ok = a.lease_time == "infinite"
        || a.lease_time
            .strip_suffix(['s', 'm', 'h', 'd'])
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    if !lease_ok {
        errs.push(format!("ap.lease_time '{}' must look like 12h, 30m or infinite", a.lease_time));
    }
    for n in &a.allow_lan {
        if is_catch_all(n) {
            errs.push(format!("ap.allow_lan entry {n} would expose every network"));
        }
    }
}

/// A WireGuard key is 32 bytes, base64 encoded: 43 chars + '='.
pub fn valid_wg_key(k: &str) -> bool {
    k.len() == 44
        && k.ends_with('=')
        && k[..43].chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
}

/// Networks allowed to reach sshd after defaults are applied.
pub fn ssh_allow(cfg: &Config) -> Vec<IpNet> {
    if cfg.ssh.allow_from.is_empty() {
        cfg.device.lan_cidrs.clone()
    } else {
        cfg.ssh.allow_from.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
        [device]
        wan_if = "eth0"
        lan_cidrs = ["192.0.2.0/24", "2001:db8::/64"]
    "#;

    #[test]
    fn valid_config_parses() {
        let cfg = parse(OK).unwrap();
        assert_eq!(ssh_allow(&cfg).len(), 2);
    }

    #[test]
    fn ifname_rules() {
        assert!(valid_ifname("eth0"));
        assert!(valid_ifname("wlan0"));
        assert!(valid_ifname("br-iot.10"));
        assert!(!valid_ifname(""));
        assert!(!valid_ifname("a-very-long-interface"));
        assert!(!valid_ifname("eth0;reboot"));
        assert!(!valid_ifname("../etc"));
        assert!(!valid_ifname(".."));
    }

    fn errors(text: &str) -> Vec<String> {
        match parse(text) {
            Err(ConfigError::Invalid(e)) => e,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_catch_all_and_host_bits() {
        let e = errors(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["0.0.0.0/0", "192.0.2.5/24"]
            [ssh]
            allow_from = ["::/0"]
            "#,
        );
        assert!(e.iter().any(|m| m.contains("whole address space")));
        assert!(e.iter().any(|m| m.contains("host bits")));
        assert!(e.iter().any(|m| m.contains("every address")));
    }

    #[test]
    fn rejects_bad_interface_port_and_timeout() {
        let e = errors(
            r#"
            [device]
            wan_if = "eth0 && rm"
            lan_cidrs = []
            [ssh]
            port = 0
            [base]
            confirm_timeout_secs = 5
            "#,
        );
        assert_eq!(e.len(), 4, "{e:?}");
    }

    #[test]
    fn vpn_wireguard_validation() {
        let e = errors(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["10.88.0.0/16"]
            [vpn]
            mode = "wireguard"
            allow_lan = ["0.0.0.0/0"]
            [vpn.wireguard]
            interface = "wg0;id"
            endpoint = "example.org"
            [[vpn.wireguard.peers]]
            name = "a b"
            public_key = "short"
            host = 1
            [[vpn.wireguard.peers]]
            name = "a b"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            host = 1
            "#,
        );
        for needle in [
            "would expose every network",
            "not a valid interface name",
            "overlaps device.lan_cidrs",
            "must be host:port",
            "must be letters",
            "is duplicated",
            "used twice",
            "1 is the server",
            "not a WireGuard key",
        ] {
            assert!(e.iter().any(|m| m.contains(needle)), "missing '{needle}' in {e:?}");
        }
    }

    #[test]
    fn vpn_tailscale_validation() {
        let e = errors(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["192.0.2.0/24"]
            [vpn]
            mode = "tailscale"
            [vpn.tailscale]
            auth_key_file = "relative/key"
            hostname = "bad host"
            debian_codename = "Trixie;x"
            "#,
        );
        assert_eq!(e.len(), 3, "{e:?}");
        assert!(valid_wg_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
        assert!(!valid_wg_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!="));
    }

    #[test]
    fn dns_validation() {
        let e = errors(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["192.0.2.0/24"]
            [dns]
            upstreams = ["127.0.0.1:53", "0.0.0.0:53"]
            allow = ["bad domain"]
            block = ["ok.example", "a..b"]
            blocklists = ["relative.txt"]
            suspicious_threshold = 101
            rate_limit_qps = 0
            upstream_timeout_ms = 5
            "#,
        );
        for needle in [
            "points back at rp-dns itself",
            "not a usable resolver",
            "dns.allow entry 'bad domain'",
            "dns.block entry 'a..b'",
            "must be absolute",
            "0-100",
            "at least 1",
            "100-10000",
        ] {
            assert!(e.iter().any(|m| m.contains(needle)), "missing '{needle}' in {e:?}");
        }
        assert!(parse(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[dns]\nupstreams = [\"1.1.1.1:53\", \"127.0.0.1:5353\"]\n"
        )
        .is_ok());
    }

    #[test]
    fn ap_validation() {
        let e = errors(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["10.77.0.0/16"]
            [ap]
            interface = "eth0"
            ssid = ""
            country = "tw"
            channel = 36
            subnet = "10.77.0.0/30"
            passphrase_file = "ap.psk"
            lease_time = "forever"
            allow_lan = ["0.0.0.0/0"]
            "#,
        );
        for needle in [
            "would cut you off",
            "ap.ssid",
            "two-letter code",
            "channel 1-13",
            "between /16 and /29",
            "overlaps",
            "absolute path",
            "12h, 30m",
            "expose every network",
        ] {
            assert!(e.iter().any(|m| m.contains(needle)), "missing '{needle}' in {e:?}");
        }
    }

    #[test]
    fn explicit_allow_from_overrides_lan() {
        let cfg = parse(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["192.0.2.0/24"]
            [ssh]
            allow_from = ["198.51.100.0/28"]
            "#,
        )
        .unwrap();
        assert_eq!(ssh_allow(&cfg), vec!["198.51.100.0/28".parse::<IpNet>().unwrap()]);
    }
}
