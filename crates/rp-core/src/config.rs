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
