//! Configuration types shared by every rp component.
//!
//! The on-disk format is TOML (`/etc/rp/rp.toml`). Every section except
//! `[device]` is optional so a fresh install only needs the basics.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Root of `rp.toml`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub device: Device,
    #[serde(default)]
    pub ssh: Ssh,
    #[serde(default)]
    pub base: Base,
}

/// Physical facts about the box.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Interface facing the home router (WAN / management uplink), e.g. `eth0`.
    pub wan_if: String,
    /// Interface used for management SSH. Usually equal to `wan_if`.
    #[serde(default)]
    pub mgmt_if: Option<String>,
    /// Home LAN networks. Used for SSH allow-lists and VPN isolation.
    pub lan_cidrs: Vec<IpNet>,
}

impl Device {
    pub fn mgmt_if(&self) -> &str {
        self.mgmt_if.as_deref().unwrap_or(&self.wan_if)
    }
}

/// SSH daemon hardening.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ssh {
    /// TCP port sshd listens on.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// Networks allowed to reach sshd. Empty = same as `device.lan_cidrs`.
    #[serde(default)]
    pub allow_from: Vec<IpNet>,
    /// Keep password logins enabled. Only disable once a key login works.
    #[serde(default = "default_true")]
    pub password_auth: bool,
}

impl Default for Ssh {
    fn default() -> Self {
        Self { port: default_ssh_port(), allow_from: Vec::new(), password_auth: true }
    }
}

/// Settings for the `base` module (firewall baseline + OS hardening).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Base {
    /// Allow mDNS (UDP 5353) so `<hostname>.local` keeps resolving.
    #[serde(default = "default_true")]
    pub allow_mdns: bool,
    /// Install and enable unattended security upgrades.
    #[serde(default = "default_true")]
    pub unattended_upgrades: bool,
    /// Seconds before an unconfirmed firewall change is rolled back automatically.
    #[serde(default = "default_confirm_timeout")]
    pub confirm_timeout_secs: u32,
}

impl Default for Base {
    fn default() -> Self {
        Self {
            allow_mdns: true,
            unattended_upgrades: true,
            confirm_timeout_secs: default_confirm_timeout(),
        }
    }
}

fn default_ssh_port() -> u16 {
    22
}
fn default_true() -> bool {
    true
}
fn default_confirm_timeout() -> u32 {
    120
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg: Config = toml::from_str(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = ["192.0.2.0/24"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.ssh.port, 22);
        assert!(cfg.ssh.password_auth);
        assert!(cfg.base.allow_mdns);
        assert_eq!(cfg.base.confirm_timeout_secs, 120);
        assert_eq!(cfg.device.mgmt_if(), "eth0");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = toml::from_str::<Config>(
            r#"
            [device]
            wan_if = "eth0"
            lan_cidrs = []
            typo = 1
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("typo"));
    }
}
