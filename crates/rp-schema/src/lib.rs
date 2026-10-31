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
    /// VPN exit node. Absent = module disabled.
    #[serde(default)]
    pub vpn: Option<Vpn>,
    /// DNS firewall. Absent = module disabled.
    #[serde(default)]
    pub dns: Option<Dns>,
    /// Protected Wi-Fi access point for IoT / guest devices. Absent = disabled.
    #[serde(default)]
    pub ap: Option<Ap>,
}

/// An isolated access point: clients get internet through the uplink but can't
/// reach the home LAN, each other, or this box's management services.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ap {
    #[serde(default = "default_ap_if")]
    pub interface: String,
    pub ssid: String,
    /// Root-only file written by `rpctl ap set-passphrase`; never put the passphrase in rp.toml.
    #[serde(default = "default_psk_file")]
    pub passphrase_file: String,
    /// ISO 3166 country code (regulatory domain).
    pub country: String,
    /// 2.4 GHz channel 1-13.
    #[serde(default = "default_channel")]
    pub channel: u8,
    #[serde(default = "default_ap_subnet")]
    pub subnet: ipnet::Ipv4Net,
    #[serde(default = "default_lease")]
    pub lease_time: String,
    /// DNS servers handed out by DHCP when the dns module is not configured.
    #[serde(default = "default_ap_dns")]
    pub dns_servers: Vec<std::net::Ipv4Addr>,
    /// Let home-LAN machines open connections to AP clients (e.g. to manage IoT devices).
    #[serde(default = "default_true")]
    pub lan_can_reach_clients: bool,
    /// Destinations AP clients MAY reach despite isolation.
    #[serde(default)]
    pub allow_lan: Vec<IpNet>,
}

fn default_ap_if() -> String {
    "wlan0".into()
}
fn default_psk_file() -> String {
    "/etc/rp/ap.psk".into()
}
fn default_channel() -> u8 {
    6
}
fn default_ap_subnet() -> ipnet::Ipv4Net {
    "10.77.0.0/24".parse().unwrap()
}
fn default_lease() -> String {
    "12h".into()
}
fn default_ap_dns() -> Vec<std::net::Ipv4Addr> {
    vec![std::net::Ipv4Addr::new(1, 1, 1, 1), std::net::Ipv4Addr::new(9, 9, 9, 9)]
}

/// DNS firewall: a filtering, logging forwarder for LAN clients.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    /// Addresses rp-dns listens on (UDP and TCP).
    #[serde(default = "default_dns_listen")]
    pub listen: Vec<std::net::SocketAddr>,
    /// Upstream resolvers, tried in order.
    pub upstreams: Vec<std::net::SocketAddr>,
    /// Blocklist files (hosts format or one domain per line).
    #[serde(default)]
    pub blocklists: Vec<String>,
    /// Domains blocked in addition to the list files (subdomains included).
    #[serde(default)]
    pub block: Vec<String>,
    /// Domains never blocked (subdomains included). Wins over every blocklist.
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block_response: BlockResponse,
    /// Also block queries whose suspicion score reaches the threshold.
    #[serde(default)]
    pub block_suspicious: bool,
    /// Score (0-100) at which a query is logged as suspicious.
    #[serde(default = "default_threshold")]
    pub suspicious_threshold: u8,
    #[serde(default = "default_events_db")]
    pub events_db: String,
    #[serde(default = "default_retention")]
    pub events_retention_days: u32,
    /// Per-client queries per second before replies are refused.
    #[serde(default = "default_qps")]
    pub rate_limit_qps: u32,
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BlockResponse {
    /// NXDOMAIN — the name does not exist.
    #[default]
    Nxdomain,
    /// 0.0.0.0 / :: answers.
    Zero,
}

fn default_dns_listen() -> Vec<std::net::SocketAddr> {
    vec!["0.0.0.0:53".parse().unwrap(), "[::]:53".parse().unwrap()]
}
fn default_threshold() -> u8 {
    60
}
fn default_events_db() -> String {
    "/var/lib/rp-dns/events.sqlite".into()
}
fn default_retention() -> u32 {
    7
}
fn default_qps() -> u32 {
    100
}
fn default_upstream_timeout() -> u64 {
    1500
}

/// VPN exit node: remote clients reach the internet through this box, and are
/// blocked from the home LAN and every private range unless explicitly allowed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vpn {
    pub mode: VpnMode,
    /// Destinations VPN clients MAY reach despite isolation (default: none).
    #[serde(default)]
    pub allow_lan: Vec<IpNet>,
    #[serde(default)]
    pub tailscale: Tailscale,
    #[serde(default)]
    pub wireguard: WireGuard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VpnMode {
    Tailscale,
    Wireguard,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tailscale {
    /// Root-only file holding a Tailscale auth key. Never put the key itself in rp.toml.
    #[serde(default)]
    pub auth_key_file: Option<String>,
    /// Name shown in the tailnet.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Debian release used for the Tailscale apt repository.
    #[serde(default = "default_codename")]
    pub debian_codename: String,
}

impl Default for Tailscale {
    fn default() -> Self {
        Self { auth_key_file: None, hostname: None, debian_codename: default_codename() }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    #[serde(default = "default_wg_if")]
    pub interface: String,
    #[serde(default = "default_wg_port")]
    pub listen_port: u16,
    /// Tunnel network; the server takes the first host address.
    #[serde(default = "default_wg_subnet")]
    pub subnet: ipnet::Ipv4Net,
    /// `host:port` clients dial (public IP or DDNS name). Needed for client configs.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// DNS server pushed to clients.
    #[serde(default = "default_wg_dns")]
    pub client_dns: std::net::IpAddr,
    #[serde(default)]
    pub peers: Vec<WgPeer>,
}

impl Default for WireGuard {
    fn default() -> Self {
        Self {
            interface: default_wg_if(),
            listen_port: default_wg_port(),
            subnet: default_wg_subnet(),
            endpoint: None,
            client_dns: default_wg_dns(),
            peers: Vec::new(),
        }
    }
}

/// A WireGuard client. Only its public key is stored; the private key is shown
/// once by `rpctl vpn add-peer` and never written anywhere on the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
    pub name: String,
    pub public_key: String,
    /// Host number inside `subnet` (2 = second address).
    pub host: u32,
}

fn default_codename() -> String {
    "trixie".into()
}
fn default_wg_if() -> String {
    "wg0".into()
}
fn default_wg_port() -> u16 {
    51820
}
fn default_wg_subnet() -> ipnet::Ipv4Net {
    "10.88.0.0/24".parse().unwrap()
}
fn default_wg_dns() -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))
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
