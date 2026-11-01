//! Configuration types shared by every rp component.
//!
//! The on-disk format is TOML (`/etc/rp/rp.toml`). Every section except
//! `[device]` is optional so a fresh install only needs the basics.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

pub mod capability;

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
    /// Edge agent: read-only observation API (+ privileged action requests).
    #[serde(default)]
    pub agent: Option<Agent>,
    /// MCP server exposing agent tools to AI clients, behind rp-policy.
    #[serde(default)]
    pub mcp: Option<Mcp>,
    /// Management API for the console app (rp-api + rp-privd).
    #[serde(default)]
    pub api: Option<Api>,
}

/// The console management API. rp-api is unprivileged; changes go through
/// rp-privd and need an admin signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Api {
    #[serde(default = "default_api_listen")]
    pub listen: std::net::SocketAddr,
    /// Also allow the tailnet (100.64.0.0/10, fd7a:115c:a1e0::/48). The WAN never is.
    #[serde(default = "default_true")]
    pub allow_tailnet: bool,
    /// Lifetime of a read session created with an admin signature.
    #[serde(default = "default_session_minutes")]
    pub session_minutes: u32,
}

impl Default for Api {
    fn default() -> Self {
        Self {
            listen: default_api_listen(),
            allow_tailnet: true,
            session_minutes: default_session_minutes(),
        }
    }
}

fn default_api_listen() -> std::net::SocketAddr {
    "0.0.0.0:8443".parse().unwrap()
}
fn default_session_minutes() -> u32 {
    15
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    #[serde(default = "default_agent_listen")]
    pub listen: std::net::SocketAddr,
    /// Bearer token callers (rp-mcp) must present. Generated on apply.
    #[serde(default = "default_agent_token")]
    pub token_file: String,
    /// Networks `scan_network` may target. Empty = LAN + AP subnet.
    #[serde(default)]
    pub scan_allow: Vec<IpNet>,
    #[serde(default = "default_scan_max")]
    pub scan_max_hosts: u32,
    /// Where action requests and the audit log live.
    #[serde(default = "default_agent_state")]
    pub state_dir: String,
    /// Minutes a privileged request waits for approval before expiring.
    #[serde(default = "default_pending")]
    pub pending_minutes: i64,
    /// Upper bound for how long an approved privileged change lasts.
    #[serde(default = "default_max_ttl")]
    pub max_ttl_minutes: i64,
}

impl Default for Agent {
    fn default() -> Self {
        Self {
            listen: default_agent_listen(),
            token_file: default_agent_token(),
            scan_allow: Vec::new(),
            scan_max_hosts: default_scan_max(),
            state_dir: default_agent_state(),
            pending_minutes: default_pending(),
            max_ttl_minutes: default_max_ttl(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mcp {
    /// Streamable HTTP endpoint (POST /mcp). Use a Tailscale address for remote clients.
    #[serde(default = "default_mcp_listen")]
    pub listen: std::net::SocketAddr,
    /// Client token hashes and capabilities (managed by `rpctl mcp add-client`).
    #[serde(default = "default_mcp_clients")]
    pub clients_file: String,
    /// rp-agent address.
    #[serde(default = "default_agent_listen")]
    pub agent: std::net::SocketAddr,
    #[serde(default = "default_agent_token")]
    pub agent_token_file: String,
    #[serde(default = "default_mcp_rate")]
    pub rate_limit_per_minute: u32,
    /// Capabilities of the local stdio transport (e.g. `ssh device rp-mcp --stdio`).
    #[serde(default = "default_stdio_caps")]
    pub stdio_capabilities: Vec<String>,
    #[serde(default = "default_mcp_audit")]
    pub audit_log: String,
}

fn default_stdio_caps() -> Vec<String> {
    vec!["read".into()]
}
fn default_mcp_audit() -> String {
    "/var/lib/rp-mcp/audit.jsonl".into()
}

fn default_agent_listen() -> std::net::SocketAddr {
    "127.0.0.1:9850".parse().unwrap()
}
fn default_mcp_listen() -> std::net::SocketAddr {
    "127.0.0.1:9851".parse().unwrap()
}
fn default_agent_token() -> String {
    "/etc/rp/agent.token".into()
}
fn default_mcp_clients() -> String {
    "/etc/rp/mcp-clients.toml".into()
}
fn default_scan_max() -> u32 {
    256
}
fn default_agent_state() -> String {
    "/var/lib/rp/agent".into()
}
fn default_pending() -> i64 {
    15
}
fn default_max_ttl() -> i64 {
    1440
}
fn default_mcp_rate() -> u32 {
    60
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
    /// Reject DNS-over-TLS / -QUIC (port 853) from AP clients so they fall back
    /// to the DNS firewall. Off by default: it is always logged either way.
    #[serde(default)]
    pub block_dot: bool,
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
    /// Cap on persistent journal size in MB, to limit SD-card wear. 0 = leave journald alone.
    #[serde(default = "default_journal_mb")]
    pub journal_max_mb: u32,
}

fn default_journal_mb() -> u32 {
    64
}

impl Default for Base {
    fn default() -> Self {
        Self {
            allow_mdns: true,
            unattended_upgrades: true,
            confirm_timeout_secs: default_confirm_timeout(),
            journal_max_mb: default_journal_mb(),
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
