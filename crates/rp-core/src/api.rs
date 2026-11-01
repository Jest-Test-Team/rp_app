//! The `api` module: the console management API.
//!
//! * `rp-api` — HTTPS for the app, as the unprivileged system user `rp-api`
//! * `rp-privd` — socket-activated root helper; only `rp-api` (and root) may
//!   connect, and changes need an admin signature
//! * firewall: the API port is open to `device.lan_cidrs` (and the tailnet
//!   with `api.allow_tailnet`), never the WAN
//! * mDNS: `_rp-security._tcp` so the app can find the device

use std::fmt::Write;

use rp_schema::Config;

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};
use crate::nft;

pub const PRIVD_SOCKET_UNIT: &str = "/etc/systemd/system/rp-privd.socket";
pub const PRIVD_UNIT: &str = "/etc/systemd/system/rp-privd.service";
pub const API_UNIT: &str = "/etc/systemd/system/rp-api.service";
pub const SNIPPET_PATH: &str = "/etc/rp/nft.d/40-api.nft";
pub const CHECK_PATH: &str = "/etc/rp/.check/api.nft";
pub const AVAHI_PATH: &str = "/etc/avahi/services/rp-security.service";
pub const API_USER: &str = "rp-api";
pub const MDNS_TYPE: &str = "_rp-security._tcp";

pub struct Api;

pub fn snippet(cfg: &Config) -> String {
    let a = cfg.api.clone().unwrap_or_default();
    let port = a.listen.port();
    let mut s = format!("# {HEADER}\n# Console API: LAN");
    if a.allow_tailnet {
        s.push_str(" and tailnet");
    }
    s.push_str(" only, never the WAN.\ntable inet rp {\n\tchain mod_input {\n");
    let _ = writeln!(s, "\t\ttcp dport {port} ip saddr @lan4 accept");
    let _ = writeln!(s, "\t\ttcp dport {port} ip6 saddr @lan6 accept");
    if a.allow_tailnet {
        let _ = writeln!(s, "\t\ttcp dport {port} ip saddr {} accept", crate::vpn::TS_V4);
        let _ = writeln!(s, "\t\ttcp dport {port} ip6 saddr {} accept", crate::vpn::TS_V6);
    }
    s.push_str("\t}\n}\n");
    s
}

fn privd_socket() -> String {
    format!(
        "# {HEADER}
[Unit]
Description=rp privileged helper socket (console API)

[Socket]
ListenStream=/run/rp/privd.sock
SocketUser=root
SocketGroup={API_USER}
SocketMode=0660
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
"
    )
}

fn privd_unit() -> String {
    format!(
        "# {HEADER}
[Unit]
Description=rp privileged helper (admin-signed console operations)
Requires=rp-privd.socket
After=rp-privd.socket

[Service]
# Root, because it applies modules like `sudo rpctl` does. It accepts only
# typed operations, from the rp-api user, signed by a paired admin key.
ExecStart=/usr/local/bin/rp-privd --config /etc/rp/rp.toml --allow-user {API_USER}
UMask=0077
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
LockPersonality=yes
"
    )
}

fn api_unit(cfg: &Config) -> String {
    let _ = cfg;
    format!(
        "# {HEADER}
[Unit]
Description=rp console API (HTTPS; unprivileged)
After=network-online.target rp-privd.socket rp-agent.service
Wants=network-online.target rp-privd.socket

[Service]
User={API_USER}
Group={API_USER}
SupplementaryGroups={group}
StateDirectory=rp-api
StateDirectoryMode=0750
ExecStart=/usr/local/bin/rp-api --config /etc/rp/rp.toml
Restart=on-failure
RestartSec=2
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryMax=64M

[Install]
WantedBy=multi-user.target
",
        group = crate::agent::TOKEN_GROUP,
    )
}

fn avahi(cfg: &Config) -> String {
    let port = cfg.api.clone().unwrap_or_default().listen.port();
    format!(
        "<?xml version=\"1.0\" standalone='no'?>
<!-- {HEADER} -->
<!DOCTYPE service-group SYSTEM \"avahi-service.dtd\">
<service-group>
  <name replace-wildcards=\"yes\">RP Security on %h</name>
  <service>
    <type>{MDNS_TYPE}</type>
    <port>{port}</port>
    <txt-record>v=1</txt-record>
  </service>
</service-group>
"
    )
}

impl Module for Api {
    fn name(&self) -> &'static str {
        "api"
    }

    fn enabled(&self, cfg: &Config) -> Result<(), String> {
        cfg.api.as_ref().map(|_| ()).ok_or_else(|| "no [api] section in the config".into())
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        if cfg.api.is_none() {
            return vec![];
        }
        let snip = snippet(cfg);
        vec![
            ManagedFile::new(SNIPPET_PATH, 0o600, snip.clone()),
            ManagedFile::check_only(CHECK_PATH, nft::combined(cfg, &snip)),
            ManagedFile::new(PRIVD_SOCKET_UNIT, 0o644, privd_socket()),
            ManagedFile::new(PRIVD_UNIT, 0o644, privd_unit()),
            ManagedFile::new(API_UNIT, 0o644, api_unit(cfg)),
            ManagedFile::new(AVAHI_PATH, 0o644, avahi(cfg)),
        ]
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![Step::cmd(&["nft", "-c", "-f", &format!("{{staged:{CHECK_PATH}}}")])]
    }

    fn post_apply(&self, _cfg: &Config) -> Vec<Step> {
        vec![
            Step::cmd(&[
                "sh",
                "-c",
                "id rp-api >/dev/null 2>&1 || useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin rp-api",
            ]),
            // To read the agent token (observation data for the app).
            Step::cmd(&["groupadd", "-f", "--system", crate::agent::TOKEN_GROUP]),
            Step::cmd(&["usermod", "-aG", crate::agent::TOKEN_GROUP, API_USER]),
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::cmd(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            Step::cmd(&["systemctl", "enable", "--now", "rp-privd.socket"]),
            Step::cmd(&["systemctl", "enable", "rp-api.service"]),
            Step::cmd(&["systemctl", "restart", "rp-api.service"]),
            Step::cmd(&["systemctl", "is-active", "--quiet", "rp-api.service"]),
            Step::best_effort(&["systemctl", "try-reload-or-restart", "avahi-daemon.service"]),
        ]
    }

    fn pre_rollback(&self) -> Vec<Step> {
        vec![Step::best_effort(&[
            "systemctl",
            "disable",
            "--now",
            "rp-api.service",
            "rp-privd.socket",
            "rp-privd.service",
        ])]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::best_effort(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            Step::best_effort(&["systemctl", "try-reload-or-restart", "avahi-daemon.service"]),
        ]
    }

    fn arms_dead_man(&self) -> bool {
        true
    }

    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }

    fn next_steps(&self, _cfg: &Config) -> Vec<String> {
        vec!["Pair the app: sudo rpctl pairing new".into()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(extra: &str) -> Config {
        parse(&format!(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[api]\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn port_is_open_to_lan_and_tailnet_only() {
        let s = snippet(&cfg(""));
        assert!(s.contains("tcp dport 8443 ip saddr @lan4 accept"));
        assert!(s.contains("tcp dport 8443 ip saddr 100.64.0.0/10 accept"));
        assert!(!s.contains("tcp dport 8443 accept"), "never open to everyone");
        let s = snippet(&cfg("allow_tailnet = false\nlisten = \"0.0.0.0:9443\"\n"));
        assert!(s.contains("tcp dport 9443 ip saddr @lan4 accept"));
        assert!(!s.contains("100.64.0.0/10"));
    }

    #[test]
    fn api_runs_unprivileged_and_privd_only_talks_to_it() {
        let files = Api.render(&cfg(""));
        let api = &files.iter().find(|f| f.path == API_UNIT).unwrap().content;
        assert!(api.contains("User=rp-api"));
        assert!(api.contains("CapabilityBoundingSet=\n"));
        assert!(api.contains("NoNewPrivileges=yes"));
        let sock = &files.iter().find(|f| f.path == PRIVD_SOCKET_UNIT).unwrap().content;
        assert!(sock.contains("SocketGroup=rp-api") && sock.contains("SocketMode=0660"));
        let privd = &files.iter().find(|f| f.path == PRIVD_UNIT).unwrap().content;
        assert!(privd.contains("--allow-user rp-api"));
        let avahi = &files.iter().find(|f| f.path == AVAHI_PATH).unwrap().content;
        assert!(
            avahi.contains("<type>_rp-security._tcp</type>") && avahi.contains("<port>8443</port>")
        );
        assert!(Api.arms_dead_man());
        assert_eq!(Api.requires(), ["base"]);
    }

    #[test]
    fn disabled_without_section() {
        let c = parse("[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n").unwrap();
        assert!(Api.enabled(&c).is_err());
        assert!(Api.render(&c).is_empty());
    }
}
