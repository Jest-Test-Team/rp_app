//! The `dns` module: run rp-dns as a sandboxed service and open DNS to the LAN.

use std::collections::BTreeSet;
use std::fmt::Write;

use rp_schema::Config;

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};
use crate::nft;

pub const UNIT_PATH: &str = "/etc/systemd/system/rp-dns.service";
pub const SNIPPET_PATH: &str = "/etc/rp/nft.d/40-dns.nft";
pub const CHECK_PATH: &str = "/etc/rp/.check/dns.nft";
pub const BIN: &str = "/usr/local/bin/rp-dns";

pub struct Dns;

fn unit() -> String {
    format!(
        "# {HEADER}
[Unit]
Description=rp DNS firewall
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={BIN} --config /etc/rp/rp.toml run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2
# Unprivileged, sandboxed: may only bind port 53 and write its state dir.
DynamicUser=yes
StateDirectory=rp-dns
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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
ProtectHostname=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
MemoryMax=96M

[Install]
WantedBy=multi-user.target
"
    )
}

/// LAN clients may query DNS; nobody else can.
pub fn snippet(cfg: &Config) -> String {
    let d = cfg.dns.as_ref().expect("dns config");
    let ports: BTreeSet<u16> = d.listen.iter().map(|a| a.port()).collect();
    let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    let ports =
        if list.len() == 1 { list[0].clone() } else { format!("{{ {} }}", list.join(", ")) };
    let mut s = format!("# {HEADER}\n# DNS firewall: answer LAN clients only.\ntable inet rp {{\n");
    s.push_str("\tchain mod_input {\n");
    for proto in ["udp", "tcp"] {
        let _ = writeln!(s, "\t\tip saddr @lan4 {proto} dport {ports} accept");
        let _ = writeln!(s, "\t\tip6 saddr @lan6 {proto} dport {ports} accept");
    }
    s.push_str("\t}\n}\n");
    s
}

impl Module for Dns {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn enabled(&self, cfg: &Config) -> Result<(), String> {
        cfg.dns.as_ref().map(|_| ()).ok_or_else(|| "no [dns] section in the config".into())
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        if cfg.dns.is_none() {
            return vec![];
        }
        let snip = snippet(cfg);
        vec![
            ManagedFile::new(UNIT_PATH, 0o644, unit()),
            ManagedFile::new(SNIPPET_PATH, 0o600, snip.clone()),
            ManagedFile::check_only(CHECK_PATH, nft::combined(cfg, &snip)),
        ]
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![
            Step::cmd(&["nft", "-c", "-f", &format!("{{staged:{CHECK_PATH}}}")]),
            // The same config the service will read, checked by the service itself.
            Step::cmd(&[BIN, "--config", "/etc/rp/rp.toml", "check"]),
        ]
    }

    fn post_apply(&self, _cfg: &Config) -> Vec<Step> {
        vec![
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::cmd(&["systemctl", "enable", "rp-dns.service"]),
            Step::cmd(&["systemctl", "restart", "rp-dns.service"]),
            Step::cmd(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            Step::cmd(&["systemctl", "is-active", "--quiet", "rp-dns.service"]),
        ]
    }

    fn pre_rollback(&self) -> Vec<Step> {
        vec![Step::best_effort(&["systemctl", "disable", "--now", "rp-dns.service"])]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::best_effort(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
        ]
    }

    fn arms_dead_man(&self) -> bool {
        true
    }

    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }

    fn next_steps(&self, _cfg: &Config) -> Vec<String> {
        vec![
            "Test from a LAN machine: dig @<this-device> example.com".into(),
            "Then set your router's DHCP DNS to this device, and keep a public resolver as the \
             SECONDARY DNS so the LAN still resolves if this device is down (fail-open)."
                .into(),
            "Recent blocks: rp-dns events --action blocked".into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(extra: &str) -> Config {
        parse(&format!(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[dns]\nupstreams = [\"1.1.1.1:53\"]\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn dns_is_open_to_the_lan_only() {
        let s = snippet(&cfg(""));
        assert!(s.contains("ip saddr @lan4 udp dport 53 accept"));
        assert!(s.contains("ip6 saddr @lan6 tcp dport 53 accept"));
        assert!(!s.contains("dport 53 accept\n\t\tudp"), "no unscoped rule");
        let multi = snippet(&cfg("listen = [\"0.0.0.0:53\", \"0.0.0.0:5353\"]\n"));
        assert!(multi.contains("udp dport { 53, 5353 } accept"));
    }

    #[test]
    fn service_is_sandboxed_and_unprivileged() {
        let u = unit();
        for line in [
            "DynamicUser=yes",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
            "ProtectSystem=strict",
            "NoNewPrivileges=yes",
            "StateDirectory=rp-dns",
            "MemoryMax=96M",
        ] {
            assert!(u.contains(line), "missing {line}");
        }
    }

    #[test]
    fn validation_runs_service_check_and_requires_base() {
        let v: Vec<String> = Dns.validate_steps(&cfg("")).iter().map(|s| s.display()).collect();
        assert!(v.iter().any(|s| s.ends_with("rp-dns --config /etc/rp/rp.toml check")));
        assert_eq!(Dns.requires(), ["base"]);
        assert_eq!(Dns.render(&cfg("")).iter().filter(|f| f.staging_only).count(), 1);
    }
}
