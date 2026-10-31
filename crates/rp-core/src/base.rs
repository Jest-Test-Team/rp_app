//! The `base` module: firewall baseline, kernel network hardening, sshd
//! hardening and unattended security upgrades.

use rp_schema::Config;

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};
use crate::nft;

pub const NFT_PATH: &str = "/etc/rp/nftables.nft";
pub const UNIT_PATH: &str = "/etc/systemd/system/rp-firewall.service";
pub const SYSCTL_PATH: &str = "/etc/sysctl.d/90-rp-base.conf";
/// sshd keeps the FIRST value it reads and Debian includes drop-ins in lexical
/// order, so this must sort before cloud-init's `50-cloud-init.conf`.
pub const SSHD_PATH: &str = "/etc/ssh/sshd_config.d/10-rp.conf";
pub const APT_PATH: &str = "/etc/apt/apt.conf.d/52rp-auto-upgrades";

pub struct Base;

fn unit() -> String {
    format!(
        "# {HEADER}\n[Unit]\nDescription=rp edge gateway firewall (nftables)\n\
         DefaultDependencies=no\nWants=network-pre.target\nBefore=network-pre.target shutdown.target\n\
         Conflicts=shutdown.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n\
         ExecStart=/usr/sbin/nft -f {NFT_PATH}\nExecReload=/usr/sbin/nft -f {NFT_PATH}\n\
         ExecStop=-/usr/sbin/nft delete table inet rp\n\n[Install]\nWantedBy=sysinit.target\n"
    )
}

fn sysctl() -> String {
    let keys = [
        ("net.ipv4.conf.all.rp_filter", "2"),
        ("net.ipv4.conf.default.rp_filter", "2"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv6.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
        ("kernel.kptr_restrict", "2"),
    ];
    let mut s = format!("# {HEADER}\n");
    for (k, v) in keys {
        s.push_str(&format!("{k} = {v}\n"));
    }
    s
}

fn sshd(cfg: &Config) -> String {
    let pw = if cfg.ssh.password_auth { "yes" } else { "no" };
    format!(
        "# {HEADER}\n# Named 10-* so it wins over later drop-ins (sshd keeps the first value).\n\
         PermitRootLogin no\nPasswordAuthentication {pw}\nKbdInteractiveAuthentication no\n\
         PermitEmptyPasswords no\nMaxAuthTries 3\nLoginGraceTime 30\nX11Forwarding no\n"
    )
}

fn apt() -> String {
    format!(
        "// {HEADER}\nAPT::Periodic::Update-Package-Lists \"1\";\n\
         APT::Periodic::Unattended-Upgrade \"1\";\nAPT::Periodic::AutocleanInterval \"7\";\n"
    )
}

impl Module for Base {
    fn name(&self) -> &'static str {
        "base"
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        let mut files = vec![
            ManagedFile::new(NFT_PATH, 0o600, nft::ruleset(cfg)),
            ManagedFile::new(UNIT_PATH, 0o644, unit()),
            ManagedFile::new(SYSCTL_PATH, 0o644, sysctl()),
            ManagedFile::new(SSHD_PATH, 0o644, sshd(cfg)),
        ];
        if cfg.base.unattended_upgrades {
            files.push(ManagedFile::new(APT_PATH, 0o644, apt()));
        }
        files
    }

    fn packages(&self, cfg: &Config) -> Vec<&'static str> {
        let mut p = vec!["nftables"];
        if cfg.base.unattended_upgrades {
            p.push("unattended-upgrades");
        }
        p
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![Step::cmd(&["nft", "-c", "-f", "{staged:/etc/rp/nftables.nft}"])]
    }

    fn post_apply(&self, _cfg: &Config) -> Vec<Step> {
        vec![
            Step::cmd(&["sshd", "-t"]),
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::cmd(&["systemctl", "enable", "rp-firewall.service"]),
            Step::cmd(&["systemctl", "restart", "rp-firewall.service"]),
            Step::cmd(&["sysctl", "--system"]),
            Step::cmd(&["systemctl", "reload", "ssh.service"]),
        ]
    }

    fn pre_rollback(&self) -> Vec<Step> {
        vec![Step::best_effort(&["systemctl", "disable", "rp-firewall.service"])]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::best_effort(&["nft", "delete", "table", "inet", "rp"]),
            Step::best_effort(&["systemctl", "restart", "rp-firewall.service"]),
            Step::cmd(&["sysctl", "--system"]),
            Step::cmd(&["systemctl", "reload", "ssh.service"]),
        ]
    }

    fn arms_dead_man(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(extra: &str) -> Config {
        parse(&format!("[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n{extra}"))
            .unwrap()
    }

    #[test]
    fn renders_expected_files() {
        let files = Base.render(&cfg(""));
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, [NFT_PATH, UNIT_PATH, SYSCTL_PATH, SSHD_PATH, APT_PATH]);
        assert!(files.iter().all(|f| f.content.contains(HEADER)));
    }

    #[test]
    fn sshd_dropin_sorts_before_cloud_init() {
        let name = SSHD_PATH.rsplit('/').next().unwrap();
        assert!(name < "50-cloud-init.conf");
    }

    #[test]
    fn password_auth_follows_config() {
        let on = sshd(&cfg(""));
        let off = sshd(&cfg("[ssh]\npassword_auth = false\n"));
        assert!(on.contains("PasswordAuthentication yes"));
        assert!(off.contains("PasswordAuthentication no"));
        assert!(off.contains("PermitRootLogin no"));
    }

    #[test]
    fn unattended_upgrades_optional() {
        let c = cfg("[base]\nunattended_upgrades = false\n");
        assert!(!Base.render(&c).iter().any(|f| f.path == APT_PATH));
        assert_eq!(Base.packages(&c), ["nftables"]);
    }
}
