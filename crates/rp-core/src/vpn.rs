//! The `vpn` module: turn the box into an internet exit node for remote
//! clients (Tailscale or kernel WireGuard) while keeping them out of the home
//! LAN and every other private range.

use std::fmt::Write;

use ipnet::IpNet;
use rp_schema::Config;

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};
use crate::nft::{self, set, split_families};

pub const SNIPPET_PATH: &str = "/etc/rp/nft.d/50-vpn.nft";
pub const CHECK_PATH: &str = "/etc/rp/.check/vpn.nft";
pub const SYSCTL_PATH: &str = "/etc/sysctl.d/91-rp-vpn.conf";
pub const TS_LIST_PATH: &str = "/etc/apt/sources.list.d/tailscale.list";
pub const TS_KEYRING: &str = "/usr/share/keyrings/tailscale-archive-keyring.gpg";
pub const WG_KEY_PATH: &str = "/etc/rp/wireguard/private.key";
pub const TS_IF: &str = "tailscale0";
pub const TS_PORT: u16 = 41641;
/// Tailscale's address ranges (CGNAT space and its IPv6 ULA prefix).
pub const TS_V4: &str = "100.64.0.0/10";
pub const TS_V6: &str = "fd7a:115c:a1e0::/48";

/// Destinations a VPN client must never reach through the exit node.
pub const PRIVATE_V4: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",
];
pub const PRIVATE_V6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];

pub struct Vpn;

pub fn wg_conf_path(cfg: &Config) -> String {
    let ifname = cfg.vpn.as_ref().map(|v| v.wireguard.interface.as_str()).unwrap_or("wg0");
    format!("/etc/wireguard/{ifname}.conf")
}

/// Interfaces VPN traffic arrives on (Tailscale first).
pub fn vpn_ifs(cfg: &Config) -> Vec<String> {
    let Some(v) = cfg.vpn.as_ref() else { return vec![TS_IF.to_string()] };
    let mut ifs = vec![];
    if v.mode.tailscale() {
        ifs.push(TS_IF.to_string());
    }
    if v.mode.wireguard() {
        ifs.push(v.wireguard.interface.clone());
    }
    ifs
}

/// nftables match for "arrives from a VPN": `iifname "x"` or `iifname { "x", "y" }`.
pub fn vpn_if_match(cfg: &Config, ifx: &str) -> String {
    match vpn_ifs(cfg).as_slice() {
        [one] => format!("{ifx} \"{one}\""),
        many => format!(
            "{ifx} {{ {} }}",
            many.iter().map(|i| format!("\"{i}\"")).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn parse_all(list: &[&str]) -> Vec<IpNet> {
    list.iter().map(|s| s.parse().unwrap()).collect()
}

/// The firewall snippet appended to the base table.
pub fn snippet(cfg: &Config) -> String {
    let v = cfg.vpn.as_ref().expect("vpn config");
    let wan = &cfg.device.wan_if;
    let vif = vpn_if_match(cfg, "iifname");

    let mut block = cfg.device.lan_cidrs.clone();
    block.extend(parse_all(PRIVATE_V4));
    block.extend(parse_all(PRIVATE_V6));
    let (block4, block6) = split_families(&block);
    let (allow4, allow6) = split_families(&v.allow_lan);

    let mut s = format!("# {HEADER}\n# VPN exit node ({:?}): internet yes, home LAN no.\n", v.mode);
    s.push_str("table inet rp {\n");
    set(&mut s, "vpn_block4", "ipv4_addr", &block4);
    set(&mut s, "vpn_block6", "ipv6_addr", &block6);
    set(&mut s, "vpn_allow4", "ipv4_addr", &allow4);
    set(&mut s, "vpn_allow6", "ipv6_addr", &allow6);

    let mut ports = vec![];
    if v.mode.tailscale() {
        ports.push(TS_PORT);
    }
    if v.mode.wireguard() {
        ports.push(v.wireguard.listen_port);
    }
    let ports = match ports.as_slice() {
        [p] => p.to_string(),
        many => format!("{{ {} }}", many.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")),
    };
    let _ = write!(s, "\n\tchain mod_input {{\n\t\tudp dport {ports} accept\n");
    // The console app over WireGuard (the tailnet is allowed by the api module).
    if let (Some(api), true) = (&cfg.api, v.mode.wireguard()) {
        let _ = writeln!(
            s,
            "\t\tiifname \"{}\" ip saddr {} tcp dport {} accept",
            v.wireguard.interface,
            v.wireguard.subnet,
            api.listen.port()
        );
    }
    s.push_str("\t}\n");

    s.push_str("\n\tchain mod_forward {\n");
    let _ = writeln!(s, "\t\t{vif} oifname \"{wan}\" ip daddr @vpn_allow4 accept");
    let _ = writeln!(s, "\t\t{vif} oifname \"{wan}\" ip6 daddr @vpn_allow6 accept");
    let _ = writeln!(s, "\t\t{vif} ip daddr @vpn_block4 drop");
    let _ = writeln!(s, "\t\t{vif} ip6 daddr @vpn_block6 drop");
    let _ = writeln!(s, "\t\t{vif} oifname \"{wan}\" accept");
    s.push_str("\t}\n");

    s.push_str("\n\tchain vpn_postrouting {\n");
    s.push_str("\t\ttype nat hook postrouting priority srcnat; policy accept;\n");
    if v.mode.tailscale() {
        let _ = writeln!(s, "\t\toifname \"{wan}\" ip saddr {TS_V4} masquerade");
        let _ = writeln!(s, "\t\toifname \"{wan}\" ip6 saddr {TS_V6} masquerade");
    }
    if v.mode.wireguard() {
        let _ = writeln!(s, "\t\toifname \"{wan}\" ip saddr {} masquerade", v.wireguard.subnet);
    }
    s.push_str("\t}\n}\n");
    s
}

fn sysctl_key(ifname: &str) -> String {
    // VLAN names like eth0.10 use '/' in sysctl paths.
    ifname.replace('.', "/")
}

fn sysctl(cfg: &Config) -> String {
    let mut s = format!("# {HEADER}\nnet.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n");
    // With forwarding on, the kernel ignores router advertisements unless
    // accept_ra = 2 — without this the uplink would lose its SLAAC address.
    let mut ifs = vec![cfg.device.wan_if.clone()];
    if cfg.device.mgmt_if() != cfg.device.wan_if {
        ifs.push(cfg.device.mgmt_if().to_string());
    }
    for i in ifs {
        let _ = writeln!(s, "net.ipv6.conf.{}.accept_ra = 2", sysctl_key(&i));
    }
    s
}

/// Server address inside the tunnel subnet (first host).
pub fn wg_server_addr(cfg: &Config) -> ipnet::Ipv4Net {
    let w = &cfg.vpn.as_ref().unwrap().wireguard;
    let host = w.subnet.hosts().next().expect("subnet has hosts");
    ipnet::Ipv4Net::new(host, w.subnet.prefix_len()).unwrap()
}

/// Address of peer number `host` inside the tunnel subnet.
pub fn wg_peer_addr(cfg: &Config, host: u32) -> std::net::Ipv4Addr {
    let w = &cfg.vpn.as_ref().unwrap().wireguard;
    std::net::Ipv4Addr::from(u32::from(w.subnet.network()) + host)
}

fn wg_conf(cfg: &Config) -> String {
    let w = &cfg.vpn.as_ref().unwrap().wireguard;
    let mut s = format!(
        "# {HEADER}\n# The private key is loaded from {WG_KEY_PATH} at start-up and is never\n\
         # written into this file.\n[Interface]\nAddress = {}\nListenPort = {}\n\
         PostUp = wg set %i private-key {WG_KEY_PATH}\n",
        wg_server_addr(cfg),
        w.listen_port
    );
    for p in &w.peers {
        let _ = write!(
            s,
            "\n[Peer]\n# {}\nPublicKey = {}\nAllowedIPs = {}/32\n",
            p.name,
            p.public_key,
            wg_peer_addr(cfg, p.host)
        );
    }
    s
}

impl Module for Vpn {
    fn name(&self) -> &'static str {
        "vpn"
    }

    fn enabled(&self, cfg: &Config) -> Result<(), String> {
        match &cfg.vpn {
            None => Err("no [vpn] section in the config".into()),
            Some(_) => Ok(()),
        }
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        let Some(v) = &cfg.vpn else { return vec![] };
        let snip = snippet(cfg);
        let mut files = vec![
            ManagedFile::new(SNIPPET_PATH, 0o600, snip.clone()),
            ManagedFile::check_only(CHECK_PATH, nft::combined(cfg, &snip)),
            ManagedFile::new(SYSCTL_PATH, 0o644, sysctl(cfg)),
        ];
        if v.mode.wireguard() {
            files.push(ManagedFile::new(&wg_conf_path(cfg), 0o600, wg_conf(cfg)));
        }
        if v.mode.tailscale() {
            files.push(
                ManagedFile::new(
                    TS_LIST_PATH,
                    0o644,
                    format!(
                        "# {HEADER}\ndeb [signed-by={TS_KEYRING}] https://pkgs.tailscale.com/stable/debian {} main\n",
                        v.tailscale.debian_codename
                    ),
                )
                .early(),
            );
        }
        files
    }

    fn pre_install(&self, cfg: &Config) -> Vec<Step> {
        match cfg.vpn.as_ref().map(|v| (v.mode, v.tailscale.debian_codename.as_str())) {
            Some((m, codename)) if m.tailscale() => {
                let url =
                    format!("https://pkgs.tailscale.com/stable/debian/{codename}.noarmor.gpg");
                vec![
                    Step::cmd(&["install", "-d", "-m", "0755", "/usr/share/keyrings"]),
                    Step::cmd(&["curl", "-fsSL", "--proto", "=https", "-o", TS_KEYRING, &url]),
                ]
            }
            _ => vec![],
        }
    }

    fn packages(&self, cfg: &Config) -> Vec<&'static str> {
        let Some(m) = cfg.vpn.as_ref().map(|v| v.mode) else { return vec![] };
        let mut p = vec![];
        if m.tailscale() {
            p.push("tailscale");
        }
        if m.wireguard() {
            p.push("wireguard-tools");
        }
        p
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![Step::cmd(&["nft", "-c", "-f", &format!("{{staged:{CHECK_PATH}}}")])]
    }

    fn post_apply(&self, cfg: &Config) -> Vec<Step> {
        let mut steps = vec![
            Step::cmd(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            Step::cmd(&["sysctl", "--system"]),
        ];
        let Some(v) = &cfg.vpn else { return steps };
        if v.mode.wireguard() {
            {
                let unit = format!("wg-quick@{}.service", v.wireguard.interface);
                // Generate the server key on the device, once, readable by root only.
                steps.push(Step::cmd(&[
                    "sh",
                    "-c",
                    "umask 077 && mkdir -p /etc/rp/wireguard && \
                     { [ -s /etc/rp/wireguard/private.key ] || wg genkey > /etc/rp/wireguard/private.key; }",
                ]));
                steps.push(Step::cmd(&["systemctl", "enable", &unit]));
                steps.push(Step::cmd(&["systemctl", "restart", &unit]));
            }
        }
        if v.mode.tailscale() {
            {
                steps.push(Step::cmd(&["systemctl", "enable", "--now", "tailscaled.service"]));
                if let Some(key) = &v.tailscale.auth_key_file {
                    // Log in only when not logged in yet: on a running node
                    // `tailscale up` refuses unless every non-default flag is
                    // repeated, so re-applying (e.g. adding WireGuard) failed.
                    // The key path and hostname are validated (no spaces/quotes).
                    let mut up = format!(
                        "tailscale status >/dev/null 2>&1 || tailscale up --auth-key=file:{key} \
                         --accept-dns=false --advertise-exit-node"
                    );
                    if let Some(h) = &v.tailscale.hostname {
                        up.push_str(&format!(" --hostname={h}"));
                    }
                    steps.push(Step::cmd(&["sh", "-c", &up]));
                }
                let mut set: Vec<String> =
                    ["tailscale", "set", "--advertise-exit-node=true", "--accept-dns=false"]
                        .iter()
                        .map(|x| x.to_string())
                        .collect();
                if let Some(h) = &v.tailscale.hostname {
                    set.push(format!("--hostname={h}"));
                }
                steps.push(Step { argv: set, best_effort: true });
            }
        }
        steps
    }

    fn pre_rollback(&self) -> Vec<Step> {
        vec![
            Step::best_effort(&["tailscale", "set", "--advertise-exit-node=false"]),
            Step::best_effort(&["sh", "-c", "systemctl disable --now 'wg-quick@*.service'"]),
        ]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![
            Step::best_effort(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            // Removing the sysctl file does not undo the live values.
            Step::cmd(&["sysctl", "-w", "net.ipv4.ip_forward=0"]),
            Step::cmd(&["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"]),
            Step::cmd(&["sysctl", "--system"]),
        ]
    }

    fn arms_dead_man(&self) -> bool {
        true
    }

    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }

    fn next_steps(&self, cfg: &Config) -> Vec<String> {
        let Some(v) = &cfg.vpn else { return vec![] };
        let mut n = vec![];
        if v.mode.wireguard() {
            n.push(format!(
                "WireGuard: forward UDP {} on your router to this device.",
                v.wireguard.listen_port
            ));
            n.push(
                "Add a client: sudo rpctl vpn add-peer <name>  (prints its config + QR once)"
                    .into(),
            );
        }
        if v.mode.tailscale() {
            {
                if v.tailscale.auth_key_file.is_none() {
                    n.push(
                        "Log in: sudo tailscale up   (then re-run: sudo rpctl apply vpn)".into(),
                    );
                }
                n.push("Approve the exit node in the Tailscale admin console (Machines > Edit route settings).".into());
                n.push("Share the machine with your friend's tailnet with 'Allow use as an exit node' enabled.".into());
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    const BASE: &str =
        "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\", \"2001:db8::/64\"]\n";

    fn cfg(vpn: &str) -> Config {
        parse(&format!("{BASE}{vpn}")).unwrap()
    }

    fn wg() -> Config {
        cfg("[vpn]\nmode = \"wireguard\"\n[[vpn.wireguard.peers]]\nname = \"phone\"\npublic_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\nhost = 2\n")
    }

    fn ts() -> Config {
        cfg("[vpn]\nmode = \"tailscale\"\n[vpn.tailscale]\nauth_key_file = \"/etc/rp/tailscale.key\"\nhostname = \"rp-exit\"\n")
    }

    #[test]
    fn lan_and_private_ranges_are_blocked_before_internet_accept() {
        let s = snippet(&wg());
        assert!(s.contains("192.0.2.0/24"), "home LAN must be in the block set");
        assert!(s.contains("10.0.0.0/8") && s.contains("192.168.0.0/16") && s.contains("fc00::/7"));
        let drop4 = s.find("iifname \"wg0\" ip daddr @vpn_block4 drop").unwrap();
        let drop6 = s.find("iifname \"wg0\" ip6 daddr @vpn_block6 drop").unwrap();
        let accept = s.find("iifname \"wg0\" oifname \"eth0\" accept").unwrap();
        assert!(drop4 < accept && drop6 < accept);
        assert!(s.contains("oifname \"eth0\" ip saddr 10.88.0.0/24 masquerade"));
        assert!(s.contains("udp dport 51820 accept"));
    }

    #[test]
    fn allow_lan_exceptions_come_first() {
        let c = cfg("[vpn]\nmode = \"wireguard\"\nallow_lan = [\"192.0.2.53/32\"]\n");
        let s = snippet(&c);
        assert!(s.contains("elements = { 192.0.2.53/32 }"));
        assert!(s.find("@vpn_allow4 accept").unwrap() < s.find("@vpn_block4 drop").unwrap());
    }

    #[test]
    fn tailscale_uses_its_interface_port_and_ranges() {
        let s = snippet(&ts());
        assert!(s.contains("iifname \"tailscale0\" ip daddr @vpn_block4 drop"));
        assert!(s.contains("udp dport 41641 accept"));
        assert!(s.contains("ip saddr 100.64.0.0/10 masquerade"));
        assert!(s.contains("ip6 saddr fd7a:115c:a1e0::/48 masquerade"));
    }

    #[test]
    fn sysctl_enables_forwarding_and_keeps_router_advertisements() {
        let s = sysctl(&wg());
        assert!(s.contains("net.ipv4.ip_forward = 1"));
        assert!(s.contains("net.ipv6.conf.eth0.accept_ra = 2"));
        assert_eq!(sysctl_key("eth0.10"), "eth0/10");
    }

    #[test]
    fn wireguard_config_never_contains_a_private_key() {
        let c = wg_conf(&wg());
        assert!(c.contains("Address = 10.88.0.1/24")); // rp-probe:allow
        assert!(c.contains("PostUp = wg set %i private-key /etc/rp/wireguard/private.key"));
        assert!(c.contains("AllowedIPs = 10.88.0.2/32")); // rp-probe:allow
        assert!(!c.contains("PrivateKey"));
    }

    #[test]
    fn render_sets_and_check_file() {
        let files = Vpn.render(&wg());
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, [SNIPPET_PATH, CHECK_PATH, SYSCTL_PATH, "/etc/wireguard/wg0.conf"]);
        assert!(files[1].staging_only && !files[0].staging_only);
        assert!(!files[1].content.contains("include"), "check file must inline the snippet");
        let t = Vpn.render(&ts());
        assert!(t.iter().any(|f| f.path == TS_LIST_PATH && f.early));
    }

    #[test]
    fn tailscale_steps_use_key_file_never_key_value() {
        let steps: Vec<String> = Vpn.post_apply(&ts()).iter().map(|s| s.display()).collect();
        // Only logs in when not logged in yet (re-applying a running node must not fail).
        assert!(steps.iter().any(|s| s.contains("tailscale status >/dev/null 2>&1 || tailscale up --auth-key=file:/etc/rp/tailscale.key --accept-dns=false --advertise-exit-node --hostname=rp-exit")), "{steps:?}");
        assert!(steps.iter().any(|s| s
            == "tailscale set --advertise-exit-node=true --accept-dns=false --hostname=rp-exit"));
        let pre: Vec<String> = Vpn.pre_install(&ts()).iter().map(|s| s.display()).collect();
        assert!(pre
            .iter()
            .any(|s| s.contains("https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg")));
    }

    #[test]
    fn rollback_turns_forwarding_off_explicitly() {
        let steps: Vec<String> = Vpn.post_rollback().iter().map(|s| s.display()).collect();
        assert!(steps.contains(&"sysctl -w net.ipv4.ip_forward=0".to_string()));
    }

    fn both() -> Config {
        cfg("[vpn]\nmode = \"both\"\n[vpn.tailscale]\nauth_key_file = \"/etc/rp/tailscale.key\"\n[[vpn.wireguard.peers]]\nname = \"phone\"\npublic_key = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"\nhost = 2\n")
    }

    #[test]
    fn both_isolates_each_interface_and_masquerades_each_range() {
        let c = both();
        assert_eq!(vpn_ifs(&c), ["tailscale0", "wg0"]);
        let s = snippet(&c);
        assert!(s.contains("udp dport { 41641, 51820 } accept"), "{s}");
        let drop4 =
            s.find("iifname { \"tailscale0\", \"wg0\" } ip daddr @vpn_block4 drop").unwrap();
        let accept = s.find("iifname { \"tailscale0\", \"wg0\" } oifname \"eth0\" accept").unwrap();
        assert!(drop4 < accept);
        assert!(s.contains("ip saddr 100.64.0.0/10 masquerade"));
        assert!(s.contains("ip saddr 10.88.0.0/24 masquerade"));
    }

    #[test]
    fn the_console_app_reaches_the_api_over_wireguard() {
        let c = cfg("[api]\n[vpn]\nmode = \"both\"\n");
        assert!(snippet(&c).contains("iifname \"wg0\" ip saddr 10.88.0.0/24 tcp dport 8443 accept"));
        assert!(crate::api::snippet(&c)
            .contains("iifname \"wg0\" ip saddr 10.88.0.0/24 tcp dport 8443 accept"));
        let nets = crate::changeset::mgmt_networks(&c);
        assert!(nets.iter().any(|n| n.to_string() == "10.88.0.0/24"));
        assert!(nets.iter().any(|n| n.to_string() == "100.64.0.0/10"));
        let ts = cfg("[api]\n[vpn]\nmode = \"tailscale\"\n");
        assert!(!snippet(&ts).contains("8443"), "no WireGuard, no extra rule");
    }

    #[test]
    fn both_installs_and_starts_both() {
        let c = both();
        assert_eq!(Vpn.packages(&c), ["tailscale", "wireguard-tools"]);
        let paths: Vec<String> = Vpn.render(&c).into_iter().map(|f| f.path).collect();
        assert!(paths.contains(&"/etc/wireguard/wg0.conf".to_string()));
        assert!(paths.contains(&TS_LIST_PATH.to_string()));
        let steps: Vec<String> = Vpn.post_apply(&c).iter().map(|s| s.display()).collect();
        assert!(steps.iter().any(|s| s == "systemctl restart wg-quick@wg0.service"));
        assert!(steps.iter().any(|s| s.contains("|| tailscale up --auth-key=file:")));
        assert!(!Vpn.pre_install(&c).is_empty(), "the Tailscale repository key is fetched");
        let checks: Vec<&str> =
            crate::changeset::verify_steps("vpn", &c).iter().map(|(n, _)| *n).collect();
        assert_eq!(checks, ["firewall_loaded", "tailscaled_active", "wireguard_up"]);
        let next = Vpn.next_steps(&c).join("\n");
        assert!(next.contains("UDP 51820") && next.contains("exit node"));
    }

    #[test]
    fn disabled_without_section() {
        let c = parse(BASE).unwrap();
        assert!(Vpn.enabled(&c).is_err());
        assert!(Vpn.render(&c).is_empty());
    }
}
