//! The `ap` module: an isolated 2.4 GHz access point for IoT / guest devices.
//!
//! hostapd runs the AP (client isolation on), dnsmasq-base hands out DHCP only
//! (no DNS server, so it never competes with rp-dns for port 53), and the
//! firewall lets clients reach the internet but not the home LAN, each other
//! (via this box), or this box's management services. NetworkManager is told
//! to leave the interface alone; rollback hands it back and NM reconnects to
//! the saved Wi-Fi network.

use std::fmt::Write;

use ipnet::{IpNet, Ipv4Net};
use rp_schema::Config;

use crate::files::{ManagedFile, HEADER};
use crate::module::{Module, Step};
use crate::nft::{self, set, split_families};
use crate::vpn::{PRIVATE_V4, PRIVATE_V6};

pub const HOSTAPD_CONF: &str = "/etc/rp/ap/hostapd.conf";
pub const DNSMASQ_CONF: &str = "/etc/rp/ap/dnsmasq.conf";
pub const HOSTAPD_UNIT: &str = "/etc/systemd/system/rp-ap-hostapd.service";
pub const DNSMASQ_UNIT: &str = "/etc/systemd/system/rp-ap-dnsmasq.service";
pub const NM_CONF: &str = "/etc/NetworkManager/conf.d/90-rp-ap.conf";
pub const SNIPPET_PATH: &str = "/etc/rp/nft.d/60-ap.nft";
pub const CHECK_PATH: &str = "/etc/rp/.check/ap.nft";
/// IPv4 forwarding for AP clients (no IPv6 is offered to them). Separate from
/// the vpn module's file so either module can be rolled back on its own.
pub const SYSCTL_PATH: &str = "/etc/sysctl.d/91-rp-ap.conf";

pub struct Ap;

fn ap(cfg: &Config) -> &rp_schema::Ap {
    cfg.ap.as_ref().expect("ap config")
}

/// Gateway address (first host of the subnet).
pub fn gateway(cfg: &Config) -> Ipv4Net {
    let a = ap(cfg);
    Ipv4Net::new(a.subnet.hosts().next().expect("subnet has hosts"), a.subnet.prefix_len()).unwrap()
}

/// DHCP pool: from the 10th host to 10 before the end (room for static devices).
pub fn dhcp_range(cfg: &Config) -> (std::net::Ipv4Addr, std::net::Ipv4Addr) {
    let a = ap(cfg);
    let hosts: Vec<_> = a.subnet.hosts().collect();
    let n = hosts.len();
    if n >= 40 {
        (hosts[9], hosts[n - 11])
    } else {
        (hosts[1], hosts[n - 1])
    }
}

/// Encode a hostapd string value; non-ASCII / special SSIDs use the P"..." form.
fn hostapd_ssid(ssid: &str) -> String {
    let plain = ssid.chars().all(|c| c.is_ascii_graphic() || c == ' ') && !ssid.contains('"');
    if plain {
        format!("ssid={ssid}")
    } else {
        format!("ssid2={}", ssid.bytes().map(|b| format!("{b:02x}")).collect::<String>())
    }
}

fn hostapd(cfg: &Config) -> String {
    let a = ap(cfg);
    format!(
        "# {HEADER}
interface={iface}
driver=nl80211
{ssid}
country_code={country}
ieee80211d=1
hw_mode=g
channel={channel}
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
# The passphrase lives only in this root-only file (rpctl ap set-passphrase).
wpa_psk_file={psk}
# Clients cannot talk to each other over the air.
ap_isolate=1
ignore_broadcast_ssid=0
",
        iface = a.interface,
        ssid = hostapd_ssid(&a.ssid),
        country = a.country,
        channel = a.channel,
        psk = a.passphrase_file,
    )
}

fn dnsmasq(cfg: &Config) -> String {
    let a = ap(cfg);
    let (lo, hi) = dhcp_range(cfg);
    let gw = gateway(cfg).addr();
    let dns: Vec<String> = if cfg.dns.is_some() {
        vec![gw.to_string()]
    } else {
        a.dns_servers.iter().map(|d| d.to_string()).collect()
    };
    format!(
        "# {HEADER}
# DHCP only: port=0 disables dnsmasq's DNS server (rp-dns owns port 53).
port=0
interface={iface}
bind-interfaces
except-interface=lo
dhcp-authoritative
dhcp-range={lo},{hi},{mask},{lease}
dhcp-option=option:router,{gw}
dhcp-option=option:dns-server,{dns}
dhcp-leasefile=/var/lib/rp/ap/dnsmasq.leases
log-dhcp
",
        iface = a.interface,
        mask = a.subnet.netmask(),
        lease = a.lease_time,
        dns = dns.join(","),
    )
}

fn hostapd_unit(cfg: &Config) -> String {
    let a = ap(cfg);
    let gw = gateway(cfg);
    format!(
        "# {HEADER}
[Unit]
Description=rp access point (hostapd) on {iface}
After=network.target NetworkManager.service
Wants=rp-ap-dnsmasq.service

[Service]
ExecStartPre=/usr/sbin/ip link set {iface} up
ExecStartPre=/usr/sbin/ip addr replace {gw} dev {iface}
ExecStart=/usr/sbin/hostapd {conf}
ExecStopPost=-/usr/sbin/ip addr flush dev {iface}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
",
        iface = a.interface,
        conf = HOSTAPD_CONF,
    )
}

fn dnsmasq_unit(cfg: &Config) -> String {
    let a = ap(cfg);
    format!(
        "# {HEADER}
[Unit]
Description=rp access point DHCP on {iface}
After=rp-ap-hostapd.service
BindsTo=rp-ap-hostapd.service

[Service]
ExecStartPre=/usr/bin/install -d -m 0755 /var/lib/rp/ap
ExecStart=/usr/sbin/dnsmasq --keep-in-foreground --conf-file={conf}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
",
        iface = a.interface,
        conf = DNSMASQ_CONF,
    )
}

fn nm_conf(cfg: &Config) -> String {
    format!(
        "# {HEADER}\n# rp's access point owns this interface; removing this file hands it back.\n\
         [keyfile]\nunmanaged-devices=interface-name:{}\n",
        ap(cfg).interface
    )
}

/// Firewall snippet for the AP.
pub fn snippet(cfg: &Config) -> String {
    let a = ap(cfg);
    let wan = &cfg.device.wan_if;
    let w = &a.interface;
    let mut block: Vec<IpNet> = cfg.device.lan_cidrs.clone();
    block.extend(PRIVATE_V4.iter().map(|s| s.parse::<IpNet>().unwrap()));
    block.extend(PRIVATE_V6.iter().map(|s| s.parse::<IpNet>().unwrap()));
    let (block4, _) = split_families(&block);
    let (allow4, _) = split_families(&a.allow_lan);

    let mut s =
        format!("# {HEADER}\n# Access point {w}: internet yes; LAN, peers and management no.\n");
    s.push_str("table inet rp {\n");
    set(&mut s, "ap_block4", "ipv4_addr", &block4);
    set(&mut s, "ap_allow4", "ipv4_addr", &allow4);
    // Filled only by approved block_device / isolate_client actions; entries expire.
    s.push_str("\tset ap_quarantine4 {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t}\n");
    s.push_str("\tset ap_quarantine_mac {\n\t\ttype ether_addr\n\t\tflags timeout\n\t}\n");

    // Quarantine first, before conntrack accepts established traffic.
    s.push_str("\n\tchain mod_prefilter {\n");
    let _ = writeln!(s, "\t\tiifname \"{w}\" ip saddr @ap_quarantine4 drop");
    let _ = writeln!(s, "\t\toifname \"{w}\" ip daddr @ap_quarantine4 drop");
    let _ = writeln!(s, "\t\tiifname \"{w}\" ether saddr @ap_quarantine_mac drop");
    s.push_str("\t}\n");

    s.push_str("\n\tchain mod_input {\n");
    let _ = writeln!(s, "\t\tiifname \"{w}\" udp sport 68 udp dport 67 accept");
    if cfg.dns.is_some() {
        let _ = writeln!(s, "\t\tiifname \"{w}\" ip saddr {} udp dport 53 accept", a.subnet);
        let _ = writeln!(s, "\t\tiifname \"{w}\" ip saddr {} tcp dport 53 accept", a.subnet);
    }
    s.push_str("\t}\n");

    s.push_str("\n\tchain mod_forward {\n");
    // Peer-to-peer through the router (hairpin); over-the-air is blocked by ap_isolate.
    let _ = writeln!(s, "\t\tiifname \"{w}\" oifname \"{w}\" drop");
    // DNS-over-TLS / -QUIC bypasses the DNS firewall: log it (and still allow).
    let _ = writeln!(
        s,
        "\t\tiifname \"{w}\" tcp dport 853 limit rate 6/minute log prefix \"rp-ap-dot \""
    );
    let _ = writeln!(
        s,
        "\t\tiifname \"{w}\" udp dport 853 limit rate 6/minute log prefix \"rp-ap-doq \""
    );
    if a.block_dot {
        // Reject (not drop) so clients in automatic "Private DNS" mode fall back
        // to plain DNS immediately instead of waiting for a timeout.
        let _ = writeln!(s, "\t\tiifname \"{w}\" tcp dport 853 reject with tcp reset");
        let _ = writeln!(s, "\t\tiifname \"{w}\" udp dport 853 reject");
    }
    let _ = writeln!(s, "\t\tiifname \"{w}\" oifname \"{wan}\" ip daddr @ap_allow4 accept");
    let _ = writeln!(s, "\t\tiifname \"{w}\" ip daddr @ap_block4 drop");
    // No IPv6 is offered to AP clients; never forward any from them.
    let _ = writeln!(s, "\t\tiifname \"{w}\" meta nfproto ipv6 drop");
    let _ = writeln!(s, "\t\tiifname \"{w}\" oifname \"{wan}\" accept");
    if a.lan_can_reach_clients {
        let _ = writeln!(s, "\t\tiifname \"{wan}\" oifname \"{w}\" ip saddr @lan4 accept");
    }
    s.push_str("\t}\n");

    s.push_str("\n\tchain ap_postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n");
    let _ = writeln!(s, "\t\toifname \"{wan}\" ip saddr {} masquerade", a.subnet);
    s.push_str("\t}\n}\n");
    s
}

impl Module for Ap {
    fn name(&self) -> &'static str {
        "ap"
    }

    fn enabled(&self, cfg: &Config) -> Result<(), String> {
        cfg.ap.as_ref().map(|_| ()).ok_or_else(|| "no [ap] section in the config".into())
    }

    fn render(&self, cfg: &Config) -> Vec<ManagedFile> {
        if cfg.ap.is_none() {
            return vec![];
        }
        let snip = snippet(cfg);
        vec![
            ManagedFile::new(HOSTAPD_CONF, 0o600, hostapd(cfg)),
            ManagedFile::new(DNSMASQ_CONF, 0o644, dnsmasq(cfg)),
            ManagedFile::new(HOSTAPD_UNIT, 0o644, hostapd_unit(cfg)),
            ManagedFile::new(DNSMASQ_UNIT, 0o644, dnsmasq_unit(cfg)),
            ManagedFile::new(NM_CONF, 0o644, nm_conf(cfg)),
            ManagedFile::new(SYSCTL_PATH, 0o644, format!("# {HEADER}\nnet.ipv4.ip_forward = 1\n")),
            ManagedFile::new(SNIPPET_PATH, 0o600, snip.clone()),
            ManagedFile::check_only(CHECK_PATH, nft::combined(cfg, &snip)),
        ]
    }

    fn packages(&self, _cfg: &Config) -> Vec<&'static str> {
        vec!["hostapd", "dnsmasq-base", "iw"]
    }

    fn validate_steps(&self, _cfg: &Config) -> Vec<Step> {
        vec![
            Step::cmd(&["nft", "-c", "-f", &format!("{{staged:{CHECK_PATH}}}")]),
            Step::cmd(&["dnsmasq", "--test", &format!("--conf-file={{staged:{DNSMASQ_CONF}}}")]),
        ]
    }

    fn post_apply(&self, cfg: &Config) -> Vec<Step> {
        let iface = &ap(cfg).interface;
        vec![
            // Hand the interface over: NetworkManager lets go first.
            Step::cmd(&["nmcli", "general", "reload", "conf"]),
            Step::best_effort(&["nmcli", "device", "set", iface, "managed", "no"]),
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::cmd(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            // Without forwarding, clients reach only this box (DHCP/DNS), never the internet.
            Step::cmd(&["sysctl", "--system"]),
            Step::cmd(&["systemctl", "enable", "rp-ap-hostapd.service", "rp-ap-dnsmasq.service"]),
            Step::cmd(&["systemctl", "restart", "rp-ap-hostapd.service"]),
            Step::cmd(&["systemctl", "restart", "rp-ap-dnsmasq.service"]),
            Step::cmd(&["systemctl", "is-active", "--quiet", "rp-ap-hostapd.service"]),
        ]
    }

    fn pre_rollback(&self) -> Vec<Step> {
        vec![Step::best_effort(&[
            "systemctl",
            "disable",
            "--now",
            "rp-ap-dnsmasq.service",
            "rp-ap-hostapd.service",
        ])]
    }

    fn post_rollback(&self) -> Vec<Step> {
        vec![
            Step::cmd(&["systemctl", "daemon-reload"]),
            Step::best_effort(&["systemctl", "reload-or-restart", "rp-firewall.service"]),
            // Removing the sysctl file does not undo the live value; reset it, then
            // re-read sysctl.d so forwarding stays on if the vpn module still needs it.
            Step::cmd(&["sysctl", "-w", "net.ipv4.ip_forward=0"]),
            Step::cmd(&["sysctl", "--system"]),
            // Give the interface back; NM reconnects to the saved network.
            Step::cmd(&["nmcli", "general", "reload", "conf"]),
            Step::best_effort(&["sh", "-c", "for d in $(nmcli -g DEVICE,TYPE device | awk -F: '$2==\"wifi\"{print $1}'); do nmcli device set \"$d\" managed yes; done"]),
        ]
    }

    fn arms_dead_man(&self) -> bool {
        true
    }

    fn requires(&self) -> &'static [&'static str] {
        &["base"]
    }

    fn next_steps(&self, cfg: &Config) -> Vec<String> {
        let a = ap(cfg);
        vec![
            format!("Join '{}' from an IoT device; it gets an address in {}.", a.ssid, a.subnet),
            "Leases: /var/lib/rp/ap/dnsmasq.leases   AP status: sudo systemctl status rp-ap-hostapd".into(),
            "To undo and reconnect this device to your Wi-Fi: sudo rpctl rollback ap".into(),
        ]
    }
}

/// Validate a WPA2 passphrase: 8-63 printable ASCII characters.
pub fn valid_passphrase(p: &str) -> bool {
    (8..=63).contains(&p.len()) && p.chars().all(|c| c.is_ascii_graphic() || c == ' ')
}

/// hostapd `wpa_psk_file` content: the wildcard MAC applies the passphrase to all clients.
pub fn psk_file_content(passphrase: &str) -> String {
    format!("00:00:00:00:00:00 {passphrase}\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(extra: &str) -> Config {
        parse(&format!(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[ap]\nssid = \"rp-iot\"\ncountry = \"TW\"\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn hostapd_is_wpa2_isolated_and_has_no_secret() {
        let h = hostapd(&cfg(""));
        for l in [
            "wpa=2",
            "rsn_pairwise=CCMP",
            "ap_isolate=1",
            "country_code=TW",
            "wpa_psk_file=/etc/rp/ap.psk",
        ] {
            assert!(h.contains(l), "missing {l}");
        }
        assert!(!h.contains("wpa_passphrase"));
        assert_eq!(hostapd_ssid("plain ssid"), "ssid=plain ssid");
        assert!(hostapd_ssid("咖啡\"x").starts_with("ssid2="));
    }

    #[test]
    fn dnsmasq_is_dhcp_only_with_sane_range() {
        let d = dnsmasq(&cfg(""));
        assert!(d.contains("port=0"));
        assert!(d.contains("dhcp-range=10.77.0.10,10.77.0.244,255.255.255.0,12h")); // rp-probe:allow
        assert!(d.contains("option:dns-server,1.1.1.1,9.9.9.9"));
        let with_dns = parse(&format!(
            "{}\n[dns]\nupstreams = [\"1.1.1.1:53\"]\n",
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[ap]\nssid = \"x-iot\"\ncountry = \"TW\""
        ))
        .unwrap();
        assert!(dnsmasq(&with_dns).contains("option:dns-server,10.77.0.1")); // rp-probe:allow
        assert!(snippet(&with_dns).contains("udp dport 53 accept"));
        assert!(!snippet(&cfg("")).contains("dport 53"));
    }

    #[test]
    fn firewall_isolates_clients() {
        let s = snippet(&cfg(""));
        let hairpin = s.find("iifname \"wlan0\" oifname \"wlan0\" drop").unwrap();
        let block = s.find("iifname \"wlan0\" ip daddr @ap_block4 drop").unwrap();
        let v6 = s.find("iifname \"wlan0\" meta nfproto ipv6 drop").unwrap();
        let accept = s.find("iifname \"wlan0\" oifname \"eth0\" accept").unwrap();
        assert!(hairpin < accept && block < accept && v6 < accept);
        assert!(s.contains("192.0.2.0/24"));
        assert!(s.contains("oifname \"eth0\" ip saddr 10.77.0.0/24 masquerade"));
        assert!(s.contains("tcp dport 853"));
        assert!(!s.contains("reject"), "DoT is only logged by default");
        let b = snippet(&cfg("block_dot = true"));
        let rej = b.find("iifname \"wlan0\" tcp dport 853 reject with tcp reset").unwrap();
        assert!(b.contains("iifname \"wlan0\" udp dport 853 reject"));
        let allow = b.find("ip daddr @ap_allow4 accept").unwrap();
        assert!(rej < allow, "an allow_lan exception must not re-open DoT");
        assert!(s.contains("iifname \"eth0\" oifname \"wlan0\" ip saddr @lan4 accept"));
        assert!(!snippet(&cfg("lan_can_reach_clients = false\n"))
            .contains("oifname \"wlan0\" ip saddr @lan4"));
    }

    #[test]
    fn quarantine_rules_come_first() {
        let s = snippet(&cfg(""));
        let pre = s.find("chain mod_prefilter {").unwrap();
        let q = s.find("iifname \"wlan0\" ip saddr @ap_quarantine4 drop").unwrap();
        let input = s.find("chain mod_input {").unwrap();
        assert!(pre < q && q < input, "quarantine lives in the prefilter chain");
        assert!(s.contains("set ap_quarantine_mac {\n\t\ttype ether_addr\n\t\tflags timeout"));
        assert!(s.contains("oifname \"wlan0\" ip daddr @ap_quarantine4 drop"));
    }

    #[test]
    fn passphrase_rules_and_file_format() {
        assert!(valid_passphrase("correct horse"));
        assert!(!valid_passphrase("short"));
        assert!(!valid_passphrase(&"x".repeat(64)));
        assert!(!valid_passphrase("tab\tnot-allowed"));
        assert_eq!(psk_file_content("abcdefgh"), "00:00:00:00:00:00 abcdefgh\n");
        // rp-probe:allow
    }

    #[test]
    fn rendered_files_and_requirements() {
        let f = Ap.render(&cfg(""));
        assert_eq!(f.len(), 8);
        let sysctl = f.iter().find(|x| x.path == SYSCTL_PATH).expect("forwarding sysctl");
        assert!(sysctl.content.contains("net.ipv4.ip_forward = 1"), "AP clients need forwarding");
        assert!(!sysctl.content.contains("ipv6"), "no IPv6 forwarding for AP clients");
        let post: Vec<String> = Ap.post_apply(&cfg("")).iter().map(|s| s.argv.join(" ")).collect();
        assert!(post.contains(&"sysctl --system".to_string()));
        let undo: Vec<String> = Ap.post_rollback().iter().map(|s| s.argv.join(" ")).collect();
        let off = undo.iter().position(|s| s == "sysctl -w net.ipv4.ip_forward=0").unwrap();
        let reread = undo.iter().position(|s| s == "sysctl --system").unwrap();
        assert!(off < reread, "re-read sysctl.d after resetting so a vpn module keeps forwarding");
        assert_eq!(f.iter().filter(|x| x.staging_only).count(), 1);
        assert!(
            f.iter().all(|x| !x.content.contains("00:00:00:00:00:00")),
            "no passphrase anywhere"
        ); // rp-probe:allow
        assert_eq!(Ap.packages(&cfg("")), ["hostapd", "dnsmasq-base", "iw"]);
    }
}
