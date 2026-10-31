//! Rendering of the `inet rp` nftables table.
//!
//! The base module owns `/etc/rp/nftables.nft`, which defines the table, the
//! filter chains and two empty extension chains (`mod_input`, `mod_forward`)
//! that the base chains jump to. Other modules drop snippets into
//! `/etc/rp/nft.d/` that re-open the table and append rules to those chains, so
//! each module can be applied and rolled back without touching another
//! module's files. The whole ruleset is still loaded atomically by one
//! `nft -f`.

use std::fmt::Write;

use ipnet::IpNet;
use rp_schema::Config;

use crate::config::ssh_allow;
use crate::files::HEADER;

pub const NFT_DIR: &str = "/etc/rp/nft.d";

/// Split networks by family and merge overlaps (nft interval sets reject them).
pub fn split_families(nets: &[IpNet]) -> (Vec<IpNet>, Vec<IpNet>) {
    let merged = IpNet::aggregate(&nets.to_vec());
    merged.into_iter().partition(|n| matches!(n, IpNet::V4(_)))
}

pub fn set(out: &mut String, name: &str, ty: &str, nets: &[IpNet]) {
    let _ = write!(out, "\tset {name} {{\n\t\ttype {ty}\n\t\tflags interval\n");
    if !nets.is_empty() {
        let list: Vec<String> = nets.iter().map(|n| n.to_string()).collect();
        let _ = writeln!(out, "\t\telements = {{ {} }}", list.join(", "));
    }
    out.push_str("\t}\n");
}

/// The base ruleset, ending with an include of every module snippet.
pub fn ruleset(cfg: &Config) -> String {
    let mut s = base_table(cfg);
    let _ = writeln!(s, "\ninclude \"{NFT_DIR}/*.nft\"");
    s
}

/// The base ruleset with `snippet` inlined instead of the include — used to
/// validate a module's snippet together with the base before installing it.
pub fn combined(cfg: &Config, snippet: &str) -> String {
    format!("{}\n{snippet}", base_table(cfg))
}

fn base_table(cfg: &Config) -> String {
    let (ssh4, ssh6) = split_families(&ssh_allow(cfg));
    let (lan4, lan6) = split_families(&cfg.device.lan_cidrs);
    let port = cfg.ssh.port;

    let mut s = String::new();
    let _ = writeln!(s, "#!/usr/sbin/nft -f\n# {HEADER}\n");
    // Declare-then-delete makes the reload idempotent and atomic.
    s.push_str("table inet rp\ndelete table inet rp\n\ntable inet rp {\n");
    set(&mut s, "ssh_allow4", "ipv4_addr", &ssh4);
    set(&mut s, "ssh_allow6", "ipv6_addr", &ssh6);
    set(&mut s, "lan4", "ipv4_addr", &lan4);
    set(&mut s, "lan6", "ipv6_addr", &lan6);

    s.push_str("\n\t# Extension points: module snippets in /etc/rp/nft.d append here.\n");
    s.push_str("\t# mod_prefilter runs before connection tracking accepts anything, so a\n");
    s.push_str("\t# quarantine also cuts connections that were already established.\n");
    s.push_str("\tchain mod_prefilter {\n\t}\n\n");
    s.push_str("\tchain mod_input {\n\t}\n\n\tchain mod_forward {\n\t}\n");

    s.push_str("\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n");
    s.push_str("\t\tjump mod_prefilter\n");
    s.push_str("\t\tct state established,related accept\n");
    s.push_str("\t\tct state invalid drop\n");
    s.push_str("\t\tiif \"lo\" accept\n");
    s.push_str("\t\tip protocol icmp limit rate 20/second accept\n");
    // ICMPv6 is required for neighbour discovery; never rate-limit it away.
    s.push_str("\t\tmeta l4proto ipv6-icmp accept\n");
    s.push_str("\t\tudp sport 67 udp dport 68 accept\n");
    s.push_str("\t\tudp sport 547 udp dport 546 accept\n");
    if cfg.base.allow_mdns {
        s.push_str("\t\tudp dport 5353 accept\n");
    }
    let _ = writeln!(s, "\t\ttcp dport {port} ip saddr @ssh_allow4 accept");
    let _ = writeln!(s, "\t\ttcp dport {port} ip6 saddr @ssh_allow6 accept");
    s.push_str("\t\tjump mod_input\n");
    s.push_str("\t\tlimit rate 10/minute burst 20 packets log prefix \"rp-input-drop \"\n");
    s.push_str("\t}\n");

    s.push_str("\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n");
    s.push_str("\t\tjump mod_prefilter\n");
    s.push_str("\t\tct state established,related accept\n");
    s.push_str("\t\tct state invalid drop\n");
    s.push_str("\t\tjump mod_forward\n");
    s.push_str("\t\tlimit rate 10/minute burst 20 packets log prefix \"rp-forward-drop \"\n");
    s.push_str("\t}\n");

    s.push_str("\n\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n");
    s.push_str("\t}\n}\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse;

    fn cfg(extra: &str) -> Config {
        parse(&format!(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\", \"2001:db8::/64\"]\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn default_policy_is_drop_and_ssh_is_scoped() {
        let r = ruleset(&cfg(""));
        assert!(r.contains("hook input priority filter; policy drop;"));
        assert!(r.contains("hook forward priority filter; policy drop;"));
        assert!(r.contains("tcp dport 22 ip saddr @ssh_allow4 accept"));
        assert!(r.contains("elements = { 192.0.2.0/24 }"));
        assert!(r.contains("elements = { 2001:db8::/64 }"));
        assert!(r.contains("udp dport 5353 accept"));
        assert!(!r.contains("tcp dport 22 accept"), "sshd must never be open to all");
    }

    #[test]
    fn extension_chains_are_jumped_to_before_logging_and_snippets_included() {
        let r = ruleset(&cfg(""));
        let jump = r.find("\t\tjump mod_input").unwrap();
        let log = r.find("log prefix \"rp-input-drop \"").unwrap();
        assert!(jump < log);
        assert!(r.contains("\t\tjump mod_forward\n"));
        assert!(r.trim_end().ends_with("include \"/etc/rp/nft.d/*.nft\""));
    }

    #[test]
    fn prefilter_runs_before_established_accept() {
        let r = ruleset(&cfg(""));
        for chain in ["chain input {", "chain forward {"] {
            let at = r.find(chain).unwrap();
            let pre = r[at..].find("jump mod_prefilter").unwrap();
            let est = r[at..].find("ct state established,related accept").unwrap();
            assert!(pre < est, "{chain}: prefilter must come first");
        }
    }

    #[test]
    fn combined_inlines_snippet_instead_of_include() {
        let c = combined(&cfg(""), "table inet rp {\n}\n");
        assert!(!c.contains("include"));
        assert!(c.ends_with("table inet rp {\n}\n"));
    }

    #[test]
    fn mdns_can_be_disabled_and_port_changed() {
        let r = ruleset(&cfg("[base]\nallow_mdns = false\n[ssh]\nport = 2222\n"));
        assert!(!r.contains("5353"));
        assert!(r.contains("tcp dport 2222 ip saddr @ssh_allow4 accept"));
    }

    #[test]
    fn overlapping_networks_are_merged_and_empty_sets_have_no_elements() {
        let r = ruleset(&cfg(
            "[ssh]\nallow_from = [\"192.0.2.0/25\", \"192.0.2.128/25\", \"192.0.2.10/32\"]\n",
        ));
        assert!(r.contains(
            "set ssh_allow4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 192.0.2.0/24 }"
        ));
        assert!(r.contains("set ssh_allow6 {\n\t\ttype ipv6_addr\n\t\tflags interval\n\t}"));
    }
}
