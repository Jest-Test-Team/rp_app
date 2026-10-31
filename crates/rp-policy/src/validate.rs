//! Argument validation for tool calls. Inputs come from a model and must be
//! treated as hostile: everything is parsed into strict types and checked
//! against allow-lists before any side effect.

use std::net::IpAddr;

use ipnet::IpNet;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Invalid(pub String);

fn bad(msg: impl Into<String>) -> Invalid {
    Invalid(msg.into())
}

/// Reject control characters, NULs, shell metacharacters and overlong text in
/// free-form string arguments (defence in depth: nothing is passed to a shell).
pub fn plain_text(field: &str, s: &str, max: usize) -> Result<(), Invalid> {
    if s.len() > max {
        return Err(bad(format!("{field} is longer than {max} characters")));
    }
    if s.chars().any(|c| c.is_control() || "`$;|&<>\\".contains(c)) {
        return Err(bad(format!("{field} contains forbidden characters")));
    }
    Ok(())
}

/// A scan target must be an IPv4 network inside one of `allowed`, no larger
/// than `max_hosts` addresses. IPv6 scanning is never allowed (address space
/// too large to be meaningful, and abusable).
pub fn scan_target(target: &str, allowed: &[IpNet], max_hosts: u32) -> Result<IpNet, Invalid> {
    let t = target.trim();
    plain_text("target", t, 64)?;
    let net: IpNet = t.parse().map_err(|_| bad(format!("target '{t}' is not a CIDR network")))?;
    let IpNet::V4(v4) = net else {
        return Err(bad("IPv6 targets are not allowed"));
    };
    if v4.prefix_len() == 0 {
        return Err(bad("0.0.0.0/0 is never an allowed target"));
    }
    let hosts = 1u64 << (32 - v4.prefix_len());
    if hosts > u64::from(max_hosts) {
        return Err(bad(format!("target {net} has {hosts} addresses; the limit is {max_hosts}")));
    }
    let inside = allowed.iter().any(|a| a.contains(&net.network()) && a.contains(&net.broadcast()));
    if !inside {
        return Err(bad(format!("target {net} is outside the allowed networks")));
    }
    Ok(IpNet::V4(v4.trunc()))
}

/// A single address that must lie inside `net` (e.g. the AP client subnet).
pub fn ip_in(field: &str, value: &str, net: &IpNet) -> Result<IpAddr, Invalid> {
    plain_text(field, value, 45)?;
    let ip: IpAddr =
        value.trim().parse().map_err(|_| bad(format!("{field} '{value}' is not an IP address")))?;
    if !net.contains(&ip) {
        return Err(bad(format!("{field} {ip} is outside {net}")));
    }
    if ip == net.network() || ip == net.broadcast() {
        return Err(bad(format!("{field} {ip} is not a host address")));
    }
    Ok(ip)
}

/// A unicast MAC address, normalised to lowercase `aa:bb:cc:dd:ee:ff`.
pub fn mac(value: &str) -> Result<String, Invalid> {
    plain_text("mac", value, 17)?;
    let v = value.trim().to_ascii_lowercase().replace('-', ":");
    let parts: Vec<&str> = v.split(':').collect();
    if parts.len() != 6
        || !parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(bad(format!("'{value}' is not a MAC address")));
    }
    let first = u8::from_str_radix(parts[0], 16).unwrap();
    if first & 1 == 1 {
        return Err(bad("multicast/broadcast MAC addresses are not allowed"));
    }
    if v == "00:00:00:00:00:00" {
        return Err(bad("the all-zero MAC is not allowed"));
    }
    Ok(v)
}

pub fn bounded(field: &str, v: i64, min: i64, max: i64) -> Result<i64, Invalid> {
    if v < min || v > max {
        return Err(bad(format!("{field} must be between {min} and {max}")));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lan() -> Vec<IpNet> {
        vec!["192.0.2.0/24".parse().unwrap(), "198.51.100.128/25".parse().unwrap()]
    }

    #[test]
    fn scan_target_is_confined_to_allowed_networks() {
        assert_eq!(scan_target("192.0.2.0/24", &lan(), 256).unwrap().to_string(), "192.0.2.0/24");
        assert_eq!(scan_target("192.0.2.77/28", &lan(), 256).unwrap().to_string(), "192.0.2.64/28");
        for bad in [
            "0.0.0.0/0",
            "192.0.2.0/16",
            "203.0.113.0/24",
            "192.0.2.0/23",
            "2001:db8::/64",
            "192.0.2.0/24; rm -rf /",
            "$(id)",
            "not-a-cidr",
            "",
        ] {
            assert!(scan_target(bad, &lan(), 256).is_err(), "{bad} should be rejected");
        }
        assert!(scan_target("198.51.100.128/25", &lan(), 64).is_err(), "size limit applies");
    }

    #[test]
    fn ip_must_be_a_host_in_the_subnet() {
        let net: IpNet = "198.51.100.128/25".parse().unwrap();
        assert!(ip_in("ip", "198.51.100.140", &net).is_ok());
        assert!(ip_in("ip", "198.51.100.128", &net).is_err());
        assert!(ip_in("ip", "198.51.100.255", &net).is_err());
        assert!(ip_in("ip", "192.0.2.10", &net).is_err());
        assert!(ip_in("ip", "198.51.100.140`reboot`", &net).is_err());
    }

    #[test]
    fn mac_rules() {
        assert_eq!(mac("02-AA-bb-CC-dd-EE").unwrap(), "02:aa:bb:cc:dd:ee");
        assert!(mac("ff:ff:ff:ff:ff:ff").is_err());
        assert!(mac("01:00:5e:00:00:01").is_err());
        assert!(mac("00:00:00:00:00:00").is_err()); // rp-probe:allow
        assert!(mac("02:aa:bb:cc:dd").is_err());
        assert!(mac("02:aa:bb:cc:dd:ee;x").is_err());
    }

    #[test]
    fn text_and_bounds() {
        assert!(plain_text("q", "ads.example", 64).is_ok());
        assert!(plain_text("q", "a\nb", 64).is_err());
        assert!(plain_text("q", "a|b", 64).is_err());
        assert!(plain_text("q", &"x".repeat(65), 64).is_err());
        assert!(bounded("ttl", 0, 1, 1440).is_err());
        assert_eq!(bounded("ttl", 60, 1, 1440).unwrap(), 60);
    }
}
