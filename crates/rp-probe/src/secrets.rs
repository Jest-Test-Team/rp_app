//! Repository secret scanner.
//!
//! Flags three kinds of leaks:
//! * exact values from a local env file (e.g. `local.env`) whose key looks
//!   sensitive (PASSWORD, SSID, USER, KEY, TOKEN, SECRET)
//! * well-known credential formats (private keys, Tailscale/GitHub/AWS tokens)
//! * addresses that look like real hosts: private-range IPv4 host addresses and
//!   MAC addresses that are not documentation / locally-administered examples

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub kind: String,
}

static PATTERNS: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        ("tailscale-key", r"\btskey-[a-z]+-[A-Za-z0-9]{8,}"),
        ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}"),
        ("aws-access-key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("wireguard-private-key", r"(?i)PrivateKey\s*=\s*[A-Za-z0-9+/]{42,43}="),
    ]
    .into_iter()
    .map(|(k, p)| (k, Regex::new(p).unwrap()))
    .collect()
});

static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap());
static MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b([0-9a-f]{2})(?::[0-9a-f]{2}){5}\b").unwrap());

/// Lines containing this marker are not scanned (for intentional examples).
pub const ALLOW_MARKER: &str = concat!("rp-probe", ":allow");

const SENSITIVE_KEYS: &[&str] = &["PASSWORD", "SSID", "USER", "KEY", "TOKEN", "SECRET"];

/// Values from `KEY=value` lines whose key looks sensitive. Placeholders and
/// very short values are ignored to avoid noise.
pub fn sensitive_values(env_text: &str) -> Vec<(String, String)> {
    env_text
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            if l.starts_with('#') {
                return None;
            }
            let (k, v) = l.split_once('=')?;
            let v = v.trim().trim_matches(|c| c == '\'' || c == '"').to_string();
            let sensitive = SENSITIVE_KEYS.iter().any(|s| k.to_ascii_uppercase().contains(s));
            (sensitive && v.len() >= 4 && !v.contains("CHANGE_ME")).then(|| (k.to_string(), v))
        })
        .collect()
}

/// A private / CGNAT IPv4 address that is not a network or broadcast address
/// is most likely a real host on someone's LAN.
fn looks_like_real_host(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    let private = ip.is_private() || (o[0] == 100 && (64..128).contains(&o[1]));
    private && o[3] != 0 && o[3] != 255
}

fn mac_is_example(first_octet: &str) -> bool {
    // Locally administered (x2, x6, xA, xE) MACs are what docs and tests use;
    // multicast (odd first octet) is a group address, never a device.
    u8::from_str_radix(first_octet, 16).map(|b| b & 0x03 != 0).unwrap_or(false)
}

pub fn scan_text(file: &str, text: &str, values: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if line.contains(ALLOW_MARKER) {
            continue;
        }
        let mut push = |kind: String| out.push(Finding { file: file.into(), line: i + 1, kind });
        for (k, v) in values {
            if line.contains(v.as_str()) {
                push(format!("value-of:{k}"));
            }
        }
        for (kind, re) in PATTERNS.iter() {
            if re.is_match(line) {
                push(kind.to_string());
            }
        }
        for c in IPV4.captures_iter(line) {
            let parts: Vec<u8> = (1..=4).filter_map(|n| c[n].parse().ok()).collect();
            if parts.len() == 4 {
                let ip = Ipv4Addr::new(parts[0], parts[1], parts[2], parts[3]);
                if looks_like_real_host(ip) {
                    push(format!("lan-host-ip:{ip}"));
                }
            }
        }
        for c in MAC.captures_iter(line) {
            let whole = c[0].to_ascii_lowercase();
            // All-zero (wildcard) and broadcast are not device addresses.
            let special = whole == "00:00:00:00:00:00" || whole == "ff:ff:ff:ff:ff:ff"; // rp-probe:allow
            if !special && !mac_is_example(&c[1]) {
                push("mac-address".into());
            }
        }
    }
    out
}

// Generated / build output (gitignored): Flutter and Gradle caches carry
// absolute paths of the build machine, not project content.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    ".venv",
    ".cache",
    "results",
    "node_modules",
    ".dart_tool",
    "build",
    "ephemeral",
    "Pods",
    ".gradle",
    ".symlinks",
];
const SKIP_FILES: &[&str] = &[
    "local.env",
    "Cargo.lock",
    ".flutter-plugins-dependencies",
    "Generated.xcconfig",
    "flutter_export_environment.sh",
];

pub fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if p.is_dir() {
                if !SKIP_DIRS.contains(&name.as_str()) {
                    stack.push(p);
                }
            } else if !SKIP_FILES.contains(&name.as_str()) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

pub fn scan_paths(paths: &[PathBuf], values: &[(String, String)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in paths {
        let files = if p.is_dir() { walk(p) } else { vec![p.clone()] };
        for f in files {
            // Binary or non-UTF-8 files are skipped.
            if let Ok(text) = std::fs::read_to_string(&f) {
                out.extend(scan_text(&f.display().to_string(), &text, values));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_sensitive_real_values() {
        let v = sensitive_values(
            "# c\nPI_USER=alice\nPI_PASSWORD='s3cret!!'\nWIFI_SSID=CHANGE_ME\nWIFI_COUNTRY=TW\nAPI_KEY=ab\n",
        );
        assert_eq!(
            v,
            [("PI_USER".into(), "alice".into()), ("PI_PASSWORD".into(), "s3cret!!".into())]
        );
    }

    fn kinds(text: &str) -> Vec<String> {
        scan_text("f", text, &[("PI_PASSWORD".into(), "s3cret!!".into())])
            .into_iter()
            .map(|f| f.kind)
            .collect()
    }

    #[test]
    fn flags_values_and_token_formats() {
        assert_eq!(kinds("pw is s3cret!! here"), ["value-of:PI_PASSWORD"]);
        assert_eq!(kinds("-----BEGIN OPENSSH PRIVATE KEY-----"), ["private-key"]); // rp-probe:allow
        assert_eq!(kinds("auth tskey-auth-kAbCdEf123456"), ["tailscale-key"]); // rp-probe:allow
    }

    #[test]
    fn ip_rules_allow_docs_and_networks_but_flag_lan_hosts() {
        assert!(kinds("lan_cidrs = [\"192.0.2.0/24\", \"198.51.100.7\"]").is_empty());
        assert!(kinds("route 192.168.0.0/16 and 10.0.0.0/8 and 0.0.0.0/0").is_empty());
        assert_eq!(kinds("pi at 192.168.1.23"), ["lan-host-ip:192.168.1.23"]); // rp-probe:allow
        assert_eq!(kinds("cgnat 100.64.10.5"), ["lan-host-ip:100.64.10.5"]); // rp-probe:allow
    }

    #[test]
    fn allow_marker_skips_line() {
        let marker = ALLOW_MARKER;
        assert!(kinds(&format!("pi at 192.168.1.23 {marker}")).is_empty()); // rp-probe:allow
    }

    #[test]
    fn wildcard_and_broadcast_macs_are_not_findings() {
        let zero = ["00"; 6].join(":");
        let bcast = ["ff"; 6].join(":");
        assert!(kinds(&format!("{zero} passphrase")).is_empty());
        assert!(kinds(&bcast).is_empty());
        assert!(kinds("01:00:5e:00:00:01").is_empty(), "multicast group address");
    }

    #[test]
    fn mac_rules() {
        assert!(kinds("mac 02:11:22:33:44:55").is_empty());
        assert_eq!(kinds("mac b8:27:eb:00:11:22"), ["mac-address"]); // rp-probe:allow
    }
}
