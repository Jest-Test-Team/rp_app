//! Public, open-source threat-intelligence blocklists for the DNS firewall,
//! downloaded daily by `rpctl dns update-feeds` (systemd timer from the dns
//! module) into [`FEED_DIR`] and loaded by rp-dns next to `dns.blocklists`.
//!
//! Only these catalogue entries can be enabled (`dns.feeds` holds ids), so a
//! change set can never point the device at an arbitrary URL.

use rp_schema::Dns;

/// Root-owned, world-readable (rp-dns runs as a dynamic user).
pub const FEED_DIR: &str = "/var/lib/rp-dns-feeds";
pub const STATUS_FILE: &str = "/var/lib/rp-dns-feeds/status.json";
/// A feed larger than this is refused (the biggest here is ~7 MB).
pub const MAX_BYTES: u64 = 30_000_000;
/// All feeds together. rp-dns keeps the lists in memory (about 70 bytes a
/// domain, twice during a reload) under MemoryMax=96M; feeds past this are
/// skipped by the updater with an error the app shows.
pub const MAX_TOTAL_ENTRIES: usize = 450_000;

pub struct Feed {
    pub id: &'static str,
    pub name: &'static str,
    pub url: &'static str,
    pub homepage: &'static str,
    pub license: &'static str,
    /// What it blocks, in plain words.
    pub blocks: &'static str,
    /// Rough number of domains (for the app; checked daily on download).
    pub approx_entries: u32,
    /// Part of the recommended "balanced" set.
    pub balanced: bool,
}

pub const FEEDS: &[Feed] = &[
    Feed {
        id: "stevenblack",
        name: "StevenBlack unified hosts",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        homepage: "https://github.com/StevenBlack/hosts",
        license: "MIT",
        blocks: "ads, trackers and known malware domains",
        approx_entries: 80_000,
        balanced: true,
    },
    Feed {
        id: "urlhaus",
        name: "URLhaus malware domains (abuse.ch)",
        url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
        homepage: "https://urlhaus.abuse.ch/",
        license: "CC0 (data) / MIT (list)",
        blocks: "sites currently spreading malware",
        approx_entries: 20_000,
        balanced: true,
    },
    Feed {
        id: "phishing_army",
        name: "Phishing Army",
        url: "https://phishing.army/download/phishing_army_blocklist.txt",
        homepage: "https://phishing.army/",
        license: "CC BY-NC 4.0 (free for personal use)",
        blocks: "phishing and scam sites",
        approx_entries: 150_000,
        balanced: true,
    },
    Feed {
        id: "hagezi_tif_mini",
        name: "HaGeZi Threat Intelligence (mini)",
        url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt",
        homepage: "https://github.com/hagezi/dns-blocklists",
        license: "GPL-3.0",
        blocks: "malware, phishing, scam and command-and-control domains from many threat feeds",
        approx_entries: 190_000,
        balanced: false,
    },
    Feed {
        id: "hagezi_light",
        name: "HaGeZi Light",
        url: "https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/domains/light.txt",
        homepage: "https://github.com/hagezi/dns-blocklists",
        license: "GPL-3.0",
        blocks: "ads, trackers and telemetry (gentle: rarely breaks sites)",
        approx_entries: 160_000,
        balanced: false,
    },
];

pub fn find(id: &str) -> Option<&'static Feed> {
    FEEDS.iter().find(|f| f.id == id)
}

/// The recommended set ("balanced").
pub fn balanced() -> Vec<String> {
    FEEDS.iter().filter(|f| f.balanced).map(|f| f.id.to_string()).collect()
}

pub fn feed_path(id: &str) -> String {
    format!("{FEED_DIR}/{id}.txt")
}

/// Every list file rp-dns loads: `dns.blocklists`, then the enabled feeds.
pub fn list_files(d: &Dns) -> Vec<String> {
    let mut v = d.blocklists.clone();
    v.extend(d.feeds.iter().filter(|id| find(id).is_some()).map(|id| feed_path(id)));
    v
}

/// Errors for `dns.feeds` (unknown ids, duplicates).
pub fn validate(d: &Dns) -> Vec<String> {
    let mut errs = vec![];
    let mut seen = std::collections::BTreeSet::new();
    for id in &d.feeds {
        if find(id).is_none() {
            let known: Vec<&str> = FEEDS.iter().map(|f| f.id).collect();
            errs.push(format!("dns.feeds entry '{id}' is not a known feed ({})", known.join(", ")));
        }
        if !seen.insert(id) {
            errs.push(format!("dns.feeds entry '{id}' is listed twice"));
        }
    }
    errs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_is_https_unique_and_balanced_is_three_feeds() {
        let mut ids = std::collections::BTreeSet::new();
        for f in FEEDS {
            assert!(f.url.starts_with("https://"), "{}", f.id);
            assert!(ids.insert(f.id), "duplicate {}", f.id);
            assert!(f.id.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{}", f.id);
        }
        assert_eq!(balanced(), ["stevenblack", "urlhaus", "phishing_army"]);
        let total: u32 = FEEDS.iter().filter(|f| f.balanced).map(|f| f.approx_entries).sum();
        assert!((total as usize) < MAX_TOTAL_ENTRIES, "the recommended set must fit");
    }

    #[test]
    fn only_catalogue_ids_are_accepted() {
        let mut d: Dns =
            toml::from_str("upstreams = [\"192.0.2.53:53\"]\nfeeds = [\"urlhaus\"]").unwrap();
        assert!(validate(&d).is_empty());
        assert_eq!(list_files(&d), ["/var/lib/rp-dns-feeds/urlhaus.txt"]);
        d.feeds = vec!["https://evil.example/list".into(), "urlhaus".into(), "urlhaus".into()];
        let e = validate(&d).join("\n");
        assert!(e.contains("not a known feed") && e.contains("listed twice"), "{e}");
        assert_eq!(list_files(&d).len(), 2, "unknown ids are never turned into paths");
    }
}
