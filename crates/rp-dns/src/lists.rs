//! Domain sets with suffix matching (a listed domain covers its subdomains).

use std::collections::HashSet;

/// Lowercase, strip one trailing dot. Returns None for names that can't be a
/// valid DNS name (empty labels, bad characters, too long).
pub fn normalize(name: &str) -> Option<String> {
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let n = n.strip_prefix("*.").unwrap_or(&n).to_string();
    if n.is_empty() || n.len() > 253 {
        return None;
    }
    let ok = n.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    });
    ok.then_some(n)
}

#[derive(Debug, Default, Clone)]
pub struct DomainSet {
    names: HashSet<String>,
}

impl DomainSet {
    pub fn insert(&mut self, name: &str) -> bool {
        match normalize(name) {
            Some(n) => self.names.insert(n),
            None => false,
        }
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The listed entry covering `name` (itself or a parent domain), if any.
    pub fn matches<'a>(&'a self, name: &str) -> Option<&'a str> {
        let mut rest = name;
        loop {
            if let Some(hit) = self.names.get(rest) {
                return Some(hit.as_str());
            }
            match rest.split_once('.') {
                Some((_, parent)) => rest = parent,
                None => return None,
            }
        }
    }

    /// Parse hosts-file or plain list text. Returns (entries added, lines ignored).
    pub fn load_text(&mut self, text: &str) -> (usize, usize) {
        let (mut added, mut ignored) = (0, 0);
        for raw in text.lines() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let first = fields.next().unwrap_or("");
            // hosts format: "0.0.0.0 domain" / "127.0.0.1 domain"
            let domain = if first.parse::<std::net::IpAddr>().is_ok() {
                fields.next().unwrap_or("")
            } else if fields.next().is_some() {
                // A plain list has exactly one domain per line; anything else is malformed.
                ignored += 1;
                continue;
            } else {
                first
            };
            if matches!(domain, "localhost" | "localhost.localdomain" | "local" | "broadcasthost") {
                ignored += 1;
                continue;
            }
            if self.insert(domain) {
                added += 1;
            } else {
                ignored += 1;
            }
        }
        (added, ignored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_rejects_garbage() {
        assert_eq!(normalize("Ads.Example.COM.").as_deref(), Some("ads.example.com"));
        assert_eq!(normalize("*.tracker.example").as_deref(), Some("tracker.example"));
        assert!(normalize("").is_none());
        assert!(normalize("a..b").is_none());
        assert!(normalize("bad name.example").is_none());
        assert!(normalize(&"a".repeat(64)).is_none());
    }

    #[test]
    fn suffix_matching_covers_subdomains_only() {
        let mut s = DomainSet::default();
        s.insert("example.com");
        assert_eq!(s.matches("example.com"), Some("example.com"));
        assert_eq!(s.matches("a.b.example.com"), Some("example.com"));
        assert_eq!(s.matches("notexample.com"), None);
        assert_eq!(s.matches("com"), None);
    }

    #[test]
    fn parses_hosts_and_plain_lists() {
        let mut s = DomainSet::default();
        let (added, ignored) = s.load_text(
            "# comment\n0.0.0.0 ads.example\n127.0.0.1 localhost\ntracker.example # inline\n\n:: v6.example\nnot a domain!\n",
        );
        assert_eq!(added, 3);
        assert_eq!(ignored, 2);
        assert!(s.matches("x.ads.example").is_some());
        assert!(s.matches("v6.example").is_some());
    }
}
