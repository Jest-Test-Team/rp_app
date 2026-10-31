//! Deterministic suspicion scoring for query names (no ML, no network).
//!
//! Signals, each capped so no single one dominates:
//! * high Shannon entropy in the longest label (DGA / encoded data)
//! * very long labels or names (DNS tunnelling carries data in labels)
//! * many labels (tunnelling chains data across labels)
//! * high digit ratio or hex-looking labels (encoded payloads)
//! * few vowels in a long label (machine-generated names)

#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub value: u8,
    pub reasons: Vec<&'static str>,
}

pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// The registrable-ish part is ignored: the last two labels (e.g. "example.com")
/// rarely carry tunnelled data, so scoring looks at everything left of them.
fn scored_labels(name: &str) -> Vec<&str> {
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() <= 2 {
        labels
    } else {
        labels[..labels.len() - 2].to_vec()
    }
}

fn is_encoded_charset(label: &str) -> bool {
    let hex = label.chars().all(|c| c.is_ascii_hexdigit());
    let b32 = label.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c));
    let b64url = label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    hex || b32 || b64url
}

pub fn score(name: &str) -> Score {
    let mut value: u32 = 0;
    let mut reasons = Vec::new();
    let labels = scored_labels(name);
    let longest = labels.iter().copied().max_by_key(|l| l.len()).unwrap_or("");
    let all_labels = name.split('.').count();

    let h = entropy(longest);
    if longest.len() >= 12 && h >= 3.5 {
        value += if h >= 4.2 { 35 } else { 20 };
        reasons.push("high-entropy-label");
    }
    if longest.len() >= 40 {
        value += 25;
        reasons.push("very-long-label");
    } else if longest.len() >= 25 {
        value += 10;
        reasons.push("long-label");
    }
    if name.len() >= 100 {
        value += 15;
        reasons.push("very-long-name");
    }
    if all_labels >= 7 {
        value += 15;
        reasons.push("many-labels");
    }
    let digits = longest.chars().filter(|c| c.is_ascii_digit()).count();
    if longest.len() >= 10 && digits * 10 >= longest.len() * 3 {
        value += 15;
        reasons.push("digit-heavy");
    }
    if longest.len() >= 16 && longest.chars().all(|c| c.is_ascii_hexdigit()) {
        value += 20;
        reasons.push("hex-label");
    }
    let vowels = longest.chars().filter(|c| "aeiou".contains(*c)).count();
    if longest.len() >= 12 && vowels * 10 < longest.len() {
        value += 15;
        reasons.push("few-vowels");
    }
    // Encoded payloads (hex, base32, base64url) in long labels: DNS tunnelling.
    if longest.len() >= 32 && h >= 4.0 && is_encoded_charset(longest) {
        let mixed = longest.chars().any(|c| c.is_ascii_digit())
            && longest.chars().any(|c| c.is_ascii_alphabetic());
        value += if mixed { 30 } else { 20 };
        reasons.push("encoded-label");
    }
    // DGA: the registered name itself is a long random string ("x7k2...q.com").
    let all: Vec<&str> = name.split('.').collect();
    if all.len() >= 2 {
        let reg = all[all.len() - 2];
        let reg_digits = reg.chars().filter(|c| c.is_ascii_digit()).count();
        let reg_vowels = reg.chars().filter(|c| "aeiou".contains(*c)).count();
        if reg.len() >= 12 && entropy(reg) >= 3.4 && (reg_digits >= 2 || reg_vowels * 5 < reg.len()) {
            value += 40;
            reasons.push("random-registered-name");
        }
    }
    Score { value: value.min(100) as u8, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_names_score_low() {
        for n in [
            "www.example.com",
            "mail.google.com",
            "raspberrypi.local",
            "api.github.com",
            "deb.debian.org",
            "time.cloudflare.com",
            "connectivity-check.ubuntu.com",
        ] {
            let s = score(n);
            assert!(s.value < 40, "{n} scored {s:?}");
        }
    }

    #[test]
    fn tunnelling_and_dga_names_score_high() {
        let tunnel =
            "4a6f686e20446f652073656e7420612073656372657420656e636f646564.data.t.example.com";
        let s = score(tunnel);
        assert!(s.value >= 70, "{s:?}");
        assert!(s.reasons.contains(&"hex-label"));

        let dga = "xj4k9qzv7wp2mbt8.example.net";
        assert!(score(dga).value >= 40, "{:?}", score(dga));

        let chained = "a1.b2.c3.d4.e5.f6.g7.example.org";
        assert!(score(chained).reasons.contains(&"many-labels"));
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(""), 0.0);
        assert_eq!(entropy("aaaa"), 0.0);
        assert!((entropy("ab") - 1.0).abs() < 1e-9);
    }
}
