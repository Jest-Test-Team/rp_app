//! Which 2.4 GHz channel the IoT access point should use.
//!
//! A board in the `sentry` profile logs `sentry: channel load ch1=47f/2ap
//! ...` every minute (frames heard and access points seen per channel, while
//! hopping). Neighbouring 2.4 GHz channels overlap (a 20 MHz signal spans
//! about ±2 channels and still interferes at ±4), so a channel is scored by
//! the load on it *and* on its neighbours, weighted by distance. Lower is
//! better. Busy channels that look quiet on their own (e.g. 3, wedged between
//! 1 and 6) score accordingly.

use std::path::Path;

use serde::Serialize;

use crate::boards::{read_logs, LogEntry};

/// Each access point counts like this many frames (beacons, management).
const AP_WEIGHT: f64 = 10.0;
pub const DEFAULT_CANDIDATES: [u8; 4] = [1, 3, 6, 11];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Load {
    pub channel: u8,
    pub frames: u32,
    pub aps: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Score {
    pub channel: u8,
    pub score: f64,
    pub frames: u32,
    pub aps: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Advice {
    pub measured_at: i64,
    pub port: String,
    pub current: Option<u8>,
    /// Candidates, best first.
    pub candidates: Vec<Score>,
    pub best: u8,
    /// The best candidate is not the current channel and is clearly better
    /// (at least 20% less load), so switching is worth a restart of the AP.
    pub switch_recommended: bool,
}

/// `ch1=47f/2ap` tokens of one summary line.
pub fn parse_summary(text: &str) -> Vec<Load> {
    text.split_whitespace()
        .filter_map(|t| {
            let (ch, rest) = t.strip_prefix("ch")?.split_once('=')?;
            let (f, a) = rest.split_once('/')?;
            Some(Load {
                channel: ch.parse().ok().filter(|c| (1..=14).contains(c))?,
                frames: f.strip_suffix('f')?.parse().ok()?,
                aps: a.strip_suffix("ap")?.parse().ok()?,
            })
        })
        .collect()
}

/// The newest complete summary in the boards' logs, at most `max_age_s` old:
/// (time, port, loads). A summary split over several lines is joined.
pub fn latest(
    root: &Path,
    ports: &[String],
    now: i64,
    max_age_s: i64,
) -> Option<(i64, String, Vec<Load>)> {
    let mut best: Option<(i64, String, Vec<LogEntry>)> = None;
    for p in ports {
        let entries: Vec<LogEntry> = read_logs(root, p, 400, Some("info"))
            .into_iter()
            .filter(|e| e.text.starts_with("sentry: channel load"))
            .collect();
        let Some(first) = entries.first() else { continue };
        if now - first.ts > max_age_s || best.as_ref().is_some_and(|b| b.0 >= first.ts) {
            continue;
        }
        // Newest first: the summary's lines share (about) one timestamp.
        let ts = first.ts;
        let group = entries.into_iter().take_while(|e| ts - e.ts <= 2).collect();
        best = Some((ts, p.clone(), group));
    }
    let (ts, port, lines) = best?;
    let mut loads: Vec<Load> = lines.iter().flat_map(|e| parse_summary(&e.text)).collect();
    loads.sort_by_key(|l| l.channel);
    loads.dedup_by_key(|l| l.channel);
    (!loads.is_empty()).then_some((ts, port, loads))
}

/// Interference on `ch`: its own load plus its neighbours', fading with
/// distance (gone at 5 channels apart).
pub fn score(loads: &[Load], ch: u8) -> f64 {
    loads
        .iter()
        .map(|l| {
            let d = (i16::from(l.channel) - i16::from(ch)).unsigned_abs() as f64;
            let w = (1.0 - d / 5.0).max(0.0);
            w * (f64::from(l.frames) + AP_WEIGHT * f64::from(l.aps))
        })
        .sum()
}

pub fn advise(
    loads: &[Load],
    candidates: &[u8],
    current: Option<u8>,
    measured_at: i64,
    port: &str,
) -> Option<Advice> {
    let mut scored: Vec<Score> = candidates
        .iter()
        .filter(|c| (1..=13).contains(*c))
        .map(|&c| {
            let own = loads.iter().find(|l| l.channel == c);
            Score {
                channel: c,
                score: (score(loads, c) * 10.0).round() / 10.0,
                frames: own.map_or(0, |l| l.frames),
                aps: own.map_or(0, |l| l.aps),
            }
        })
        .collect();
    scored.sort_by(|a, b| a.score.total_cmp(&b.score).then(a.channel.cmp(&b.channel)));
    let best = scored.first()?.channel;
    let cur_score = current.map(|c| score(loads, c));
    let switch_recommended = match (current, cur_score) {
        (Some(c), Some(s)) => c != best && scored[0].score <= s * 0.8,
        _ => true,
    };
    Some(Advice {
        measured_at,
        port: port.into(),
        current,
        candidates: scored,
        best,
        switch_recommended,
    })
}

/// Candidate list from `1,3,6,11` (only channels 1-13).
pub fn parse_candidates(s: &str) -> Option<Vec<u8>> {
    let v: Vec<u8> = s
        .split(',')
        .map(|c| c.trim().parse().ok().filter(|c| (1..=13).contains(c)))
        .collect::<Option<_>>()?;
    (!v.is_empty() && v.len() <= 13).then_some(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the S3 heard on 2026-11-27.
    const MEASURED: &str = "sentry: channel load ch1=65f/2ap ch2=10f/2ap ch3=12f/1ap ch5=59f/2ap \
        ch6=224f/4ap ch7=100f/4ap ch8=96f/2ap ch9=234f/6ap";
    const CONT: &str = "sentry: channel load (cont.) ch10=102f/8ap ch11=156f/6ap ch12=12f/3ap";

    #[test]
    fn parses_summary_lines() {
        let l = parse_summary(MEASURED);
        assert_eq!(l.len(), 8);
        assert_eq!(l[0], Load { channel: 1, frames: 65, aps: 2 });
        assert!(parse_summary("sentry: channel load ch99=1f/1ap chx=2f/1ap ch3=f/1ap").is_empty());
    }

    #[test]
    fn overlap_makes_channel_3_worse_than_channel_1() {
        let mut loads = parse_summary(MEASURED);
        loads.extend(parse_summary(CONT));
        assert!(score(&loads, 3) > score(&loads, 1), "3 sits between busy 1, 5 and 6");
        let a = advise(&loads, &[1, 3], Some(6), 0, "/dev/rp-approver").unwrap();
        assert_eq!(a.best, 1);
        assert!(a.switch_recommended, "6 is far busier");
        let a = advise(&loads, &DEFAULT_CANDIDATES, Some(1), 0, "p").unwrap();
        assert_eq!(a.best, 1);
        assert!(!a.switch_recommended, "already on the best channel");
    }

    #[test]
    fn small_gains_are_not_worth_a_switch() {
        let loads =
            [Load { channel: 1, frames: 100, aps: 0 }, Load { channel: 11, frames: 90, aps: 0 }];
        let a = advise(&loads, &[1, 11], Some(1), 0, "p").unwrap();
        assert_eq!(a.best, 11);
        assert!(!a.switch_recommended, "10% is noise");
    }

    #[test]
    fn candidates_are_validated() {
        assert_eq!(parse_candidates("1, 3,6"), Some(vec![1, 3, 6]));
        assert_eq!(parse_candidates("1,14"), None);
        assert_eq!(parse_candidates(""), None);
    }

    #[test]
    fn latest_joins_a_split_summary_and_ignores_old_ones() {
        let root = std::env::temp_dir().join(format!("rp-channels-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let port = "/dev/rp-approver".to_string();
        let hub = crate::boards::Hub::new(&root, std::slice::from_ref(&port));
        hub.log(&port, "info", "board", MEASURED);
        hub.log(&port, "info", "board", CONT);
        let now = rp_policy::approvals::now();
        let (_, p, loads) = latest(&root, std::slice::from_ref(&port), now, 600).unwrap();
        assert_eq!(p, port);
        assert_eq!(loads.len(), 11, "both lines");
        assert!(latest(&root, &[port], now + 3600, 600).is_none(), "too old");
    }
}
