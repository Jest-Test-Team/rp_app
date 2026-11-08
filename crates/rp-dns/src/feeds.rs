//! Daily update of the threat-intelligence feeds (rp_core::dns_feeds).
//!
//! Each enabled feed is downloaded to a temporary file, refused if it is too
//! big, HTML (a captive portal or error page) or has no valid domain, then
//! written normalised (one domain per line) and renamed into place. A failed
//! download keeps yesterday's file, so the DNS firewall never loses a list
//! because a server was down. Disabled feeds' files are removed.

use std::collections::BTreeMap;
use std::path::Path;

use rp_core::dns_feeds::{find, MAX_BYTES, MAX_TOTAL_ENTRIES};
use serde_json::{json, Value};

use crate::lists::DomainSet;

/// Downloads `url` into `dest` (https only, size- and time-limited).
pub type Fetch<'a> = &'a dyn Fn(&str, &Path) -> Result<(), String>;

#[derive(Debug, Clone, PartialEq)]
pub struct FeedStatus {
    pub id: String,
    /// Domains in the file now in use (0 if none yet).
    pub entries: usize,
    /// Last successful update (unix time), if any.
    pub updated_at: Option<i64>,
    /// Why the last attempt failed (the previous file, if any, stays in use).
    pub error: Option<String>,
}

impl FeedStatus {
    fn json(&self) -> Value {
        json!({"id": self.id, "entries": self.entries, "updated_at": self.updated_at,
               "error": self.error, "ok": self.error.is_none()})
    }
}

/// The status file as written by [`update`] (empty if never run).
pub fn read_status(dir: &Path) -> Value {
    std::fs::read_to_string(dir.join("status.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| json!({"updated_at": null, "feeds": []}))
}

fn previous(dir: &Path) -> BTreeMap<String, (usize, Option<i64>)> {
    read_status(dir)["feeds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|f| {
            Some((
                f["id"].as_str()?.to_string(),
                (f["entries"].as_u64().unwrap_or(0) as usize, f["updated_at"].as_i64()),
            ))
        })
        .collect()
}

fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
    }
    std::fs::rename(&tmp, path)
}

/// Parse a downloaded feed. Ok(domains) or why it is refused.
pub fn check(text: &str) -> Result<DomainSet, String> {
    let head = text.get(..text.len().min(512)).unwrap_or("").to_ascii_lowercase();
    if head.contains("<html") || head.contains("<!doctype") {
        return Err("the server sent a web page instead of a list".into());
    }
    let mut set = DomainSet::default();
    set.load_text(text);
    if set.is_empty() {
        return Err("the list contains no valid domain".into());
    }
    Ok(set)
}

/// Update `ids` in `dir`. Returns one status per feed (also written to
/// `dir/status.json`) and whether any list file changed (reload rp-dns).
pub fn update(dir: &Path, ids: &[String], fetch: Fetch, now: i64) -> (Vec<FeedStatus>, bool) {
    let _ = std::fs::create_dir_all(dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    }
    let prev = previous(dir);
    let mut changed = false;
    let mut total = 0usize;
    let mut out = vec![];
    for id in ids {
        let (old_entries, old_at) = prev.get(id).cloned().unwrap_or((0, None));
        let file = dir.join(format!("{id}.txt"));
        let has_old = file.exists();
        let keep = |e: String| FeedStatus {
            id: id.clone(),
            entries: if has_old { old_entries } else { 0 },
            updated_at: if has_old { old_at } else { None },
            error: Some(e),
        };
        let Some(feed) = find(id) else {
            out.push(keep("not a known feed".into()));
            continue;
        };
        let dl = dir.join(format!("{id}.download"));
        let res = fetch(feed.url, &dl)
            .and_then(|_| {
                let size = std::fs::metadata(&dl).map_err(|e| e.to_string())?.len();
                if size > MAX_BYTES {
                    return Err(format!("too big ({size} bytes)"));
                }
                std::fs::read_to_string(&dl).map_err(|e| format!("unreadable: {e}"))
            })
            .and_then(|t| check(&t));
        let _ = std::fs::remove_file(&dl);
        match res {
            Ok(set) if total + set.len() > MAX_TOTAL_ENTRIES => {
                let _ = std::fs::remove_file(&file);
                changed |= has_old;
                out.push(FeedStatus {
                    id: id.clone(),
                    entries: 0,
                    updated_at: None,
                    error: Some(format!(
                        "skipped: together with the feeds above it exceeds {MAX_TOTAL_ENTRIES} domains"
                    )),
                });
            }
            Ok(set) => {
                let mut text = format!(
                    "# {} ({}), {} — updated {now} by rpctl dns update-feeds\n",
                    feed.name, feed.license, feed.homepage
                );
                for d in set.sorted() {
                    text.push_str(d);
                    text.push('\n');
                }
                match write_atomic(&file, &text) {
                    Ok(()) => {
                        total += set.len();
                        changed = true;
                        out.push(FeedStatus {
                            id: id.clone(),
                            entries: set.len(),
                            updated_at: Some(now),
                            error: None,
                        });
                    }
                    Err(e) => out.push(keep(format!("cannot write: {e}"))),
                }
            }
            Err(e) => {
                total += if has_old { old_entries } else { 0 };
                out.push(keep(e));
            }
        }
    }
    // Lists no longer enabled stop blocking.
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(id) = name.strip_suffix(".txt") {
                if !ids.iter().any(|i| i == id) {
                    let _ = std::fs::remove_file(e.path());
                    changed = true;
                }
            }
        }
    }
    let status =
        json!({"updated_at": now, "feeds": out.iter().map(FeedStatus::json).collect::<Vec<_>>()});
    let _ = write_atomic(&dir.join("status.json"), &serde_json::to_string_pretty(&status).unwrap());
    (out, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("rp-feeds-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn serve(body: &'static str) -> impl Fn(&str, &Path) -> Result<(), String> {
        move |url: &str, dest: &Path| {
            assert!(url.starts_with("https://"));
            std::fs::write(dest, body).map_err(|e| e.to_string())
        }
    }

    #[test]
    fn a_good_feed_is_normalised_and_counted() {
        let d = dir("good");
        let hosts =
            "# comment\n127.0.0.1 localhost\n0.0.0.0 Ads.Example.com\n0.0.0.0 track.example.net\n";
        let (st, changed) = update(&d, &["stevenblack".into()], &serve(hosts), 1000);
        assert!(changed);
        assert_eq!(st[0].entries, 2);
        assert_eq!(st[0].error, None);
        let text = std::fs::read_to_string(d.join("stevenblack.txt")).unwrap();
        assert!(text.ends_with("ads.example.com\ntrack.example.net\n"), "{text}");
        assert_eq!(read_status(&d)["feeds"][0]["entries"], 2);
    }

    #[test]
    fn a_failed_download_keeps_yesterdays_list() {
        let d = dir("keep");
        update(&d, &["urlhaus".into()], &serve("bad.example\n"), 1000);
        let fail = |_: &str, _: &Path| Err("HTTP 503".to_string());
        let (st, changed) = update(&d, &["urlhaus".into()], &fail, 2000);
        assert!(!changed);
        assert_eq!(st[0].error.as_deref(), Some("HTTP 503"));
        assert_eq!((st[0].entries, st[0].updated_at), (1, Some(1000)));
        assert!(d.join("urlhaus.txt").exists());
    }

    #[test]
    fn web_pages_and_empty_lists_are_refused() {
        let d = dir("html");
        let (st, _) =
            update(&d, &["phishing_army".into()], &serve("<!DOCTYPE html><html>login</html>"), 1);
        assert!(st[0].error.as_deref().unwrap().contains("web page"));
        let (st, _) = update(&d, &["phishing_army".into()], &serve("# nothing\n\n"), 2);
        assert!(st[0].error.as_deref().unwrap().contains("no valid domain"));
        assert!(!d.join("phishing_army.txt").exists());
    }

    #[test]
    fn disabled_feeds_are_removed_and_unknown_ids_never_fetched() {
        let d = dir("rm");
        update(&d, &["urlhaus".into()], &serve("bad.example\n"), 1);
        let never = |u: &str, _: &Path| -> Result<(), String> { panic!("fetched {u}") };
        let (st, changed) = update(&d, &["../../etc/passwd".into()], &never, 2);
        assert!(changed);
        assert!(!d.join("urlhaus.txt").exists());
        assert_eq!(st[0].error.as_deref(), Some("not a known feed"));
    }
}
