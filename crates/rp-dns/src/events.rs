//! Security events, written to SQLite by a background thread.
//!
//! The query path never blocks on the database: events go through a bounded
//! channel and are dropped (and counted) if the writer falls behind. Writes
//! are batched in transactions to limit SD-card wear.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use serde_json::json;

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub ts: i64,
    pub client: String,
    pub qname: String,
    pub qtype: String,
    pub action: String,
    pub reason: String,
    pub score: u8,
}

impl Event {
    pub fn json(&self) -> serde_json::Value {
        json!({
            "ts": self.ts, "client": self.client, "qname": self.qname, "qtype": self.qtype,
            "action": self.action, "reason": self.reason, "score": self.score,
        })
    }
}

pub fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Clone)]
pub struct Sink {
    tx: Option<SyncSender<Event>>,
    pub dropped: Arc<AtomicU64>,
}

impl Sink {
    pub fn disabled() -> Self {
        Self { tx: None, dropped: Arc::new(AtomicU64::new(0)) }
    }

    pub fn send(&self, e: Event) {
        if let Some(tx) = &self.tx {
            if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) = tx.try_send(e) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    client TEXT NOT NULL,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    action TEXT NOT NULL,
    reason TEXT NOT NULL,
    score INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);";

pub fn open(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

fn prune(conn: &Connection, retention_days: u32) {
    let cutoff = now_secs() - i64::from(retention_days) * 86_400;
    let _ = conn.execute("DELETE FROM events WHERE ts < ?1", params![cutoff]);
}

/// Start the writer thread. If the database can't be opened, events are
/// discarded and the DNS service keeps running (fail-open).
pub fn start(path: PathBuf, retention_days: u32) -> Sink {
    let (tx, rx) = sync_channel::<Event>(4096);
    let dropped = Arc::new(AtomicU64::new(0));
    match open(&path) {
        Ok(conn) => {
            prune(&conn, retention_days);
            std::thread::spawn(move || writer(conn, rx, retention_days));
            Sink { tx: Some(tx), dropped }
        }
        Err(e) => {
            eprintln!("rp-dns: warning: events disabled, cannot open {}: {e}", path.display());
            Sink { tx: None, dropped }
        }
    }
}

fn writer(mut conn: Connection, rx: Receiver<Event>, retention_days: u32) {
    let mut last_prune = Instant::now();
    let mut batch: Vec<Event> = Vec::with_capacity(256);
    loop {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(e) => {
                batch.push(e);
                while batch.len() < 256 {
                    match rx.try_recv() {
                        Ok(e) => batch.push(e),
                        Err(_) => break,
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        if !batch.is_empty() {
            if let Ok(tx) = conn.transaction() {
                for e in batch.drain(..) {
                    let _ = tx.execute(
                        "INSERT INTO events (ts, client, qname, qtype, action, reason, score)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![e.ts, e.client, e.qname, e.qtype, e.action, e.reason, e.score],
                    );
                }
                let _ = tx.commit();
            }
        }
        if last_prune.elapsed() > Duration::from_secs(3600) {
            prune(&conn, retention_days);
            last_prune = Instant::now();
        }
    }
}

/// Query stored events, newest first.
pub fn query(
    path: &Path,
    since: i64,
    action: Option<&str>,
    limit: u32,
) -> rusqlite::Result<Vec<Event>> {
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt = conn.prepare(
        "SELECT ts, client, qname, qtype, action, reason, score FROM events
         WHERE ts >= ?1 AND (?2 IS NULL OR action = ?2)
         ORDER BY ts DESC, id DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![since, action, limit], |r| {
        Ok(Event {
            ts: r.get(0)?,
            client: r.get(1)?,
            qname: r.get(2)?,
            qtype: r.get(3)?,
            action: r.get(4)?,
            reason: r.get(5)?,
            score: r.get(6)?,
        })
    })?;
    rows.collect()
}

/// Aggregates for a dashboard: totals per action, block rate, top domains.
pub fn stats(path: &Path, since: i64, top: u32) -> rusqlite::Result<serde_json::Value> {
    use serde_json::json;
    let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut by_action = serde_json::Map::new();
    let mut total = 0i64;
    {
        let mut st =
            conn.prepare("SELECT action, COUNT(*) FROM events WHERE ts >= ?1 GROUP BY action")?;
        let rows =
            st.query_map(params![since], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (a, n) = row?;
            total += n;
            by_action.insert(a, json!(n));
        }
    }
    let top_q = |filter: &str| -> rusqlite::Result<Vec<serde_json::Value>> {
        let sql = format!(
            "SELECT qname, COUNT(*) AS n FROM events WHERE ts >= ?1 {filter}
             GROUP BY qname ORDER BY n DESC, qname LIMIT ?2"
        );
        let mut st = conn.prepare(&sql)?;
        let rows = st.query_map(params![since, top], |r| {
            Ok(json!({"domain": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?}))
        })?;
        rows.collect()
    };
    let top_domains = top_q("")?;
    let top_blocked = top_q("AND action = 'blocked'")?;
    let mut clients = Vec::new();
    {
        let mut st = conn.prepare(
            "SELECT client, COUNT(*) AS n, SUM(action = 'blocked') FROM events WHERE ts >= ?1
             GROUP BY client ORDER BY n DESC LIMIT ?2",
        )?;
        let rows = st.query_map(params![since, top], |r| {
            Ok(json!({"client": r.get::<_, String>(0)?, "count": r.get::<_, i64>(1)?,
                      "blocked": r.get::<_, i64>(2)?}))
        })?;
        for r in rows {
            clients.push(r?);
        }
    }
    let blocked = by_action.get("blocked").and_then(|v| v.as_i64()).unwrap_or(0);
    let rate = if total > 0 { blocked as f64 / total as f64 } else { 0.0 };
    Ok(json!({
        "total": total,
        "by_action": by_action,
        "blocked": blocked,
        "block_rate": (rate * 10_000.0).round() / 10_000.0,
        "top_domains": top_domains,
        "top_blocked": top_blocked,
        "top_clients": clients,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_aggregate_by_action_domain_and_client() {
        let dir = std::env::temp_dir().join(format!("rp-dns-stats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.sqlite");
        let conn = open(&db).unwrap();
        let ins = |q: &str, a: &str, c: &str| {
            conn.execute(
                "INSERT INTO events (ts, client, qname, qtype, action, reason, score) VALUES (?1, ?2, ?3, 'A', ?4, '', 0)",
                params![now_secs(), c, q, a],
            )
            .unwrap();
        };
        for _ in 0..3 {
            ins("ads.example", "blocked", "192.0.2.7");
        }
        ins("www.example", "allowed", "192.0.2.7");
        ins("www.example", "allowed", "192.0.2.8");
        ins("x1y2.example", "suspicious", "192.0.2.8");
        let s = stats(&db, 0, 5).unwrap();
        assert_eq!(s["total"], 6);
        assert_eq!(s["blocked"], 3);
        assert_eq!(s["block_rate"], 0.5);
        assert_eq!(s["top_domains"][0]["domain"], "ads.example");
        assert_eq!(s["top_blocked"].as_array().unwrap().len(), 1);
        assert_eq!(s["top_clients"][0]["client"], "192.0.2.7");
        assert_eq!(s["top_clients"][0]["blocked"], 3);
        assert_eq!(stats(&db, now_secs() + 10, 5).unwrap()["total"], 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ev(qname: &str, action: &str) -> Event {
        Event {
            ts: now_secs(),
            client: "192.0.2.7".into(),
            qname: qname.into(),
            qtype: "A".into(),
            action: action.into(),
            reason: "test".into(),
            score: 0,
        }
    }

    #[test]
    fn writes_batches_and_queries_back() {
        let dir = std::env::temp_dir().join(format!("rp-dns-ev-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = dir.join("events.sqlite");
        let sink = start(db.clone(), 7);
        sink.send(ev("ads.example", "blocked"));
        sink.send(ev("x.example", "suspicious"));
        std::thread::sleep(Duration::from_millis(1200));
        let all = query(&db, 0, None, 10).unwrap();
        assert_eq!(all.len(), 2);
        let blocked = query(&db, 0, Some("blocked"), 10).unwrap();
        assert_eq!(blocked[0].qname, "ads.example");
        assert_eq!(sink.dropped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unwritable_db_disables_events_without_panicking() {
        let sink = start(PathBuf::from("/proc/rp-dns-cannot-write/events.sqlite"), 7);
        sink.send(ev("a.example", "blocked"));
        Sink::disabled().send(ev("b.example", "blocked"));
    }
}
