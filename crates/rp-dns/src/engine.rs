//! Query handling: parse, rate-limit, decide, answer locally or forward.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use rp_schema::{BlockResponse, Dns};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::events::{now_secs, Event, Sink};
use crate::lists::{normalize, DomainSet};
use crate::ratelimit::RateLimiter;
use crate::score::{score, Score};

#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Forward { suspicious: Option<Score> },
    Block { reason: String, score: Option<Score> },
}

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub suspicious: AtomicU64,
    pub refused: AtomicU64,
    pub malformed: AtomicU64,
    pub upstream_failures: AtomicU64,
}

pub struct Lists {
    pub allow: DomainSet,
    pub block: DomainSet,
}

impl Lists {
    /// Build from config: inline entries plus list files (missing files are
    /// reported and skipped so a typo can't take DNS down).
    pub fn load(cfg: &Dns) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let mut allow = DomainSet::default();
        for d in &cfg.allow {
            allow.insert(d);
        }
        let mut block = DomainSet::default();
        for d in &cfg.block {
            block.insert(d);
        }
        for f in &cfg.blocklists {
            match std::fs::read_to_string(f) {
                Ok(t) => {
                    block.load_text(&t);
                }
                Err(e) => warnings.push(format!("blocklist {f}: {e}")),
            }
        }
        (Self { allow, block }, warnings)
    }
}

pub struct Engine {
    pub cfg: Dns,
    pub lists: RwLock<Arc<Lists>>,
    limiter: Mutex<RateLimiter>,
    /// Per upstream: skip it until this instant after a failure.
    down_until: Mutex<Vec<Option<Instant>>>,
    pub events: Sink,
    pub stats: Stats,
}

impl Engine {
    pub fn new(cfg: Dns, lists: Lists, events: Sink) -> Self {
        Self {
            limiter: Mutex::new(RateLimiter::new(cfg.rate_limit_qps)),
            down_until: Mutex::new(vec![None; cfg.upstreams.len()]),
            cfg,
            lists: RwLock::new(Arc::new(lists)),
            events,
            stats: Stats::default(),
        }
    }

    pub fn decide(&self, qname: &str) -> Decision {
        let lists = self.lists.read().unwrap().clone();
        if lists.allow.matches(qname).is_some() {
            return Decision::Forward { suspicious: None };
        }
        if let Some(hit) = lists.block.matches(qname) {
            return Decision::Block { reason: format!("blocklist:{hit}"), score: None };
        }
        let s = score(qname);
        if s.value >= self.cfg.suspicious_threshold {
            if self.cfg.block_suspicious {
                return Decision::Block {
                    reason: format!("score:{}", s.reasons.join("+")),
                    score: Some(s),
                };
            }
            return Decision::Forward { suspicious: Some(s) };
        }
        Decision::Forward { suspicious: None }
    }

    fn event(
        &self,
        client: IpAddr,
        qname: &str,
        qtype: RecordType,
        action: &str,
        reason: String,
        s: u8,
    ) {
        self.events.send(Event {
            ts: now_secs(),
            client: client.to_string(),
            qname: qname.to_string(),
            qtype: qtype.to_string(),
            action: action.to_string(),
            reason,
            score: s,
        });
    }

    /// Handle one DNS message. `None` means: send nothing (unparseable input).
    pub async fn handle(&self, packet: &[u8], client: IpAddr, via_tcp: bool) -> Option<Vec<u8>> {
        let req = match Message::from_vec(packet) {
            Ok(m) => m,
            Err(_) => {
                self.stats.malformed.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if req.message_type() != MessageType::Query {
            return None;
        }
        self.stats.queries.fetch_add(1, Ordering::Relaxed);

        if !self.limiter.lock().unwrap().allow(client, Instant::now()) {
            self.stats.refused.fetch_add(1, Ordering::Relaxed);
            return reply(&req, ResponseCode::Refused, None);
        }
        if req.op_code() != OpCode::Query {
            return reply(&req, ResponseCode::NotImp, None);
        }
        if req.queries().len() != 1 {
            return reply(&req, ResponseCode::FormErr, None);
        }
        let q = &req.queries()[0];
        let qtype = q.query_type();
        let qname = normalize(&q.name().to_ascii()).unwrap_or_default();

        match self.decide(&qname) {
            Decision::Block { reason, score } => {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                self.event(
                    client,
                    &qname,
                    qtype,
                    "blocked",
                    reason,
                    score.map(|s| s.value).unwrap_or(0),
                );
                block_reply(&req, self.cfg.block_response)
            }
            Decision::Forward { suspicious } => {
                if let Some(s) = suspicious {
                    self.stats.suspicious.fetch_add(1, Ordering::Relaxed);
                    self.event(client, &qname, qtype, "suspicious", s.reasons.join("+"), s.value);
                }
                match self.forward(packet, req.id(), via_tcp).await {
                    Some(resp) => Some(resp),
                    None => {
                        self.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
                        reply(&req, ResponseCode::ServFail, None)
                    }
                }
            }
        }
    }

    /// Upstream indexes in try order: healthy ones first (config order), then
    /// ones marked down — so a dead resolver costs one timeout per hold-down,
    /// not one per query.
    fn upstream_order(&self) -> Vec<usize> {
        let now = Instant::now();
        let down = self.down_until.lock().unwrap();
        let (mut healthy, mut sick): (Vec<usize>, Vec<usize>) =
            (0..self.cfg.upstreams.len()).partition(|&i| down[i].is_none_or(|t| t <= now));
        healthy.append(&mut sick);
        healthy
    }

    fn mark(&self, i: usize, ok: bool) {
        let mut down = self.down_until.lock().unwrap();
        down[i] = if ok { None } else { Some(Instant::now() + UPSTREAM_HOLD_DOWN) };
    }

    async fn forward(&self, packet: &[u8], id: u16, via_tcp: bool) -> Option<Vec<u8>> {
        let timeout = Duration::from_millis(self.cfg.upstream_timeout_ms);
        for i in self.upstream_order() {
            let up = self.cfg.upstreams[i];
            let r = if via_tcp {
                tokio::time::timeout(timeout, forward_tcp(up, packet)).await
            } else {
                tokio::time::timeout(timeout, forward_udp(up, packet)).await
            };
            match r {
                // Only accept a reply that answers our query.
                Ok(Ok(resp)) if resp.len() >= 2 && u16::from_be_bytes([resp[0], resp[1]]) == id => {
                    self.mark(i, true);
                    return Some(resp);
                }
                _ => self.mark(i, false),
            }
        }
        None
    }
}

const UPSTREAM_HOLD_DOWN: Duration = Duration::from_secs(30);

async fn forward_udp(up: SocketAddr, packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if up.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(up).await?; // connected socket: replies from other sources are ignored
    sock.send(packet).await?;
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

async fn forward_tcp(up: SocketAddr, packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(up).await?;
    s.write_all(&(packet.len() as u16).to_be_bytes()).await?;
    s.write_all(packet).await?;
    let len = s.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    s.read_exact(&mut buf).await?;
    Ok(buf)
}

fn reply(req: &Message, code: ResponseCode, answers: Option<Vec<Record>>) -> Option<Vec<u8>> {
    let mut m = Message::new();
    m.set_id(req.id())
        .set_message_type(MessageType::Response)
        .set_op_code(req.op_code())
        .set_recursion_desired(req.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code);
    m.add_queries(req.queries().to_vec());
    if let Some(a) = answers {
        m.add_answers(a);
    }
    m.to_vec().ok()
}

fn block_reply(req: &Message, how: BlockResponse) -> Option<Vec<u8>> {
    let q = &req.queries()[0];
    match (how, q.query_type()) {
        (BlockResponse::Zero, RecordType::A) => {
            let r = Record::from_rdata(q.name().clone(), 60, RData::A(A(Ipv4Addr::UNSPECIFIED)));
            reply(req, ResponseCode::NoError, Some(vec![r]))
        }
        (BlockResponse::Zero, RecordType::AAAA) => {
            let r =
                Record::from_rdata(q.name().clone(), 60, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
            reply(req, ResponseCode::NoError, Some(vec![r]))
        }
        (BlockResponse::Zero, _) => reply(req, ResponseCode::NoError, Some(vec![])),
        (BlockResponse::Nxdomain, _) => reply(req, ResponseCode::NXDomain, None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    fn cfg(extra: &str) -> Dns {
        let text = format!(
            "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[dns]\nupstreams = [\"127.0.0.1:9\"]\nupstream_timeout_ms = 200\n{extra}"
        );
        rp_core::config::parse(&text).unwrap().dns.unwrap()
    }

    fn engine(extra: &str) -> Engine {
        let c = cfg(extra);
        let (lists, _) = Lists::load(&c);
        Engine::new(c, lists, Sink::disabled())
    }

    fn query(name: &str, t: RecordType) -> Vec<u8> {
        let mut m = Message::new();
        m.set_id(4242).set_message_type(MessageType::Query).set_recursion_desired(true);
        m.add_query(Query::query(Name::from_str(name).unwrap(), t));
        m.to_vec().unwrap()
    }

    fn client() -> IpAddr {
        "192.0.2.7".parse().unwrap()
    }

    #[test]
    fn allow_beats_block_and_scores_flag_tunnels() {
        let e = engine("block = [\"example.com\"]\nallow = [\"good.example.com\"]\n");
        assert!(matches!(e.decide("ads.example.com"), Decision::Block { .. }));
        assert_eq!(e.decide("x.good.example.com"), Decision::Forward { suspicious: None });
        let t = "4a6f686e20446f652073656e7420612073656372657420656e636f646564.t.example.org";
        assert!(matches!(e.decide(t), Decision::Forward { suspicious: Some(_) }));
        let strict = engine("block_suspicious = true\n");
        assert!(matches!(strict.decide(t), Decision::Block { .. }));
    }

    #[tokio::test]
    async fn blocked_names_get_nxdomain_or_zero() {
        let e = engine("block = [\"ads.example\"]\n");
        let r = Message::from_vec(
            &e.handle(&query("ads.example.", RecordType::A), client(), false).await.unwrap(),
        )
        .unwrap();
        assert_eq!(r.response_code(), ResponseCode::NXDomain);
        assert_eq!(r.id(), 4242);
        let z = engine("block = [\"ads.example\"]\nblock_response = \"zero\"\n");
        let r = Message::from_vec(
            &z.handle(&query("x.ads.example.", RecordType::A), client(), false).await.unwrap(),
        )
        .unwrap();
        assert_eq!(r.response_code(), ResponseCode::NoError);
        assert_eq!(r.answers().len(), 1);
    }

    #[tokio::test]
    async fn unreachable_upstream_gives_servfail() {
        let e = engine("");
        let r = Message::from_vec(
            &e.handle(&query("www.example.", RecordType::A), client(), false).await.unwrap(),
        )
        .unwrap();
        assert_eq!(r.response_code(), ResponseCode::ServFail);
        assert_eq!(e.stats.upstream_failures.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn garbage_is_dropped_and_rate_limit_refuses() {
        let e = engine("rate_limit_qps = 1\nblock = [\"ads.example\"]\n");
        assert!(e.handle(b"\x00\x01garbage", client(), false).await.is_none());
        assert_eq!(e.stats.malformed.load(Ordering::Relaxed), 1);
        let q = query("ads.example.", RecordType::A);
        let codes: Vec<ResponseCode> = futures_codes(&e, &q, 4).await;
        assert!(codes.contains(&ResponseCode::Refused), "{codes:?}");
    }

    async fn futures_codes(e: &Engine, q: &[u8], n: usize) -> Vec<ResponseCode> {
        let mut out = vec![];
        for _ in 0..n {
            let r = e.handle(q, client(), false).await.unwrap();
            out.push(Message::from_vec(&r).unwrap().response_code());
        }
        out
    }
}
