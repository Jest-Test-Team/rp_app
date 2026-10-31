//! DNS test helpers: a query client and a fake upstream resolver.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Address the fake upstream answers with (documentation range).
pub const FAKE_ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);

pub struct Answer {
    pub rcode: String,
    pub answers: Vec<String>,
    pub millis: f64,
}

impl Answer {
    pub fn json(&self) -> String {
        serde_json::json!({"rcode": self.rcode, "answers": self.answers, "ms": self.millis})
            .to_string()
    }
}

pub fn build_query(name: &str, qtype: RecordType, id: u16) -> anyhow::Result<Vec<u8>> {
    let mut m = Message::new();
    m.set_id(id).set_message_type(MessageType::Query).set_recursion_desired(true);
    m.add_query(Query::query(Name::from_str(name)?, qtype));
    Ok(m.to_vec()?)
}

fn decode(resp: &[u8], started: Instant) -> anyhow::Result<Answer> {
    let m = Message::from_vec(resp)?;
    Ok(Answer {
        rcode: format!("{:?}", m.response_code()),
        answers: m.answers().iter().filter_map(|r| r.data().map(|d| d.to_string())).collect(),
        millis: started.elapsed().as_secs_f64() * 1000.0,
    })
}

pub fn query(
    server: SocketAddr,
    name: &str,
    qtype: RecordType,
    tcp: bool,
    timeout: Duration,
) -> anyhow::Result<Answer> {
    let id = (std::process::id() as u16) ^ 0x5a5a;
    let q = build_query(name, qtype, id)?;
    let started = Instant::now();
    if tcp {
        let mut s = TcpStream::connect_timeout(&server, timeout)?;
        s.set_read_timeout(Some(timeout))?;
        s.write_all(&(q.len() as u16).to_be_bytes())?;
        s.write_all(&q)?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len)?;
        let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
        s.read_exact(&mut buf)?;
        decode(&buf, started)
    } else {
        let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let s = UdpSocket::bind(bind)?;
        s.set_read_timeout(Some(timeout))?;
        s.connect(server)?;
        s.send(&q)?;
        let mut buf = vec![0u8; 4096];
        let n = s.recv(&mut buf)?;
        decode(&buf[..n], started)
    }
}

/// Send raw bytes over UDP; returns whether any reply arrived.
pub fn send_raw(server: SocketAddr, bytes: &[u8], timeout: Duration) -> std::io::Result<bool> {
    let s = UdpSocket::bind(if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
    s.set_read_timeout(Some(timeout))?;
    s.connect(server)?;
    s.send(bytes)?;
    let mut buf = [0u8; 4096];
    Ok(s.recv(&mut buf).is_ok())
}

fn answer(req: &[u8]) -> Option<Vec<u8>> {
    let q = Message::from_vec(req).ok()?;
    let mut m = Message::new();
    m.set_id(q.id())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(q.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(ResponseCode::NoError);
    m.add_queries(q.queries().to_vec());
    if let Some(first) = q.queries().first() {
        if first.query_type() == RecordType::A {
            m.add_answer(Record::from_rdata(first.name().clone(), 30, RData::A(A(FAKE_ANSWER))));
        }
    }
    m.to_vec().ok()
}

/// A resolver that answers every A query with FAKE_ANSWER (UDP and TCP), or —
/// with `silent` — swallows queries to simulate a dead upstream.
pub fn fake_upstream(bind: SocketAddr, silent: bool) -> std::io::Result<()> {
    let udp = UdpSocket::bind(bind)?;
    let tcp = TcpListener::bind(udp.local_addr()?)?;
    eprintln!("fake upstream on {}", udp.local_addr()?);
    std::thread::spawn(move || {
        for s in tcp.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let mut len = [0u8; 2];
                if s.read_exact(&mut len).is_err() {
                    return;
                }
                let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
                if s.read_exact(&mut buf).is_err() || silent {
                    return;
                }
                if let Some(r) = answer(&buf) {
                    let _ = s.write_all(&(r.len() as u16).to_be_bytes());
                    let _ = s.write_all(&r);
                }
            });
        }
    });
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = udp.recv_from(&mut buf)?;
        if silent {
            continue;
        }
        if let Some(r) = answer(&buf[..n]) {
            let _ = udp.send_to(&r, peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_upstream_answers_udp_and_tcp() {
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        std::thread::spawn(move || fake_upstream(addr, false));
        std::thread::sleep(Duration::from_millis(200));
        let t = Duration::from_secs(2);
        let a = query(addr, "www.example.", RecordType::A, false, t).unwrap();
        assert_eq!(a.rcode, "NoError");
        assert_eq!(a.answers, ["203.0.113.99"]);
        let b = query(addr, "www.example.", RecordType::A, true, t).unwrap();
        assert_eq!(b.answers, ["203.0.113.99"]);
    }
}
