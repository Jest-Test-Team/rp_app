//! Minimal TCP throughput measurement (an iperf stand-in with no dependencies).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

pub struct Result {
    pub bytes: u64,
    pub seconds: f64,
}

impl Result {
    pub fn mbps(&self) -> f64 {
        if self.seconds <= 0.0 {
            0.0
        } else {
            self.bytes as f64 * 8.0 / self.seconds / 1_000_000.0
        }
    }
    pub fn json(&self, role: &str) -> String {
        format!(
            "{{\"role\":\"{role}\",\"bytes\":{},\"seconds\":{:.3},\"mbps\":{:.2}}}",
            self.bytes,
            self.seconds,
            self.mbps()
        )
    }
}

/// Accept one connection and count bytes until the peer closes.
pub fn serve_once(bind: SocketAddr) -> std::io::Result<Result> {
    let listener = TcpListener::bind(bind)?;
    let (mut s, _) = listener.accept()?;
    let start = Instant::now();
    let mut buf = vec![0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        match s.read(&mut buf)? {
            0 => break,
            n => bytes += n as u64,
        }
    }
    Ok(Result { bytes, seconds: start.elapsed().as_secs_f64() })
}

/// Send zeros for `secs` seconds.
pub fn send(connect: SocketAddr, secs: f64) -> std::io::Result<Result> {
    let mut s = TcpStream::connect_timeout(&connect, Duration::from_secs(5))?;
    let buf = vec![0u8; 128 * 1024];
    let start = Instant::now();
    let mut bytes = 0u64;
    while start.elapsed().as_secs_f64() < secs {
        s.write_all(&buf)?;
        bytes += buf.len() as u64;
    }
    s.shutdown(std::net::Shutdown::Write)?;
    Ok(Result { bytes, seconds: start.elapsed().as_secs_f64() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_round_trip() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let srv = std::thread::spawn(move || serve_once(addr).unwrap());
        std::thread::sleep(Duration::from_millis(100));
        let c = send(addr, 0.2).unwrap();
        let s = srv.join().unwrap();
        assert_eq!(c.bytes, s.bytes);
        assert!(c.mbps() > 0.0);
        assert!(s.json("server").contains("\"mbps\":"));
    }
}
