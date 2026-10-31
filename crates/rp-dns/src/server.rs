//! UDP and TCP listeners.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;

use crate::engine::Engine;

const MAX_TCP_CLIENTS: usize = 64;
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Bind a socket; IPv6 sockets are v6-only so `0.0.0.0:53` and `[::]:53` can coexist.
fn socket(addr: SocketAddr, ty: socket2::Type) -> std::io::Result<socket2::Socket> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let s = socket2::Socket::new(domain, ty, None)?;
    if addr.is_ipv6() {
        s.set_only_v6(true)?;
    }
    s.set_reuse_address(true)?;
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s)
}

pub fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    UdpSocket::from_std(socket(addr, socket2::Type::DGRAM)?.into())
}

pub fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let s = socket(addr, socket2::Type::STREAM)?;
    s.listen(128)?;
    TcpListener::from_std(s.into())
}

pub async fn serve_udp(sock: UdpSocket, engine: Arc<Engine>) {
    let sock = Arc::new(sock);
    let mut buf = vec![0u8; 4096];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        let packet = buf[..n].to_vec();
        let (sock, engine) = (sock.clone(), engine.clone());
        tokio::spawn(async move {
            if let Some(resp) = engine.handle(&packet, peer.ip(), false).await {
                let _ = sock.send_to(&resp, peer).await;
            }
        });
    }
}

pub async fn serve_tcp(listener: TcpListener, engine: Arc<Engine>) {
    let limit = Arc::new(Semaphore::new(MAX_TCP_CLIENTS));
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else { continue };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            drop(stream); // too many clients: shed load instead of queueing
            continue;
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            let _permit = permit;
            loop {
                let len = match tokio::time::timeout(TCP_IDLE, stream.read_u16()).await {
                    Ok(Ok(l)) if l > 0 => l as usize,
                    _ => break,
                };
                let mut buf = vec![0u8; len];
                if !matches!(
                    tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut buf)).await,
                    Ok(Ok(_))
                ) {
                    break;
                }
                match engine.handle(&buf, peer.ip(), true).await {
                    Some(resp) => {
                        let ok = stream.write_all(&(resp.len() as u16).to_be_bytes()).await.is_ok()
                            && stream.write_all(&resp).await.is_ok();
                        if !ok {
                            break;
                        }
                    }
                    None => break,
                }
            }
        });
    }
}
