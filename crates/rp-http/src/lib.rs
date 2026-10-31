//! A deliberately tiny HTTP/1.1 implementation for JSON APIs on a trusted
//! network: one request per connection, Content-Length bodies only, strict
//! size and time limits. Small attack surface, no framework.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub const MAX_HEADER_BYTES: usize = 16 * 1024;
pub const MAX_BODY_BYTES: usize = 256 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 32;

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub peer: Option<SocketAddr>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// `Authorization: Bearer <token>` value.
    pub fn bearer(&self) -> Option<&str> {
        self.header("authorization")?.strip_prefix("Bearer ").map(str::trim)
    }

    pub fn query_param(&self, key: &str) -> Option<String> {
        self.query.split('&').find_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (k == key).then(|| percent_decode(v))
        })
    }

    pub fn json(&self) -> Result<serde_json::Value, String> {
        serde_json::from_slice(&self.body).map_err(|e| format!("invalid JSON body: {e}"))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: &'static str,
}

impl Response {
    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(v).unwrap_or_default(),
            content_type: "application/json",
        }
    }
    pub fn error(status: u16, msg: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": msg }))
    }
    pub fn empty(status: u16) -> Self {
        Self { status, body: Vec::new(), content_type: "application/json" }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_request(stream: &mut TcpStream, peer: Option<SocketAddr>) -> Result<Request, u16> {
    let mut reader = BufReader::new(stream);
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = reader.read_until(b'\n', &mut line).await.map_err(|_| 400u16)?;
        if n == 0 {
            return Err(400);
        }
        head.extend_from_slice(&line);
        if head.len() > MAX_HEADER_BYTES {
            return Err(413);
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
    }
    let text = String::from_utf8(head).map_err(|_| 400u16)?;
    let mut lines = text.lines();
    let start = lines.next().ok_or(400u16)?;
    let mut parts = start.split_whitespace();
    let method = parts.next().ok_or(400u16)?.to_string();
    let target = parts.next().ok_or(400u16)?.to_string();
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(400);
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').ok_or(400u16)?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    if headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding")) {
        return Err(400); // chunked bodies are not supported (and a smuggling vector)
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.parse().map_err(|_| 400u16))
        .transpose()?
        .unwrap_or(0);
    if len > MAX_BODY_BYTES {
        return Err(413);
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await.map_err(|_| 400u16)?;
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    Ok(Request { method, path, query, headers, body, peer })
}

async fn write_response(stream: &mut TcpStream, r: &Response) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        r.status,
        reason(r.status),
        r.content_type,
        r.body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&r.body).await?;
    stream.shutdown().await
}

/// Serve `handler` on `listener` until the task is dropped.
pub async fn serve<F, Fut>(listener: TcpListener, handler: F)
where
    F: Fn(Request) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Response> + Send + 'static,
{
    let handler = Arc::new(handler);
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let Ok((mut stream, peer)) = listener.accept().await else { continue };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            let _ = write_response(&mut stream, &Response::error(503, "busy")).await;
            continue;
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let resp = match tokio::time::timeout(IO_TIMEOUT, read_request(&mut stream, Some(peer)))
                .await
            {
                Ok(Ok(req)) => handler(req).await,
                Ok(Err(code)) => Response::error(code, reason(code)),
                Err(_) => Response::error(400, "timeout"),
            };
            let _ = tokio::time::timeout(IO_TIMEOUT, write_response(&mut stream, &resp)).await;
        });
    }
}

/// Minimal client: one request, `Connection: close`.
pub async fn request(
    addr: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Option<&serde_json::Value>,
) -> Result<(u16, serde_json::Value), String> {
    request_with_headers(addr, method, path, bearer, &[], body).await
}

/// Like [`request`] with extra headers (names/values must not contain CR/LF).
pub async fn request_with_headers(
    addr: &str,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    extra: &[(&str, &str)],
    body: Option<&serde_json::Value>,
) -> Result<(u16, serde_json::Value), String> {
    for (k, v) in extra {
        if k.contains(['\r', '\n', ':']) || v.contains(['\r', '\n']) {
            return Err("header injection attempt".into());
        }
    }
    if path.contains(['\r', '\n', ' ']) {
        return Err("invalid request path".into());
    }
    let fut = async {
        let mut s = TcpStream::connect(addr).await.map_err(|e| format!("connect {addr}: {e}"))?;
        let payload = body.map(|b| serde_json::to_vec(b).unwrap()).unwrap_or_default();
        let mut head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
            payload.len()
        );
        if body.is_some() {
            head.push_str("Content-Type: application/json\r\n");
        }
        if let Some(t) = bearer {
            head.push_str(&format!("Authorization: Bearer {t}\r\n"));
        }
        for (k, v) in extra {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        head.push_str("\r\n");
        s.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
        s.write_all(&payload).await.map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        s.take((MAX_BODY_BYTES * 4) as u64)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&buf);
        let (head, body) = text.split_once("\r\n\r\n").ok_or("malformed response")?;
        let status: u16 = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or("malformed status line")?;
        let v = if body.trim().is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(body).map_err(|e| format!("bad JSON from {addr}: {e}"))?
        };
        Ok((status, v))
    };
    tokio::time::timeout(Duration::from_secs(15), fut)
        .await
        .map_err(|_| format!("{addr}: timeout"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[tokio::test]
    async fn round_trip_auth_and_limits() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(serve(listener, |req: Request| async move {
            if req.bearer() != Some("t0ken") {
                return Response::error(401, "unauthorized");
            }
            let v = req.json().unwrap_or_default();
            Response::json(
                200,
                &serde_json::json!({"path": req.path, "q": req.query_param("x"), "echo": v}),
            )
        }));
        let (s, v) =
            request(&addr, "POST", "/a?x=1%202", Some("t0ken"), Some(&serde_json::json!({"k": 1})))
                .await
                .unwrap();
        assert_eq!(s, 200);
        assert_eq!(v["q"], "1 2");
        assert_eq!(v["echo"]["k"], 1);
        let (s, _) = request(&addr, "GET", "/", Some("wrong"), None).await.unwrap();
        assert_eq!(s, 401);

        // Oversized body is refused before it is read.
        let mut raw = TcpStream::connect(&addr).await.unwrap();
        raw.write_all(
            format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY_BYTES + 1).as_bytes(),
        )
        .await
        .unwrap();
        let mut out = String::new();
        raw.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 413"), "{out}");

        // Chunked transfer encoding is rejected.
        let mut raw = TcpStream::connect(&addr).await.unwrap();
        raw.write_all(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
            .await
            .unwrap();
        let mut out = String::new();
        raw.read_to_string(&mut out).await.unwrap();
        assert!(out.starts_with("HTTP/1.1 400"), "{out}");
    }
}
