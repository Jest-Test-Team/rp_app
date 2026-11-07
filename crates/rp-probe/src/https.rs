//! A tiny HTTPS client for tests, with certificate pinning by SHA-256 (the
//! same rule the app applies). Prints {"status", "body", "cert_sha256"}.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct Pin {
    want: Option<String>,
    seen: Mutex<Option<String>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for Pin {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = hex::encode(Sha256::digest(end_entity.as_ref()));
        *self.seen.lock().unwrap() = Some(fp.clone());
        match &self.want {
            Some(w) if !w.eq_ignore_ascii_case(&fp) => {
                Err(rustls::Error::General(format!("certificate pin mismatch: got {fp}")))
            }
            _ => Ok(ServerCertVerified::assertion()),
        }
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn request(
    addr: &str,
    method: &str,
    path: &str,
    pin: Option<String>,
    bearer: Option<String>,
    body: Option<String>,
    headers: &[String],
) -> anyhow::Result<serde_json::Value> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(Pin { want: pin, seen: Mutex::new(None), provider: provider.clone() });
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr).trim_matches(['[', ']']);
    let name = ServerName::try_from(host.to_string()).unwrap_or(ServerName::try_from("localhost")?);
    let mut tls = match connector.connect(name, tcp).await {
        Ok(s) => s,
        Err(e) => {
            return Ok(serde_json::json!({"status": 0, "tls_error": e.to_string(),
                "cert_sha256": verifier.seen.lock().unwrap().clone()}));
        }
    };
    let body = body.unwrap_or_default();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    if let Some(t) = bearer {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    for h in headers {
        req.push_str(h);
        req.push_str("\r\n");
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "DELETE") {
        req.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await?;
    tls.write_all(body.as_bytes()).await?;
    let mut out = Vec::new();
    let _ = tls.read_to_end(&mut out).await;
    let text = String::from_utf8_lossy(&out);
    let (head, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let hdrs: serde_json::Map<String, serde_json::Value> = head
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), serde_json::json!(v.trim())))
        .collect();
    let body_json: serde_json::Value =
        serde_json::from_str(rest).unwrap_or(serde_json::json!(rest));
    Ok(serde_json::json!({"status": status, "headers": hdrs, "body": body_json,
        "cert_sha256": verifier.seen.lock().unwrap().clone()}))
}
