//! The API's TLS identity: a self-signed certificate created on first start.
//! The app pins its SHA-256 fingerprint at pairing (proved by HMAC), so no CA
//! is involved.

use std::path::Path;
use std::sync::Arc;

use sha2::{Digest, Sha256};

pub struct Identity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl Identity {
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(&self.cert_der))
    }
}

/// Load `<dir>/cert.der` + `<dir>/key.der`, or create them.
pub fn load_or_create(dir: &Path, names: &[String]) -> anyhow::Result<Identity> {
    let (cp, kp) = (dir.join("cert.der"), dir.join("key.der"));
    if let (Ok(c), Ok(k)) = (std::fs::read(&cp), std::fs::read(&kp)) {
        return Ok(Identity { cert_der: c, key_der: k });
    }
    let mut params = rcgen::CertificateParams::new(names.to_vec())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "RP Security device");
    params.not_before = rcgen::date_time_ymd(2025, 1, 1);
    params.not_after = rcgen::date_time_ymd(2045, 1, 1);
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key)?;
    let id = Identity { cert_der: cert.der().to_vec(), key_der: key.serialize_der() };
    std::fs::create_dir_all(dir)?;
    rp_policy::admin::write_private(&kp, "")?; // create 0600 first
    std::fs::write(&kp, &id.key_der)?;
    std::fs::write(&cp, &id.cert_der)?;
    Ok(id)
}

pub fn acceptor(id: &Identity) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(id.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(id.key_der.clone())),
        )?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}
