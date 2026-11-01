//! Console-API test helpers: deterministic test keys, signed envelopes,
//! pairing proofs, and raw requests to rp-privd's socket.

use clap::Subcommand;
use ed25519_dalek::SigningKey;

#[derive(Subcommand)]
pub enum ConsoleCmd {
    /// Base64 public key of the test key with this seed (never use outside tests).
    Pubkey {
        #[arg(long)]
        seed: u8,
    },
    /// Admin id for the test key with this seed.
    AdminId {
        #[arg(long)]
        seed: u8,
    },
    /// Print a signed envelope as JSON.
    Sign {
        #[arg(long)]
        seed: u8,
        #[arg(long)]
        device: String,
        #[arg(long)]
        nonce: String,
        /// Unix time the request expires (default: now + 60).
        #[arg(long)]
        expires_at: Option<i64>,
        #[arg(long)]
        payload: String,
    },
    /// Client pairing proof (hex HMAC).
    PairProof {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        nonce: String,
    },
    /// Expected server pairing proof.
    ServerProof {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        pubkey: String,
        #[arg(long)]
        nonce: String,
        #[arg(long)]
        cert: String,
        #[arg(long)]
        admin: String,
    },
    /// Send one request to rp-privd and print the response JSON.
    Privd {
        #[arg(long)]
        socket: std::path::PathBuf,
        /// Request JSON.
        #[arg(long)]
        request: Option<String>,
        /// Send these raw bytes (hex) instead of a framed request.
        #[arg(long)]
        raw_hex: Option<String>,
    },
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn run(c: ConsoleCmd) -> anyhow::Result<()> {
    use rp_policy::{admin, pairing};
    match c {
        ConsoleCmd::Pubkey { seed } => println!("{}", admin::public_key_b64(&key(seed))),
        ConsoleCmd::AdminId { seed } => {
            println!("{}", admin::admin_id(&admin::public_key_b64(&key(seed))))
        }
        ConsoleCmd::Sign { seed, device, nonce, expires_at, payload } => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
                as i64;
            let s =
                admin::sign(&key(seed), &device, &nonce, expires_at.unwrap_or(now + 60), &payload);
            println!("{}", serde_json::to_string(&s)?);
        }
        ConsoleCmd::PairProof { secret, device, pubkey, nonce } => {
            let s = hex::decode(secret)?;
            println!(
                "{}",
                pairing::hmac_hex(&s, &pairing::client_message(&device, &pubkey, &nonce))
            );
        }
        ConsoleCmd::ServerProof { secret, device, pubkey, nonce, cert, admin } => {
            let s = hex::decode(secret)?;
            println!(
                "{}",
                pairing::hmac_hex(
                    &s,
                    &pairing::server_message(&device, &pubkey, &nonce, &cert, &admin)
                )
            );
        }
        ConsoleCmd::Privd { socket, request, raw_hex } => {
            use std::io::{Read, Write};
            let mut s = std::os::unix::net::UnixStream::connect(&socket)?;
            s.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
            match (request, raw_hex) {
                (_, Some(h)) => {
                    s.write_all(&hex::decode(h)?)?;
                    s.shutdown(std::net::Shutdown::Write)?;
                }
                (Some(r), None) => {
                    let v: serde_json::Value = serde_json::from_str(&r)?;
                    rp_privd::write_frame(&mut s, &v)?;
                }
                (None, None) => anyhow::bail!("give --request or --raw-hex"),
            }
            let mut out = Vec::new();
            s.read_to_end(&mut out)?;
            if out.len() < 4 {
                println!("{{\"closed\": true}}");
            } else {
                println!("{}", String::from_utf8_lossy(&out[4..]));
            }
        }
    }
    Ok(())
}
