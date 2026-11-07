//! Console-API test helpers: deterministic test keys, signed envelopes,
//! pairing proofs, and raw requests to rp-privd's socket.

use clap::Subcommand;
use ed25519_dalek::SigningKey;

#[derive(Subcommand)]
pub enum ConsoleCmd {
    /// Create a random admin key file (mode 600) for tests against real devices.
    Keygen {
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Base64 public key of a test key (seed, or --key-file).
    Pubkey {
        #[arg(long, default_value_t = 0)]
        seed: u8,
        #[arg(long)]
        key_file: Option<std::path::PathBuf>,
    },
    /// Admin id of a test key.
    AdminId {
        #[arg(long, default_value_t = 0)]
        seed: u8,
        #[arg(long)]
        key_file: Option<std::path::PathBuf>,
    },
    /// Print a signed envelope as JSON.
    Sign {
        /// Deterministic test key (never pair one with a real device).
        #[arg(long, default_value_t = 0)]
        seed: u8,
        #[arg(long)]
        key_file: Option<std::path::PathBuf>,
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

fn key(seed: u8, file: Option<&std::path::Path>) -> anyhow::Result<SigningKey> {
    match file {
        Some(f) => {
            let raw = hex::decode(std::fs::read_to_string(f)?.trim())?;
            let b: [u8; 32] =
                raw.try_into().map_err(|_| anyhow::anyhow!("key file must hold 32 bytes hex"))?;
            Ok(SigningKey::from_bytes(&b))
        }
        None => {
            anyhow::ensure!(seed != 0, "give --seed N (test keys) or --key-file");
            Ok(SigningKey::from_bytes(&[seed; 32]))
        }
    }
}

pub fn run(c: ConsoleCmd) -> anyhow::Result<()> {
    use rp_policy::{admin, pairing};
    match c {
        ConsoleCmd::Keygen { out } => {
            rp_policy::admin::write_private(&out, &rp_policy::pairing::new_secret())?;
            println!("{}", admin::public_key_b64(&key(0, Some(&out))?));
        }
        ConsoleCmd::Pubkey { seed, key_file } => {
            println!("{}", admin::public_key_b64(&key(seed, key_file.as_deref())?))
        }
        ConsoleCmd::AdminId { seed, key_file } => {
            println!(
                "{}",
                admin::admin_id(&admin::public_key_b64(&key(seed, key_file.as_deref())?))
            )
        }
        ConsoleCmd::Sign { seed, key_file, device, nonce, expires_at, payload } => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()
                as i64;
            let k = key(seed, key_file.as_deref())?;
            let s = admin::sign(&k, &device, &nonce, expires_at.unwrap_or(now + 60), &payload);
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
