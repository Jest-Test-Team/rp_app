//! Release signing (maintainers / CI) and test releases.
//!
//! * keygen: a minisign key pair; the secret key is encrypted with the
//!   password from an environment variable (never an argument)
//! * sign / verify: SHA256SUMS ↔ SHA256SUMS.minisig
//! * pack: an rp-<target>.tar.gz + SHA256SUMS from local binaries (tests)

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use sha2::{Digest, Sha256};

#[derive(Subcommand)]
pub enum ReleaseCmd {
    /// Create minisign.key (secret, mode 600) and minisign.pub in DIR.
    Keygen {
        #[arg(long)]
        out_dir: PathBuf,
        /// Environment variable with the key password (omit for an unencrypted test key).
        #[arg(long)]
        password_env: Option<String>,
    },
    /// Sign FILE, writing FILE.minisig.
    Sign {
        #[arg(long)]
        secret_key_file: PathBuf,
        #[arg(long)]
        password_env: Option<String>,
        #[arg(long)]
        file: PathBuf,
    },
    /// Verify FILE against FILE.minisig.
    Verify {
        #[arg(long)]
        public_key_file: PathBuf,
        #[arg(long)]
        file: PathBuf,
    },
    /// Pack binaries from BIN_DIR as rp-<target>.tar.gz plus SHA256SUMS in OUT.
    Pack {
        #[arg(long)]
        bin_dir: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        out: PathBuf,
    },
}

const BINS: &[&str] = &["rpctl", "rp-dns", "rp-agent", "rp-mcp", "rp-privd", "rp-api"];

fn password(var: &Option<String>) -> anyhow::Result<Option<String>> {
    match var {
        None => Ok(None),
        Some(v) => Ok(Some(std::env::var(v).map_err(|_| anyhow::anyhow!("{v} is not set"))?)),
    }
}

fn write_private(p: &Path, s: &str) -> anyhow::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(p)?.write_all(s.as_bytes())?;
    Ok(())
}

pub fn run(c: ReleaseCmd) -> anyhow::Result<()> {
    match c {
        ReleaseCmd::Keygen { out_dir, password_env } => {
            std::fs::create_dir_all(&out_dir)?;
            let pw = password(&password_env)?;
            let kp = match pw {
                Some(p) => minisign::KeyPair::generate_encrypted_keypair(Some(p))?,
                None => minisign::KeyPair::generate_unencrypted_keypair()?,
            };
            write_private(
                &out_dir.join("minisign.key"),
                &kp.sk.to_box(Some("rp release signing key"))?.to_string(),
            )?;
            std::fs::write(out_dir.join("minisign.pub"), kp.pk.to_box()?.to_string())?;
            println!("{}", kp.pk.to_base64());
        }
        ReleaseCmd::Sign { secret_key_file, password_env, file } => {
            let boxed =
                minisign::SecretKeyBox::from_string(&std::fs::read_to_string(&secret_key_file)?)?;
            let sk = boxed.into_secret_key(password(&password_env)?)?;
            let data = std::fs::read(&file)?;
            let sig = minisign::sign(None, &sk, data.as_slice(), None, None)?;
            let out = PathBuf::from(format!("{}.minisig", file.display()));
            std::fs::write(&out, sig.to_string())?;
            println!("{}", out.display());
        }
        ReleaseCmd::Verify { public_key_file, file } => {
            let pk = std::fs::read_to_string(&public_key_file)?;
            let sig = std::fs::read_to_string(format!("{}.minisig", file.display()))?;
            rp_core::update::verify_signature(&std::fs::read(&file)?, &sig, &pk)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("signature OK");
        }
        ReleaseCmd::Pack { bin_dir, target, out } => {
            std::fs::create_dir_all(&out)?;
            let name = format!("rp-{target}.tar.gz");
            let f = std::fs::File::create(out.join(&name))?;
            let mut b =
                tar::Builder::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()));
            for bin in BINS {
                let data = std::fs::read(bin_dir.join(bin))?;
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_mode(0o755);
                h.set_cksum();
                b.append_data(&mut h, format!("rp-{target}/bin/{bin}"), data.as_slice())?;
            }
            b.into_inner()?.finish()?;
            let sha = hex::encode(Sha256::digest(std::fs::read(out.join(&name))?));
            std::fs::write(out.join("SHA256SUMS"), format!("{sha}  {name}\n"))?;
            println!("{}", out.join(&name).display());
        }
    }
    Ok(())
}
