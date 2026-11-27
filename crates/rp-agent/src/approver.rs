//! Talking to the hardware approval key over its serial port.
//!
//! The protocol is `rp-wire`; signature checks are `rp_policy::hwkey`. This
//! module opens the port, asks the key about one action and turns the answer
//! into a [`Proof`] (or a refusal). [`KeyLink`] is a trait so tests can put a
//! software key on the other end.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rp_core::files::under_root;
use rp_policy::approvals::Action;
use rp_policy::hwkey::{self, HwKeys};
use rp_schema::{Approver, Config};
use rp_wire::{HostMsg, KeyMsg};

/// How the approval of one action was confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proof {
    /// An enrolled key signed it after a button press.
    Key { id: String, name: String },
    /// A local administrator opened a bypass window (keys lost or broken).
    Bypass { until: i64 },
}

/// What the person did on the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Approved(Proof),
    /// Denied on the key (short press). The request is denied, not left pending.
    DeniedOnKey {
        id: String,
        name: String,
    },
}

pub trait KeyLink {
    fn send(&mut self, line: &str) -> io::Result<()>;
    /// The next line, or `None` once `deadline` passes.
    fn recv(&mut self, deadline: Instant) -> io::Result<Option<String>>;
}

pub type Opener<'a> = &'a dyn Fn(&Approver, &Path) -> io::Result<Box<dyn KeyLink>>;

pub fn keys_path(a: &Approver, root: &Path) -> PathBuf {
    under_root(root, &a.keys_file)
}

pub fn bypass_path(cfg: &Config, root: &Path) -> PathBuf {
    crate::admin_ops::agent_state(cfg, root).join("approver-bypass")
}

/// Wait for the next message the key sends, skipping its log lines.
fn next_msg(link: &mut dyn KeyLink, deadline: Instant) -> Result<Option<String>, String> {
    loop {
        match link.recv(deadline).map_err(|e| format!("approval key: {e}"))? {
            None => return Ok(None),
            Some(l) if KeyMsg::parse(&l).is_some() => return Ok(Some(l)),
            Some(_) => continue,
        }
    }
}

/// Ask the key for its public key (used by `rpctl approver enroll`).
pub fn hello(link: &mut dyn KeyLink, wait: Duration) -> Result<([u8; 32], String), String> {
    link.send(&HostMsg::Hello.to_string()).map_err(|e| format!("approval key: {e}"))?;
    let deadline = Instant::now() + wait;
    while let Some(l) = next_msg(link, deadline)? {
        if let Some(KeyMsg::Key { public_key, version }) = KeyMsg::parse(&l) {
            return Ok((public_key, version.to_string()));
        }
    }
    Err("the approval key did not answer HELLO".into())
}

/// Confirm the approval of `action`: an open bypass window, or a button press
/// on an enrolled key. Errors leave the request pending.
pub fn confirm(
    cfg: &Config,
    a: &Approver,
    root: &Path,
    action: &Action,
    open: Opener<'_>,
) -> Result<Outcome, String> {
    let now = rp_policy::approvals::now();
    if let Some(until) = hwkey::bypass_until(&bypass_path(cfg, root), now) {
        return Ok(Outcome::Approved(Proof::Bypass { until }));
    }
    let keys = HwKeys::load(&keys_path(a, root))?;
    if keys.active().next().is_none() {
        return Err(hwkey::HwError::NoKeys.to_string());
    }
    let id = hwkey::id_bytes(action).ok_or("malformed action id")?;
    let mut nonce = [0u8; rp_wire::NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let ask = HostMsg::Ask { id, digest: hwkey::action_digest(action), nonce };

    let mut link = open(a, root).map_err(|e| {
        format!("approval key not reachable at {}: {e} (or `rpctl approver bypass`)", a.port)
    })?;
    link.send(&ask.to_string()).map_err(|e| format!("approval key: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(a.wait_seconds);
    while let Some(l) = next_msg(link.as_mut(), deadline)? {
        match KeyMsg::parse(&l) {
            Some(KeyMsg::Decide { id: got, approve, signature }) => {
                let k = keys
                    .verify(action, &nonce, &got, approve, &signature)
                    .map_err(|e| e.to_string())?;
                let (key_id, name) = (k.id.clone(), k.name.clone());
                return Ok(if approve {
                    Outcome::Approved(Proof::Key { id: key_id, name })
                } else {
                    Outcome::DeniedOnKey { id: key_id, name }
                });
            }
            Some(KeyMsg::Timeout { id: got }) if got == id => {
                return Err("the approval key gave up waiting for a press; still pending".into());
            }
            Some(KeyMsg::Err(e)) => return Err(format!("approval key: {e}")),
            _ => continue,
        }
    }
    let _ = link.send(&HostMsg::Cancel.to_string());
    Err(format!("nobody pressed the approval key within {}s; still pending", a.wait_seconds))
}

/// The real key: a USB CDC serial port (`/dev/ttyACM*` on the Pi).
pub struct Serial {
    port: std::fs::File,
    buf: Vec<u8>,
}

impl Serial {
    pub fn open(path: &Path) -> io::Result<Self> {
        let port = std::fs::OpenOptions::new().read(true).write(true).open(path)?;
        // Raw mode, no echo, and reads that return after 0.2 s without data,
        // so `recv` can honour its deadline without a reader thread.
        // `-hupcl` keeps DTR up on close, which would otherwise reset the board.
        // stty works on its stdin, our open descriptor: some drivers (macOS)
        // reset the settings when the last descriptor closes.
        let st = std::process::Command::new("stty")
            .args(["raw", "-echo", "-hupcl", "min", "0", "time", "2"])
            .stdin(port.try_clone()?)
            .status()?;
        if !st.success() {
            return Err(io::Error::other(format!("stty failed on {}", path.display())));
        }
        Ok(Self { port, buf: Vec::new() })
    }

    pub fn opener(a: &Approver, root: &Path) -> io::Result<Box<dyn KeyLink>> {
        Ok(Box::new(Self::open(&under_root(root, &a.port))?))
    }
}

impl KeyLink for Serial {
    fn send(&mut self, line: &str) -> io::Result<()> {
        self.port.write_all(format!("{line}\n").as_bytes())?;
        self.port.flush()
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<String>> {
        let mut chunk = [0u8; 256];
        loop {
            if let Some(nl) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=nl).collect();
                return Ok(Some(String::from_utf8_lossy(&line).trim_end().to_string()));
            }
            if self.buf.len() > 4 * rp_wire::MAX_LINE {
                self.buf.clear(); // garbage without newlines (boot ROM output)
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            match self.port.read(&mut chunk) {
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod testkey {
    //! A software key that behaves like the firmware.
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::VecDeque;

    #[derive(Clone, Copy)]
    pub enum Press {
        Approve,
        Deny,
        Nothing,
        /// Sign a different nonce than the one asked (a replayed answer).
        Replay,
    }

    pub struct SoftKey {
        pub sk: SigningKey,
        pub press: Press,
        out: VecDeque<String>,
    }

    impl SoftKey {
        pub fn new(seed: u8, press: Press) -> Self {
            Self { sk: SigningKey::from_bytes(&[seed; 32]), press, out: VecDeque::new() }
        }
    }

    impl KeyLink for SoftKey {
        fn send(&mut self, line: &str) -> io::Result<()> {
            self.out.push_back("I (123) boot: some log line".into());
            match HostMsg::parse(line) {
                Some(HostMsg::Hello) => self.out.push_back(
                    KeyMsg::Key { public_key: self.sk.verifying_key().to_bytes(), version: "test" }
                        .to_string(),
                ),
                Some(HostMsg::Ask { id, digest, mut nonce }) => {
                    let approve = match self.press {
                        Press::Nothing => {
                            self.out.push_back(KeyMsg::Timeout { id }.to_string());
                            return Ok(());
                        }
                        Press::Replay => {
                            nonce[0] ^= 1;
                            true
                        }
                        Press::Approve => true,
                        Press::Deny => false,
                    };
                    let msg = rp_wire::signing_message(&id, &digest, &nonce, approve);
                    let signature = self.sk.sign(&msg).to_bytes();
                    self.out.push_back(KeyMsg::Decide { id, approve, signature }.to_string());
                }
                Some(HostMsg::Cancel) => self.out.push_back(KeyMsg::Ok.to_string()),
                None => self.out.push_back(KeyMsg::Err("bad line").to_string()),
            }
            Ok(())
        }

        fn recv(&mut self, _deadline: Instant) -> io::Result<Option<String>> {
            Ok(self.out.pop_front())
        }
    }
}
