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
use rp_wire::{HostMsg, KeyMsg, Profile};

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

/// What a board says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardInfo {
    pub public_key: [u8; 32],
    pub version: String,
    pub chip: String,
    pub profile: Profile,
    pub supported: Vec<Profile>,
}

/// Wait until the board answers `HELLO` and `INFO`. Opening a USB-serial
/// bridge can restart a classic ESP32, so ask again until `wait` runs out.
pub fn handshake(link: &mut dyn KeyLink, wait: Duration) -> Result<BoardInfo, String> {
    let deadline = Instant::now() + wait;
    let mut key: Option<([u8; 32], String)> = None;
    while Instant::now() < deadline {
        let q = if key.is_none() { HostMsg::Hello } else { HostMsg::Info };
        link.send(&q.to_string()).map_err(|e| format!("board: {e}"))?;
        let step = (Instant::now() + Duration::from_millis(600)).min(deadline);
        while let Some(l) = next_msg(link, step)? {
            match KeyMsg::parse(&l) {
                Some(KeyMsg::Key { public_key, version }) => {
                    key = Some((public_key, version.to_string()));
                    break;
                }
                Some(KeyMsg::Info { chip, profile, supported, .. }) if key.is_some() => {
                    let (public_key, version) = key.take().unwrap();
                    return Ok(BoardInfo {
                        public_key,
                        version,
                        chip: chip.to_string(),
                        profile,
                        supported: supported.iter().collect(),
                    });
                }
                _ => continue,
            }
        }
    }
    Err("the board did not answer (is it an rp board, and on this port?)".into())
}

/// Switch a board to another profile. It answers OK and restarts.
pub fn set_profile(link: &mut dyn KeyLink, p: Profile, wait: Duration) -> Result<(), String> {
    let info = handshake(link, wait)?;
    if !info.supported.contains(&p) {
        return Err(format!("{} boards do not support the {} profile", info.chip, p.as_str()));
    }
    link.send(&HostMsg::SetProfile(p).to_string()).map_err(|e| format!("board: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    while let Some(l) = next_msg(link, deadline)? {
        match KeyMsg::parse(&l) {
            Some(KeyMsg::Ok) => return Ok(()),
            Some(KeyMsg::Err(e)) => return Err(format!("board: {e}")),
            _ => continue,
        }
    }
    Err("the board did not confirm the profile change".into())
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
    let info = handshake(link.as_mut(), Duration::from_secs(5))?;
    if info.profile != Profile::Approver {
        return Err(format!(
            "the board at {} runs the {} profile; switch it back to approver",
            a.port,
            info.profile.as_str()
        ));
    }
    let board_id = hwkey::key_id(&info.public_key);
    if !keys.active().any(|k| k.id == board_id) {
        return Err(format!("the board at {} (key {board_id}) is not an enrolled key", a.port));
    }
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
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true);
        // Never become the controlling terminal of a daemon or of rpctl run
        // without one: a modem-line change would then hang up the session.
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut opts, libc::O_NOCTTY);
        let port = opts.open(path)?;
        // Raw mode, no echo, and reads that return after 0.2 s without data,
        // so `recv` can honour its deadline without a reader thread.
        // `-hupcl` keeps DTR up on close, which would otherwise reset the board;
        // `clocal` ignores the modem lines, which these boards do not drive.
        // stty works on its stdin, our open descriptor: some drivers (macOS)
        // reset the settings when the last descriptor closes.
        let st = std::process::Command::new("stty")
            .args(["115200", "raw", "-echo", "-hupcl", "clocal", "min", "0", "time", "2"])
            .stdin(port.try_clone()?)
            .status()?;
        if !st.success() {
            return Err(io::Error::other(format!("stty failed on {}", path.display())));
        }
        release_control_lines(&port);
        Ok(Self { port, buf: Vec::new() })
    }

    /// The main key's port, or the backup key's when the main one is absent;
    /// through rp-boards when it runs.
    pub fn opener(a: &Approver, root: &Path) -> io::Result<Box<dyn KeyLink>> {
        crate::boards::open_port(root, &a.port)
            .or_else(|_| crate::boards::open_port(root, &a.backup_port))
    }
}

/// Drop DTR and RTS together. On classic ESP32 boards these lines drive EN
/// (reset) and GPIO0 (BOOT) through the auto-download circuit; with both low
/// neither is pulled, so the board runs normally. Setting them in one call
/// avoids passing through RTS-only (reset) or DTR-only (BOOT held).
#[cfg(unix)]
fn release_control_lines(port: &std::fs::File) {
    use std::os::fd::AsRawFd;
    let fd = port.as_raw_fd();
    let mut bits: libc::c_int = 0;
    // SAFETY: TIOCMGET/TIOCMSET read/write one c_int through valid pointers.
    unsafe {
        if libc::ioctl(fd, libc::TIOCMGET, &mut bits) == 0 {
            bits &= !(libc::TIOCM_DTR | libc::TIOCM_RTS);
            libc::ioctl(fd, libc::TIOCMSET, &bits);
        }
    }
}

#[cfg(not(unix))]
fn release_control_lines(_: &std::fs::File) {}

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
        pub profile: Profile,
        out: VecDeque<String>,
    }

    impl SoftKey {
        pub fn new(seed: u8, press: Press) -> Self {
            Self {
                sk: SigningKey::from_bytes(&[seed; 32]),
                press,
                profile: Profile::Approver,
                out: VecDeque::new(),
            }
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
                Some(HostMsg::Ask { .. }) if self.profile != Profile::Approver => {
                    self.out.push_back(KeyMsg::Err("not in the approver profile").to_string())
                }
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
                Some(HostMsg::Info) => self.out.push_back(
                    KeyMsg::Info {
                        chip: "soft",
                        profile: self.profile,
                        version: "test",
                        supported: rp_wire::Profiles::empty()
                            .with(Profile::Approver)
                            .with(Profile::Sentry),
                    }
                    .to_string(),
                ),
                Some(HostMsg::SetProfile(p)) => {
                    self.profile = p;
                    self.out.push_back(KeyMsg::Ok.to_string());
                }
                None => self.out.push_back(KeyMsg::Err("bad line").to_string()),
            }
            Ok(())
        }

        fn recv(&mut self, _deadline: Instant) -> io::Result<Option<String>> {
            Ok(self.out.pop_front())
        }
    }
}
