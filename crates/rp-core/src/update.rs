//! Signed, all-or-nothing software updates (plan §4.8).
//!
//! 1. Download `SHA256SUMS`, `SHA256SUMS.minisig` and `rp-<target>.tar.gz`.
//! 2. Verify the minisign signature of `SHA256SUMS` with the device's key
//!    (`/etc/rp/minisign.pub`), then the archive's SHA-256. Unsigned releases
//!    are refused.
//! 3. Unpack into `/opt/rp/releases/<tag>/` (paths checked; no shell tar).
//! 4. Smoke-test the new rpctl against the *current* config — the v0.1 lesson:
//!    a daemon that does not understand the live config must never go live.
//! 5. Switch every binary at once (`/usr/local/bin/<bin>` symlinks, renamed
//!    into place), restart the services that were running, and switch back
//!    automatically if any of them does not come up.
//!
//! The first update from a plain-file install adopts the old binaries into
//! `/opt/rp/releases/<old version>/` so it can be rolled back to.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::apply::Target;
use crate::files::under_root;
use crate::module::Step;

pub const RELEASES: &str = "/opt/rp/releases";
pub const BIN_DIR: &str = "/usr/local/bin";
pub const DOWNLOADS: &str = "/var/lib/rp/updates";
pub const STATE: &str = "/var/lib/rp/update.json";
pub const PUBKEY: &str = "/etc/rp/minisign.pub";
pub const DEFAULT_BASE: &str = "https://github.com/Jest-Test-Team/rp_app/releases/download";
pub const BINS: &[&str] = &["rpctl", "rp-dns", "rp-agent", "rp-mcp", "rp-privd", "rp-api"];
pub const SERVICES: &[&str] =
    &["rp-dns.service", "rp-agent.service", "rp-mcp.service", "rp-api.service"];

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("invalid release tag '{0}'")]
    BadTag(String),
    #[error("no update signing key on this device ({PUBKEY})")]
    NoKey,
    #[error("download failed: {0}")]
    Download(String),
    #[error("signature check failed: {0}")]
    Signature(String),
    #[error("checksum mismatch for {0}")]
    Checksum(String),
    #[error("archive rejected: {0}")]
    Archive(String),
    #[error("the new release failed its self-test: {0}")]
    SmokeTest(String),
    #[error("services did not come back ({0}); switched back to {1}")]
    RolledBack(String, String),
    #[error("nothing to roll back to")]
    NoPrevious,
    #[error("io error: {0}")]
    Io(String),
}

impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        UpdateError::Io(e.to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub current: Option<String>,
    pub previous: Option<String>,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub tag: String,
    pub at: i64,
    pub result: String,
}

#[derive(Debug, Clone)]
pub struct Options {
    pub tag: String,
    /// Download base (`https://…/releases/download` or `file:///dir`).
    pub base_url: String,
    /// Rust target triple; detected from `uname -m` when None.
    pub target: Option<String>,
    pub config: PathBuf,
    /// Wait after restarting before checking services.
    pub settle: Duration,
    pub dry_run: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub tag: String,
    pub previous: Option<String>,
    pub restarted: Vec<String>,
    pub steps: Vec<String>,
    pub already_current: bool,
}

pub fn valid_tag(t: &str) -> bool {
    t.len() <= 32
        && t.starts_with('v')
        && t[1..].split('.').count() >= 3
        && t[1..].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
}

pub fn target_for(machine: &str) -> Option<&'static str> {
    match machine.trim() {
        "armv7l" => Some("armv7-unknown-linux-gnueabihf"),
        "aarch64" | "arm64" => Some("aarch64-unknown-linux-gnu"),
        "x86_64" => Some("x86_64-unknown-linux-gnu"),
        _ => None,
    }
}

fn p(t: &Target, path: &str) -> PathBuf {
    under_root(&t.root, path)
}

pub fn load_state(t: &Target) -> State {
    fs::read_to_string(p(t, STATE))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(t: &Target, s: &State) -> Result<(), UpdateError> {
    let path = p(t, STATE);
    if let Some(d) = path.parent() {
        fs::create_dir_all(d)?;
    }
    fs::write(&path, serde_json::to_string_pretty(s).unwrap())?;
    Ok(())
}

fn run(t: &Target, argv: &[String]) -> Result<String, String> {
    match t.runner.run(argv) {
        Ok(o) if o.ok() => Ok(o.stdout),
        Ok(o) => Err(o.stderr.trim().to_string()),
        Err(e) => Err(e.to_string()),
    }
}

fn fetch(t: &Target, url: &str, dest: &Path) -> Result<(), UpdateError> {
    if let Some(local) = url.strip_prefix("file://") {
        fs::copy(local, dest).map_err(|e| UpdateError::Download(format!("{url}: {e}")))?;
        return Ok(());
    }
    if !url.starts_with("https://") {
        return Err(UpdateError::Download(format!("{url}: only https:// or file:// sources")));
    }
    let argv: Vec<String> = ["curl", "-fsSL", "--proto", "=https", "--retry", "3", "-o"]
        .iter()
        .map(|s| s.to_string())
        .chain([dest.display().to_string(), url.to_string()])
        .collect();
    run(t, &argv).map(|_| ()).map_err(|e| UpdateError::Download(format!("{url}: {e}")))
}

/// Verify `SHA256SUMS` against its minisign signature.
pub fn verify_signature(sums: &[u8], sig: &str, pubkey: &str) -> Result<(), UpdateError> {
    let pk = if pubkey.lines().count() > 1 {
        minisign_verify::PublicKey::decode(pubkey)
    } else {
        minisign_verify::PublicKey::from_base64(pubkey.trim())
    }
    .map_err(|e| UpdateError::Signature(format!("bad public key: {e}")))?;
    let s = minisign_verify::Signature::decode(sig)
        .map_err(|e| UpdateError::Signature(format!("bad signature: {e}")))?;
    pk.verify(sums, &s, false).map_err(|e| UpdateError::Signature(e.to_string()))
}

pub fn sha_for(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let (h, f) = (it.next()?, it.next()?);
        (f.trim_start_matches('*') == file && h.len() == 64).then(|| h.to_lowercase())
    })
}

/// Unpack `rp-<target>/bin/*` into `dest/bin`. Anything else, links, and
/// paths escaping the directory are refused.
pub fn unpack(archive: &Path, dest: &Path) -> Result<Vec<String>, UpdateError> {
    let f = fs::File::open(archive)?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(f));
    let bin_dir = dest.join("bin");
    fs::create_dir_all(&bin_dir)?;
    let mut got = vec![];
    for entry in ar.entries().map_err(|e| UpdateError::Archive(e.to_string()))? {
        let mut e = entry.map_err(|e| UpdateError::Archive(e.to_string()))?;
        let path = e.path().map_err(|e| UpdateError::Archive(e.to_string()))?.into_owned();
        let comps: Vec<String> =
            path.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        if comps.iter().any(|c| c == ".." || c.starts_with('/')) {
            return Err(UpdateError::Archive(format!("unsafe path {}", path.display())));
        }
        let kind = e.header().entry_type();
        if kind.is_symlink() || kind.is_hard_link() {
            return Err(UpdateError::Archive(format!(
                "links are not allowed ({})",
                path.display()
            )));
        }
        // rp-<target>/bin/<name>
        if comps.len() == 3 && comps[1] == "bin" && kind.is_file() {
            let name = &comps[2];
            if !BINS.contains(&name.as_str()) {
                return Err(UpdateError::Archive(format!("unexpected binary {name}")));
            }
            let mut data = vec![];
            e.read_to_end(&mut data).map_err(|e| UpdateError::Archive(e.to_string()))?;
            let out = bin_dir.join(name);
            fs::write(&out, data)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&out, fs::Permissions::from_mode(0o755))?;
            }
            got.push(name.clone());
        }
    }
    for b in BINS {
        if !got.iter().any(|g| g == b) {
            return Err(UpdateError::Archive(format!("{b} missing from the archive")));
        }
    }
    Ok(got)
}

fn link_target(tag: &str, bin: &str) -> String {
    format!("{RELEASES}/{tag}/bin/{bin}")
}

/// Point every binary at `tag`, each with an atomic rename.
fn switch(t: &Target, tag: &str) -> Result<(), UpdateError> {
    for b in BINS {
        let link = p(t, &format!("{BIN_DIR}/{b}"));
        if let Some(d) = link.parent() {
            fs::create_dir_all(d)?;
        }
        let tmp = link.with_file_name(format!(".{b}.rp-new"));
        let _ = fs::remove_file(&tmp);
        #[cfg(unix)]
        std::os::unix::fs::symlink(link_target(tag, b), &tmp)?;
        #[cfg(not(unix))]
        fs::write(&tmp, link_target(tag, b))?;
        fs::rename(&tmp, &link)?;
    }
    Ok(())
}

/// Which release is live: from the rpctl symlink, or None for a plain install.
pub fn live_tag(t: &Target) -> Option<String> {
    let l = fs::read_link(p(t, &format!("{BIN_DIR}/rpctl"))).ok()?;
    let s = l.to_string_lossy();
    s.strip_prefix(&format!("{RELEASES}/"))?.split('/').next().map(str::to_string)
}

/// Move plain-file binaries (installed by install.sh) into a release dir.
fn adopt_plain_install(t: &Target, installing: &str) -> Result<Option<String>, UpdateError> {
    let rpctl = p(t, &format!("{BIN_DIR}/rpctl"));
    let meta = match fs::symlink_metadata(&rpctl) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    if meta.file_type().is_symlink() {
        return Ok(live_tag(t));
    }
    let version = run(t, &[rpctl.display().to_string(), "--version".into()])
        .ok()
        .and_then(|o| o.split_whitespace().nth(1).map(|v| format!("v{v}")))
        .filter(|v| valid_tag(v))
        .unwrap_or_else(|| "v0.0.0-adopted".into());
    // Never overwrite the release being installed with the old binaries.
    let version = if version == installing { format!("{version}-previous") } else { version };
    let dir = p(t, &format!("{RELEASES}/{version}/bin"));
    fs::create_dir_all(&dir)?;
    for b in BINS {
        let src = p(t, &format!("{BIN_DIR}/{b}"));
        if src.exists() {
            fs::copy(&src, dir.join(b))?;
        }
    }
    Ok(Some(version))
}

fn active(t: &Target, unit: &str) -> bool {
    run(t, &["systemctl".into(), "is-active".into(), "--quiet".into(), unit.into()]).is_ok()
}

fn restart(t: &Target, units: &[String], rep: &mut Report) {
    for u in units {
        let argv: Vec<String> = vec!["systemctl".into(), "restart".into(), u.clone()];
        rep.steps.push(Step { argv: argv.clone(), best_effort: true }.display());
        let _ = run(t, &argv);
    }
}

pub fn install(t: &Target, o: &Options) -> Result<Report, UpdateError> {
    if !valid_tag(&o.tag) {
        return Err(UpdateError::BadTag(o.tag.clone()));
    }
    let mut rep = Report { tag: o.tag.clone(), ..Report::default() };
    let pubkey = fs::read_to_string(p(t, PUBKEY)).map_err(|_| UpdateError::NoKey)?;
    let target = match &o.target {
        Some(x) => x.clone(),
        None => {
            let m = run(t, &["uname".into(), "-m".into()]).unwrap_or_default();
            target_for(&m)
                .ok_or_else(|| UpdateError::Archive(format!("unsupported machine '{}'", m.trim())))?
                .to_string()
        }
    };
    if live_tag(t).as_deref() == Some(o.tag.as_str()) {
        rep.already_current = true;
        return Ok(rep);
    }
    let dl = p(t, &format!("{DOWNLOADS}/{}", o.tag));
    fs::create_dir_all(&dl)?;
    let base = o.base_url.trim_end_matches('/');
    let archive_name = format!("rp-{target}.tar.gz");
    for f in ["SHA256SUMS", "SHA256SUMS.minisig", archive_name.as_str()] {
        let url = if base.starts_with("file://") {
            format!("{base}/{f}")
        } else {
            format!("{base}/{}/{f}", o.tag)
        };
        rep.steps.push(format!("download {url}"));
        fetch(t, &url, &dl.join(f))?;
    }
    let sums = fs::read(dl.join("SHA256SUMS"))?;
    let sig = fs::read_to_string(dl.join("SHA256SUMS.minisig"))
        .map_err(|_| UpdateError::Signature("no signature".into()))?;
    verify_signature(&sums, &sig, &pubkey)?;
    let want = sha_for(&String::from_utf8_lossy(&sums), &archive_name)
        .ok_or_else(|| UpdateError::Checksum(archive_name.clone()))?;
    let got = hex::encode(Sha256::digest(fs::read(dl.join(&archive_name))?));
    if got != want {
        return Err(UpdateError::Checksum(archive_name));
    }
    rep.steps.push("signature and checksum verified".into());
    if o.dry_run {
        return Ok(rep);
    }

    let rel = p(t, &format!("{RELEASES}/{}", o.tag));
    let _ = fs::remove_dir_all(&rel);
    unpack(&dl.join(&archive_name), &rel)?;

    // Self-test: the new rpctl runs and accepts the live config.
    let new_rpctl = rel.join("bin/rpctl").display().to_string();
    run(t, &[new_rpctl.clone(), "--version".into()]).map_err(UpdateError::SmokeTest)?;
    run(t, &[new_rpctl, "--config".into(), o.config.display().to_string(), "check".into()])
        .map_err(|e| UpdateError::SmokeTest(format!("rejects the current config: {e}")))?;

    let previous = adopt_plain_install(t, &o.tag)?;
    rep.previous = previous.clone();
    let was_active: Vec<String> =
        SERVICES.iter().filter(|u| active(t, u)).map(|u| u.to_string()).collect();
    switch(t, &o.tag)?;
    rep.steps.push(format!("switched {} binaries to {}", BINS.len(), o.tag));
    restart(t, &was_active, &mut rep);
    std::thread::sleep(o.settle);
    let down: Vec<String> = was_active.iter().filter(|u| !active(t, u)).cloned().collect();
    let mut st = load_state(t);
    if !down.is_empty() {
        let back = previous.clone().ok_or(UpdateError::NoPrevious)?;
        switch(t, &back)?;
        restart(t, &was_active, &mut rep);
        st.history.push(HistoryEntry {
            tag: o.tag.clone(),
            at: crate::changeset::now(),
            result: format!("rolled back: {}", down.join(", ")),
        });
        save_state(t, &st)?;
        return Err(UpdateError::RolledBack(down.join(", "), back));
    }
    rep.restarted = was_active;
    st.previous = previous;
    st.current = Some(o.tag.clone());
    st.history.push(HistoryEntry {
        tag: o.tag.clone(),
        at: crate::changeset::now(),
        result: "installed".into(),
    });
    save_state(t, &st)?;
    Ok(rep)
}

/// Switch back to the previous release.
pub fn rollback(t: &Target, settle: Duration) -> Result<Report, UpdateError> {
    let mut st = load_state(t);
    let prev = st.previous.clone().ok_or(UpdateError::NoPrevious)?;
    if !p(t, &format!("{RELEASES}/{prev}/bin/rpctl")).exists() {
        return Err(UpdateError::NoPrevious);
    }
    let mut rep = Report { tag: prev.clone(), previous: st.current.clone(), ..Report::default() };
    let was_active: Vec<String> =
        SERVICES.iter().filter(|u| active(t, u)).map(|u| u.to_string()).collect();
    switch(t, &prev)?;
    restart(t, &was_active, &mut rep);
    std::thread::sleep(settle);
    rep.restarted = was_active;
    st.history.push(HistoryEntry {
        tag: prev.clone(),
        at: crate::changeset::now(),
        result: "rolled back by an admin".into(),
    });
    st.previous = st.current.take();
    st.current = Some(prev);
    save_state(t, &st)?;
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;
    use std::io::Write;

    struct Rel {
        dir: PathBuf,
        pubkey: String,
    }

    fn tarball(dir: &Path, target: &str, bins: &[&str], extra: Option<(&str, &[u8])>) -> PathBuf {
        let path = dir.join(format!("rp-{target}.tar.gz"));
        let f = fs::File::create(&path).unwrap();
        let mut b =
            tar::Builder::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()));
        for name in bins {
            let data = format!("#!/bin/sh\necho {name}\n");
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, format!("rp-{target}/bin/{name}"), data.as_bytes()).unwrap();
        }
        if let Some((p, d)) = extra {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            b.append_data(&mut h, p, d).unwrap();
        }
        b.into_inner().unwrap().finish().unwrap();
        path
    }

    /// A signed release in a temp dir (file:// base).
    fn release(tag: &str, sign: bool, bins: &[&str]) -> Rel {
        let dir =
            std::env::temp_dir().join(format!("rp-rel-{tag}-{}-{}", std::process::id(), sign));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let t = "armv7-unknown-linux-gnueabihf";
        let tb = tarball(&dir, t, bins, None);
        let sha = hex::encode(Sha256::digest(fs::read(&tb).unwrap()));
        let sums = format!("{sha}  rp-{t}.tar.gz\n");
        fs::write(dir.join("SHA256SUMS"), &sums).unwrap();
        let kp = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
        let sig = minisign::sign(Some(&kp.pk), &kp.sk, sums.as_bytes(), None, None).unwrap();
        if sign {
            fs::write(dir.join("SHA256SUMS.minisig"), sig.to_string()).unwrap();
        }
        Rel { dir, pubkey: kp.pk.to_base64() }
    }

    fn device(tag: &str, pubkey: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rp-upd-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let w = |p: &str, c: &str| {
            let f = under_root(&root, p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, c).unwrap();
        };
        w(PUBKEY, pubkey);
        for b in BINS {
            w(&format!("{BIN_DIR}/{b}"), "old binary");
        }
        w("/etc/rp/rp.toml", "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n");
        root
    }

    fn opts(rel: &Rel, root: &Path, tag: &str) -> Options {
        Options {
            tag: tag.into(),
            base_url: format!("file://{}", rel.dir.display()),
            target: Some("armv7-unknown-linux-gnueabihf".into()),
            config: under_root(root, "/etc/rp/rp.toml"),
            settle: Duration::ZERO,
            dry_run: false,
        }
    }

    fn rr() -> RecordingRunner {
        RecordingRunner::default().with_response("/usr/local/bin/rpctl --version", "rpctl 0.1.0\n")
    }

    #[test]
    fn installs_switches_all_binaries_and_adopts_the_old_ones() {
        let rel = release("v0.2.0", true, BINS);
        let root = device("ok", &rel.pubkey);
        let r = RecordingRunner {
            responses: vec![(
                format!("{}/usr/local/bin/rpctl --version", root.display()),
                "rpctl 0.1.0\n".into(),
            )],
            ..RecordingRunner::default()
        };
        let t = Target { root: root.clone(), runner: &r };
        let rep = install(&t, &opts(&rel, &root, "v0.2.0")).unwrap();
        assert_eq!(rep.previous.as_deref(), Some("v0.1.0"));
        for b in BINS {
            let l = fs::read_link(under_root(&root, &format!("{BIN_DIR}/{b}"))).unwrap();
            assert_eq!(l, PathBuf::from(format!("/opt/rp/releases/v0.2.0/bin/{b}")));
            assert!(
                under_root(&root, &format!("/opt/rp/releases/v0.1.0/bin/{b}")).exists(),
                "old {b} adopted"
            );
        }
        assert_eq!(live_tag(&t).as_deref(), Some("v0.2.0"));
        let calls = r.calls();
        assert!(calls.iter().any(|c| c.ends_with("/opt/rp/releases/v0.2.0/bin/rpctl --version")));
        assert!(
            calls.iter().any(|c| c.contains("v0.2.0/bin/rpctl --config") && c.ends_with(" check")),
            "smoke test against the live config"
        );
        assert_eq!(rep.restarted.len(), SERVICES.len(), "every running service restarted");
        let st = load_state(&t);
        assert_eq!(
            (st.current.as_deref(), st.previous.as_deref()),
            (Some("v0.2.0"), Some("v0.1.0"))
        );
        // Same tag again is a no-op.
        assert!(install(&t, &opts(&rel, &root, "v0.2.0")).unwrap().already_current);
        let _ = rr();
    }

    #[test]
    fn unsigned_or_tampered_releases_are_refused() {
        let rel = release("v0.2.1", false, BINS);
        let root = device("unsigned", &rel.pubkey);
        let r = RecordingRunner::default();
        let t = Target { root: root.clone(), runner: &r };
        assert!(matches!(install(&t, &opts(&rel, &root, "v0.2.1")), Err(UpdateError::Download(_))));

        let rel = release("v0.2.2", true, BINS);
        let root = device("wrongkey", &release("v0.2.3", true, BINS).pubkey);
        let t = Target { root: root.clone(), runner: &r };
        assert!(matches!(
            install(&t, &opts(&rel, &root, "v0.2.2")),
            Err(UpdateError::Signature(_))
        ));

        let rel = release("v0.2.4", true, BINS);
        let root = device("tampered", &rel.pubkey);
        let t = Target { root: root.clone(), runner: &r };
        let f = fs::OpenOptions::new()
            .append(true)
            .open(rel.dir.join("rp-armv7-unknown-linux-gnueabihf.tar.gz"))
            .unwrap();
        writeln!(&f, "trailing garbage").unwrap();
        assert!(matches!(install(&t, &opts(&rel, &root, "v0.2.4")), Err(UpdateError::Checksum(_))));
        assert!(
            fs::read_link(under_root(&root, "/usr/local/bin/rpctl")).is_err(),
            "nothing switched"
        );

        let root = device("nokey", "");
        fs::remove_file(under_root(&root, PUBKEY)).unwrap();
        let t = Target { root: root.clone(), runner: &r };
        assert!(matches!(install(&t, &opts(&rel, &root, "v0.2.4")), Err(UpdateError::NoKey)));
        assert!(matches!(
            install(&t, &opts(&rel, &root, "main; reboot")),
            Err(UpdateError::BadTag(_))
        ));
    }

    #[test]
    fn a_release_that_rejects_the_config_never_goes_live() {
        let rel = release("v0.3.0", true, BINS);
        let root = device("smoke", &rel.pubkey);
        let fail = format!("{}/opt/rp/releases/v0.3.0/bin/rpctl --config", root.display());
        let r = RecordingRunner::failing(&[&fail]);
        let t = Target { root: root.clone(), runner: &r };
        let e = install(&t, &opts(&rel, &root, "v0.3.0")).unwrap_err();
        assert!(matches!(e, UpdateError::SmokeTest(_)), "{e}");
        assert_eq!(
            fs::read_to_string(under_root(&root, "/usr/local/bin/rpctl")).unwrap(),
            "old binary"
        );
    }

    #[test]
    fn services_that_do_not_come_back_trigger_an_automatic_switch_back() {
        let rel = release("v0.4.0", true, BINS);
        let root = device("down", &rel.pubkey);
        // First install v0.4.0 cleanly, then a v0.5.0 whose rp-api never starts.
        let ok = RecordingRunner::default();
        let t = Target { root: root.clone(), runner: &ok };
        install(&t, &opts(&rel, &root, "v0.4.0")).unwrap();
        struct Flaky(std::cell::Cell<u32>);
        impl crate::runner::Runner for Flaky {
            fn run(&self, argv: &[String]) -> std::io::Result<crate::runner::Output> {
                let line = argv.join(" ");
                let fail = if line == "systemctl is-active --quiet rp-api.service" {
                    let n = self.0.get();
                    self.0.set(n + 1);
                    n == 1 // active before the switch, down after it
                } else {
                    false
                };
                Ok(crate::runner::Output {
                    status: i32::from(fail),
                    stdout: String::new(),
                    stderr: String::new(),
                })
            }
        }
        let rel5 = release("v0.5.0", true, BINS);
        fs::write(under_root(&root, PUBKEY), &rel5.pubkey).unwrap();
        let flaky = Flaky(std::cell::Cell::new(0));
        let t = Target { root: root.clone(), runner: &flaky };
        let e = install(&t, &opts(&rel5, &root, "v0.5.0")).unwrap_err();
        assert!(
            matches!(&e, UpdateError::RolledBack(u, back) if u == "rp-api.service" && back == "v0.4.0"),
            "{e}"
        );
        assert_eq!(live_tag(&t).as_deref(), Some("v0.4.0"));
        assert!(load_state(&t).history.last().unwrap().result.starts_with("rolled back"));
    }

    #[test]
    fn manual_rollback_returns_to_the_previous_release() {
        let rel = release("v0.6.0", true, BINS);
        let root = device("manual", &rel.pubkey);
        let r = RecordingRunner {
            responses: vec![(
                format!("{}/usr/local/bin/rpctl --version", root.display()),
                "rpctl 0.1.0\n".into(),
            )],
            ..RecordingRunner::default()
        };
        let t = Target { root: root.clone(), runner: &r };
        install(&t, &opts(&rel, &root, "v0.6.0")).unwrap();
        let rep = rollback(&t, Duration::ZERO).unwrap();
        assert_eq!(rep.tag, "v0.1.0");
        assert_eq!(live_tag(&t).as_deref(), Some("v0.1.0"));
        assert_eq!(load_state(&t).previous.as_deref(), Some("v0.6.0"));
    }

    #[test]
    fn hostile_archives_are_rejected() {
        let dir = std::env::temp_dir().join(format!("rp-hostile-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let t = "x86_64-unknown-linux-gnu";
        let missing = tarball(&dir, t, &["rpctl"], None);
        assert!(
            matches!(unpack(&missing, &dir.join("out1")), Err(UpdateError::Archive(m)) if m.contains("missing"))
        );
        let extra = tarball(&dir, t, BINS, Some(("rp-x/bin/evil", b"x")));
        assert!(
            matches!(unpack(&extra, &dir.join("out2")), Err(UpdateError::Archive(m)) if m.contains("unexpected"))
        );
        // A link entry.
        let path = dir.join("link.tar.gz");
        {
            let f = fs::File::create(&path).unwrap();
            let mut b =
                tar::Builder::new(flate2::write::GzEncoder::new(f, flate2::Compression::fast()));
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(tar::EntryType::Symlink);
            h.set_size(0);
            h.set_cksum();
            b.append_link(&mut h, "rp-x/bin/rpctl", "/etc/shadow").unwrap();
            b.into_inner().unwrap().finish().unwrap();
        }
        assert!(
            matches!(unpack(&path, &dir.join("out3")), Err(UpdateError::Archive(m)) if m.contains("links"))
        );
    }

    #[test]
    fn reinstalling_the_running_version_keeps_new_and_old_binaries_apart() {
        let rel = release("v0.1.0", true, BINS);
        let root = device("same", &rel.pubkey);
        let r = RecordingRunner {
            responses: vec![(
                format!("{}/usr/local/bin/rpctl --version", root.display()),
                "rpctl 0.1.0\n".into(),
            )],
            ..RecordingRunner::default()
        };
        let t = Target { root: root.clone(), runner: &r };
        let rep = install(&t, &opts(&rel, &root, "v0.1.0")).unwrap();
        assert_eq!(rep.previous.as_deref(), Some("v0.1.0-previous"));
        let new =
            fs::read_to_string(under_root(&root, "/opt/rp/releases/v0.1.0/bin/rpctl")).unwrap();
        assert!(new.contains("echo rpctl"), "the release's binary, not the old one");
        let old =
            fs::read_to_string(under_root(&root, "/opt/rp/releases/v0.1.0-previous/bin/rpctl"))
                .unwrap();
        assert_eq!(old, "old binary");
    }

    #[test]
    fn helpers() {
        assert!(valid_tag("v0.2.0") && valid_tag("v0.2.0-rc.1"));
        assert!(!valid_tag("0.2.0") && !valid_tag("v1") && !valid_tag("v0.2.0;x"));
        assert_eq!(target_for("armv7l\n"), Some("armv7-unknown-linux-gnueabihf"));
        assert_eq!(target_for("armv6l"), None);
        assert_eq!(
            sha_for(&format!("{}  *a.tar.gz\n", "AB".repeat(32)), "a.tar.gz"),
            Some("ab".repeat(32))
        );
        assert_eq!(sha_for("x  a\n", "a"), None);
    }
}
