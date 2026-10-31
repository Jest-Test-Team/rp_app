//! Safe apply / rollback of a module's managed files.
//!
//! Order of operations for `apply`:
//! 1. render → diff against the target (no diff = no-op)
//! 2. install missing packages
//! 3. write files to a staging dir and run the module's validation steps
//!    (e.g. `nft -c`) — nothing on the live system has changed yet
//! 4. back up every file about to be replaced, write a manifest
//! 5. install files atomically (tmp + rename, explicit mode)
//! 6. run post-apply steps; any failure restores the backup automatically
//! 7. optionally arm a dead-man timer that rolls back unless confirmed

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rp_schema::Config;
use serde::{Deserialize, Serialize};

use crate::files::{under_root, ManagedFile};
use crate::module::{Module, Step};
use crate::runner::Runner;

pub const STATE_DIR: &str = "/var/lib/rp";

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("io error on {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("command failed: {cmd}\n{stderr}")]
    Command { cmd: String, stderr: String },
    #[error("validation failed: {cmd}\n{stderr}")]
    Validation { cmd: String, stderr: String },
    #[error("post-apply step failed ({cmd}); changes were rolled back\n{stderr}")]
    RolledBack { cmd: String, stderr: String },
    #[error("no backup found for module '{0}'")]
    NoBackup(String),
    #[error("corrupt manifest {path}: {msg}")]
    Manifest { path: String, msg: String },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> ApplyError + '_ {
    move |source| ApplyError::Io { path: path.display().to_string(), source }
}

/// Where and how to apply.
pub struct Target<'a> {
    /// Filesystem root (normally `/`; a temp dir in tests).
    pub root: PathBuf,
    pub runner: &'a dyn Runner,
}

#[derive(Debug, Clone, Default)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub install_packages: bool,
    /// Arm a rollback timer of this many seconds (modules that support it).
    pub dead_man_secs: Option<u32>,
    /// argv prefix used by the dead-man timer to call rpctl back.
    pub rpctl_argv: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    pub existed: bool,
    pub diff: String,
}

#[derive(Debug, Default)]
pub struct Report {
    pub changes: Vec<FileChange>,
    /// Commands run (or, in a dry run, that would run).
    pub steps: Vec<String>,
    pub backup_id: Option<String>,
    pub needs_confirm: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    path: String,
    existed: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    module: String,
    id: String,
    files: Vec<ManifestEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ModuleState {
    pub backup_id: String,
    pub confirmed: bool,
    pub rolled_back: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub modules: BTreeMap<String, ModuleState>,
}

impl Target<'_> {
    fn path(&self, target: &str) -> PathBuf {
        under_root(&self.root, target)
    }
    fn backup_dir(&self, module: &str, id: &str) -> PathBuf {
        self.path(&format!("{STATE_DIR}/backups/{module}/{id}"))
    }
    fn staging_dir(&self, module: &str) -> PathBuf {
        self.path(&format!("{STATE_DIR}/staging/{module}"))
    }
    fn state_path(&self) -> PathBuf {
        self.path(&format!("{STATE_DIR}/state.json"))
    }

    pub fn load_state(&self) -> State {
        fs::read_to_string(self.state_path())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, state: &State) -> Result<(), ApplyError> {
        let p = self.state_path();
        write_atomic(&p, &serde_json::to_string_pretty(state).unwrap(), 0o600)
    }

    fn run(&self, step: &Step, report: &mut Report) -> Result<(), (String, String)> {
        let cmd = step.display();
        report.steps.push(cmd.clone());
        match self.runner.run(&step.argv) {
            Ok(o) if o.ok() => Ok(()),
            Ok(o) if step.best_effort => {
                let _ = o;
                Ok(())
            }
            Ok(o) => Err((cmd, o.stderr)),
            Err(_) if step.best_effort => Ok(()),
            Err(e) => Err((cmd, e.to_string())),
        }
    }
}

fn write_atomic(path: &Path, content: &str, mode: u32) -> Result<(), ApplyError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io(parent))?;
    }
    let tmp = path.with_extension("rp-tmp");
    fs::write(&tmp, content).map_err(io(&tmp))?;
    set_mode(&tmp, mode)?;
    fs::rename(&tmp, path).map_err(io(path))
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ApplyError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io(path))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), ApplyError> {
    Ok(())
}

fn unified_diff(path: &str, old: &str, new: &str) -> String {
    similar::TextDiff::from_lines(old, new)
        .unified_diff()
        .context_radius(2)
        .header(&format!("a{path}"), &format!("b{path}"))
        .to_string()
}

/// Compute what `apply` would change.
pub fn plan(module: &dyn Module, cfg: &Config, t: &Target) -> Vec<FileChange> {
    module
        .render(cfg)
        .into_iter()
        .filter_map(|f| {
            let current = fs::read_to_string(t.path(&f.path)).ok();
            if current.as_deref() == Some(f.content.as_str()) {
                return None;
            }
            Some(FileChange {
                diff: unified_diff(&f.path, current.as_deref().unwrap_or(""), &f.content),
                existed: current.is_some(),
                path: f.path,
            })
        })
        .collect()
}

fn missing_packages(module: &dyn Module, cfg: &Config, t: &Target) -> Vec<&'static str> {
    module
        .packages(cfg)
        .into_iter()
        .filter(|p| {
            let argv: Vec<String> =
                ["dpkg-query", "-W", "-f=${Status}", p].iter().map(|s| s.to_string()).collect();
            !matches!(t.runner.run(&argv), Ok(o) if o.ok() && o.stdout.contains("install ok installed"))
        })
        .collect()
}

fn substitute_staged(step: &Step, staging: &Path) -> Step {
    let argv = step
        .argv
        .iter()
        .map(|a| match a.strip_prefix("{staged:").and_then(|r| r.strip_suffix('}')) {
            Some(p) => under_root(staging, p).display().to_string(),
            None => a.clone(),
        })
        .collect();
    Step { argv, best_effort: step.best_effort }
}

fn new_backup_id() -> String {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!("{}-{:09}", d.as_secs(), d.subsec_nanos())
}

pub fn apply(
    module: &dyn Module,
    cfg: &Config,
    t: &Target,
    opts: &ApplyOptions,
) -> Result<Report, ApplyError> {
    let mut report = Report { changes: plan(module, cfg, t), ..Report::default() };
    if report.changes.is_empty() {
        return Ok(report);
    }
    let files: Vec<ManagedFile> = module.render(cfg);
    let staging = t.staging_dir(module.name());

    let missing = if opts.install_packages { missing_packages(module, cfg, t) } else { vec![] };
    let mut install = vec![];
    if !missing.is_empty() {
        let mut argv = vec![
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            "--no-install-recommends",
        ];
        argv.extend(missing.iter().copied());
        install.push(Step::cmd(&argv));
    }
    let validate: Vec<Step> =
        module.validate_steps().iter().map(|s| substitute_staged(s, &staging)).collect();
    let dead_man = opts
        .dead_man_secs
        .filter(|_| module.arms_dead_man())
        .map(|secs| dead_man_step(module.name(), secs, &opts.rpctl_argv));

    if opts.dry_run {
        let post = module.post_apply();
        let all = install.iter().chain(&validate).chain(&post).chain(&dead_man);
        report.steps = all.map(Step::display).collect();
        report.needs_confirm = dead_man.is_some();
        return Ok(report);
    }

    for s in &install {
        t.run(s, &mut report).map_err(|(cmd, stderr)| ApplyError::Command { cmd, stderr })?;
    }

    // Stage and validate before touching anything live.
    let _ = fs::remove_dir_all(&staging);
    for f in &files {
        write_atomic(&under_root(&staging, &f.path), &f.content, f.mode)?;
    }
    for s in &validate {
        t.run(s, &mut report).map_err(|(cmd, stderr)| ApplyError::Validation { cmd, stderr })?;
    }

    // Back up.
    let id = new_backup_id();
    let bdir = t.backup_dir(module.name(), &id);
    let mut entries = Vec::new();
    for f in &files {
        let live = t.path(&f.path);
        let existed = live.exists();
        if existed {
            let dst = under_root(&bdir.join("files"), &f.path);
            if let Some(p) = dst.parent() {
                fs::create_dir_all(p).map_err(io(p))?;
            }
            fs::copy(&live, &dst).map_err(io(&live))?;
        }
        entries.push(ManifestEntry { path: f.path.clone(), existed });
    }
    let manifest = Manifest { module: module.name().into(), id: id.clone(), files: entries };
    write_atomic(
        &bdir.join("manifest.json"),
        &serde_json::to_string_pretty(&manifest).unwrap(),
        0o600,
    )?;

    // Install.
    for f in &files {
        write_atomic(&t.path(&f.path), &f.content, f.mode)?;
    }
    let _ = fs::remove_dir_all(&staging);

    let mut state = t.load_state();
    state.modules.insert(
        module.name().into(),
        ModuleState { backup_id: id.clone(), confirmed: dead_man.is_none(), rolled_back: false },
    );
    t.save_state(&state)?;

    for s in &module.post_apply() {
        if let Err((cmd, stderr)) = t.run(s, &mut report) {
            let _ = rollback(module, t, Some(&id));
            return Err(ApplyError::RolledBack { cmd, stderr });
        }
    }

    if let Some(s) = &dead_man {
        t.run(s, &mut report).map_err(|(cmd, stderr)| ApplyError::Command { cmd, stderr })?;
        report.needs_confirm = true;
    }
    report.backup_id = Some(id);
    Ok(report)
}

/// The transient systemd timer that rolls back unless `rpctl confirm` runs.
pub fn dead_man_step(module: &str, secs: u32, rpctl_argv: &[String]) -> Step {
    let unit = format!("rp-confirm-{module}");
    let mut argv: Vec<String> = vec![
        "systemd-run".into(),
        format!("--unit={unit}"),
        format!("--on-active={secs}"),
        "--timer-property=AccuracySec=1s".into(),
    ];
    argv.extend(rpctl_argv.iter().cloned());
    argv.extend(["rollback".into(), module.into(), "--auto".into()]);
    Step { argv, best_effort: false }
}

/// Cancel pending dead-man timers and mark modules confirmed.
pub fn confirm(t: &Target) -> Result<Vec<String>, ApplyError> {
    let mut state = t.load_state();
    let mut done = Vec::new();
    let mut report = Report::default();
    for (name, m) in state.modules.iter_mut() {
        if !m.confirmed && !m.rolled_back {
            let unit = format!("rp-confirm-{name}.timer");
            let _ = t.run(&Step::best_effort(&["systemctl", "stop", &unit]), &mut report);
            m.confirmed = true;
            done.push(name.clone());
        }
    }
    t.save_state(&state)?;
    Ok(done)
}

/// Restore the files saved by an apply (latest one when `id` is None).
pub fn rollback(module: &dyn Module, t: &Target, id: Option<&str>) -> Result<Report, ApplyError> {
    let state = t.load_state();
    let id = match id {
        Some(i) => i.to_string(),
        None => state
            .modules
            .get(module.name())
            .map(|m| m.backup_id.clone())
            .ok_or_else(|| ApplyError::NoBackup(module.name().into()))?,
    };
    let bdir = t.backup_dir(module.name(), &id);
    let mpath = bdir.join("manifest.json");
    let text =
        fs::read_to_string(&mpath).map_err(|_| ApplyError::NoBackup(module.name().into()))?;
    let manifest: Manifest = serde_json::from_str(&text).map_err(|e| ApplyError::Manifest {
        path: mpath.display().to_string(),
        msg: e.to_string(),
    })?;

    let mut report = Report { backup_id: Some(id.clone()), ..Report::default() };
    for e in &manifest.files {
        let live = t.path(&e.path);
        if e.existed {
            let src = under_root(&bdir.join("files"), &e.path);
            let content = fs::read_to_string(&src).map_err(io(&src))?;
            let mode = file_mode(&src).unwrap_or(0o644);
            write_atomic(&live, &content, mode)?;
        } else if live.exists() {
            fs::remove_file(&live).map_err(io(&live))?;
        }
        report.changes.push(FileChange {
            path: e.path.clone(),
            existed: e.existed,
            diff: String::new(),
        });
    }
    for s in &module.post_rollback() {
        let _ = t.run(s, &mut report);
    }

    let mut state = t.load_state();
    if let Some(m) = state.modules.get_mut(module.name()) {
        if m.backup_id == id {
            m.rolled_back = true;
        }
    }
    t.save_state(&state)?;
    Ok(report)
}

#[cfg(unix)]
fn file_mode(p: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p).ok().map(|m| m.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_mode(_p: &Path) -> Option<u32> {
    None
}
