//! What every rpctl module provides.

use rp_schema::Config;

use crate::files::ManagedFile;

/// One external command run during apply or rollback.
///
/// Arguments are passed as an argv vector — never through a shell — so config
/// values can't inject commands. `{staged:/abs/path}` is replaced with the path
/// of the not-yet-installed rendered copy of that managed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub argv: Vec<String>,
    /// Failure is logged but does not abort.
    pub best_effort: bool,
}

impl Step {
    pub fn cmd(argv: &[&str]) -> Self {
        Self { argv: argv.iter().map(|s| s.to_string()).collect(), best_effort: false }
    }
    pub fn best_effort(argv: &[&str]) -> Self {
        Self { best_effort: true, ..Self::cmd(argv) }
    }
    pub fn display(&self) -> String {
        self.argv.join(" ")
    }
}

pub trait Module {
    fn name(&self) -> &'static str;
    /// Files this module owns, fully rendered from config.
    fn render(&self, cfg: &Config) -> Vec<ManagedFile>;
    /// Debian packages required before apply.
    fn packages(&self, _cfg: &Config) -> Vec<&'static str> {
        Vec::new()
    }
    /// Checks run against staged files *before* anything is installed.
    fn validate_steps(&self) -> Vec<Step> {
        Vec::new()
    }
    /// Commands run after the files are installed.
    fn post_apply(&self) -> Vec<Step> {
        Vec::new()
    }
    /// Commands run after files are restored by rollback.
    fn post_rollback(&self) -> Vec<Step> {
        Vec::new()
    }
    /// Arm an automatic rollback timer that `rpctl confirm` must cancel.
    fn arms_dead_man(&self) -> bool {
        false
    }
}

/// All modules known to this build, by name.
pub fn lookup(name: &str) -> Option<Box<dyn Module>> {
    match name {
        "base" => Some(Box::new(crate::base::Base)),
        _ => None,
    }
}

pub const MODULES: &[&str] = &["base"];
