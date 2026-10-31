//! Executing external commands, with a recording implementation for tests
//! and dry runs.

use std::cell::RefCell;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

pub trait Runner {
    fn run(&self, argv: &[String]) -> std::io::Result<Output>;
}

/// Runs commands for real, without a shell.
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<Output> {
        let (prog, args) = argv.split_first().expect("empty argv");
        let out = Command::new(prog).args(args).output()?;
        Ok(Output {
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Records commands instead of running them. Each command succeeds unless its
/// joined argv starts with one of `fail_prefixes`; `responses` supplies canned
/// stdout for commands starting with a given prefix (first match wins).
#[derive(Default)]
pub struct RecordingRunner {
    pub calls: RefCell<Vec<String>>,
    pub fail_prefixes: Vec<String>,
    pub responses: Vec<(String, String)>,
}

impl RecordingRunner {
    pub fn failing(prefixes: &[&str]) -> Self {
        Self { fail_prefixes: prefixes.iter().map(|s| s.to_string()).collect(), ..Self::default() }
    }
    pub fn with_response(mut self, prefix: &str, stdout: &str) -> Self {
        self.responses.push((prefix.to_string(), stdout.to_string()));
        self
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Runner for RecordingRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<Output> {
        let line = argv.join(" ");
        let fail = self.fail_prefixes.iter().any(|p| line.starts_with(p));
        let stdout = self
            .responses
            .iter()
            .find(|(p, _)| line.starts_with(p.as_str()))
            .map(|(_, out)| out.clone())
            .unwrap_or_default();
        self.calls.borrow_mut().push(line);
        Ok(Output {
            status: if fail { 1 } else { 0 },
            stdout,
            stderr: if fail { "simulated failure".into() } else { String::new() },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(String::from).collect()
    }

    #[test]
    fn recording_runner_records_fails_and_responds() {
        let r = RecordingRunner::failing(&["nft -c"]).with_response("id -u", "0\n");
        assert_eq!(r.run(&argv("id -u")).unwrap().stdout, "0\n");
        assert!(!r.run(&argv("nft -c -f x")).unwrap().ok());
        assert!(r.run(&argv("nft -f x")).unwrap().ok());
        assert_eq!(r.calls(), ["id -u", "nft -c -f x", "nft -f x"]);
    }
}
