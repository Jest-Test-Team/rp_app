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
/// joined argv starts with one of `fail_prefixes`.
#[derive(Default)]
pub struct RecordingRunner {
    pub calls: RefCell<Vec<String>>,
    pub fail_prefixes: Vec<String>,
}

impl RecordingRunner {
    pub fn failing(prefixes: &[&str]) -> Self {
        Self {
            calls: RefCell::default(),
            fail_prefixes: prefixes.iter().map(|s| s.to_string()).collect(),
        }
    }
    pub fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
}

impl Runner for RecordingRunner {
    fn run(&self, argv: &[String]) -> std::io::Result<Output> {
        let line = argv.join(" ");
        let fail = self.fail_prefixes.iter().any(|p| line.starts_with(p));
        self.calls.borrow_mut().push(line);
        Ok(Output {
            status: if fail { 1 } else { 0 },
            stdout: String::new(),
            stderr: if fail { "simulated failure".into() } else { String::new() },
        })
    }
}
