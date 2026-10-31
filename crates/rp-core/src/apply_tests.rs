//! apply / rollback against a throwaway root with a recording runner.

use std::fs;
use std::path::PathBuf;

use crate::apply::{apply, confirm, rollback, ApplyError, ApplyOptions, Target};
use crate::base::{Base, NFT_PATH, SSHD_PATH};
use crate::config::parse;
use crate::files::under_root;
use crate::runner::RecordingRunner;

fn tmp_root(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("rp-core-test-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).unwrap();
    p
}

fn cfg() -> rp_schema::Config {
    parse("[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n").unwrap()
}

fn opts() -> ApplyOptions {
    ApplyOptions {
        dead_man_secs: Some(120),
        rpctl_argv: vec!["/usr/local/bin/rpctl".into()],
        ..ApplyOptions::default()
    }
}

#[test]
fn dry_run_changes_nothing() {
    let root = tmp_root("dry");
    let r = RecordingRunner::default();
    let t = Target { root: root.clone(), runner: &r };
    let rep = apply(&Base, &cfg(), &t, &ApplyOptions { dry_run: true, ..opts() }).unwrap();
    assert_eq!(rep.changes.len(), 5);
    assert!(rep.needs_confirm);
    assert!(rep.steps.iter().any(|s| s.starts_with("systemd-run --unit=rp-confirm-base")));
    assert!(r.calls().is_empty(), "dry run must not execute anything");
    assert!(!under_root(&root, NFT_PATH).exists());
}

#[test]
fn apply_installs_backs_up_and_is_idempotent() {
    let root = tmp_root("apply");
    let sshd = under_root(&root, SSHD_PATH);
    fs::create_dir_all(sshd.parent().unwrap()).unwrap();
    fs::write(&sshd, "original\n").unwrap();

    let r = RecordingRunner::default();
    let t = Target { root: root.clone(), runner: &r };
    let rep = apply(&Base, &cfg(), &t, &opts()).unwrap();
    assert!(rep.needs_confirm);
    let calls = r.calls();
    let nft_check = calls.iter().position(|c| c.starts_with("nft -c -f")).unwrap();
    let restart = calls.iter().position(|c| c.contains("restart rp-firewall")).unwrap();
    assert!(nft_check < restart, "validation must run before the firewall is loaded");
    assert!(calls[nft_check].contains("/var/lib/rp/staging/base/etc/rp/nftables.nft"));
    assert!(fs::read_to_string(under_root(&root, NFT_PATH)).unwrap().contains("policy drop"));
    assert!(!fs::read_to_string(&sshd).unwrap().contains("original"));

    // Second apply with identical config: no changes, no commands.
    let r2 = RecordingRunner::default();
    let t2 = Target { root: root.clone(), runner: &r2 };
    let rep2 = apply(&Base, &cfg(), &t2, &opts()).unwrap();
    assert!(rep2.changes.is_empty());
    assert!(r2.calls().is_empty());

    // Rollback restores the pre-existing file and removes new ones.
    let rb = rollback(&Base, &t2, None).unwrap();
    let c2 = r2.calls();
    let disable = c2.iter().position(|c| c == "systemctl disable rp-firewall.service").unwrap();
    let reload = c2.iter().position(|c| c == "systemctl daemon-reload").unwrap();
    assert!(disable < reload, "unit must be disabled before its file is removed");
    assert_eq!(rb.changes.len(), 5);
    assert_eq!(fs::read_to_string(&sshd).unwrap(), "original\n");
    assert!(!under_root(&root, NFT_PATH).exists());
    assert!(t2.load_state().modules["base"].rolled_back);
}

#[test]
fn failed_validation_leaves_system_untouched() {
    let root = tmp_root("validate");
    let r = RecordingRunner::failing(&["nft -c"]);
    let t = Target { root: root.clone(), runner: &r };
    let err = apply(&Base, &cfg(), &t, &opts()).unwrap_err();
    assert!(matches!(err, ApplyError::Validation { .. }), "{err}");
    assert!(!under_root(&root, NFT_PATH).exists());
    assert!(!r.calls().iter().any(|c| c.contains("restart")));
}

#[test]
fn failed_post_step_rolls_back_automatically() {
    let root = tmp_root("post");
    let r = RecordingRunner::failing(&["sshd -t"]);
    let t = Target { root: root.clone(), runner: &r };
    let err = apply(&Base, &cfg(), &t, &opts()).unwrap_err();
    assert!(matches!(err, ApplyError::RolledBack { .. }), "{err}");
    assert!(!under_root(&root, NFT_PATH).exists(), "rollback must remove newly created files");
    assert!(!r.calls().iter().any(|c| c.starts_with("systemd-run")), "no dead-man after failure");
}

#[test]
fn confirm_stops_dead_man_timer() {
    let root = tmp_root("confirm");
    let r = RecordingRunner::default();
    let t = Target { root: root.clone(), runner: &r };
    apply(&Base, &cfg(), &t, &opts()).unwrap();
    assert!(!t.load_state().modules["base"].confirmed);
    assert_eq!(confirm(&t).unwrap(), vec!["base".to_string()]);
    assert!(r.calls().iter().any(|c| c == "systemctl stop rp-confirm-base.timer"));
    assert!(t.load_state().modules["base"].confirmed);
    assert!(confirm(&t).unwrap().is_empty());
}

#[test]
fn rollback_without_backup_errors() {
    let root = tmp_root("nobackup");
    let r = RecordingRunner::default();
    let t = Target { root, runner: &r };
    assert!(matches!(rollback(&Base, &t, None), Err(ApplyError::NoBackup(_))));
}

fn vpn_cfg(mode: &str) -> rp_schema::Config {
    parse(&format!(
        "[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n[vpn]\nmode = \"{mode}\"\n"
    ))
    .unwrap()
}

#[test]
fn vpn_requires_base_and_config_section() {
    use crate::vpn::Vpn;
    let root = tmp_root("vpn-req");
    let r = RecordingRunner::default();
    let t = Target { root, runner: &r };
    let err = apply(&Vpn, &vpn_cfg("wireguard"), &t, &opts()).unwrap_err();
    assert!(matches!(err, ApplyError::Requires(..)), "{err}");
    let err = apply(&Vpn, &cfg(), &t, &opts()).unwrap_err();
    assert!(matches!(err, ApplyError::Disabled(..)), "{err}");
}

#[test]
fn vpn_tailscale_installs_repo_before_packages_and_never_installs_check_file() {
    use crate::vpn::{Vpn, CHECK_PATH, TS_LIST_PATH};
    let root = tmp_root("vpn-ts");
    let r = RecordingRunner::default();
    let t = Target { root: root.clone(), runner: &r };
    apply(&Base, &cfg(), &t, &opts()).unwrap();
    let r2 = RecordingRunner::default(); // dpkg-query returns nothing => packages missing
    let t2 = Target { root: root.clone(), runner: &r2 };
    let o = ApplyOptions { install_packages: true, ..opts() };
    apply(&Vpn, &vpn_cfg("tailscale"), &t2, &o).unwrap();
    let calls = r2.calls();
    let key = calls.iter().position(|c| c.starts_with("curl -fsSL --proto =https")).unwrap();
    let update = calls.iter().position(|c| c.ends_with("apt-get update")).unwrap();
    let install = calls
        .iter()
        .position(|c| c.contains("apt-get install") && c.ends_with("tailscale"))
        .unwrap();
    assert!(key < update && update < install);
    assert!(under_root(&root, TS_LIST_PATH).exists());
    assert!(!under_root(&root, CHECK_PATH).exists(), "check-only file must not be installed");
    // Second apply: the check-only file must not count as a pending change.
    let r3 = RecordingRunner::default();
    let t3 = Target { root, runner: &r3 };
    assert!(apply(&Vpn, &vpn_cfg("tailscale"), &t3, &opts()).unwrap().changes.is_empty());
}

#[test]
fn vpn_failure_after_early_files_restores_them() {
    use crate::vpn::{Vpn, TS_LIST_PATH};
    let root = tmp_root("vpn-fail");
    let r = RecordingRunner::default();
    let t = Target { root: root.clone(), runner: &r };
    apply(&Base, &cfg(), &t, &opts()).unwrap();
    let r2 = RecordingRunner::failing(&["env DEBIAN_FRONTEND=noninteractive apt-get install"]);
    let t2 = Target { root: root.clone(), runner: &r2 };
    let o = ApplyOptions { install_packages: true, ..opts() };
    let err = apply(&Vpn, &vpn_cfg("tailscale"), &t2, &o).unwrap_err();
    assert!(matches!(err, ApplyError::Command { .. }), "{err}");
    assert!(!under_root(&root, TS_LIST_PATH).exists(), "apt source must be removed again");
}
