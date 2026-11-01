//! Change set life cycle against a throwaway root with a recording runner.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::apply::Target;
use crate::base::NFT_PATH;
use crate::changeset::*;
use crate::files::under_root;
use crate::preflight::Status;
use crate::runner::RecordingRunner;

const CFG: &str =
    "# keep this comment\n[device]\nwan_if = \"eth0\"\nlan_cidrs = [\"192.0.2.0/24\"]\n";

fn fake_root(tag: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("rp-cs-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    for b in crate::preflight::REQUIRED_BINARIES {
        let p = under_root(&root, &format!("/usr/sbin/{b}"));
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, "").unwrap();
    }
    let w = |p: &str, c: &str| {
        let f = under_root(&root, p);
        fs::create_dir_all(f.parent().unwrap()).unwrap();
        fs::write(f, c).unwrap();
    };
    w("/sys/class/net/eth0/carrier", "1\n");
    w("/sys/class/net/eth0/device/vendor", "x");
    w("/etc/os-release", "ID=debian\n");
    let config = root.join("rp.toml");
    fs::write(&config, CFG).unwrap();
    (root, config)
}

fn runner() -> RecordingRunner {
    RecordingRunner::default()
        .with_response("id -u", "0\n")
        .with_response("dpkg-query", "install ok installed")
        .with_response("uname -m", "armv7l\n")
}

fn patch(v: Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

fn ready(t: &Target, config: &Path, p: Value) -> ChangeSet {
    let rev = revision(t, config).unwrap();
    let cs = create(t, config, "base", rev, patch(p), "admin:test").unwrap();
    let cs = preflight(t, config, &cs.id, Some("192.0.2.10".parse().unwrap())).unwrap();
    assert_eq!(cs.status, CsStatus::Preflighted, "{:#?}", cs.checks);
    cs
}

#[test]
fn only_whitelisted_keys_can_be_patched() {
    let e = patch_config(CFG, "base", &patch(json!({"device.wan_if": "wlan0"}))).unwrap_err();
    assert!(e.to_string().contains("cannot be changed"), "{e}");
    let e = patch_config(CFG, "agent", &patch(json!({"agent.token_file": "/tmp/x"}))).unwrap_err();
    assert!(e.to_string().contains("cannot be changed"));
    let e = patch_config(CFG, "base", &patch(json!({"base.allow_mdns": "no"}))).unwrap_err();
    assert!(e.to_string().contains("expected Bool"));
    let e = patch_config(CFG, "nope", &patch(json!({"x": 1}))).unwrap_err();
    assert!(matches!(e, CsError::UnknownModule(_)));
    assert!(patch_config(CFG, "base", &Map::new()).is_err());
    let e = patch_config(
        CFG,
        "vpn",
        &patch(json!({"vpn.mode": "tailscale", "vpn.tailscale.auth_key_file": "/etc/shadow"})),
    )
    .unwrap_err();
    assert!(e.to_string().contains("only"));
}

#[test]
fn patch_creates_sections_keeps_comments_and_validates() {
    let out = patch_config(
        CFG,
        "ap",
        &patch(json!({"ap.ssid": "<SSID>", "ap.country": "TW", "ap.block_dot": true})),
    )
    .unwrap();
    assert!(out.starts_with("# keep this comment"));
    let cfg = crate::config::parse(&out).unwrap();
    assert!(cfg.ap.unwrap().block_dot);
    // The resulting config must still validate as a whole.
    let e = patch_config(&out, "ap", &patch(json!({"ap.channel": 99}))).unwrap_err();
    assert!(matches!(e, CsError::Invalid(_)), "{e}");
    // null removes a key (back to its default).
    let out2 = patch_config(&out, "ap", &patch(json!({"ap.block_dot": null}))).unwrap();
    assert!(!crate::config::parse(&out2).unwrap().ap.unwrap().block_dot);
    // Injection attempts are plain strings that fail validation.
    let e =
        patch_config(CFG, "base", &patch(json!({"ssh.allow_from": ["0.0.0.0/0"]}))).unwrap_err();
    assert!(e.to_string().contains("every address"));
}

#[test]
fn revision_follows_content_including_hand_edits() {
    let (root, config) = fake_root("rev");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let r1 = revision(&t, &config).unwrap();
    assert_eq!(revision(&t, &config).unwrap(), r1);
    fs::write(&config, format!("{CFG}\n[base]\nallow_mdns = false\n")).unwrap();
    assert_eq!(peek_revision(&t, &config), r1 + 1);
    assert_eq!(revision(&t, &config).unwrap(), r1 + 1);
    let e =
        create(&t, &config, "base", r1, patch(json!({"base.allow_mdns": true})), "a").unwrap_err();
    assert!(matches!(e, CsError::Conflict { current } if current == r1 + 1));
}

#[test]
fn apply_arms_timer_and_confirm_keeps_the_change() {
    let (root, config) = fake_root("confirm");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    assert!(cs.config_diff.contains("+allow_mdns = false"));
    assert!(!cs.files.is_empty());
    assert!(cs.checks.iter().any(|c| c.name == "api_lockout" && c.status == Status::Pass));
    assert!(cs.new_config.contains("allow_mdns = false"));
    assert!(cs.public().new_config.is_empty());

    let cs = apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()).unwrap();
    assert_eq!(cs.status, CsStatus::AwaitingConfirm, "{:?} {:?}", cs.error, cs.verification);
    assert!(cs.deadline.unwrap() > now());
    let calls = r.calls();
    let timer = calls.iter().find(|c| c.starts_with("systemd-run --unit=rp-changeset-")).unwrap();
    assert!(timer.ends_with(&format!("rpctl changeset expire {}", cs.id)));
    assert!(timer.contains("--on-active=120"));
    assert!(!calls.iter().any(|c| c.contains("rp-confirm-base")), "no second timer");
    assert!(fs::read_to_string(&config).unwrap().contains("allow_mdns = false"));
    assert!(under_root(&root, NFT_PATH).exists());

    let cs = confirm(&t, &config, &cs.id).unwrap();
    assert_eq!(cs.status, CsStatus::Confirmed);
    assert!(r.calls().iter().any(|c| c == &format!("systemctl stop rp-changeset-{}.timer", cs.id)));
    assert!(confirm(&t, &config, &cs.id).is_err(), "confirm only once");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn unconfirmed_change_is_undone_by_the_timer() {
    let (root, config) = fake_root("expire");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    let cs = apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()).unwrap();
    let rev_applied = revision(&t, &config).unwrap();
    let cs = expire(&t, &config, &cs.id).unwrap();
    assert_eq!(cs.status, CsStatus::RolledBack);
    assert!(cs.error.unwrap().contains("not confirmed in time"));
    assert_eq!(fs::read_to_string(&config).unwrap(), CFG, "config restored byte for byte");
    assert!(!under_root(&root, NFT_PATH).exists(), "first apply undone entirely");
    assert!(revision(&t, &config).unwrap() > rev_applied, "revision moves forward, never back");
    // A late expire is a no-op.
    assert_eq!(expire(&t, &config, &cs.id).unwrap().status, CsStatus::RolledBack);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn failed_on_device_check_rolls_back_immediately() {
    let (root, config) = fake_root("verify");
    let r = RecordingRunner { fail_prefixes: vec!["nft list table".into()], ..runner() };
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    let cs = apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()).unwrap();
    assert_eq!(cs.status, CsStatus::Failed);
    assert!(cs
        .verification
        .iter()
        .any(|c| c.name == "firewall_loaded" && c.status == Status::Fail));
    assert_eq!(fs::read_to_string(&config).unwrap(), CFG);
    assert!(!under_root(&root, NFT_PATH).exists());
    assert!(!r.calls().iter().any(|c| c.starts_with("systemd-run --unit=rp-changeset-")));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn no_timer_means_no_change() {
    let (root, config) = fake_root("notimer");
    let r = RecordingRunner { fail_prefixes: vec!["systemd-run".into()], ..runner() };
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    let cs = apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()).unwrap();
    assert_eq!(cs.status, CsStatus::Failed);
    assert!(cs.error.unwrap().contains("rollback timer"));
    assert_eq!(fs::read_to_string(&config).unwrap(), CFG);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn stale_change_sets_are_superseded() {
    let (root, config) = fake_root("stale");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    fs::write(&config, format!("{CFG}# edited by hand\n")).unwrap();
    assert_eq!(get(&t, &config, &cs.id).unwrap().status, CsStatus::Superseded);
    assert!(matches!(
        apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()),
        Err(CsError::Conflict { .. })
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn app_outside_management_networks_fails_preflight() {
    let (root, config) = fake_root("lockout");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let rev = revision(&t, &config).unwrap();
    let cs =
        create(&t, &config, "base", rev, patch(json!({"base.allow_mdns": false})), "a").unwrap();
    let cs = preflight(&t, &config, &cs.id, Some("198.51.100.7".parse().unwrap())).unwrap();
    assert_eq!(cs.status, CsStatus::Created);
    assert!(cs.checks.iter().any(|c| c.name == "api_lockout" && c.status == Status::Fail));
    assert!(matches!(
        apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()),
        Err(CsError::State(CsStatus::Created, _))
    ));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn concurrent_changes_are_refused_while_locked() {
    let (root, config) = fake_root("lock");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let rev = revision(&t, &config).unwrap();
    let held = Lock::acquire(&t).unwrap();
    let e = create(&t, &config, "base", rev, patch(json!({"base.allow_mdns": false})), "a");
    assert!(matches!(e, Err(CsError::Busy)));
    drop(held);
    assert!(create(&t, &config, "base", rev, patch(json!({"base.allow_mdns": false})), "a").is_ok());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn manual_rollback_only_for_the_latest_change() {
    let (root, config) = fake_root("manual");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    let cs = apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()).unwrap();
    confirm(&t, &config, &cs.id).unwrap();
    let rb = rollback(&t, &config, &cs.id).unwrap();
    assert_eq!(rb.status, CsStatus::RolledBack);
    assert_eq!(fs::read_to_string(&config).unwrap(), CFG);
    assert!(rollback(&t, &config, &cs.id).is_err(), "not twice");

    let cs2 = ready(&t, &config, json!({"base.journal_max_mb": 32}));
    let cs2 = apply_cs(&t, &config, &cs2.id, &CsApplyOptions::default()).unwrap();
    confirm(&t, &config, &cs2.id).unwrap();
    fs::write(&config, format!("{}# later hand edit\n", fs::read_to_string(&config).unwrap()))
        .unwrap();
    assert!(matches!(rollback(&t, &config, &cs2.id), Err(CsError::Conflict { .. })));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn ids_are_validated_and_listing_is_newest_first() {
    let (root, config) = fake_root("list");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    assert!(matches!(get(&t, &config, "../../etc/passwd"), Err(CsError::NotFound(_))));
    let a = ready(&t, &config, json!({"base.allow_mdns": false}));
    assert_eq!(list(&t, &config).len(), 1);
    assert_eq!(list(&t, &config)[0].id, a.id);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn expiry_waits_for_the_lock_instead_of_giving_up() {
    let (root, config) = fake_root("wait");
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let cs = ready(&t, &config, json!({"base.allow_mdns": false}));
    let cs = apply_cs(&t, &config, &cs.id, &CsApplyOptions::default()).unwrap();
    let held = Lock::acquire(&t).unwrap();
    let (root2, config2, id) = (root.clone(), config.clone(), cs.id.clone());
    let h = std::thread::spawn(move || {
        let r = runner();
        let t = Target { root: root2, runner: &r };
        expire(&t, &config2, &id).map(|c| c.status)
    });
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(!h.is_finished(), "expire must block while another change holds the lock");
    drop(held);
    assert_eq!(h.join().unwrap().unwrap(), CsStatus::RolledBack);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn missing_prerequisite_module_fails_preflight_cleanly() {
    let (root, config) = fake_root("requires");
    fs::write(&config, format!("{CFG}[dns]\nupstreams = [\"198.51.100.53:53\"]\n")).unwrap();
    let r = runner();
    let t = Target { root: root.clone(), runner: &r };
    let rev = revision(&t, &config).unwrap();
    let cs =
        create(&t, &config, "dns", rev, patch(json!({"dns.block": ["ads.example"]})), "a").unwrap();
    let cs = preflight(&t, &config, &cs.id, None).unwrap();
    assert_eq!(cs.status, CsStatus::Created);
    let c = cs.checks.iter().find(|c| c.name == "requires:base").unwrap();
    assert_eq!(c.status, Status::Fail);
    let _ = fs::remove_dir_all(&root);
}
