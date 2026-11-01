//! Path A of the console's install flow: files written onto a freshly flashed
//! Raspberry Pi OS boot partition so the device installs rp on first boot and
//! waits to be paired — no SSH, no keyboard, no screen.
//!
//! * `user-data` (cloud-init): hostname, optional admin user with an SSH key,
//!   and a first-boot run that moves the pairing secret off the card, then
//!   downloads the release installer (SHA-256 pinned), installs it, writes a
//!   config for the detected network and applies base, agent and api
//!   (`rpctl setup`).
//! * `network-config`: Wi-Fi, when given (Ethernet needs nothing).
//! * `rp-pairing.toml`: the one-time pairing secret, shredded after copying.
//! * `meta-data`: a fresh `instance_id` so cloud-init runs again.
//!
//! The console app has a Dart port of this function; both must produce the
//! same bytes (shared golden files in test/fixtures/provision).

use serde::{Deserialize, Serialize};

pub const BOOT_MOUNT: &str = "/boot/firmware";
pub const DEFAULT_REPO: &str = "Jest-Test-Team/rp_app";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Wifi {
    pub ssid: String,
    pub password: String,
    pub country: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Spec {
    pub hostname: String,
    /// Release tag, e.g. "v0.2.0".
    pub tag: String,
    /// SHA-256 of that release's install.sh (from its SHA256SUMS).
    pub install_sha256: String,
    pub repo: String,
    /// 64 hex characters.
    pub pairing_secret: String,
    pub instance_id: String,
    /// Optional admin login: (user name, SSH public key). Password logins stay off.
    pub admin: Option<(String, String)>,
    pub wifi: Option<Wifi>,
    pub timezone: Option<String>,
}

/// JSON strings are valid YAML double-quoted scalars: safe for any input.
fn q(s: &str) -> String {
    serde_json::to_string(s).expect("string")
}

pub fn validate(s: &Spec) -> Result<(), Vec<String>> {
    let mut e = vec![];
    let host_ok = !s.hostname.is_empty()
        && s.hostname.len() <= 63
        && s.hostname.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !s.hostname.starts_with('-');
    if !host_ok {
        e.push("hostname: 1-63 letters, digits or '-'".into());
    }
    let tag_ok = s.tag.starts_with('v')
        && s.tag.len() <= 32
        && s.tag[1..].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        && s.tag[1..].split('.').count() >= 3;
    if !tag_ok {
        e.push("tag: a release tag like v0.2.0".into());
    }
    let hex64 = |x: &str| x.len() == 64 && x.chars().all(|c| c.is_ascii_hexdigit());
    if !hex64(&s.install_sha256) {
        e.push("install_sha256: 64 hex characters".into());
    }
    if !hex64(&s.pairing_secret) {
        e.push("pairing_secret: 64 hex characters".into());
    }
    let repo_ok = s.repo.split('/').count() == 2
        && s.repo.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'));
    if !repo_ok {
        e.push("repo: OWNER/NAME".into());
    }
    if !(1..=64).contains(&s.instance_id.len())
        || !s.instance_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        e.push("instance_id: letters, digits or '-'".into());
    }
    if let Some((user, key)) = &s.admin {
        let u_ok = !user.is_empty()
            && user.len() <= 32
            && user.chars().next().is_some_and(|c| c.is_ascii_lowercase() || c == '_')
            && user
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'));
        if !u_ok {
            e.push("admin user: a lowercase Linux user name".into());
        }
        let parts: Vec<&str> = key.split_whitespace().collect();
        let k_ok = parts.len() >= 2
            && !key.contains(['\n', '\r'])
            && ["ssh-ed25519", "ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com", "ssh-rsa"]
                .contains(&parts[0])
            && parts[1].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));
        if !k_ok {
            e.push("admin key: one OpenSSH public key line".into());
        }
    }
    if let Some(w) = &s.wifi {
        if w.ssid.is_empty() || w.ssid.len() > 32 || w.ssid.chars().any(char::is_control) {
            e.push("wifi ssid: 1-32 bytes".into());
        }
        if !(8..=63).contains(&w.password.len())
            || w.password.chars().any(|c| !(' '..='~').contains(&c))
        {
            e.push("wifi password: 8-63 printable ASCII characters".into());
        }
        if w.country.len() != 2 || !w.country.chars().all(|c| c.is_ascii_alphabetic()) {
            e.push("wifi country: two-letter code".into());
        }
    }
    if let Some(tz) = &s.timezone {
        if tz.is_empty()
            || !tz.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '+'))
        {
            e.push("timezone: an IANA name like Asia/Taipei".into());
        }
    }
    if e.is_empty() {
        Ok(())
    } else {
        Err(e)
    }
}

/// The first-boot script: one shell line, logged to /var/log/rp-firstboot.log.
pub fn firstboot_command(s: &Spec) -> String {
    let url = format!("https://github.com/{}/releases/download/{}/install.sh", s.repo, s.tag);
    format!(
        "set -e; exec >>/var/log/rp-firstboot.log 2>&1; \
         curl -fsSL --proto =https --retry 20 --retry-all-errors --retry-delay 5 -o /root/rp-install.sh {url}; \
         echo '{sha}  /root/rp-install.sh' | sha256sum -c -; \
         bash /root/rp-install.sh --release {tag} --repo {repo}; \
         rpctl setup --no-pairing; \
         echo rp-firstboot: done",
        sha = s.install_sha256,
        tag = s.tag,
        repo = s.repo,
    )
}

/// Files to write into the boot partition: (name, content).
pub fn files(s: &Spec) -> Result<Vec<(String, String)>, Vec<String>> {
    validate(s)?;
    let mut ud = String::from("#cloud-config\n# Generated by RP Security (rp provisioning v1)\n");
    ud.push_str(&format!("hostname: {}\nmanage_etc_hosts: true\n", q(&s.hostname)));
    if let Some(tz) = &s.timezone {
        ud.push_str(&format!("timezone: {}\n", q(tz)));
    }
    match &s.admin {
        Some((user, key)) => {
            ud.push_str(&format!(
                "\nusers:\n- name: {}\n  groups: users,adm,sudo,netdev\n  shell: /bin/bash\n  lock_passwd: true\n  ssh_authorized_keys:\n  - {}\n\nssh_pwauth: false\n",
                q(user),
                q(key.trim())
            ));
        }
        None => ud.push_str("\nssh_pwauth: false\n"),
    }
    ud.push_str("\nruncmd:\n");
    if let Some(w) = &s.wifi {
        ud.push_str("- [rfkill, unblock, wifi]\n");
        ud.push_str(&format!(
            "- [raspi-config, nonint, do_wifi_country, {}]\n",
            q(&w.country.to_uppercase())
        ));
    }
    if s.admin.is_some() {
        ud.push_str("- [systemctl, enable, --now, ssh]\n");
    }
    ud.push_str("- [install, -d, -m, \"0755\", /etc/rp]\n");
    ud.push_str(&format!(
        "- [install, -m, \"0600\", {BOOT_MOUNT}/rp-pairing.toml, /etc/rp/pairing.toml]\n"
    ));
    ud.push_str(&format!("- [shred, -u, {BOOT_MOUNT}/rp-pairing.toml]\n"));
    ud.push_str(&format!("- [sh, -c, {}]\n", q(&firstboot_command(s))));

    let mut out = vec![("user-data".to_string(), ud)];
    if let Some(w) = &s.wifi {
        out.push((
            "network-config".into(),
            format!(
                "# Generated by RP Security (rp provisioning v1)\nnetwork:\n  version: 2\n  renderer: NetworkManager\n  wifis:\n    wlan0:\n      dhcp4: true\n      optional: true\n      regulatory-domain: {}\n      access-points:\n        {}:\n          password: {}\n",
                q(&w.country.to_uppercase()),
                q(&w.ssid),
                q(&w.password)
            ),
        ));
    }
    out.push((
        "rp-pairing.toml".into(),
        format!("# One-time pairing secret; moved to /etc/rp and shredded on first boot.\nsecret = \"{}\"\n", s.pairing_secret.to_lowercase()),
    ));
    Ok(out)
}

/// Update `meta-data` text with a new instance_id (cloud-init re-runs).
pub fn meta_data(existing: &str, instance_id: &str) -> String {
    let mut lines: Vec<String> = existing
        .lines()
        .filter(|l| !l.starts_with("instance_id:") && !l.starts_with("instance-id:"))
        .map(str::to_string)
        .collect();
    if !lines.iter().any(|l| l.starts_with("dsmode:")) {
        lines.push("dsmode: local".into());
    }
    lines.push(format!("instance_id: {instance_id}"));
    lines.join("\n") + "\n"
}

/// Pairing details for the app (QR code JSON) when the device id and
/// certificate are not known yet (they are created on first boot).
pub fn pairing_qr(s: &Spec, port: u16) -> String {
    serde_json::json!({"v": 1, "host": format!("{}.local", s.hostname), "port": port, "secret": s.pairing_secret})
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn spec() -> Spec {
        Spec {
            hostname: "rp-security".into(),
            tag: "v0.2.0".into(),
            install_sha256: "a".repeat(64),
            repo: DEFAULT_REPO.into(),
            pairing_secret: "0123456789abcdef".repeat(4),
            instance_id: "rp-20261101-1".into(),
            admin: None,
            wifi: None,
            timezone: None,
        }
    }

    #[test]
    fn minimal_card_has_no_logins_and_a_pinned_installer() {
        let f = files(&spec()).unwrap();
        let ud = &f[0].1;
        assert!(ud.starts_with("#cloud-config\n"));
        assert!(ud.contains("ssh_pwauth: false"));
        assert!(!ud.contains("users:"), "no login account unless asked for");
        assert!(ud.contains("sha256sum -c -"));
        assert!(ud.contains(&"a".repeat(64)));
        assert!(ud.contains("rpctl setup --no-pairing"));
        assert!(!ud.contains(&spec().pairing_secret), "the secret is never in user-data");
        assert_eq!(f.len(), 2, "no network-config for Ethernet");
        assert!(f[1].1.contains(&spec().pairing_secret));
        let shred = ud.find("shred -u").or_else(|| ud.find("[shred, -u")).unwrap();
        let install = ud.find("rp-install.sh").unwrap();
        assert!(shred < install, "the secret leaves the card before anything is downloaded");
    }

    #[test]
    fn wifi_and_admin_key_are_quoted_safely() {
        let mut s = spec();
        s.wifi = Some(Wifi {
            ssid: "Home \"Net\": #1".into(),
            password: "p@ss: word'\"".into(),
            country: "tw".into(),
        });
        s.admin =
            Some(("admin".into(), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample user@host".into()));
        let f = files(&s).unwrap();
        let nc = &f.iter().find(|x| x.0 == "network-config").unwrap().1;
        assert!(nc.contains(r#""Home \"Net\": #1":"#));
        assert!(nc.contains(r#"password: "p@ss: word'\"""#));
        assert!(nc.contains("regulatory-domain: \"TW\""));
        let ud = &f[0].1;
        assert!(ud.contains("lock_passwd: true"));
        assert!(ud.contains("ssh_authorized_keys:"));
        assert!(ud.contains("[systemctl, enable, --now, ssh]"));
    }

    #[test]
    fn invalid_input_is_rejected() {
        let mut s = spec();
        s.hostname = "bad host".into();
        s.tag = "main; rm -rf /".into();
        s.install_sha256 = "x".into();
        s.repo = "evil".into();
        s.admin = Some(("Root".into(), "ssh-ed25519 AAA\nrm -rf /".into()));
        s.wifi = Some(Wifi { ssid: "".into(), password: "short".into(), country: "TWN".into() });
        let e = validate(&s).unwrap_err();
        assert_eq!(e.len(), 9, "{e:?}");
    }

    #[test]
    fn matches_the_golden_files_shared_with_the_app() {
        let dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/provision");
        for name in ["minimal", "full"] {
            let spec: Spec = serde_json::from_str(
                &std::fs::read_to_string(dir.join(format!("{name}.spec.json"))).unwrap(),
            )
            .unwrap();
            let want: std::collections::BTreeMap<String, String> = serde_json::from_str(
                &std::fs::read_to_string(dir.join(format!("{name}.files.json"))).unwrap(),
            )
            .unwrap();
            let got: std::collections::BTreeMap<String, String> =
                files(&spec).unwrap().into_iter().collect();
            assert_eq!(got, want, "{name}: regenerate with rpctl bootfs render --spec");
        }
    }

    #[test]
    fn meta_data_gets_a_new_instance_id() {
        let m = meta_data("dsmode: local\ninstance_id: rpios-old\n", "rp-new");
        assert_eq!(m, "dsmode: local\ninstance_id: rp-new\n");
        assert_eq!(meta_data("", "x"), "dsmode: local\ninstance_id: x\n");
    }
}
