//! Hardware capability detection.
//!
//! `gather` reads facts (sysfs, procfs, `iw`, `ip`) and `evaluate` turns them
//! into per-module availability. `evaluate` is pure so every hardware shape
//! can be tested from a fixture.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;

use rp_schema::capability::{
    Capabilities, DeviceInfo, IfaceInfo, IfaceKind, ModuleCapability, Reason,
};
use rp_schema::Config;
use serde::{Deserialize, Serialize};

use crate::apply::Target;
use crate::files::under_root;

/// Architectures release binaries are built for (x86_64 for development).
pub const SUPPORTED_ARCHES: &[&str] = &["armv7l", "aarch64", "arm64", "x86_64"];
pub const LOW_MEMORY_MB: u64 = 512;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HwIface {
    pub name: String,
    pub kind: Option<IfaceKind>,
    pub carrier: bool,
    #[serde(default)]
    pub ap_mode: Option<bool>,
    #[serde(default)]
    pub bands: Vec<String>,
    #[serde(default)]
    pub wpa3: Option<bool>,
}

/// Observed hardware facts. Serializable so fixtures can be written as JSON.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HwFacts {
    pub model: String,
    pub arch: String,
    pub mem_kb: u64,
    pub os: String,
    pub ifaces: Vec<HwIface>,
    pub kernel_wireguard: bool,
    /// Interface carrying the management session.
    pub mgmt_if: Option<String>,
}

/// Wi-Fi facts per phy from `iw list`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Phy {
    pub ap_mode: bool,
    pub bands: Vec<String>,
    pub sae: bool,
}

/// Parse `iw list` into phy name → capabilities.
pub fn parse_iw_list(text: &str) -> BTreeMap<String, Phy> {
    let mut out: BTreeMap<String, Phy> = BTreeMap::new();
    let mut cur: Option<String> = None;
    let mut in_modes = false;
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix("Wiphy ") {
            cur = Some(name.trim().to_string());
            out.entry(name.trim().to_string()).or_default();
            in_modes = false;
            continue;
        }
        let Some(phy) = cur.as_ref().and_then(|c| out.get_mut(c)) else { continue };
        if t.starts_with("Supported interface modes:") {
            in_modes = true;
            continue;
        }
        if in_modes {
            if let Some(m) = t.strip_prefix("* ") {
                if m == "AP" {
                    phy.ap_mode = true;
                }
                continue;
            }
            in_modes = false;
        }
        let band = match t {
            "Band 1:" => Some("2.4"),
            "Band 2:" => Some("5"),
            "Band 4:" => Some("6"),
            _ => None,
        };
        if let Some(b) = band {
            if !phy.bands.iter().any(|x| x == b) {
                phy.bands.push(b.into());
            }
        }
        // SAE shows up as an authentication/AKM suite or an extended feature
        // (e.g. SAE_OFFLOAD); hostapd can also do SAE in software on any
        // mac80211 driver that lists it. A heuristic: unknown drivers get WPA2.
        if t.contains("SAE") {
            phy.sae = true;
        }
    }
    out
}

fn run_stdout(t: &Target, argv: &[&str]) -> Option<String> {
    let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    t.runner.run(&argv).ok().filter(|o| o.ok()).map(|o| o.stdout)
}

fn read(t: &Target, p: &str) -> Option<String> {
    fs::read(under_root(&t.root, p)).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// Device name of the route towards `peer` (`ip -j route get`).
pub fn route_dev(t: &Target, peer: IpAddr) -> Option<String> {
    let j = run_stdout(t, &["ip", "-j", "route", "get", &peer.to_string()])?;
    let v: serde_json::Value = serde_json::from_str(&j).ok()?;
    v.get(0)?.get("dev")?.as_str().map(str::to_string)
}

/// Collect facts. `peer` is the management client's address (the app's or the
/// SSH session's) and decides which interface counts as the management link.
pub fn gather(t: &Target, cfg: Option<&Config>, peer: Option<IpAddr>) -> HwFacts {
    let model = read(t, "/proc/device-tree/model")
        .map(|m| m.trim_end_matches('\0').trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let arch = run_stdout(t, &["uname", "-m"]).map(|s| s.trim().to_string()).unwrap_or_default();
    let mem_kb = read(t, "/proc/meminfo")
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        })
        .unwrap_or(0);
    let os = read(t, "/etc/os-release")
        .and_then(|o| {
            o.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
        })
        .unwrap_or_default();

    let phys = run_stdout(t, &["iw", "list"]).map(|s| parse_iw_list(&s));
    let mut names: Vec<String> = fs::read_dir(under_root(&t.root, "/sys/class/net"))
        .map(|rd| rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect())
        .unwrap_or_default();
    names.retain(|n| n != "lo");
    names.sort();

    let ifaces = names
        .into_iter()
        .map(|name| {
            let sys = format!("/sys/class/net/{name}");
            let has = |p: &str| under_root(&t.root, &format!("{sys}/{p}")).exists();
            let wireless = has("wireless") || has("phy80211");
            let kind = if wireless {
                IfaceKind::Wifi
            } else if name.starts_with("wg")
                || name.starts_with("tailscale")
                || name.starts_with("tun")
            {
                IfaceKind::Vpn
            } else if has("device") {
                IfaceKind::Ethernet
            } else {
                IfaceKind::Other
            };
            let carrier = read(t, &format!("{sys}/carrier")).is_some_and(|c| c.trim() == "1");
            let mut i =
                HwIface { name: name.clone(), kind: Some(kind), carrier, ..HwIface::default() };
            if kind == IfaceKind::Wifi {
                let phy = read(t, &format!("{sys}/phy80211/name")).map(|p| p.trim().to_string());
                match (phys.as_ref(), phy) {
                    (Some(map), Some(p)) if map.contains_key(&p) => {
                        let c = &map[&p];
                        i.ap_mode = Some(c.ap_mode);
                        i.bands = c.bands.clone();
                        i.wpa3 = Some(c.sae);
                    }
                    (Some(map), _) if map.len() == 1 => {
                        // One radio: it must be this one.
                        let c = map.values().next().unwrap();
                        i.ap_mode = Some(c.ap_mode);
                        i.bands = c.bands.clone();
                        i.wpa3 = Some(c.sae);
                    }
                    _ => {
                        i.ap_mode = run_stdout(
                            t,
                            &["nmcli", "-g", "WIFI-PROPERTIES.AP", "device", "show", &name],
                        )
                        .map(|o| o.trim() == "yes");
                    }
                }
            }
            i
        })
        .collect();

    let kernel_wireguard = under_root(&t.root, "/sys/module/wireguard").exists()
        || run_stdout(t, &["modinfo", "-n", "wireguard"]).is_some();

    let mgmt_if = peer
        .and_then(|p| route_dev(t, p))
        .or_else(|| cfg.map(|c| c.device.mgmt_if().to_string()))
        .or_else(|| {
            let j = run_stdout(t, &["ip", "-j", "route", "show", "default"])?;
            let v: serde_json::Value = serde_json::from_str(&j).ok()?;
            v.get(0)?.get("dev")?.as_str().map(str::to_string)
        });

    HwFacts { model, arch, mem_kb, os, ifaces, kernel_wireguard, mgmt_if }
}

fn cap(reasons: Vec<Reason>, notes: Vec<Reason>, options: Vec<String>) -> ModuleCapability {
    ModuleCapability { available: reasons.is_empty(), reasons, notes, options }
}

/// Judge facts: which modules this hardware can run, and why not.
pub fn evaluate(hw: &HwFacts) -> Capabilities {
    let supported = SUPPORTED_ARCHES.contains(&hw.arch.as_str());
    let ram_mb = hw.mem_kb / 1024;
    let mgmt = hw.mgmt_if.as_deref();

    let interfaces: Vec<IfaceInfo> = hw
        .ifaces
        .iter()
        .map(|i| IfaceInfo {
            name: i.name.clone(),
            kind: i.kind.unwrap_or(IfaceKind::Other),
            carrier: i.carrier,
            is_mgmt: Some(i.name.as_str()) == mgmt,
            ap_mode: i.ap_mode,
            bands: i.bands.clone(),
            wpa3: i.wpa3,
        })
        .collect();

    let mut modules = BTreeMap::new();
    let arch_block = if supported { vec![] } else { vec![Reason::UnsupportedArch] };
    let low_mem =
        if ram_mb > 0 && ram_mb < LOW_MEMORY_MB { vec![Reason::LowMemory] } else { vec![] };

    for m in ["base", "agent", "api", "firewall"] {
        modules.insert(m.to_string(), cap(arch_block.clone(), vec![], vec![]));
    }
    modules.insert("dns".into(), cap(arch_block.clone(), low_mem.clone(), vec![]));

    let mut vpn_opts = vec!["tailscale".to_string()];
    let mut vpn_notes = vec![];
    if hw.kernel_wireguard {
        vpn_opts.push("wireguard".into());
    } else {
        vpn_notes.push(Reason::NoKernelWireguard);
    }
    modules.insert("vpn".into(), cap(arch_block.clone(), vpn_notes, vpn_opts));

    // AP: an AP-capable radio that is not the management link, plus a wired
    // uplink with carrier to route its clients through.
    let wifi: Vec<&IfaceInfo> = interfaces.iter().filter(|i| i.kind == IfaceKind::Wifi).collect();
    let capable: Vec<&IfaceInfo> =
        wifi.iter().copied().filter(|i| i.ap_mode != Some(false)).collect();
    let usable: Vec<&IfaceInfo> = capable.iter().copied().filter(|i| !i.is_mgmt).collect();
    let uplink = interfaces.iter().any(|i| i.kind == IfaceKind::Ethernet && i.carrier);
    let mut reasons = arch_block.clone();
    let mut notes = vec![];
    if wifi.is_empty() {
        reasons.push(Reason::NoWifiInterface);
    } else if capable.is_empty() {
        reasons.push(Reason::NoApCapableWifi);
    } else if usable.is_empty() {
        reasons.push(Reason::WouldDropManagementLink);
    }
    if !uplink {
        reasons.push(Reason::NoWiredUplink);
    }
    if usable.iter().any(|i| i.ap_mode.is_none()) {
        notes.push(Reason::ApSupportUnknown);
    }
    if !usable.is_empty() && !usable.iter().any(|i| i.wpa3 == Some(true)) {
        notes.push(Reason::Wpa2Only);
    }
    let opts = usable.iter().map(|i| i.name.clone()).collect();
    modules.insert("ap".into(), cap(reasons, notes, opts));

    Capabilities {
        device: DeviceInfo {
            model: hw.model.clone(),
            arch: hw.arch.clone(),
            ram_mb,
            os: hw.os.clone(),
            supported,
        },
        interfaces,
        modules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IW: &str = "Wiphy phy0
\tmax # scan SSIDs: 4
\tSupported Ciphers:
\t\t* CCMP-128 (00-0f-ac:4)
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * monitor
\tBand 1:
\t\tCapabilities: 0x1862
\tsoftware interface modes (can always be added):
";

    fn pi2b() -> HwFacts {
        HwFacts {
            model: "Raspberry Pi 2 Model B Rev 1.1".into(),
            arch: "armv7l".into(),
            mem_kb: 942_000,
            os: "Debian GNU/Linux 13 (trixie)".into(),
            ifaces: vec![
                HwIface {
                    name: "eth0".into(),
                    kind: Some(IfaceKind::Ethernet),
                    carrier: true,
                    ..HwIface::default()
                },
                HwIface {
                    name: "wlan0".into(),
                    kind: Some(IfaceKind::Wifi),
                    carrier: true,
                    ap_mode: Some(true),
                    bands: vec!["2.4".into()],
                    wpa3: Some(false),
                },
            ],
            kernel_wireguard: true,
            mgmt_if: Some("eth0".into()),
        }
    }

    fn ap(c: &Capabilities) -> &ModuleCapability {
        &c.modules["ap"]
    }

    #[test]
    fn parses_iw_list() {
        let p = parse_iw_list(IW);
        assert_eq!(p["phy0"], Phy { ap_mode: true, bands: vec!["2.4".into()], sae: false });
        let p = parse_iw_list(&IW.replace("* AP", "* P2P-client").replace("CCMP-128", "SAE"));
        assert!(!p["phy0"].ap_mode);
        assert!(p["phy0"].sae);
        assert!(parse_iw_list("").is_empty());
    }

    #[test]
    fn pi2b_with_ethernet_can_run_everything() {
        let c = evaluate(&pi2b());
        assert!(c.device.supported);
        assert_eq!(c.device.ram_mb, 919);
        assert!(c.modules.values().all(|m| m.available), "{c:#?}");
        assert_eq!(ap(&c).options, ["wlan0"]);
        assert_eq!(ap(&c).notes, [Reason::Wpa2Only]);
        assert_eq!(c.modules["vpn"].options, ["tailscale", "wireguard"]);
        assert!(c.interfaces.iter().find(|i| i.name == "eth0").unwrap().is_mgmt);
    }

    #[test]
    fn no_wifi_disables_ap_only() {
        let mut hw = pi2b();
        hw.ifaces.retain(|i| i.name != "wlan0");
        let c = evaluate(&hw);
        assert_eq!(ap(&c).reasons, [Reason::NoWifiInterface]);
        assert!(c.modules["vpn"].available && c.modules["dns"].available);
    }

    #[test]
    fn wifi_as_management_link_is_refused() {
        let mut hw = pi2b();
        hw.ifaces.retain(|i| i.name != "eth0");
        hw.mgmt_if = Some("wlan0".into());
        let c = evaluate(&hw);
        assert_eq!(ap(&c).reasons, [Reason::WouldDropManagementLink, Reason::NoWiredUplink]);
        assert!(c.interfaces[0].is_mgmt);
    }

    #[test]
    fn unplugged_ethernet_blocks_ap_but_not_vpn() {
        let mut hw = pi2b();
        hw.ifaces[0].carrier = false;
        hw.mgmt_if = Some("wlan0".into());
        let c = evaluate(&hw);
        assert!(ap(&c).reasons.contains(&Reason::NoWiredUplink));
        assert!(c.modules["vpn"].available);
    }

    #[test]
    fn adapter_without_ap_mode() {
        let mut hw = pi2b();
        hw.ifaces[1].ap_mode = Some(false);
        assert_eq!(ap(&evaluate(&hw)).reasons, [Reason::NoApCapableWifi]);
        hw.ifaces[1].ap_mode = None;
        assert!(ap(&evaluate(&hw)).notes.contains(&Reason::ApSupportUnknown));
    }

    #[test]
    fn armv6_is_unsupported_everywhere() {
        let mut hw = pi2b();
        hw.arch = "armv6l".into();
        let c = evaluate(&hw);
        assert!(!c.device.supported);
        assert!(c.modules.values().all(|m| m.reasons.contains(&Reason::UnsupportedArch)));
    }

    #[test]
    fn low_memory_and_missing_wireguard_are_notes() {
        let mut hw = pi2b();
        hw.mem_kb = 400_000;
        hw.kernel_wireguard = false;
        let c = evaluate(&hw);
        assert!(c.modules["dns"].available);
        assert_eq!(c.modules["dns"].notes, [Reason::LowMemory]);
        assert_eq!(c.modules["vpn"].options, ["tailscale"]);
        assert_eq!(c.modules["vpn"].notes, [Reason::NoKernelWireguard]);
    }

    #[test]
    fn reasons_serialize_as_snake_case() {
        let j = serde_json::to_string(&Reason::WouldDropManagementLink).unwrap();
        assert_eq!(j, "\"would_drop_management_link\"");
    }

    #[test]
    fn gathers_from_a_fixture_root() {
        use crate::runner::RecordingRunner;
        let root = std::env::temp_dir().join(format!("rp-caps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mk = |p: &str, c: &str| {
            let f = under_root(&root, p);
            fs::create_dir_all(f.parent().unwrap()).unwrap();
            fs::write(f, c).unwrap();
        };
        mk("/proc/device-tree/model", "Raspberry Pi 2 Model B Rev 1.1\0");
        mk("/proc/meminfo", "MemTotal:         942000 kB\nMemFree: 1 kB\n");
        mk("/etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n");
        mk("/sys/class/net/eth0/carrier", "1\n");
        mk("/sys/class/net/eth0/device/x", "");
        mk("/sys/class/net/wlan0/carrier", "0\n");
        mk("/sys/class/net/wlan0/phy80211/name", "phy0\n");
        mk("/sys/class/net/lo/carrier", "1\n");
        mk("/sys/module/wireguard/x", "");
        let r = RecordingRunner::default()
            .with_response("uname -m", "armv7l\n")
            .with_response("iw list", IW)
            .with_response("ip -j route get", r#"[{"dst":"192.0.2.5","dev":"eth0"}]"#);
        let t = Target { root: root.clone(), runner: &r };
        let hw = gather(&t, None, Some("192.0.2.5".parse().unwrap()));
        let _ = fs::remove_dir_all(&root);
        assert_eq!(hw.model, "Raspberry Pi 2 Model B Rev 1.1");
        assert_eq!(hw.mem_kb, 942_000);
        assert_eq!(hw.ifaces.len(), 2);
        assert_eq!(hw.ifaces[1].ap_mode, Some(true));
        assert_eq!(hw.mgmt_if.as_deref(), Some("eth0"));
        assert!(hw.kernel_wireguard);
        assert!(evaluate(&hw).modules["ap"].available);
    }
}
