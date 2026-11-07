//! What a device can run, as reported to rpctl and the console app.
//!
//! Reasons are a closed enum so clients localise them instead of parsing text.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Capabilities {
    pub device: DeviceInfo,
    pub interfaces: Vec<IfaceInfo>,
    /// Keyed by module name (`base`, `vpn`, `dns`, `ap`, `agent`, `firewall`, `api`).
    pub modules: BTreeMap<String, ModuleCapability>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub model: String,
    /// `uname -m` (armv7l, aarch64, ...).
    pub arch: String,
    pub ram_mb: u64,
    pub os: String,
    /// Release binaries exist for this architecture.
    pub supported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IfaceKind {
    Ethernet,
    Wifi,
    Vpn,
    Other,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IfaceInfo {
    pub name: String,
    pub kind: IfaceKind,
    pub carrier: bool,
    /// Carries the management session (the app's or the admin's SSH).
    pub is_mgmt: bool,
    /// Wi-Fi only: can run an access point (None = unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ap_mode: Option<bool>,
    /// Wi-Fi only: "2.4", "5", "6" (GHz).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bands: Vec<String>,
    /// Wi-Fi only: WPA3-SAE looks supported by the driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wpa3: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ModuleCapability {
    /// The hardware and OS can run the module.
    pub available: bool,
    /// Why it is not available (empty when available).
    #[serde(default)]
    pub reasons: Vec<Reason>,
    /// Soft limitations that do not block the module.
    #[serde(default)]
    pub notes: Vec<Reason>,
    /// Module-specific choices, e.g. VPN modes or AP-capable interfaces.
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// No release build for this CPU (ARMv6: Pi 1 / Zero).
    UnsupportedArch,
    /// No Wi-Fi interface at all.
    NoWifiInterface,
    /// Wi-Fi present but the driver cannot run an access point.
    NoApCapableWifi,
    /// The only AP-capable Wi-Fi carries the management connection.
    WouldDropManagementLink,
    /// No wired uplink with carrier to route AP clients through.
    NoWiredUplink,
    /// AP support could not be determined (iw / nmcli missing).
    ApSupportUnknown,
    /// Only WPA2 can be offered.
    Wpa2Only,
    /// Kernel has no WireGuard; Tailscale (userspace) still works.
    NoKernelWireguard,
    /// Less than 512 MB RAM: keep blocklists small.
    LowMemory,
}
