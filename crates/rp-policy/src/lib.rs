//! rp-policy: every decision about what an agent tool may do is made here, in
//! deterministic code — never by the model calling the tool.
//!
//! * [`auth`]: bearer tokens (stored only as SHA-256), principals, capabilities
//! * [`validate`]: argument validation (CIDR allow-lists, subnets, MACs, bounds)
//! * [`ratelimit`]: per-principal limits
//! * [`approvals`]: privileged actions wait for a human `rpctl approve` on the device
//! * [`audit`]: append-only, hash-chained audit log
//! * [`admin`]: console admins (Ed25519 keys) and signed, single-use requests
//! * [`pairing`]: one-time-secret pairing of a new console admin

pub mod admin;
pub mod approvals;
pub mod audit;
pub mod auth;
pub mod pairing;
pub mod ratelimit;
pub mod validate;

use serde::{Deserialize, Serialize};

/// What a tool is allowed to do. Ordered by risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    /// Observe only.
    Read,
    /// Generates network traffic (e.g. a neighbour scan) but changes nothing.
    Active,
    /// Changes network state. Always requires human approval on the device.
    Privileged,
}

impl Capability {
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Read => "read",
            Capability::Active => "active",
            Capability::Privileged => "privileged",
        }
    }
}
