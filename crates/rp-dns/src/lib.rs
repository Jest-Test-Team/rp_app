//! rp-dns: a filtering, logging DNS forwarder.
//!
//! Policy is deterministic — allowlist, blocklist and heuristic scoring — and
//! the service fails open: a broken event database or a missing blocklist file
//! never stops name resolution.

pub mod engine;
pub mod events;
pub mod lists;
pub mod ratelimit;
pub mod score;
pub mod server;
