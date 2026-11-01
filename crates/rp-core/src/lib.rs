//! Core logic for the rp edge security gateway: config validation, rendering
//! of managed system files, preflight checks and safe apply / rollback.

pub mod agent;
pub mod ap;
pub mod apply;
pub mod base;
pub mod capabilities;
pub mod changeset;
pub mod config;
pub mod dns;
pub mod files;
pub mod module;
pub mod nft;
pub mod preflight;
pub mod runner;
pub mod secrets;
pub mod vpn;
pub mod wg;

#[cfg(test)]
mod apply_tests;
#[cfg(test)]
mod changeset_tests;
