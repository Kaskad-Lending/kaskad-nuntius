//! Pontifex bridge enclave crate root: wires the pure keyex core to NSM, RA-TLS
//! peer handover, and the VSOCK claim API. [`run`] is the enclave entry (Linux
//! only); the modules below are seam-injected and unit-tested off-host.

pub mod claimflow;
pub mod config;
pub mod handler;
pub mod state;
pub mod transport;

#[cfg(target_os = "linux")]
pub mod nitro;
#[cfg(target_os = "linux")]
pub mod serve;

#[cfg(target_os = "linux")]
mod egress;

#[cfg(target_os = "linux")]
mod runner;
#[cfg(target_os = "linux")]
pub use runner::run;
