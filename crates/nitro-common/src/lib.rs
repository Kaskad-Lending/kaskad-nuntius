//! Low-level Nitro enclave primitives shared by the oracle and bridge
//! images: NSM access, an NSM-rooted CSPRNG, length-prefixed vsock
//! framing, and structural attestation-document parsing.
//!
//! [`attest`] decodes document structure; [`verify`] performs the full
//! cryptographic check (COSE ES384, cert chain to the pinned AWS Nitro root).

pub mod attest;
pub mod verify;
pub mod vsock;

#[cfg(target_os = "linux")]
pub mod nsm;
#[cfg(target_os = "linux")]
pub mod rng;
