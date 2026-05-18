//! AWS IAM credentials fetched from the host over VSOCK.
//!
//! The enclave has no direct access to the EC2 IMDS endpoint
//! (`169.254.169.254`) — it cannot reach the host's link-local network.
//! A small Python service on the host (`/opt/kaskad/aws-creds-proxy.py`,
//! installed as `kaskad-creds-proxy.service`) reads the instance-role
//! credentials from IMDSv2 once per fetch and writes them to a VSOCK
//! port (default 5002) as length-prefixed JSON.
//!
//! Only used inside the enclave (cfg-gated on `target_os = "linux"`).
//! On the host / dev machine this module returns an error so the
//! caller can fall back to the unsealed code path.
//!
//! Wire format on VSOCK:
//!
//!   [4 bytes BE length][JSON body]
//!
//! JSON body:
//!
//!   {
//!     "AccessKeyId":     "...",
//!     "SecretAccessKey": "...",
//!     "Token":           "...",
//!     "Region":          "us-east-1",
//!     "EifBucket":       "kaskad-oracle-eif",
//!     "KmsSealingAlias": "alias/kaskad-oracle-sealing"
//!   }
//!
//! Each seal / unseal re-fetches creds, so callers never hold them
//! long enough to need expiry tracking.

use eyre::Result;
use serde::Deserialize;

/// Default VSOCK port the host's `kaskad-creds-proxy` listens on.
pub const HOST_CREDS_VSOCK_PORT: u32 = 5002;

/// Host CID (`VMADDR_CID_HOST`) — the parent EC2 instance's address on
/// the local VSOCK fabric.
pub const HOST_CID: u32 = 2;

/// Decoded IAM credentials. Field names match the IMDSv2 response so
/// the JSON deserialises directly.
#[derive(Debug, Clone, Deserialize)]
pub struct IamCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "Token")]
    pub session_token: String,
    /// AWS region of the host instance. `sealing.rs` derives S3 / KMS
    /// endpoints from it, keeping the EIF region-agnostic.
    #[serde(rename = "Region")]
    pub region: String,
    /// S3 bucket holding this region's `sealed-key.bin`.
    #[serde(rename = "EifBucket")]
    pub eif_bucket: String,
    /// KMS alias of this region's sealing key.
    #[serde(rename = "KmsSealingAlias")]
    pub kms_sealing_alias: String,
}

#[cfg(target_os = "linux")]
pub fn fetch_creds_via_vsock() -> Result<IamCredentials> {
    use std::io::{Read, Write};
    use std::time::Duration;
    use vsock::{VsockAddr, VsockStream};

    let addr = VsockAddr::new(HOST_CID, HOST_CREDS_VSOCK_PORT);
    let mut sock = VsockStream::connect(&addr)?;
    sock.set_read_timeout(Some(Duration::from_secs(10)))?;
    sock.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Send a 1-byte ping so the host knows we're alive (the proxy
    // accepts and immediately replies — no actual request payload).
    sock.write_all(&[0])?;

    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 {
        return Err(eyre::eyre!(
            "creds proxy returned implausible length: {}",
            len
        ));
    }

    let mut body = vec![0u8; len];
    sock.read_exact(&mut body)?;
    let creds: IamCredentials =
        serde_json::from_slice(&body).map_err(|e| eyre::eyre!("creds JSON parse: {}", e))?;
    Ok(creds)
}

#[cfg(not(target_os = "linux"))]
pub fn fetch_creds_via_vsock() -> Result<IamCredentials> {
    Err(eyre::eyre!(
        "VSOCK IAM creds fetch is enclave-only (Linux/Nitro)"
    ))
}
