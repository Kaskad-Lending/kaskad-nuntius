//! Keyex control channel (VSOCK/TCP port 5005), blocking, mirroring the bridge
//! serve loop. It serves the operator during boot: attest the genesis candidate
//! (so it can be registered on-chain), accept owner-signed handover approvals,
//! confirm the baked registry, and report health. All handlers are synchronous —
//! there is no chain I/O on this path.

use std::net::{TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy_primitives::Address;
use eyre::Result;
use keyex::api::{Ack, ApprovalResult, Attestation, KeyexHealth as HealthReply, OracleRequest};
use keyex::approval::{verify_approvals, ApprovalMode, ApprovalRequest};
use keyex::policy::VerifiedApproval;
use nitro_common::nsm::Nsm;
use nitro_common::vsock::{read_frame_deadline, write_frame, MAX_FRAME};
use serde_json::Value;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use super::state::OracleKeyexState;
use super::{bound_vsock_listen_fd, classify_accept, enclave_mode, AcceptFault};

/// Keyex control VSOCK port.
const CONTROL_PORT: u32 = 5005;
/// Concurrent in-flight control requests.
const MAX_INFLIGHT: usize = 64;
/// Whole-request read budget.
const REQUEST_DEADLINE: Duration = Duration::from_secs(15);
/// Per-response write timeout.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
/// Pause after a resource-exhaustion accept fault.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

const DOMAIN_NAME: &str = "Kaskad Keyex";
const DOMAIN_VERSION: &str = "1";

/// Everything a control handler needs, shared read-only across connections.
pub struct ControlCtx {
    pub state: Arc<Mutex<OracleKeyexState>>,
    pub pcr0: [u8; 48],
    pub version: u64,
    pub owners: Vec<Address>,
    pub threshold: usize,
    pub chain_id: u64,
    pub registry: Address,
}

/// Serve the control channel forever. Spawned before boot so the operator can
/// register the genesis candidate while `run_boot` blocks awaiting registration.
pub async fn serve_control(ctx: ControlCtx) -> Result<()> {
    let listener = create_listener(CONTROL_PORT)?;
    info!(port = CONTROL_PORT, enclave = enclave_mode(), "keyex control channel listening");
    let ctx = Arc::new(ctx);
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    loop {
        let stream = match accept_connection(&listener)? {
            CtlAccept::Conn(s) => s,
            CtlAccept::Retry => continue,
            CtlAccept::Backoff => {
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let permit = match Arc::clone(&sem).try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                drop(stream);
                warn!("keyex control overload — dropping connection");
                continue;
            }
        };
        let ctx = Arc::clone(&ctx);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if handle_control_connection(stream, &ctx).is_err() {
                warn!("keyex control connection error");
            }
        });
    }
}

fn create_listener(port: u32) -> Result<TcpListener> {
    if enclave_mode() {
        // SAFETY: `bound_vsock_listen_fd` returns a freshly bound+listening fd we own.
        Ok(unsafe { TcpListener::from_raw_fd(bound_vsock_listen_fd(port)?) })
    } else {
        info!(port, "keyex control: TCP fallback (no ENCLAVE_MODE)");
        Ok(TcpListener::bind(format!("127.0.0.1:{port}"))?)
    }
}

/// One accept attempt.
enum CtlAccept {
    Conn(TcpStream),
    Retry,
    Backoff,
}

fn accept_connection(listener: &TcpListener) -> Result<CtlAccept> {
    if enclave_mode() {
        let mut addr: libc::sockaddr = unsafe { std::mem::zeroed() };
        let mut len: libc::socklen_t = std::mem::size_of::<libc::sockaddr>() as libc::socklen_t;
        let client_fd = unsafe { libc::accept(listener.as_raw_fd(), &mut addr as *mut _, &mut len) };
        if client_fd < 0 {
            return Ok(fault_to_accept(classify_accept(
                std::io::Error::last_os_error().raw_os_error(),
            )?));
        }
        // SAFETY: `client_fd` is a fresh owned fd returned by accept.
        Ok(CtlAccept::Conn(unsafe { TcpStream::from_raw_fd(client_fd) }))
    } else {
        match listener.accept() {
            Ok((stream, _)) => Ok(CtlAccept::Conn(stream)),
            Err(e) => Ok(fault_to_accept(classify_accept(e.raw_os_error())?)),
        }
    }
}

fn fault_to_accept(fault: AcceptFault) -> CtlAccept {
    match fault {
        AcceptFault::RetryNow => CtlAccept::Retry,
        AcceptFault::Backoff => CtlAccept::Backoff,
    }
}

fn handle_control_connection(mut stream: TcpStream, ctx: &ControlCtx) -> Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let buf = read_frame_deadline(&mut stream, MAX_FRAME, deadline)?;
    let resp = match serde_json::from_slice::<OracleRequest>(&buf) {
        Ok(req) => handle_oracle_request(req, ctx),
        // R-8: never echo attacker bytes back — a fixed, generic error.
        Err(_) => br#"{"error":"bad_request"}"#.to_vec(),
    };
    write_frame(&mut stream, &resp, MAX_FRAME)?;
    Ok(())
}

fn handle_oracle_request(req: OracleRequest, ctx: &ControlCtx) -> Vec<u8> {
    match req {
        OracleRequest::Configure { registry, rh_rpcs, oracle_peers } => {
            match registry.trim().parse::<Address>() {
                Ok(a) if a == ctx.registry => {
                    let https: Vec<String> =
                        rh_rpcs.into_iter().filter(|u| u.starts_with("https://")).collect();
                    if let Ok(mut st) = ctx.state.lock() {
                        st.set_config(https, oracle_peers);
                    }
                    encode(&Ack { ok: true })
                }
                // Registry mismatch: the host cannot redirect the enclave's registry.
                _ => encode(&Ack { ok: false }),
            }
        }
        OracleRequest::Approval { typed_data, signatures } => {
            match process_approval(
                &typed_data,
                &signatures,
                ctx.chain_id,
                &ctx.owners,
                ctx.threshold,
            ) {
                Ok(va) => {
                    if let Ok(mut st) = ctx.state.lock() {
                        st.add_approval(va);
                    }
                    encode(&ApprovalResult { accepted: true, reason: None })
                }
                Err(reason) => encode(&ApprovalResult { accepted: false, reason: Some(reason) }),
            }
        }
        OracleRequest::GetAttestation { nonce } => attestation_reply(ctx, nonce),
        OracleRequest::KeyexHealth => health_reply(ctx),
    }
}

/// Fresh NSM attestation binding the caller's optional nonce and the current key.
fn attestation_reply(ctx: &ControlCtx, nonce: Option<String>) -> Vec<u8> {
    let (pubkey, addr) = match ctx.state.lock().ok().map(|st| (st.signer_pubkey(), st.signer_addr()))
    {
        Some((Some(pk), Some(a))) => (pk, a),
        _ => return err_reply("not_ready"),
    };
    let nonce_bytes = match nonce {
        None => None,
        Some(s) => match hex::decode(s.trim().trim_start_matches("0x")) {
            Ok(b) => Some(b),
            Err(_) => return err_reply("bad_nonce"),
        },
    };
    let nsm = match Nsm::new() {
        Ok(n) => n,
        Err(_) => return err_reply("nsm_unavailable"),
    };
    match nsm.attestation(None, nonce_bytes, Some(pubkey)) {
        Ok(doc) => encode(&Attestation::new(&doc, addr, &ctx.pcr0)),
        Err(_) => err_reply("attestation_failed"),
    }
}

fn health_reply(ctx: &ControlCtx) -> Vec<u8> {
    let (state, source, addr) = match ctx.state.lock() {
        Ok(st) => st.health(),
        Err(_) => return err_reply("state_poisoned"),
    };
    encode(&HealthReply {
        state,
        source,
        signer: addr.map(|a| a.to_string()).unwrap_or_default(),
        version: ctx.version.to_string(),
        pcr0: format!("0x{}", hex::encode(ctx.pcr0)),
    })
}

/// Parse an EIP-712 typedData approval into an [`ApprovalRequest`], cross-checking
/// the domain against the baked name/version/chain. Pure — the KAT test binds it
/// to the on-chain KskdEntry digest.
fn parse_approval_request(td: &Value, expected_chain_id: u64) -> Result<ApprovalRequest, String> {
    let domain = td.get("domain").ok_or("typedData has no domain")?;
    if domain.get("name").and_then(Value::as_str) != Some(DOMAIN_NAME) {
        return Err("approval domain name mismatch".into());
    }
    if domain.get("version").and_then(Value::as_str) != Some(DOMAIN_VERSION) {
        return Err("approval domain version mismatch".into());
    }
    let cid = parse_u64_flexible(domain.get("chainId"))?;
    if cid != expected_chain_id {
        return Err(format!("approval chainId {cid} != baked {expected_chain_id}"));
    }
    let msg = td.get("message").ok_or("typedData has no message")?;
    let pcr0 = parse_hex_bytes::<48>(msg.get("pcr0"))?;
    let version = parse_u64_flexible(msg.get("version"))?;
    let mode_u8 = parse_u8_flexible(msg.get("mode"))?;
    let mode =
        ApprovalMode::try_from(mode_u8).map_err(|_| format!("invalid approval mode {mode_u8}"))?;
    let label = parse_hex_bytes::<32>(msg.get("label"))?;
    Ok(ApprovalRequest { pcr0, version, mode, label, chain_id: expected_chain_id })
}

/// Verify an approval message reached owner quorum. Malformed signatures are
/// dropped (not fatal); [`verify_approvals`] enforces distinct-owner threshold.
fn process_approval(
    td: &Value,
    sigs_hex: &[String],
    expected_chain_id: u64,
    owners: &[Address],
    threshold: usize,
) -> Result<VerifiedApproval, String> {
    let req = parse_approval_request(td, expected_chain_id)?;
    let mut sigs: Vec<[u8; 65]> = Vec::with_capacity(sigs_hex.len());
    for s in sigs_hex {
        let t = s.trim();
        let hexpart = t.strip_prefix("0x").unwrap_or(t);
        if let Ok(raw) = hex::decode(hexpart) {
            if let Ok(arr) = <[u8; 65]>::try_from(raw) {
                sigs.push(arr);
            }
        }
    }
    verify_approvals(&req, &sigs, owners, threshold).map_err(|e| e.to_string())?;
    Ok(VerifiedApproval::from_request(&req))
}

fn parse_u64_flexible(v: Option<&Value>) -> Result<u64, String> {
    match v {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| "number is not a u64".to_string()),
        Some(Value::String(s)) => {
            let s = s.trim();
            match s.strip_prefix("0x") {
                Some(hexpart) => u64::from_str_radix(hexpart, 16).map_err(|_| "bad hex u64".into()),
                None => s.parse::<u64>().map_err(|_| "bad decimal u64".into()),
            }
        }
        _ => Err("missing or non-numeric field".into()),
    }
}

fn parse_u8_flexible(v: Option<&Value>) -> Result<u8, String> {
    let n = parse_u64_flexible(v)?;
    u8::try_from(n).map_err(|_| "value out of u8 range".into())
}

fn parse_hex_bytes<const N: usize>(v: Option<&Value>) -> Result<[u8; N], String> {
    let s = v.and_then(Value::as_str).ok_or("missing hex field")?;
    let bytes = hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| "field is not hex")?;
    <[u8; N]>::try_from(bytes).map_err(|_| format!("field is not {N} bytes"))
}

fn encode<T: serde::Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_else(|_| br#"{"error":"encode"}"#.to_vec())
}

/// A fixed-code error reply. `code` is always a literal from this module, never
/// caller-derived, so no attacker bytes reach the wire.
fn err_reply(code: &str) -> Vec<u8> {
    format!(r#"{{"error":"{code}"}}"#).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use keyex::approval::approval_digest;
    use sha3::{Digest, Keccak256};

    fn v1_label() -> [u8; 32] {
        Keccak256::digest(b"kaskad/pontifex/v1").into()
    }

    fn canonical_pcr0() -> [u8; 48] {
        let mut p = [0u8; 48];
        for (i, b) in p.iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    fn canonical_typed_data() -> Value {
        serde_json::json!({
            "domain": {"name": "Kaskad Keyex", "version": "1", "chainId": 46630},
            "message": {
                "pcr0": format!("0x{}", hex::encode(canonical_pcr0())),
                "version": "1",
                "mode": 1,
                "label": format!("0x{}", hex::encode(v1_label())),
            }
        })
    }

    #[test]
    fn parse_matches_forge_kat() {
        let req = parse_approval_request(&canonical_typed_data(), 46630).unwrap();
        assert_eq!(req.pcr0, canonical_pcr0());
        assert_eq!(req.version, 1);
        assert_eq!(req.mode, ApprovalMode::Carry);
        assert_eq!(req.label, v1_label());
        let digest = approval_digest(&req);
        assert_eq!(
            hex::encode(digest.as_slice()),
            "cb8a371abea52badb34086be1ed4d34b1af468a4804f61754fb89188c441a7fc"
        );
    }

    #[test]
    fn rejects_wrong_chain_and_domain() {
        assert!(parse_approval_request(&canonical_typed_data(), 4663).is_err());
        let mut td = canonical_typed_data();
        td["domain"]["name"] = Value::from("Wrong");
        assert!(parse_approval_request(&td, 46630).is_err());
    }

    #[test]
    fn u64_accepts_number_decimal_and_hex() {
        assert_eq!(parse_u64_flexible(Some(&Value::from(46630))).unwrap(), 46630);
        assert_eq!(parse_u64_flexible(Some(&Value::from("46630"))).unwrap(), 46630);
        assert_eq!(parse_u64_flexible(Some(&Value::from("0xb626"))).unwrap(), 46630);
        assert!(parse_u64_flexible(None).is_err());
    }

    #[test]
    fn quorum_enforced_over_canonical_digest() {
        let td = canonical_typed_data();
        let req = parse_approval_request(&td, 46630).unwrap();
        let digest = approval_digest(&req);

        let k1 = SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let k2 = SigningKey::from_bytes((&[2u8; 32]).into()).unwrap();
        let o1 = keyex::sig::address_from_key(k1.verifying_key());
        let o2 = keyex::sig::address_from_key(k2.verifying_key());
        let s1 = keyex::sig::sign_recoverable(&k1, &digest).unwrap();
        let s2 = keyex::sig::sign_recoverable(&k2, &digest).unwrap();
        let sigs = vec![hex::encode(s1), format!("0x{}", hex::encode(s2))];
        let owners = vec![o1, o2];

        assert!(process_approval(&td, &sigs, 46630, &owners, 2).is_ok());
        // Threshold above the distinct-owner count must fail.
        assert!(process_approval(&td, &sigs, 46630, &owners, 3).is_err());
        // A single signature cannot meet a threshold of 2.
        assert!(process_approval(&td, &sigs[..1], 46630, &owners, 2).is_err());
    }
}
