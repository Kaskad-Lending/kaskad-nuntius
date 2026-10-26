//! Owner-quorum approval generator. Reuses the enclave's own `approval_digest`,
//! `sign_recoverable` and `verify_approvals` so the emitted file is byte-identical
//! to what the oracle verifies on the control channel. Self-checks the forge KAT
//! before signing, then self-verifies the produced signature against the owner set.
//!
//! Inputs (env):
//!   KEYEX_GEN_KEY_FILE  path to a file whose first 0x?[0-9a-f]{64} is the owner key
//!   KEYEX_GEN_PCR0      48-byte hex (0x optional) — the image PCR0 being approved
//!   KEYEX_GEN_MODE      carry|fresh|child (or 1|2|3)
//!   KEYEX_GEN_ROLE      oracle|bridge (or 1|2) — role this approval is scoped to
//!   KEYEX_GEN_VERSION   u64 keyex version
//!   KEYEX_GEN_LABEL     32-byte hex (0x optional) — keccak256(label string)
//!   KEYEX_GEN_CHAIN_ID  u64 chain id
//!   KEYEX_GEN_EXPIRY    absolute unix seconds, or +N seconds from the local clock
//!   KEYEX_GEN_NONCE     optional 32-byte hex; default = keccak256 of the request
//!   KEYEX_GEN_EXPECT_SIGNER  optional 0x address; abort unless the key derives it
//!
//! Emits to stdout: {"typedData":{"domain":{…},"message":{…}},"signatures":["0x…"]}

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use eyre::{bail, Context, Result};
use k256::ecdsa::SigningKey;
use keyex::approval::{approval_digest, verify_approvals, ApprovalMode, ApprovalRequest};
use keyex::policy::EnclaveRole;
use keyex::sig::{address_from_key, sign_recoverable};
use sha3::{Digest, Keccak256};

/// keccak256("kaskad/pontifex/v1") — canonical KAT label.
fn v1_label() -> [u8; 32] {
    Keccak256::digest(b"kaskad/pontifex/v1").into()
}

/// The forge parity vector: pcr0 = [0,1,…,47].
fn canonical_pcr0() -> [u8; 48] {
    let mut p = [0u8; 48];
    for (i, b) in p.iter_mut().enumerate() {
        *b = i as u8;
    }
    p
}

/// The forge parity vector: nonce = [0,1,…,31].
fn canonical_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, b) in n.iter_mut().enumerate() {
        *b = i as u8;
    }
    n
}

fn strip0x(s: &str) -> &str {
    s.trim().strip_prefix("0x").unwrap_or(s.trim())
}

fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let raw = hex::decode(strip0x(s)).wrap_err_with(|| format!("{what}: bad hex"))?;
    if raw.len() != N {
        bail!("{what}: expected {N} bytes, got {}", raw.len());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn env(k: &str) -> Result<String> {
    std::env::var(k).wrap_err_with(|| format!("missing env {k}"))
}

fn parse_mode(s: &str) -> Result<ApprovalMode> {
    match s.trim().to_ascii_lowercase().as_str() {
        "carry" | "1" => Ok(ApprovalMode::Carry),
        "fresh" | "2" => Ok(ApprovalMode::Fresh),
        "child" | "3" => Ok(ApprovalMode::Child),
        other => bail!("bad KEYEX_GEN_MODE: {other}"),
    }
}

fn parse_role(s: &str) -> Result<EnclaveRole> {
    match s.trim().to_ascii_lowercase().as_str() {
        "oracle" | "1" => Ok(EnclaveRole::Oracle),
        "bridge" | "2" => Ok(EnclaveRole::Bridge),
        other => bail!("bad KEYEX_GEN_ROLE: {other}"),
    }
}

fn local_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .wrap_err("local clock before epoch")?
        .as_secs())
}

/// Absolute unix seconds, or `+N` relative to `now`. The enclave judges expiry
/// against the NSM-signed clock, so a skewed local clock only shifts the window
/// the owners intended — it never bypasses the gate.
fn parse_expiry(s: &str, now: u64) -> Result<u64> {
    let t = s.trim();
    if let Some(rel) = t.strip_prefix('+') {
        let secs: u64 = rel.parse().wrap_err("KEYEX_GEN_EXPIRY: bad +N")?;
        return Ok(now + secs);
    }
    t.parse().wrap_err("KEYEX_GEN_EXPIRY")
}

/// Deterministic nonce: keccak256 over the whole request. Two approvals that
/// differ in any field get distinct nonces without introducing an RNG.
fn derive_nonce(
    pcr0: &[u8; 48],
    version: u64,
    mode: ApprovalMode,
    label: &[u8; 32],
    role: EnclaveRole,
    expiry: u64,
    chain_id: u64,
) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(b"kaskad/keyex/approval-nonce/v1");
    h.update(pcr0);
    h.update(version.to_be_bytes());
    h.update([mode as u8]);
    h.update(label);
    h.update([role as u8]);
    h.update(expiry.to_be_bytes());
    h.update(chain_id.to_be_bytes());
    h.finalize().into()
}

/// First 0x?[0-9a-f]{64} token in the key file; never printed.
fn load_key(path: &str) -> Result<SigningKey> {
    let blob = fs::read_to_string(path).wrap_err_with(|| format!("read key file {path}"))?;
    let tok = blob
        .split(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
        .map(strip0x)
        .find(|t| t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()))
        .ok_or_else(|| eyre::eyre!("no 32-byte hex key in {path}"))?;
    let bytes = hex::decode(tok).wrap_err("key hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| eyre::eyre!("key not 32 bytes"))?;
    SigningKey::from_bytes((&arr).into()).wrap_err("key not a valid secp256k1 scalar")
}

fn main() -> Result<()> {
    // 1. Prove the encoder matches the on-chain forge digest before signing anything.
    let kat = approval_digest(&ApprovalRequest {
        pcr0: canonical_pcr0(),
        version: 1,
        mode: ApprovalMode::Carry,
        label: v1_label(),
        role: EnclaveRole::Oracle,
        expiry: 1_900_000_000,
        nonce: canonical_nonce(),
        chain_id: 46630,
    });
    let want = "9f1dbb456fb885648a5ce9918aae3ac642af66ca82f85b505903f674f98773f4";
    if hex::encode(kat) != want {
        bail!(
            "KAT parity FAILED: encoder does not match forge (got {})",
            hex::encode(kat)
        );
    }
    eprintln!("[gen] forge KAT parity OK ({want})");

    // 2. Build the requested approval.
    let pcr0 = hex_n::<48>(&env("KEYEX_GEN_PCR0")?, "KEYEX_GEN_PCR0")?;
    let version: u64 = env("KEYEX_GEN_VERSION")?
        .trim()
        .parse()
        .wrap_err("KEYEX_GEN_VERSION")?;
    let mode = parse_mode(&env("KEYEX_GEN_MODE")?)?;
    let label = hex_n::<32>(&env("KEYEX_GEN_LABEL")?, "KEYEX_GEN_LABEL")?;
    let role = parse_role(&env("KEYEX_GEN_ROLE")?)?;
    let chain_id: u64 = env("KEYEX_GEN_CHAIN_ID")?
        .trim()
        .parse()
        .wrap_err("KEYEX_GEN_CHAIN_ID")?;
    let now = local_now()?;
    let expiry = parse_expiry(&env("KEYEX_GEN_EXPIRY")?, now)?;
    if expiry <= now {
        bail!("KEYEX_GEN_EXPIRY {expiry} is not in the future (local now {now}) — the enclave would refuse it");
    }
    let nonce = match std::env::var("KEYEX_GEN_NONCE") {
        Ok(n) => hex_n::<32>(&n, "KEYEX_GEN_NONCE")?,
        Err(_) => derive_nonce(&pcr0, version, mode, &label, role, expiry, chain_id),
    };
    let req = ApprovalRequest {
        pcr0,
        version,
        mode,
        label,
        role,
        expiry,
        nonce,
        chain_id,
    };

    // 3. Load owner key, sign the digest (self-checking recoverable signer).
    let sk = load_key(&env("KEYEX_GEN_KEY_FILE")?)?;
    let signer = address_from_key(sk.verifying_key());
    eprintln!("[gen] signer = {signer}");
    if let Ok(expect) = std::env::var("KEYEX_GEN_EXPECT_SIGNER") {
        let e = expect.trim().to_ascii_lowercase();
        if e != format!("{signer:#x}") && e != format!("{signer:x}") {
            bail!("signer {signer} != expected {expect} — wrong key file");
        }
    }
    let digest = approval_digest(&req);
    let sig = sign_recoverable(&sk, &digest)?;

    // 4. Self-verify this one signature at the local clock, so a malformed or
    //    already-dead approval fails here rather than in the enclave. The real
    //    quorum is the Safe's; this only proves the signature recovers to `signer`
    //    inside the window. A local clock far behind NSM can still mint a
    //    short-lived file; the printed window is what the owner checks.
    verify_approvals(&req, &[sig], &[signer], 1, now)
        .wrap_err("produced signature does not recover to this signer inside the window")?;
    eprintln!(
        "[gen] self-verify OK: digest={} mode={:?} role={:?} expiry={} (valid for {}s) chain={}",
        hex::encode(digest),
        req.mode,
        req.role,
        req.expiry,
        req.expiry - now,
        req.chain_id
    );

    // 5. Emit the exact typedData shape the enclave's parser reads.
    let out = serde_json::json!({
        "typedData": {
            "domain": { "name": "Kaskad Keyex", "version": "1", "chainId": req.chain_id },
            "message": {
                "pcr0": format!("0x{}", hex::encode(req.pcr0)),
                "version": req.version.to_string(),
                "mode": req.mode as u8,
                "label": format!("0x{}", hex::encode(req.label)),
                "role": req.role as u8,
                "expiry": req.expiry.to_string(),
                "nonce": format!("0x{}", hex::encode(req.nonce)),
            }
        },
        "signatures": [format!("0x{}", hex::encode(sig))]
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    eprintln!(
        "[gen] the enclave needs a Safe quorum's worth of signatures over this exact \
         typedData; the nonce is derived from the request, so every owner running \
         with identical inputs lands on this digest. Use an ABSOLUTE \
         KEYEX_GEN_EXPIRY when collecting several — `+N` resolves per run and \
         would fork the digest."
    );
    Ok(())
}
