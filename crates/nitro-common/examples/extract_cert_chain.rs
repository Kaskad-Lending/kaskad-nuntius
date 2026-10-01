//! Emit the on-chain warm-up cert chain from a Nitro genesis attestation doc.
//! CERT_CHAIN = cabundle[1..] (skip the pinned root) ++ leaf, each 0x-hex DER,
//! comma-separated — the exact env RegisterOracleSigner.s.sol reads. Reuses
//! `parse_attestation_doc`; no verification here — the on-chain warm-up
//! validates every link from ROOT_CA_CERT_HASH.
//!
//! Input (env):
//!   CERT_DOC_FILE  file whose content is the attestation-doc hex (0x optional,
//!                  whitespace ignored) — the `.attestation` of genesis/latest.json.
//!
//! stdout: the CERT_CHAIN value. stderr: audit diagnostics (root keccak to match
//! ROOT_CA_CERT_HASH, per-cert keccak, PCR0, the signer address the doc binds).

use std::fs;

use eyre::{bail, Context, Result};
use nitro_common::attest::parse_attestation_doc;
use sha3::{Digest, Keccak256};

fn keccak(bytes: &[u8]) -> String {
    hex::encode(Keccak256::digest(bytes))
}

fn main() -> Result<()> {
    let path = std::env::var("CERT_DOC_FILE").wrap_err("missing env CERT_DOC_FILE")?;
    let raw = fs::read_to_string(&path).wrap_err_with(|| format!("read {path}"))?;
    let joined: String = raw.split_whitespace().collect();
    let hexstr = joined.strip_prefix("0x").unwrap_or(&joined);
    let doc_bytes = hex::decode(hexstr).wrap_err("attestation doc: bad hex")?;

    let doc = parse_attestation_doc(&doc_bytes).wrap_err("parse attestation doc")?;

    // cabundle is root-first; the root is pinned on-chain as ROOT_CA_CERT_HASH,
    // so warm cabundle[1..] then the leaf certificate.
    if doc.cabundle.len() < 2 {
        bail!(
            "cabundle has {} certs, need root + >=1 intermediate",
            doc.cabundle.len()
        );
    }
    let root = &doc.cabundle[0];
    let mut chain: Vec<&[u8]> = doc.cabundle[1..].iter().map(|c| c.as_slice()).collect();
    chain.push(doc.certificate.as_slice());

    eprintln!(
        "[cert] cabundle certs: {} (root + {} intermediate)",
        doc.cabundle.len(),
        doc.cabundle.len() - 1
    );
    eprintln!(
        "[cert] ROOT keccak (must equal on-chain ROOT_CA_CERT_HASH): 0x{}",
        keccak(root)
    );
    for (i, c) in chain.iter().enumerate() {
        let tag = if i + 1 == chain.len() {
            "leaf"
        } else {
            "intermediate"
        };
        eprintln!(
            "[cert] warm #{i} ({tag}): {} bytes, keccak 0x{}",
            c.len(),
            keccak(c)
        );
    }
    if let Some(pcr0) = doc.pcr0() {
        eprintln!("[cert] PCR0 (48B): 0x{}", hex::encode(pcr0));
        eprintln!(
            "[cert] PCR0[..32] (expectedPCR0): 0x{}",
            hex::encode(&pcr0[..32])
        );
    }
    match &doc.public_key {
        Some(pk) if pk.len() == 65 && pk[0] == 0x04 => {
            let d = Keccak256::digest(&pk[1..]);
            eprintln!("[cert] doc-bound signer: 0x{}", hex::encode(&d[12..]));
        }
        Some(pk) => eprintln!(
            "[cert] public_key present but not 65-byte SEC1 (len {})",
            pk.len()
        ),
        None => eprintln!("[cert] WARNING: no public_key in doc"),
    }

    let out: Vec<String> = chain
        .iter()
        .map(|c| format!("0x{}", hex::encode(c)))
        .collect();
    println!("{}", out.join(","));
    Ok(())
}
