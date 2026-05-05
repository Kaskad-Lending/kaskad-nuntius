//! KMS attestation-based key sealing.
//!
//! Persists the enclave's secp256k1 signing key across spot reclaims
//! / instance refreshes WITHOUT exposing the plaintext to the host.
//!
//! - **First boot.** Enclave generates a fresh key, wraps with
//!   `kms:Encrypt` (host-side OK — plaintext only ever touches our
//!   own request body, which leaves the enclave already encrypted),
//!   uploads ciphertext to S3 with `If-None-Match: *`.
//!
//! - **Restart.** Enclave fetches the sealed blob, generates an
//!   ephemeral RSA-2048 keypair *inside* the enclave, asks the NSM
//!   for an attestation document carrying the RSA pubkey in
//!   `public_key`, calls `kms:Decrypt` with `Recipient =
//!   AttestationDocument`. KMS verifies attestation against the key
//!   policy (`kms:RecipientAttestation:PCR0` allowlist) and returns
//!   the plaintext re-encrypted with the ephemeral RSA pubkey. Host
//!   sees only the ciphertext-for-recipient.
//!
//! HTTP transport: the existing `reqwest` client wired through the
//! VSOCK→TCP CONNECT bridge on `127.0.0.1:5000` (same path the
//! exchange-fetch HttpClient uses).
//!
//! Enclave-only — cfg-gated on `target_os = "linux"`.

#![cfg(target_os = "linux")]

use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4::SigningParams;
use aws_smithy_runtime_api::client::identity::Identity;
use base64::Engine;
use eyre::{eyre, Result};
use http::Request as HttpRequest;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

use crate::aws_creds::{fetch_creds_via_vsock, IamCredentials};

const AWS_REGION: &str = "us-east-1";
const S3_BUCKET: &str = "kaskad-oracle-eif";
const S3_KEY: &str = "sealed-key.bin";
const KMS_KEY_ALIAS: &str = "alias/kaskad-oracle-sealing";

const KMS_HOST: &str = "kms.us-east-1.amazonaws.com";

pub enum LoadOutcome {
    /// Successfully unsealed an existing key from S3.
    UnsealedExisting([u8; 32]),
    /// No sealed blob found — caller must generate + seal.
    NoSealedBlob,
}

/// Try to fetch and decrypt the sealed key. Returns `NoSealedBlob` on
/// 404 so the caller can switch to generate-and-seal.
pub async fn try_unseal() -> Result<LoadOutcome> {
    let creds = fetch_creds_via_vsock()?;
    let http = build_proxied_client()?;

    let blob = match s3_get(&http, &creds, S3_BUCKET, S3_KEY).await? {
        Some(b) => b,
        None => return Ok(LoadOutcome::NoSealedBlob),
    };

    // Ephemeral RSA-2048 keypair lives only on this stack frame.
    let mut rng = rsa::rand_core::OsRng;
    let priv_key =
        RsaPrivateKey::new(&mut rng, 2048).map_err(|e| eyre!("RSA-2048 keygen: {}", e))?;
    let pub_key = RsaPublicKey::from(&priv_key);
    let pub_der = pub_key
        .to_public_key_der()
        .map_err(|e| eyre!("RSA pubkey DER encode: {}", e))?;

    let attestation = nsm_attestation_with_public_key(pub_der.as_bytes())?;

    let body = serde_json::json!({
        "CiphertextBlob": base64::engine::general_purpose::STANDARD.encode(&blob),
        "Recipient": {
            "AttestationDocument": base64::engine::general_purpose::STANDARD.encode(&attestation),
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
        }
    })
    .to_string();
    let resp = kms_post(&http, &creds, "TrentService.Decrypt", body.as_bytes()).await?;
    let parsed: serde_json::Value = serde_json::from_slice(&resp)?;
    let cfr_b64 = parsed
        .get("CiphertextForRecipient")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre!("kms:Decrypt: no CiphertextForRecipient in response"))?;
    let cfr = base64::engine::general_purpose::STANDARD.decode(cfr_b64)?;

    let plaintext = priv_key
        .decrypt(Oaep::new::<Sha256>(), &cfr)
        .map_err(|e| eyre!("RSA-OAEP decrypt: {}", e))?;

    if plaintext.len() != 32 {
        return Err(eyre!(
            "sealed key wrong length: expected 32, got {}",
            plaintext.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&plaintext);
    Ok(LoadOutcome::UnsealedExisting(out))
}

/// Wrap a 32-byte signing key with the sealing KMS key and upload to
/// S3 with `If-None-Match: *`. Returns Err if the object already
/// exists (concurrent first-boot race).
pub async fn seal_and_upload(plaintext_key: &[u8; 32]) -> Result<()> {
    let creds = fetch_creds_via_vsock()?;
    let http = build_proxied_client()?;

    // KMS Encrypt
    let body = serde_json::json!({
        "KeyId": KMS_KEY_ALIAS,
        "Plaintext": base64::engine::general_purpose::STANDARD.encode(plaintext_key),
    })
    .to_string();
    let resp = kms_post(&http, &creds, "TrentService.Encrypt", body.as_bytes()).await?;
    let parsed: serde_json::Value = serde_json::from_slice(&resp)?;
    let cipher_b64 = parsed
        .get("CiphertextBlob")
        .and_then(|v| v.as_str())
        .ok_or_else(|| eyre!("kms:Encrypt: no CiphertextBlob"))?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(cipher_b64)?;

    s3_put_if_not_exists(&http, &creds, S3_BUCKET, S3_KEY, &ciphertext).await?;
    Ok(())
}

// ─── HTTP plumbing ───────────────────────────────────────────────

fn build_proxied_client() -> Result<reqwest::Client> {
    let proxy = reqwest::Proxy::all("http://127.0.0.1:5000")
        .map_err(|e| eyre!("VSOCK proxy config: {}", e))?;
    Ok(reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .proxy(proxy)
        .build()?)
}

// ─── KMS ─────────────────────────────────────────────────────────

async fn kms_post(
    http: &reqwest::Client,
    creds: &IamCredentials,
    target: &str,
    body: &[u8],
) -> Result<Vec<u8>> {
    let url = format!("https://{}/", KMS_HOST);
    let mut req = HttpRequest::builder()
        .method("POST")
        .uri(&url)
        .header("host", KMS_HOST)
        .header("content-type", "application/x-amz-json-1.1")
        .header("x-amz-target", target)
        .body(body.to_vec())
        .map_err(|e| eyre!("build KMS http req: {}", e))?;

    sign_request(&mut req, creds, "kms")?;

    let mut builder = http.post(&url).body(req.body().clone());
    for (name, value) in req.headers().iter() {
        builder = builder.header(name.as_str(), value.to_str()?);
    }
    let resp = builder.send().await?;
    let status = resp.status();
    let bytes = resp.bytes().await?.to_vec();
    if !status.is_success() {
        let preview = String::from_utf8_lossy(&bytes[..bytes.len().min(400)]);
        return Err(eyre!("KMS {} HTTP {}: {}", target, status, preview));
    }
    Ok(bytes)
}

// ─── S3 ──────────────────────────────────────────────────────────

async fn s3_get(
    http: &reqwest::Client,
    creds: &IamCredentials,
    bucket: &str,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let host = format!("{}.s3.{}.amazonaws.com", bucket, AWS_REGION);
    let url = format!("https://{}/{}", host, key);
    let mut req = HttpRequest::builder()
        .method("GET")
        .uri(&url)
        .header("host", &host)
        .body(Vec::<u8>::new())
        .map_err(|e| eyre!("build S3 http req: {}", e))?;
    sign_request(&mut req, creds, "s3")?;

    let mut builder = http.get(&url);
    for (name, value) in req.headers().iter() {
        builder = builder.header(name.as_str(), value.to_str()?);
    }
    let resp = builder.send().await?;
    match resp.status().as_u16() {
        200..=299 => Ok(Some(resp.bytes().await?.to_vec())),
        404 => Ok(None),
        other => {
            let txt = resp.text().await.unwrap_or_default();
            Err(eyre!("S3 GET {} HTTP {}: {}", url, other, txt))
        }
    }
}

async fn s3_put_if_not_exists(
    http: &reqwest::Client,
    creds: &IamCredentials,
    bucket: &str,
    key: &str,
    body: &[u8],
) -> Result<()> {
    let host = format!("{}.s3.{}.amazonaws.com", bucket, AWS_REGION);
    let url = format!("https://{}/{}", host, key);
    let mut req = HttpRequest::builder()
        .method("PUT")
        .uri(&url)
        .header("host", &host)
        .header("if-none-match", "*")
        .body(body.to_vec())
        .map_err(|e| eyre!("build S3 PUT req: {}", e))?;
    sign_request(&mut req, creds, "s3")?;

    let mut builder = http.put(&url).body(req.body().clone());
    for (name, value) in req.headers().iter() {
        builder = builder.header(name.as_str(), value.to_str()?);
    }
    let resp = builder.send().await?;
    match resp.status().as_u16() {
        200..=299 => Ok(()),
        412 => Err(eyre!(
            "sealed key already present in S3 (concurrent first-boot)"
        )),
        other => {
            let txt = resp.text().await.unwrap_or_default();
            Err(eyre!("S3 PUT {} HTTP {}: {}", url, other, txt))
        }
    }
}

// ─── SigV4 ───────────────────────────────────────────────────────

fn sign_request(
    req: &mut HttpRequest<Vec<u8>>,
    creds: &IamCredentials,
    service: &str,
) -> Result<()> {
    let mut settings = SigningSettings::default();
    if service == "s3" {
        // S3 requires the signed payload's SHA-256 in
        // `x-amz-content-sha256`. Other services accept
        // `UNSIGNED-PAYLOAD`.
        settings.payload_checksum_kind = aws_sigv4::http_request::PayloadChecksumKind::XAmzSha256;
    }

    let identity: Identity = Credentials::new(
        &creds.access_key_id,
        &creds.secret_access_key,
        Some(creds.session_token.clone()),
        None,
        "kaskad-vsock-imds",
    )
    .into();

    let params: aws_sigv4::http_request::SigningParams = SigningParams::builder()
        .identity(&identity)
        .region(AWS_REGION)
        .name(service)
        .time(SystemTime::now())
        .settings(settings)
        .build()
        .map_err(|e| eyre!("sigv4 SigningParams: {}", e))?
        .into();

    let headers: Vec<(&str, &str)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str(), v.to_str().unwrap_or("")))
        .collect();

    let signable = SignableRequest::new(
        req.method().as_str(),
        req.uri().to_string(),
        headers.iter().copied(),
        SignableBody::Bytes(req.body()),
    )
    .map_err(|e| eyre!("sigv4 SignableRequest: {}", e))?;

    let (signing_instructions, _signature) = sign(signable, &params)
        .map_err(|e| eyre!("sigv4 sign: {}", e))?
        .into_parts();
    signing_instructions.apply_to_request_http1x(req);
    Ok(())
}

// ─── NSM ─────────────────────────────────────────────────────────

fn nsm_attestation_with_public_key(pubkey_der: &[u8]) -> Result<Vec<u8>> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        return Err(eyre!("nsm_init failed: {}", fd));
    }
    let req = Request::Attestation {
        public_key: Some(pubkey_der.to_vec().into()),
        user_data: None,
        nonce: None,
    };
    let resp = nsm_process_request(fd, req);
    nsm_exit(fd);
    match resp {
        Response::Attestation { document } => Ok(document),
        Response::Error(e) => Err(eyre!("NSM Attestation error: {:?}", e)),
        other => Err(eyre!("NSM unexpected response: {:?}", other)),
    }
}
