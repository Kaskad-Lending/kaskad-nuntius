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
//! Enclave-only — gated on `target_os = "linux"` by the `mod`
//! declaration in main.rs.

use std::time::SystemTime;

use aes::Aes256;
use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4::SigningParams;
use aws_smithy_runtime_api::client::identity::Identity;
use base64::Engine;
use bcder::decode::{Constructed, DecodeError};
use bcder::{Mode, Oid, Tag};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use eyre::{eyre, Result};
use http::Request as HttpRequest;
use rsa::pkcs8::EncodePublicKey;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// DER-encoded body (tag/length stripped) of `id-envelopedData`
/// `1.2.840.113549.1.7.3` — content type of a CMS `ContentInfo`
/// wrapping an `EnvelopedData` (RFC 5652 §4).
const OID_ENVELOPED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
/// DER-encoded body of `id-aes256-CBC` `2.16.840.1.101.3.4.1.42` —
/// expected content-encryption algorithm (RFC 3565).
const OID_AES_256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

use crate::aws_creds::{fetch_creds_via_vsock, IamCredentials};

const S3_KEY: &str = "sealed-key.bin";

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

    let blob = match s3_get(&http, &creds, S3_KEY).await? {
        Some(b) => b,
        None => return Ok(LoadOutcome::NoSealedBlob),
    };

    // Ephemeral RSA-2048 keypair lives only on this stack frame.
    // RNG is rooted in NSM hardware — `OsRng` would be `/dev/urandom`,
    // seeded from host-supplied virtio-rng, which would let the host
    // predict this key and decrypt KMS' `CiphertextForRecipient`.
    let mut rng = crate::nsm_rng::NsmRng::new()
        .map_err(|e| eyre!("NSM RNG init for ephemeral RSA: {}", e))?;
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
    // CiphertextForRecipient is a CMS EnvelopedData, not a bare
    // RSA-OAEP ciphertext — unwrap both layers.
    let cfr_der = base64::engine::general_purpose::STANDARD.decode(cfr_b64)?;
    let out = decrypt_cfr(&cfr_der, &priv_key)?;
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
        "KeyId": creds.kms_sealing_alias,
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

    s3_put_if_not_exists(&http, &creds, S3_KEY, &ciphertext).await?;
    Ok(())
}

// ─── CiphertextForRecipient (CMS EnvelopedData) ──────────────────

/// Components extracted from a CMS `EnvelopedData` by [`parse_cfr`].
struct EnvelopedFields {
    /// RSA-OAEP-wrapped content-encryption key (`encryptedKey`).
    wrapped_cek: Vec<u8>,
    /// AES-256-CBC initialization vector (16 bytes).
    iv: Vec<u8>,
    /// AES-256-CBC `encryptedContent`, segments concatenated.
    encrypted_content: Vec<u8>,
}

/// The `EncryptedContentInfo` payload — IV plus ciphertext.
struct EncryptedContent {
    iv: Vec<u8>,
    encrypted_content: Vec<u8>,
}

/// Decrypt a KMS `CiphertextForRecipient` into the sealed 32-byte key.
///
/// `cfr_der` is a CMS `EnvelopedData` (RFC 5652) — BER-encoded, possibly
/// with indefinite-length segments. Its single `KeyTransRecipientInfo`
/// carries an AES-256 content-encryption key wrapped under
/// RSAES-OAEP-SHA256 for `priv_key`; the AES-256-CBC `encryptedContent`
/// is the original plaintext with PKCS#7 padding.
fn decrypt_cfr(cfr_der: &[u8], priv_key: &RsaPrivateKey) -> Result<[u8; 32]> {
    // 1-2. BER-parse ContentInfo → EnvelopedData → recipient + content.
    let fields = parse_cfr(cfr_der)?;

    // 3. RSA-OAEP-SHA256 unwrap → 32-byte AES-256 CEK.
    let cek = priv_key
        .decrypt(Oaep::new::<Sha256>(), &fields.wrapped_cek)
        .map_err(|e| eyre!("CFR step 3: RSA-OAEP unwrap of content key: {}", e))?;
    let cek: [u8; 32] = cek.as_slice().try_into().map_err(|_| {
        eyre!(
            "CFR step 3: content key wrong length: expected 32, got {}",
            cek.len()
        )
    })?;

    // 4. IV must be 16 bytes.
    let iv: [u8; 16] = fields.iv.as_slice().try_into().map_err(|_| {
        eyre!(
            "CFR step 4: AES-CBC IV is not 16 bytes (got {})",
            fields.iv.len()
        )
    })?;

    // 5. AES-256-CBC decrypt, strip PKCS#7 padding.
    let mut buf = fields.encrypted_content;
    let plaintext = Aes256CbcDec::new(&cek.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| eyre!("CFR step 5: AES-256-CBC decrypt / PKCS#7 unpad: {}", e))?;

    // 6. Sealed signing key is exactly 32 bytes.
    plaintext.try_into().map_err(|_| {
        eyre!(
            "CFR step 6: sealed key wrong length: expected 32, got {}",
            plaintext.len()
        )
    })
}

/// BER-parse a CMS `ContentInfo`/`EnvelopedData` and extract the
/// recipient's wrapped key, the content-encryption IV, and the
/// (possibly segmented) `encryptedContent`.
///
/// Uses `bcder` in BER mode so AWS KMS's indefinite-length encoding —
/// rejected by strict-DER parsers — decodes correctly.
fn parse_cfr(cfr_der: &[u8]) -> Result<EnvelopedFields> {
    Mode::Ber
        .decode(cfr_der, parse_content_info)
        .map_err(|e: DecodeError<_>| eyre!("CFR step 1-2: BER-parse CMS EnvelopedData: {}", e))
}

/// `ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT EnvelopedData }`.
fn parse_content_info<S: bcder::decode::Source>(
    cons: &mut Constructed<S>,
) -> Result<EnvelopedFields, DecodeError<S::Error>> {
    cons.take_sequence(|seq| {
        let content_type = Oid::take_from(seq)?;
        if content_type.as_ref() != OID_ENVELOPED_DATA {
            return Err(seq.content_err("contentType is not id-envelopedData"));
        }
        // content [0] EXPLICIT — an explicit context tag wrapping the
        // EnvelopedData SEQUENCE.
        seq.take_constructed_if(Tag::CTX_0, parse_enveloped_data)
    })
}

/// `EnvelopedData ::= SEQUENCE { version INTEGER, originatorInfo [0] IMPLICIT
/// OPTIONAL, recipientInfos SET OF RecipientInfo, encryptedContentInfo
/// EncryptedContentInfo, unprotectedAttrs [1] IMPLICIT OPTIONAL }`.
fn parse_enveloped_data<S: bcder::decode::Source>(
    cons: &mut Constructed<S>,
) -> Result<EnvelopedFields, DecodeError<S::Error>> {
    cons.take_sequence(|seq| {
        let _version = seq.take_u8()?;
        // originatorInfo [0] IMPLICIT — optional; skip if present.
        seq.take_opt_constructed_if(Tag::CTX_0, |inner| inner.skip_all())?;

        // recipientInfos SET OF RecipientInfo — take the first.
        let wrapped_cek = seq.take_set(parse_first_recipient)?;

        // encryptedContentInfo.
        let content = parse_encrypted_content_info(seq)?;

        // unprotectedAttrs [1] IMPLICIT — optional; skip if present.
        seq.take_opt_constructed_if(Tag::CTX_1, |inner| inner.skip_all())?;

        Ok(EnvelopedFields {
            wrapped_cek,
            iv: content.iv,
            encrypted_content: content.encrypted_content,
        })
    })
}

/// Take the first `RecipientInfo` from a `SET OF`, require it to be a
/// `KeyTransRecipientInfo`, and return its `encryptedKey` bytes.
///
/// `KeyTransRecipientInfo ::= SEQUENCE { version INTEGER, rid
/// RecipientIdentifier, keyEncryptionAlgorithm AlgorithmIdentifier,
/// encryptedKey OCTET STRING }`.
fn parse_first_recipient<S: bcder::decode::Source>(
    set: &mut Constructed<S>,
) -> Result<Vec<u8>, DecodeError<S::Error>> {
    let wrapped = set.take_sequence(|ktri| {
        // version 0 (issuerAndSerial) or 2 (subjectKeyIdentifier).
        let _version = ktri.take_u8()?;
        // rid: issuerAndSerialNumber SEQUENCE | [0] subjectKeyIdentifier.
        ktri.capture_one()?;
        // keyEncryptionAlgorithm AlgorithmIdentifier (RSAES-OAEP).
        ktri.capture_one()?;
        // encryptedKey OCTET STRING — RSA-OAEP-wrapped CEK.
        let key = ktri.take_value_if(Tag::OCTET_STRING, collect_octets)?;
        Ok(key)
    })?;
    // Reject any further recipientInfos — KMS emits exactly one.
    if set.skip_one()?.is_some() {
        return Err(set.content_err("expected exactly one recipientInfo"));
    }
    Ok(wrapped)
}

/// `EncryptedContentInfo ::= SEQUENCE { contentType OID,
/// contentEncryptionAlgorithm AlgorithmIdentifier, encryptedContent
/// [0] IMPLICIT OCTET STRING OPTIONAL }`.
fn parse_encrypted_content_info<S: bcder::decode::Source>(
    cons: &mut Constructed<S>,
) -> Result<EncryptedContent, DecodeError<S::Error>> {
    cons.take_sequence(|eci| {
        // contentType OID (id-data) — accepted as-is.
        let _content_type = Oid::take_from(eci)?;

        // contentEncryptionAlgorithm: AES-256-CBC, parameter = IV OCTET STRING.
        let iv = eci.take_sequence(|alg| {
            let oid = Oid::take_from(alg)?;
            if oid.as_ref() != OID_AES_256_CBC {
                return Err(alg.content_err("contentEncryptionAlgorithm is not aes-256-CBC"));
            }
            alg.take_value_if(Tag::OCTET_STRING, collect_octets)
        })?;

        // encryptedContent [0] IMPLICIT OCTET STRING — primitive, or a
        // constructed (segmented) OCTET STRING under indefinite-length
        // BER. `collect_octets` reads its content by tag, so the
        // IMPLICIT context tag here is matched by `take_opt_value_if`.
        let encrypted_content = eci
            .take_opt_value_if(Tag::CTX_0, collect_octets)?
            .ok_or_else(|| eci.content_err("EnvelopedData has no encryptedContent"))?;

        Ok(EncryptedContent {
            iv,
            encrypted_content,
        })
    })
}

/// Collect the octets of an OCTET STRING value's content, concatenating
/// every segment of a constructed (indefinite-length BER) encoding.
///
/// `from_content` keys off the value's primitive/constructed form, not
/// its outer tag, so this also serves IMPLICIT-tagged OCTET STRINGs.
fn collect_octets<S: bcder::decode::Source>(
    content: &mut bcder::decode::Content<S>,
) -> Result<Vec<u8>, DecodeError<S::Error>> {
    let octet_string = bcder::OctetString::from_content(content)?;
    Ok(octet_string.octets().collect())
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
    let host = format!("kms.{}.amazonaws.com", creds.region);
    let url = format!("https://{}/", host);
    let mut req = HttpRequest::builder()
        .method("POST")
        .uri(&url)
        .header("host", &host)
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
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let host = format!("{}.s3.{}.amazonaws.com", creds.eif_bucket, creds.region);
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
    key: &str,
    body: &[u8],
) -> Result<()> {
    let host = format!("{}.s3.{}.amazonaws.com", creds.eif_bucket, creds.region);
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
        .region(creds.region.as_str())
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

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePrivateKey;

    // Test vectors generated with the OpenSSL CLI (3.2.x):
    //
    //   openssl genrsa -out priv.pem 2048
    //   openssl req -new -x509 -key priv.pem -out cert.pem -days 3650 \
    //     -subj "/CN=tee-oracle-test"
    //   printf 'KASKAD-SEALED-KEY-TEST-VECTOR-AB' > plain.bin   # 32 bytes
    //
    //   # definite-length DER:
    //   openssl cms -encrypt -binary -aes-256-cbc -in plain.bin \
    //     -recip cert.pem -keyopt rsa_padding_mode:oaep \
    //     -keyopt rsa_oaep_md:sha256 -outform DER -out cms_def.der
    //
    //   # indefinite-length BER (-stream forces streaming CMS output —
    //   # this is the encoding AWS KMS emits and that broke the old
    //   # strict-DER parser):
    //   openssl cms -encrypt -binary -aes-256-cbc -in plain.bin \
    //     -recip cert.pem -keyopt rsa_padding_mode:oaep \
    //     -keyopt rsa_oaep_md:sha256 -outform DER -stream \
    //     -out cms_indef.der
    //
    //   # private key as PKCS#8 DER (rsa crate built without `pem`):
    //   openssl pkcs8 -topk8 -nocrypt -inform PEM -in priv.pem \
    //     -outform DER -out priv_pkcs8.der

    /// RSA-2048 private key, PKCS#8 DER, hex.
    const KEY_PKCS8_DER_HEX: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b3f8c9a705643c06562964f20accd6a96f3ef827dbee54cfc759f0dbaf80e0b35ce379133be9accd7f5727f048e7472f47b8408c97a9ad473825f1fb6f68c6a5180703e5f87f23d25b15de16dc2ff2ba5f48c59076f9d25afec014dae12514d733989d980106beb04adbfc43770b072ef70f22d8d4dd11e6ef1b5f5bfa92bacfbd8492e523b25b4f22ce301ec8c5dd94cc75aa6a0f3b369469b857e0df52238dcde9a2b85864595efc87218d5532e15fef35d7ba1ece33b7d2ae794d0363eee228a1358b153ec4350e72e0ec97c67bc6b258e8152fec4fa5ccc2f219fe75ad755ce2d1026bfac92694568a4c8d13a3cf659c4b12bbc17a095d36e74c9285a78d02030100010282010057975fc9a6d19c77370b2982b5e7f11800b9447cddc916c51390be2da5b2d369e86d1bb9d5408b266ef223d18a21ea1ee448943df8f88f89a895ab3ac503d91e73ddc23374a8a86e127fc79a17ab4c7711b5f0d5b95a285bba3e11486028b48672a9b615cb76156be6db3f6134788d13fa118753c1f2206ae577cc870f22c7c14e82ef49c7a88c2c8980307943da327d44a5bdf12bed1eeb7aa9b228817a7a132c209fef60e2f11af08ea5a81b07eb0699efa6a46be2faaa30cd6f92d558f78c20d66b66f0ea97f84a9ffb7ef0bd16aa2aea878e2f44d9e5f4301681857fdcd67668a700358a5ddbafcf204abb909a60759b4c06d5612064d0fc7a5a350207df02818100f06dccce779cad7229278965c8e26a238ff796dbebb449207694795526a0e081cca29f63ad765e6979d3fa705e5e8391caf10c81876396d67be0678775357a619a71558869a34af6903225fd3baa24b6183f7c482f74bac93bf910e8bba80b49bb85f3bd918677b85d918176bd236b4d412b129ec9a8d68d853e0b59fc1a44d702818100bfa0a32555012149af77190029c29d2f84c631636f076781c40ad98e5847de5c2bb02d38e21d108dc719b0d31467afbbec4d3b850ae1f9765a729e5e48315447fc412f636691577ce3e640ab0c8a8676cfd7f316b18e3bc143bc2b75b2c1181f0f48069150fa23c539dd7c1aebc1f5a6d12dcd28263796a9aa308e7dd9e3463b02818059e8054d33e74fe8bfc0fc1d26c89bfe1e68ec6de2af3125459271e8c8a02234078ccc639ecb03b5178c903b12deeefe46d06ae7c8f411c4b4e00e76d5faa07ffd1be26b376d8babb5f23ac87e563a9229711c0d7649854b98f4a34114635b8d3fe57066f4133f939ed1b982e8696547a755ef0997c95e29dfa87ae03468b25302818026fab314fdf48be3e43852b290cc109340ebdbd2011cbd764cfd74019b7d8b02aeb4588e90981eece80a16c8e906aa5d8c94ad3dc3d7f1999c8e621e858adb3d0557f11ec4175e777e1831215a1cb77b658de4d9c1e64fcb614ede7c438f39abdfbce3f11d4ab48a02da45cb68177d33a0ab33672e56f263b2c5cbc657d2fe4f02818100eca75f3794987fbbcd5c44cc6ab5de8c56d30816f2fd7430924f6f9311b0db4e54448adb018b27d8458636a9628b7cce6d1643fdbbbf83cd0034a524f8cf0ec8776b090520ce299c2674d29ae9fc0b17eb3b61e6ee7fb65a49669271d53db758de3127ec1d251d99e244703549462decc4cb68635fe8c16a4c60a2148a946385";

    /// CMS `EnvelopedData`, definite-length DER, hex.
    const CMS_DEFINITE_HEX: &str = "308201f106092a864886f70d010703a08201e2308201de02010031820179308201750201003032301a3118301606035504030c0f7465652d6f7261636c652d7465737402145f298b2bc448fe9a1da463425cab3f2ba7b8c782303806092a864886f70d010107302ba00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201048201004041fdfef20e8b29d96385857083185c6a5074f8f59ea0f10fa4db5991d5d54a868a90152f3eb3e09f099870027da1b8bd634e9da4c02a09a1fb2463f0c5cb941a8047bd52c114d0f431b9db95a1ef73d5bd35382e9fb4129001c3ee9bbcb91ad5e446d01df74fb89910236197d5d9d3fcb72d51538b14d5db9ad6406e9b237536ee3d4dd64606c33b7aade3ba91bca4f39b7dad636be72c2e8dbba0759da5b545835c62e51eb9aa2793aa4d886b85078e7b840d10f2cf5f1270c46fc295125dbade9284dfe38e3e35f86a33ab68ea6f14384bff7baab96fc3ec16fb2f04f77e831d34a9ad35a12eed2aae15af42fd00175cd3651aeb7a8d5711c045460a11fb305c06092a864886f70d010701301d060960864801650304012a0410e0e6e14e44fa704617e9bb0ce6cdb4828030cd338db31cec63f498cbcc2ced5169fcf110b1e2a8710f7eb60dc9f86023f03eb6272b3273058afb308ef92583d7f144";

    /// CMS `EnvelopedData`, indefinite-length BER (`openssl ... -stream`),
    /// hex. `encryptedContent` here is a constructed, segmented OCTET
    /// STRING — the case that broke the old RustCrypto `der` parser.
    const CMS_INDEFINITE_HEX: &str = "308006092a864886f70d010703a080308002010031820179308201750201003032301a3118301606035504030c0f7465652d6f7261636c652d7465737402145f298b2bc448fe9a1da463425cab3f2ba7b8c782303806092a864886f70d010107302ba00d300b0609608648016503040201a11a301806092a864886f70d010108300b0609608648016503040201048201003e18a408947bb1e16e3c2fe00784ae4defea829f5d4b75f20429ae966f351f386e437a14c1d99ca2667b03921c0efe9ec75a626869fa014e5d6d5bcea14c9259f05b868b7b015c6dc702c5b383237eaed7dac365cb34931b0a0d1d308e3945d479f2b70b3abffe20f326b705a33090378f6482410a8e66c6400e2e662acea5c50509dc8add0202a465187c28dcbda408155ef697e6d8e1a7ca41841db5fdf7933f1faf18edcc7c7dc355eca6d6165431694c8d3e64192f6948b97b0c8f8d4fee5cf4a682fda3b661928ec48c25a0508ac08427a627d17b5ef91fb51b93b93336c52c98cdd56a8db5f252a8f1b5c22780ca5b7349c30f04145d8a6198426b09d2308006092a864886f70d010701301d060960864801650304012a04107a2e536e2fc1be3f5efbb8f0ed6e92eea0800420d32a316247bb958803e6e896eff37d0fdd8b2ff44f33a2bde4336ce62a0fef890410bff8664fc17213ad04f12512dde94aae00000000000000000000";

    /// An unrelated RSA-2048 key (PKCS#8 DER, hex) — recipient mismatch
    /// fixture for the negative test. Generated the same way as the
    /// real key but never used to encrypt the vectors.
    const WRONG_KEY_PKCS8_DER_HEX: &str = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100f2c5c5029a25745421a4b636dbd87107ca90fb2aaf63ada822efba142f8c747f26c1b33d811ed6963739dcfc9b4825d510d38d99b555104d0f748c5ea9e4eadcddc5f1493c0e93068696f3f35536b25d308238b1a00b5097f995f4d8190e74e5d76ae8b929296cd33a63deae15edea574508618760a5ace25505cad871446733a60295139074b4120e07a232fe08e8811cb349f590c225e448b30b9438f9813ad1e317354eeb0e07e3dabe1c1871c327bc56d996de946fe01795a43b48a7a43815d7da78cbefdafd55d0a26b8e95d61b60d443c60b7da05577a667f0a99d06c39386cfa0a7657c8ab298f05a0e6f67ee2c7b982de3b3373fa3e7ab0b6372c22702030100010282010014e06438521070781fa0836424f44586aefe580041597d55c7bdfd041406ac5496d2475b3d9eecedb94d5f84801c972c42fdd38a693e7f0ab163e0acef47d683d70a58dd11ae0b29f4d446f6cb82caef1a91c82af6214d9fe9558cdadc64bd86af9c9640a89a7dace308dd8848d879b3617b5405093996015735b54e21875ea70bcf41d06cd59bb47ebe7e21bdfa480e71bbe917bf02e7182011d79c299cebb8a97759ea7966322a823ef88c83cbae636bc7077fd477bd6624ad6765cd5f8b7e18bc40d1eeff984d636ecafa2059a82aab624a1aa26aad4a9a70e8dba79f9103f23b7a01d4888422b0caa1902aa5832a443a7eb3f424a30a2036b1ca1a26eb7902818100fb4d976d321f340496e634dce2c6a13ba9cebecb85c7dd15cd17880427741d6049ac9be0f84c1e003cd930863b3d34a0c1df40136b56f3aa60eefb8e124a39316065360aa1183d0fe7b4c18582b004d8653ed1c1ce8b522667784c967cffeeba867a6157439e552da510e5cabfe2c1d97edec779b745c9b7ef964256eaa1bdf302818100f74f5ca9bef38dfa6d51bff0461bd50a39623e0c5869b501f11f943026ab8fe78f7ecfad28ffb66a062e0c6f6f1dd5fdc1d502d86196e3394c700dfec696acbdfcf9ec44de8119552d79dfdb85f6e76dea24776912afe8486c28530482dd993f012c662c054b1cfb685a0277dba769a15387d11f5e4ad9e502ca4cc340bb13fd02818100de23414681f6b9199175dea69e432c44bc1e87e309d798e36b8e706a13a1fd519eee583feddc02ecfcdc939b24043f6016dfcc191e5a173bb541aad573ef6e4cea43ad188a3c0dc5e070945bfb20b2b7c20f5c852f9951bda6dadd006d70224b7911f6b7978aff0a410e05c24a0a1c86b032272bbd48903dea27ed6e3d2b49e702818060e3138f60c2b40db7043ee8d7de9180d6e8591ca70a8aa23f1fbb037e32da46c29dd0a8ab163b15a0642bf50018353c9bd262b1f8d18f25647fc5cbd96b3033a2471b3c03db99dc17dbd64a7f5a32628a474d0cba08763ce13a8f03866d605b218f8e5b929b51b860b25aa330478f0767dd1e9d666876a2d48c02b4bfc84ad502818057b7962d3dc6ff563f4ecab1dc575880d4dd7178522a3b7a447c69112863fa5aff755126327c503db160c3361ab1eba2d6b07d77a92b6520defc9c78b4cf013d180afb35616570cedf2705708c71644f2440557b181b58ea8e42da86db8452a5d2e0986c15b07fcacc481af1b5c9622cf99dea3d5874a1cf942d6301cde4f334";

    /// The 32-byte plaintext both vectors encrypt.
    const EXPECTED_PLAINTEXT: &[u8; 32] = b"KASKAD-SEALED-KEY-TEST-VECTOR-AB";

    fn key_from_hex(hex_der: &str) -> RsaPrivateKey {
        let der = hex::decode(hex_der).expect("decode key hex");
        RsaPrivateKey::from_pkcs8_der(&der).expect("parse PKCS#8 key")
    }

    fn test_key() -> RsaPrivateKey {
        key_from_hex(KEY_PKCS8_DER_HEX)
    }

    /// Definite-length DER `EnvelopedData` decrypts to the known plaintext.
    #[test]
    fn decrypt_cfr_definite_length() {
        let cfr = hex::decode(CMS_DEFINITE_HEX).expect("decode CMS hex");
        let out = decrypt_cfr(&cfr, &test_key()).expect("decrypt definite-length CFR");
        assert_eq!(&out, EXPECTED_PLAINTEXT);
    }

    /// Indefinite-length BER `EnvelopedData` — segmented `encryptedContent`
    /// — decrypts to the known plaintext. This is the regression case:
    /// the old strict-DER parser rejected it with "indefinite length
    /// disallowed".
    #[test]
    fn decrypt_cfr_indefinite_length_ber() {
        let cfr = hex::decode(CMS_INDEFINITE_HEX).expect("decode CMS hex");
        let out = decrypt_cfr(&cfr, &test_key()).expect("decrypt indefinite-length CFR");
        assert_eq!(&out, EXPECTED_PLAINTEXT);
    }

    /// A wrong RSA key fails at the RSA-OAEP unwrap step rather than
    /// panicking or silently returning garbage.
    #[test]
    fn decrypt_cfr_wrong_key_errors() {
        let other = key_from_hex(WRONG_KEY_PKCS8_DER_HEX);
        let cfr = hex::decode(CMS_DEFINITE_HEX).expect("decode CMS hex");
        let err = decrypt_cfr(&cfr, &other).expect_err("must fail with wrong key");
        assert!(err.to_string().contains("step 3"), "got: {err}");
    }

    /// Truncated / non-CMS input is rejected at the BER-parse step.
    #[test]
    fn decrypt_cfr_garbage_errors() {
        let err = decrypt_cfr(&[0x30, 0x03, 0x02, 0x01, 0x00], &test_key())
            .expect_err("must reject non-CMS input");
        assert!(err.to_string().contains("step 1-2"), "got: {err}");
    }
}
