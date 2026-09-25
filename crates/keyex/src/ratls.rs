//! RA-TLS transport for the Pontifex keyex: TLS 1.3 mutual auth with custom
//! verifiers that trust the attestation, not PKI, plus the in-band nonce +
//! attestation exchange that binds each attested key to its TLS channel.
//!
//! The verifiers accept any presented chain but MUST still validate the TLS 1.3
//! `CertificateVerify` signature (`rustls::crypto::verify_tls13_signature`) —
//! that proves the peer holds the presented cert's private key and is the MITM
//! defence this module exists for. TLS 1.2 is rejected outright.
//!
//! After the handshake, both directions: send a 32-byte nonce, read the peer's,
//! attest with `nonce = peer's nonce` / `public_key = my TLS point`, verify the
//! peer's attestation with `expected_nonce = my nonce`, check the channel
//! binding ([`crate::binding`]), then apply the policy engine
//! ([`crate::policy`]). Every refusal/error path zeroizes the transferable key.
//!
//! Framing: each in-band message is a 4-byte big-endian length + payload (raw,
//! not JSON — the JSON VSOCK API of ENCLAVE.md wraps this channel, it is not
//! inside it).

use std::sync::Arc;

use eyre::{bail, eyre, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig,
    SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::{Zeroize, Zeroizing};

use crate::binding::{check_nonce, check_peer_key, AttestationView};
use crate::kdf::derive_child;
use crate::policy::{
    client_accepts_server, decide_handover, ClientDecision, ClientRefusal, EnclaveRole, FetchKind,
    HandoffRefusal, ImageIdentity, KeyDecision, VerifiedApproval,
};

/// Upper bound on a single in-band frame. Attestation documents are ~5 KiB;
/// this caps a hostile length prefix well under the TLS record machinery.
const MAX_FRAME: usize = 64 * 1024;

/// Nonce length: 32 bytes of CSPRNG output (ENCLAVE.md).
pub const NONCE_LEN: usize = 32;

/// Draw a fresh channel nonce. The enclave passes `nitro_common` `NsmRng`; the
/// caller owns the CSPRNG so the enclave never falls back to `OsRng`.
pub fn fresh_nonce<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut n);
    n
}

/// The 32-byte secp256k1 key that may cross the channel.
pub type TransferKey = [u8; 32];

// ---------------------------------------------------------------------------
// Crypto provider + ephemeral cert
// ---------------------------------------------------------------------------

/// The ring-backed [`CryptoProvider`] this crate builds all configs and
/// verifiers on. Passed explicitly (never installed process-wide) so tests and
/// the enclave share one deterministic backend.
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A freshly generated ephemeral self-signed cert over a P-256 key, plus the
/// 65-byte uncompressed EC point of that key — the bytes an attestation binds
/// (`public_key`), NOT the SPKI DER wrapper (see [`public_point_from_cert`]).
pub struct EphemeralCert {
    pub cert_der: CertificateDer<'static>,
    pub key_der: PrivateKeyDer<'static>,
    pub public_point: Vec<u8>,
}

/// Generate an rcgen self-signed cert over a fresh P-256 key.
pub fn generate_ephemeral_cert() -> Result<EphemeralCert> {
    let certified = rcgen::generate_simple_self_signed(vec!["ratls.local".to_string()])
        .map_err(|e| eyre!("rcgen self-signed cert: {e}"))?;
    let cert_der = certified.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let public_point = public_point_from_cert(&cert_der)?;
    Ok(EphemeralCert {
        cert_der,
        key_der,
        public_point,
    })
}

/// Extract the 65-byte uncompressed EC point (`0x04 || X || Y`) from a cert's
/// SubjectPublicKeyInfo BIT STRING — the value an attestation binds as its
/// `public_key`. Deliberately the raw SEC1 point, not the SPKI DER SEQUENCE:
/// `nitro_common::verify` forces an attestation `public_key` to be exactly a
/// 65-byte `0x04` point, and both P-256 (RA-TLS cert) and secp256k1 (oracle
/// signer) uncompressed points share that shape, so the [`crate::binding`]
/// channel check compares like against like. Returning the ~91-byte SPKI DER
/// here would make that comparison fail closed on every real handshake.
pub fn public_point_from_cert(cert: &CertificateDer<'_>) -> Result<Vec<u8>> {
    use x509_cert::der::Decode;
    let parsed = x509_cert::Certificate::from_der(cert.as_ref())
        .map_err(|e| eyre!("parse peer cert: {e}"))?;
    let point = parsed
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    if point.len() != 65 || point[0] != 0x04 {
        bail!(
            "cert public key is not a 65-byte uncompressed EC point ({} bytes)",
            point.len()
        );
    }
    Ok(point.to_vec())
}

// ---------------------------------------------------------------------------
// Custom verifiers: trust the attestation, not PKI
// ---------------------------------------------------------------------------

/// Accepts any presented chain but verifies the TLS 1.3 `CertificateVerify`
/// signature and refuses TLS 1.2. One struct serves both roles: as
/// [`ServerCertVerifier`] on the client and [`ClientCertVerifier`] on the
/// server.
#[derive(Debug)]
pub struct AttestationCertVerifier {
    provider: Arc<CryptoProvider>,
}

impl AttestationCertVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Arc<Self> {
        Arc::new(Self { provider })
    }

    fn schemes(&self) -> &WebPkiSupportedAlgorithms {
        &self.provider.signature_verification_algorithms
    }
}

/// TLS 1.2 is never permitted; keyex pins TLS 1.3.
fn reject_tls12() -> Result<HandshakeSignatureValid, TlsError> {
    Err(TlsError::General("RA-TLS requires TLS 1.3".into()))
}

impl ServerCertVerifier for AttestationCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // Any chain is accepted: the in-band attestation, not PKI, is the trust
        // root. The channel is still bound by verify_tls13_signature below.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        reject_tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        // Proves the peer holds the presented cert's private key. Skipping this
        // is the MITM hole this slice closes.
        verify_tls13_signature(message, cert, dss, self.schemes())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes().supported_schemes()
    }
}

impl ClientCertVerifier for AttestationCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        reject_tls12()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, self.schemes())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes().supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// Config builders (TLS 1.3 only, mutual auth, custom verifiers)
// ---------------------------------------------------------------------------

/// Client config: presents `cert`, verifies the server with the attestation
/// verifier, TLS 1.3 only.
pub fn client_config(provider: Arc<CryptoProvider>, cert: &EphemeralCert) -> Result<ClientConfig> {
    let verifier = AttestationCertVerifier::new(provider.clone());
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| eyre!("client TLS1.3 versions: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![cert.cert_der.clone()], cert.key_der.clone_key())
        .map_err(|e| eyre!("client auth cert: {e}"))
}

/// Server config: presents `cert`, requires + verifies a client cert with the
/// attestation verifier, TLS 1.3 only.
pub fn server_config(provider: Arc<CryptoProvider>, cert: &EphemeralCert) -> Result<ServerConfig> {
    let verifier = AttestationCertVerifier::new(provider.clone());
    ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| eyre!("server TLS1.3 versions: {e}"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert.cert_der.clone()], cert.key_der.clone_key())
        .map_err(|e| eyre!("server single cert: {e}"))
}

// ---------------------------------------------------------------------------
// Injected attestation seams
// ---------------------------------------------------------------------------

/// Produce this enclave's NSM attestation over `(peer nonce, my TLS point)`.
/// The enclave passes the real NSM `Request::Attestation`; tests pass a fake.
/// Off hardware the real fresh-nonce document cannot be produced (slice 12).
pub trait AttestFn {
    fn attest(&self, nonce: &[u8; NONCE_LEN], my_point: &[u8]) -> Vec<u8>;
}

impl<F: Fn(&[u8; NONCE_LEN], &[u8]) -> Vec<u8>> AttestFn for F {
    fn attest(&self, nonce: &[u8; NONCE_LEN], my_point: &[u8]) -> Vec<u8> {
        self(nonce, my_point)
    }
}

/// The three fields the binding checks read off a cryptographically-verified
/// peer attestation: its PCR0, the nonce it answers, and the key it attests.
pub struct VerifiedPeer {
    pub pcr0: [u8; 48],
    pub nonce: Option<Vec<u8>>,
    pub public_key: Vec<u8>,
}

/// Cryptographically verify a peer attestation document (COSE ES384, chain to
/// the pinned AWS Nitro root at the injected clock, timestamp, nonce) and
/// surface the fields binding needs. The enclave wires this to
/// `nitro_common::verify_attestation`; tests pass a fake because a genuine
/// fresh-nonce NSM document is off-hardware (slice 12).
pub trait PeerVerifier {
    fn verify(&self, doc: &[u8], my_nonce: &[u8; NONCE_LEN]) -> Result<VerifiedPeer>;
}

/// Production verifier: full `nitro_common` cryptographic check against an
/// injected clock, then a structural re-parse to surface the nonce (which
/// `verify_attestation` consumes and drops).
pub struct NsmPeerVerifier {
    pub now_unix_secs: u64,
}

impl PeerVerifier for NsmPeerVerifier {
    fn verify(&self, doc: &[u8], my_nonce: &[u8; NONCE_LEN]) -> Result<VerifiedPeer> {
        // Nonce pins freshness → no max_age. Fail-closed on any COSE/chain error.
        let verified = nitro_common::verify::verify_attestation(
            doc,
            self.now_unix_secs,
            None,
            Some(my_nonce),
        )?;
        // Take the key from the VERIFIED struct (semantic_checks already forced
        // a 65-byte 0x04 point); re-parse only to surface the nonce verify drops.
        let parsed = nitro_common::attest::parse_attestation_doc(doc)?;
        Ok(VerifiedPeer {
            pcr0: verified.pcr0,
            nonce: parsed.nonce,
            public_key: verified.public_key,
        })
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// Why the post-handshake exchange refused. Closed set → real enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeRefusal {
    /// Peer attestation failed COSE/chain/timestamp/nonce verification.
    AttestationInvalid,
    /// Attested nonce did not answer our channel nonce.
    NonceMismatch,
    /// Attested key did not equal the peer's TLS public-key point.
    KeyMismatch,
    /// Server handover policy refused this attested peer.
    PolicyRefused(HandoffRefusal),
    /// Client saw the server decline to hand a key over.
    ServerDeclined,
    /// Client acceptance policy rejected the server's attested identity.
    ClientRejected(ClientRefusal),
    /// Framing/protocol error on the wire.
    Protocol,
}

/// Server side outcome. On a hand-over the key was framed to the client and
/// the local copy wiped; on refusal a decline marker was sent and the key
/// wiped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerExchange {
    HandedOwnKey,
    HandedChild,
    Refused(ExchangeRefusal),
}

/// Client side outcome. `Installed` carries the received key in a wiping
/// wrapper for the caller to install; every other path leaves no key.
pub enum ClientExchange {
    Installed(Zeroizing<TransferKey>),
    Refused(ExchangeRefusal),
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| eyre!("frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        bail!("frame length {len} exceeds max {MAX_FRAME}");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Send my nonce, read the peer's, attest with the peer's nonce, exchange
/// documents. Returns `(peer_nonce, peer_doc)`. Shared by both sides.
async fn nonce_and_doc_exchange<S, A>(
    stream: &mut S,
    my_nonce: &[u8; NONCE_LEN],
    my_point: &[u8],
    attest_fn: &A,
) -> Result<([u8; NONCE_LEN], Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
    A: AttestFn,
{
    write_frame(stream, my_nonce).await?;
    let peer_nonce_bytes = read_frame(stream).await?;
    let peer_nonce: [u8; NONCE_LEN] = peer_nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| eyre!("peer nonce is not {NONCE_LEN} bytes"))?;

    // My attestation answers the PEER's nonce and binds MY TLS point.
    let my_doc = attest_fn.attest(&peer_nonce, my_point);
    write_frame(stream, &my_doc).await?;
    let peer_doc = read_frame(stream).await?;
    Ok((peer_nonce, peer_doc))
}

/// Verify + bind a peer document to this channel. Typed refusal on failure.
fn evaluate_peer(
    verifier: &impl PeerVerifier,
    peer_doc: &[u8],
    my_nonce: &[u8; NONCE_LEN],
    peer_point: &[u8],
) -> Result<VerifiedPeer, ExchangeRefusal> {
    let verified = verifier
        .verify(peer_doc, my_nonce)
        .map_err(|_| ExchangeRefusal::AttestationInvalid)?;
    let view = AttestationView::new(verified.nonce.as_deref(), &verified.public_key);
    check_nonce(&view, my_nonce).map_err(|_| ExchangeRefusal::NonceMismatch)?;
    check_peer_key(&view, peer_point).map_err(|_| ExchangeRefusal::KeyMismatch)?;
    Ok(verified)
}

/// Wipe a secret and yield the refusal. Every server refusal/error routes here
/// so the transferable key is zeroized before the function returns.
fn refuse_wipe<Z: Zeroize>(mut secret: Z, reason: ExchangeRefusal) -> ServerExchange {
    secret.zeroize();
    ServerExchange::Refused(reason)
}

// ---------------------------------------------------------------------------
// Channel context + role inputs (bundled so signatures stay small)
// ---------------------------------------------------------------------------

/// The post-handshake TLS stream plus the six fixed facts every exchange reads:
/// my nonce and TLS point, the peer's TLS point (from its cert), and the
/// injected verify + attest seams. Borrowed; `stream` is the mutable half.
pub struct Channel<'a, S, V, A> {
    pub stream: &'a mut S,
    pub my_nonce: &'a [u8; NONCE_LEN],
    pub my_point: &'a [u8],
    pub peer_point: &'a [u8],
    pub verifier: &'a V,
    pub attest_fn: &'a A,
}

/// Server-side policy inputs for [`decide_handover`].
pub struct HandoverInputs<'a> {
    pub own: &'a ImageIdentity,
    pub role: EnclaveRole,
    pub own_key_is_candidate: bool,
    pub approvals: &'a [VerifiedApproval],
}

/// Client-side policy inputs for [`client_accepts_server`].
pub struct AcceptInputs<'a> {
    pub kind: FetchKind,
    pub own_pcr0: &'a [u8; 48],
    pub baked_ancestors: &'a [[u8; 48]],
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Grant frame tags. Closed set on the wire; mirrored by the client reader.
const TAG_DECLINE: u8 = 0;
const TAG_GRANT: u8 = 1;

/// Server post-handshake exchange: attest the client, then decide handover and
/// either frame the key or decline. `own_key` is this enclave's key; it is
/// wiped on every non-grant path and after a successful send.
///
/// Generic over the secret wrapper so the wipe is observable in tests; the
/// enclave passes `Zeroizing<TransferKey>`.
pub async fn server_exchange<S, V, A, K>(
    ctx: Channel<'_, S, V, A>,
    inputs: HandoverInputs<'_>,
    mut own_key: K,
) -> Result<ServerExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: PeerVerifier,
    A: AttestFn,
    K: Zeroize + AsRef<[u8; 32]>,
{
    let Channel {
        stream,
        my_nonce,
        my_point,
        peer_point,
        verifier,
        attest_fn,
    } = ctx;
    let HandoverInputs {
        own,
        role,
        own_key_is_candidate,
        approvals,
    } = inputs;

    let (_peer_nonce, peer_doc) =
        match nonce_and_doc_exchange(stream, my_nonce, my_point, attest_fn).await {
            Ok(v) => v,
            Err(_) => {
                // I/O or framing failure: wipe and decline, best-effort.
                own_key.zeroize();
                let _ = write_frame(stream, &[TAG_DECLINE]).await;
                return Ok(ServerExchange::Refused(ExchangeRefusal::Protocol));
            }
        };

    let verified = match evaluate_peer(verifier, &peer_doc, my_nonce, peer_point) {
        Ok(v) => v,
        Err(reason) => {
            // Decline is best-effort; the wipe must run regardless of its I/O.
            let _ = write_frame(stream, &[TAG_DECLINE]).await;
            return Ok(refuse_wipe(own_key, reason));
        }
    };

    match decide_handover(own, role, &verified.pcr0, own_key_is_candidate, approvals) {
        KeyDecision::OwnKey => {
            // Zeroizing frame: an async panic/timeout between fill and send still
            // wipes the key copy on drop, not just on the explicit path below.
            let mut frame = Zeroizing::new(Vec::with_capacity(1 + 32));
            frame.push(TAG_GRANT);
            frame.extend_from_slice(own_key.as_ref());
            own_key.zeroize();
            write_frame(stream, &frame).await?;
            Ok(ServerExchange::HandedOwnKey)
        }
        KeyDecision::Child(label) => {
            let child = Zeroizing::new(derive_child(own_key.as_ref(), &label));
            own_key.zeroize();
            let mut frame = Zeroizing::new(Vec::with_capacity(1 + 32));
            frame.push(TAG_GRANT);
            frame.extend_from_slice(child.as_ref());
            write_frame(stream, &frame).await?;
            Ok(ServerExchange::HandedChild)
        }
        KeyDecision::Refuse(r) => {
            let _ = write_frame(stream, &[TAG_DECLINE]).await;
            Ok(refuse_wipe(own_key, ExchangeRefusal::PolicyRefused(r)))
        }
    }
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Client post-handshake exchange: attest the server, decide acceptance, then
/// read the grant. A received key is wiped unless our own policy accepted and
/// the server granted; on any refusal no key is returned.
pub async fn client_exchange<S, V, A>(
    ctx: Channel<'_, S, V, A>,
    inputs: AcceptInputs<'_>,
) -> Result<ClientExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: PeerVerifier,
    A: AttestFn,
{
    let Channel {
        stream,
        my_nonce,
        my_point,
        peer_point,
        verifier,
        attest_fn,
    } = ctx;
    let AcceptInputs {
        kind,
        own_pcr0,
        baked_ancestors,
    } = inputs;

    let (_peer_nonce, peer_doc) =
        nonce_and_doc_exchange(stream, my_nonce, my_point, attest_fn).await?;

    let verified = match evaluate_peer(verifier, &peer_doc, my_nonce, peer_point) {
        Ok(v) => v,
        Err(reason) => return drain_and_refuse(stream, reason).await,
    };

    let decision = client_accepts_server(kind, own_pcr0, &verified.pcr0, baked_ancestors);

    // Always read the server's grant frame so the stream stays in step; wipe
    // whatever arrives unless we accepted.
    let frame = Zeroizing::new(read_frame(stream).await?);
    if frame.first() == Some(&TAG_GRANT) && frame.len() == 1 + 32 {
        match decision {
            ClientDecision::Reject(r) => {
                // Server would hand over, but our policy rejects it — wipe, refuse.
                Ok(ClientExchange::Refused(ExchangeRefusal::ClientRejected(r)))
            }
            ClientDecision::Accept => {
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&frame[1..]);
                Ok(ClientExchange::Installed(key))
            }
        }
    } else {
        // Decline marker (or anything not a well-formed grant): no key.
        Ok(ClientExchange::Refused(ExchangeRefusal::ServerDeclined))
    }
}

/// Client hit a binding/verification refusal before the grant. Read and drop
/// the server's frame (stream stays in step, any key bytes are wiped on drop).
async fn drain_and_refuse<S>(stream: &mut S, reason: ExchangeRefusal) -> Result<ClientExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let _drained = Zeroizing::new(read_frame(stream).await.unwrap_or_default());
    Ok(ClientExchange::Refused(reason))
}

// ---------------------------------------------------------------------------
// Handshake drivers: bind the exchange to a LIVE TLS session
// ---------------------------------------------------------------------------

/// The four facts a handshake driver needs beyond the transport: this enclave's
/// ephemeral cert (its private key drives the TLS handshake, its public point is
/// what the exchange attests), this channel's nonce, and the injected verify +
/// attest seams. Bundled so the driver signatures stay small.
pub struct Handshake<'a, V, A> {
    pub my_cert: &'a EphemeralCert,
    pub my_nonce: &'a [u8; NONCE_LEN],
    pub verifier: &'a V,
    pub attest_fn: &'a A,
}

/// The peer's 65-byte SEC1 point read off a LIVE post-handshake rustls session —
/// the binding's ground truth. It comes from the leaf the peer proved possession
/// of via TLS 1.3 `CertificateVerify`, never a caller-supplied value. Fail-closed
/// if the peer presented no leaf (mutual auth should make that unreachable).
fn live_peer_point(peer_certs: Option<&[CertificateDer<'_>]>) -> Result<Vec<u8>> {
    let leaf = peer_certs
        .and_then(|chain| chain.first())
        .ok_or_else(|| eyre!("peer presented no certificate after handshake"))?;
    public_point_from_cert(leaf)
}

/// Server side: accept the TLS 1.3 session over `transport`, bind the channel to
/// the client's real TLS point, then run [`server_exchange`]. This closes the gap
/// between "a handshake happened" and "the exchange is bound to THIS session":
/// `peer_point` is read from the live connection, not passed in, so a MITM cannot
/// present one cert to TLS and attest a different key in band.
pub async fn run_server_handshake<S, V, A, K>(
    acceptor: &TlsAcceptor,
    transport: S,
    hs: Handshake<'_, V, A>,
    inputs: HandoverInputs<'_>,
    own_key: K,
) -> Result<ServerExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: PeerVerifier,
    A: AttestFn,
    K: Zeroize + AsRef<[u8; 32]>,
{
    let mut tls = acceptor.accept(transport).await?;
    // Read the peer point BEFORE the mutable borrow the exchange takes; the
    // immutable borrow of `tls` ends with this statement.
    let peer_point = live_peer_point(tls.get_ref().1.peer_certificates())?;
    let ctx = Channel {
        stream: &mut tls,
        my_nonce: hs.my_nonce,
        my_point: &hs.my_cert.public_point,
        peer_point: &peer_point,
        verifier: hs.verifier,
        attest_fn: hs.attest_fn,
    };
    server_exchange(ctx, inputs, own_key).await
}

/// Client side: connect the TLS 1.3 session to `server_name` over `transport`,
/// bind the channel to the server's real TLS point, then run [`client_exchange`].
pub async fn run_client_handshake<S, V, A>(
    connector: &TlsConnector,
    server_name: ServerName<'static>,
    transport: S,
    hs: Handshake<'_, V, A>,
    inputs: AcceptInputs<'_>,
) -> Result<ClientExchange>
where
    S: AsyncRead + AsyncWrite + Unpin,
    V: PeerVerifier,
    A: AttestFn,
{
    let mut tls = connector.connect(server_name, transport).await?;
    let peer_point = live_peer_point(tls.get_ref().1.peer_certificates())?;
    let ctx = Channel {
        stream: &mut tls,
        my_nonce: hs.my_nonce,
        my_point: &hs.my_cert.public_point,
        peer_point: &peer_point,
        verifier: hs.verifier,
        attest_fn: hs.attest_fn,
    };
    client_exchange(ctx, inputs).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::CertifiedKey;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::duplex;

    const US_HEX: &str =
        "/home/oxide/projects/kastad/kaskad-pontifex/test/fixtures/attestation-us.hex";
    // Inside both fixture leaf validity windows.
    const NOW: u64 = 1789682698;

    fn load_fixture(path: &str) -> Vec<u8> {
        let hex = std::fs::read_to_string(path).expect("read fixture");
        let s = hex.trim();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn nonce(fill: u8) -> [u8; NONCE_LEN] {
        [fill; NONCE_LEN]
    }

    fn pcr(fill: u8) -> [u8; 48] {
        [fill; 48]
    }

    // ---- TLS 1.3 handshake with both custom verifiers ----

    #[tokio::test]
    async fn handshake_succeeds_with_matching_ephemeral_certs() {
        let provider = crypto_provider();
        let server_cert = generate_ephemeral_cert().unwrap();
        let client_cert = generate_ephemeral_cert().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            server_config(provider.clone(), &server_cert).unwrap(),
        ));
        let connector =
            TlsConnector::from(Arc::new(client_config(provider, &client_cert).unwrap()));

        let (c, s) = duplex(16 * 1024);
        // Post-handshake byte exchange keeps both streams alive through the full
        // TLS 1.3 flight (a client that drops on connect() would BrokenPipe the
        // server before it reads the client's Certificate/Finished).
        let srv = tokio::spawn(async move {
            let mut tls = acceptor.accept(s).await?;
            tls.write_all(b"s").await?;
            let mut b = [0u8; 1];
            tls.read_exact(&mut b).await?;
            std::io::Result::Ok(b[0])
        });
        let sni = ServerName::try_from("ratls.local").unwrap();
        let cli = tokio::spawn(async move {
            let mut tls = connector.connect(sni, c).await?;
            let mut b = [0u8; 1];
            tls.read_exact(&mut b).await?;
            tls.write_all(b"c").await?;
            std::io::Result::Ok(b[0])
        });

        let (sr, cr) = tokio::join!(srv, cli);
        let sr = sr.unwrap();
        let cr = cr.unwrap();
        assert!(
            sr.is_ok(),
            "server handshake: {:?} / client: {:?}",
            sr.err(),
            cr.as_ref().err()
        );
        assert!(cr.is_ok(), "client handshake: {:?}", cr.err());
        assert_eq!(sr.unwrap(), b'c');
        assert_eq!(cr.unwrap(), b's');
    }

    #[tokio::test]
    async fn mismatched_client_key_is_rejected() {
        // MITM: the client presents cert A but signs CertificateVerify with
        // key B. verify_tls13_signature must fire and abort the handshake.
        let provider = crypto_provider();
        let server_cert = generate_ephemeral_cert().unwrap();
        let cert_a = generate_ephemeral_cert().unwrap();
        let key_b = generate_ephemeral_cert().unwrap();

        let acceptor = TlsAcceptor::from(Arc::new(
            server_config(provider.clone(), &server_cert).unwrap(),
        ));

        // Client config presenting cert A's chain with key B's signing key.
        let signing_key = provider
            .key_provider
            .load_private_key(key_b.key_der.clone_key())
            .unwrap();
        let certified = Arc::new(CertifiedKey::new(
            vec![cert_a.cert_der.clone()],
            signing_key,
        ));

        #[derive(Debug)]
        struct FixedResolver(Arc<CertifiedKey>);
        impl rustls::client::ResolvesClientCert for FixedResolver {
            fn resolve(
                &self,
                _hints: &[&[u8]],
                _schemes: &[SignatureScheme],
            ) -> Option<Arc<CertifiedKey>> {
                Some(self.0.clone())
            }
            fn has_certs(&self) -> bool {
                true
            }
        }

        let verifier = AttestationCertVerifier::new(provider.clone());
        let client_cfg = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(FixedResolver(certified)));
        let connector = TlsConnector::from(Arc::new(client_cfg));

        let (c, s) = duplex(16 * 1024);
        let srv = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
        let sni = ServerName::try_from("ratls.local").unwrap();
        let cli = tokio::spawn(async move { connector.connect(sni, c).await.map(|_| ()) });

        let (sr, cr) = tokio::join!(srv, cli);
        assert!(
            sr.unwrap().is_err() || cr.unwrap().is_err(),
            "mismatched CertificateVerify key must be rejected"
        );
    }

    // ---- full handshake driver: live point extraction + exchange ----

    #[tokio::test]
    async fn driver_full_handshake_binds_live_points_and_installs() {
        // Two real TLS 1.3 sessions over a duplex, driven end to end. Each side's
        // verifier reports the PEER's REAL live point (a truthful attestation) and
        // answers OUR nonce; same PCR0 → server grants own key, client accepts.
        // This can ONLY pass if both drivers extract the exact 65-byte peer point
        // off the live session — a wrong extraction fails check_peer_key.
        let provider = crypto_provider();
        let server_cert = generate_ephemeral_cert().unwrap();
        let client_cert = generate_ephemeral_cert().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            server_config(provider.clone(), &server_cert).unwrap(),
        ));
        let connector =
            TlsConnector::from(Arc::new(client_config(provider, &client_cert).unwrap()));

        let shared = pcr(0xAB);
        let server_nonce = nonce(0x11);
        let client_nonce = nonce(0x22);

        let srv_verifier = FakeVerifier {
            pcr0: shared,
            nonce: Some(server_nonce.to_vec()),
            public_key: client_cert.public_point.clone(),
        };
        let cli_verifier = FakeVerifier {
            pcr0: shared,
            nonce: Some(client_nonce.to_vec()),
            public_key: server_cert.public_point.clone(),
        };
        let srv_attest = |_n: &[u8; NONCE_LEN], _p: &[u8]| b"srv-doc".to_vec();
        let cli_attest = |_n: &[u8; NONCE_LEN], _p: &[u8]| b"cli-doc".to_vec();

        let own = ImageIdentity {
            pcr0: shared,
            version: 5,
        };
        let wiped = Arc::new(AtomicBool::new(false));
        let granted = SpyKey {
            bytes: [0x42u8; 32],
            wiped: wiped.clone(),
        };

        let (c, s) = duplex(64 * 1024);
        let sni = ServerName::try_from("ratls.local").unwrap();

        let server_fut = run_server_handshake(
            &acceptor,
            s,
            Handshake {
                my_cert: &server_cert,
                my_nonce: &server_nonce,
                verifier: &srv_verifier,
                attest_fn: &srv_attest,
            },
            HandoverInputs {
                own: &own,
                role: EnclaveRole::Oracle,
                own_key_is_candidate: false,
                approvals: &[],
            },
            granted,
        );
        let client_fut = run_client_handshake(
            &connector,
            sni,
            c,
            Handshake {
                my_cert: &client_cert,
                my_nonce: &client_nonce,
                verifier: &cli_verifier,
                attest_fn: &cli_attest,
            },
            AcceptInputs {
                kind: FetchKind::RootFromRoot,
                own_pcr0: &shared,
                baked_ancestors: &[],
            },
        );

        let (sr, cr) = tokio::join!(server_fut, client_fut);
        assert_eq!(sr.unwrap(), ServerExchange::HandedOwnKey);
        assert!(
            wiped.load(Ordering::SeqCst),
            "handed key wiped locally after grant"
        );
        match cr.unwrap() {
            ClientExchange::Installed(k) => assert_eq!(*k, [0x42u8; 32]),
            ClientExchange::Refused(r) => panic!("expected install, got {r:?}"),
        }
    }

    #[tokio::test]
    async fn driver_refuses_when_attested_key_is_not_the_live_tls_point() {
        // The server's verifier reports an IMPOSTOR's point, not the client's real
        // live point. The driver feeds the LIVE point into the binding, so
        // check_peer_key fires → KeyMismatch, key wiped, decline on the wire. This
        // proves the live point (not the attestation's self-report) is the ground
        // truth the binding compares against.
        let provider = crypto_provider();
        let server_cert = generate_ephemeral_cert().unwrap();
        let client_cert = generate_ephemeral_cert().unwrap();
        let impostor = generate_ephemeral_cert().unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(
            server_config(provider.clone(), &server_cert).unwrap(),
        ));
        let connector =
            TlsConnector::from(Arc::new(client_config(provider, &client_cert).unwrap()));

        let shared = pcr(0xAB);
        let server_nonce = nonce(0x11);
        let client_nonce = nonce(0x22);

        let srv_verifier = FakeVerifier {
            pcr0: shared,
            nonce: Some(server_nonce.to_vec()),
            public_key: impostor.public_point.clone(),
        };
        let cli_verifier = FakeVerifier {
            pcr0: shared,
            nonce: Some(client_nonce.to_vec()),
            public_key: server_cert.public_point.clone(),
        };
        let srv_attest = |_n: &[u8; NONCE_LEN], _p: &[u8]| b"srv-doc".to_vec();
        let cli_attest = |_n: &[u8; NONCE_LEN], _p: &[u8]| b"cli-doc".to_vec();

        let own = ImageIdentity {
            pcr0: shared,
            version: 5,
        };
        let wiped = Arc::new(AtomicBool::new(false));
        let granted = SpyKey {
            bytes: [0x42u8; 32],
            wiped: wiped.clone(),
        };

        let (c, s) = duplex(64 * 1024);
        let sni = ServerName::try_from("ratls.local").unwrap();

        let server_fut = run_server_handshake(
            &acceptor,
            s,
            Handshake {
                my_cert: &server_cert,
                my_nonce: &server_nonce,
                verifier: &srv_verifier,
                attest_fn: &srv_attest,
            },
            HandoverInputs {
                own: &own,
                role: EnclaveRole::Oracle,
                own_key_is_candidate: false,
                approvals: &[],
            },
            granted,
        );
        let client_fut = run_client_handshake(
            &connector,
            sni,
            c,
            Handshake {
                my_cert: &client_cert,
                my_nonce: &client_nonce,
                verifier: &cli_verifier,
                attest_fn: &cli_attest,
            },
            AcceptInputs {
                kind: FetchKind::RootFromRoot,
                own_pcr0: &shared,
                baked_ancestors: &[],
            },
        );

        let (sr, cr) = tokio::join!(server_fut, client_fut);
        assert_eq!(
            sr.unwrap(),
            ServerExchange::Refused(ExchangeRefusal::KeyMismatch)
        );
        assert!(wiped.load(Ordering::SeqCst), "key wiped on refusal");
        assert!(matches!(
            cr.unwrap(),
            ClientExchange::Refused(ExchangeRefusal::ServerDeclined)
        ));
    }

    // ---- refuse-wipe primitive ----

    struct SpyKey {
        bytes: [u8; 32],
        wiped: Arc<AtomicBool>,
    }
    impl Zeroize for SpyKey {
        fn zeroize(&mut self) {
            self.bytes.zeroize();
            self.wiped.store(true, Ordering::SeqCst);
        }
    }
    impl AsRef<[u8; 32]> for SpyKey {
        fn as_ref(&self) -> &[u8; 32] {
            &self.bytes
        }
    }

    #[test]
    fn refuse_wipe_zeroizes_and_refuses() {
        let flag = Arc::new(AtomicBool::new(false));
        let spy = SpyKey {
            bytes: [7u8; 32],
            wiped: flag.clone(),
        };
        let out = refuse_wipe(spy, ExchangeRefusal::NonceMismatch);
        assert!(flag.load(Ordering::SeqCst), "key must be wiped");
        assert_eq!(out, ServerExchange::Refused(ExchangeRefusal::NonceMismatch));
    }

    // ---- nonce-exchange routine: nonce / key mismatch → Refuse AND wipe ----

    /// Fake peer verifier returning a controlled VerifiedPeer, so the binding
    /// refusals (which a real fresh-nonce NSM doc can't reach off-hardware) are
    /// exercised end to end through the routine.
    struct FakeVerifier {
        pcr0: [u8; 48],
        nonce: Option<Vec<u8>>,
        public_key: Vec<u8>,
    }
    impl PeerVerifier for FakeVerifier {
        fn verify(&self, _doc: &[u8], _my_nonce: &[u8; NONCE_LEN]) -> Result<VerifiedPeer> {
            Ok(VerifiedPeer {
                pcr0: self.pcr0,
                nonce: self.nonce.clone(),
                public_key: self.public_key.clone(),
            })
        }
    }

    /// Drive one server_exchange with a fake client peer over a duplex, asserting
    /// the refusal reason and that the SpyKey was wiped and no key reached the
    /// wire (the client saw a decline tag).
    async fn run_server_refusal(
        verifier: FakeVerifier,
        my_nonce: [u8; NONCE_LEN],
        peer_point: Vec<u8>,
        expected: ExchangeRefusal,
    ) {
        let (mut srv_side, mut cli_side) = duplex(16 * 1024);
        let wiped = Arc::new(AtomicBool::new(false));
        let spy = SpyKey {
            bytes: [9u8; 32],
            wiped: wiped.clone(),
        };
        let my_point = b"server-point".to_vec();

        // Fake client peer: sends a nonce and a (fixture) doc, then reads the tag.
        let peer = tokio::spawn(async move {
            write_frame(&mut cli_side, &nonce(0x55)).await.unwrap();
            let _server_nonce = read_frame(&mut cli_side).await.unwrap();
            let _server_doc = read_frame(&mut cli_side).await.unwrap();
            write_frame(&mut cli_side, &load_fixture(US_HEX))
                .await
                .unwrap();
            // Read the server's grant/decline frame.
            read_frame(&mut cli_side).await.unwrap()
        });

        let attest = |_n: &[u8; NONCE_LEN], _s: &[u8]| b"server-doc".to_vec();
        let own = ImageIdentity {
            pcr0: pcr(0xAA),
            version: 5,
        };
        let out = server_exchange(
            Channel {
                stream: &mut srv_side,
                my_nonce: &my_nonce,
                my_point: &my_point,
                peer_point: &peer_point,
                verifier: &verifier,
                attest_fn: &attest,
            },
            HandoverInputs {
                own: &own,
                role: EnclaveRole::Oracle,
                own_key_is_candidate: false,
                approvals: &[],
            },
            spy,
        )
        .await
        .unwrap();

        let client_frame = peer.await.unwrap();
        assert_eq!(out, ServerExchange::Refused(expected));
        assert!(
            wiped.load(Ordering::SeqCst),
            "own key must be wiped on refuse"
        );
        assert_eq!(client_frame, vec![TAG_DECLINE], "no key may reach the wire");
    }

    #[tokio::test]
    async fn server_refuses_and_wipes_on_nonce_mismatch() {
        // Verified peer answers a different nonce than ours → NonceMismatch.
        let v = FakeVerifier {
            pcr0: pcr(0xAA),
            nonce: Some(vec![0xEE; NONCE_LEN]),
            public_key: b"peer-point".to_vec(),
        };
        run_server_refusal(
            v,
            nonce(0x11),
            b"peer-point".to_vec(),
            ExchangeRefusal::NonceMismatch,
        )
        .await;
    }

    #[tokio::test]
    async fn server_refuses_and_wipes_on_key_mismatch() {
        // Nonce matches, but the attested key is not the peer's TLS point.
        let my_nonce = nonce(0x22);
        let v = FakeVerifier {
            pcr0: pcr(0xAA),
            nonce: Some(my_nonce.to_vec()),
            public_key: b"attested-other-key".to_vec(),
        };
        run_server_refusal(
            v,
            my_nonce,
            b"peer-tls-point".to_vec(),
            ExchangeRefusal::KeyMismatch,
        )
        .await;
    }

    #[tokio::test]
    async fn real_verifier_refuses_nonceless_fixture() {
        // End-to-end with the REAL nitro_common verifier: the recorded fixture
        // carries no nonce, so verify_attestation(expected_nonce=my) fails →
        // AttestationInvalid, key wiped, decline on the wire.
        let (mut srv_side, mut cli_side) = duplex(16 * 1024);
        let wiped = Arc::new(AtomicBool::new(false));
        let spy = SpyKey {
            bytes: [3u8; 32],
            wiped: wiped.clone(),
        };

        let peer = tokio::spawn(async move {
            write_frame(&mut cli_side, &nonce(0x55)).await.unwrap();
            let _n = read_frame(&mut cli_side).await.unwrap();
            let _d = read_frame(&mut cli_side).await.unwrap();
            write_frame(&mut cli_side, &load_fixture(US_HEX))
                .await
                .unwrap();
            read_frame(&mut cli_side).await.unwrap()
        });

        let attest = |_n: &[u8; NONCE_LEN], _s: &[u8]| b"server-doc".to_vec();
        let verifier = NsmPeerVerifier { now_unix_secs: NOW };
        let own = ImageIdentity {
            pcr0: pcr(0xAA),
            version: 5,
        };
        let out = server_exchange(
            Channel {
                stream: &mut srv_side,
                my_nonce: &nonce(0x11),
                my_point: b"server-point",
                peer_point: b"peer-point",
                verifier: &verifier,
                attest_fn: &attest,
            },
            HandoverInputs {
                own: &own,
                role: EnclaveRole::Oracle,
                own_key_is_candidate: false,
                approvals: &[],
            },
            spy,
        )
        .await
        .unwrap();

        let client_frame = peer.await.unwrap();
        assert_eq!(
            out,
            ServerExchange::Refused(ExchangeRefusal::AttestationInvalid)
        );
        assert!(wiped.load(Ordering::SeqCst));
        assert_eq!(client_frame, vec![TAG_DECLINE]);
    }

    // ---- client side: accept → Installed, key mismatch → Refuse + no key ----

    /// Scripted server peer: reads the client nonce, sends its own nonce and a
    /// doc, reads the client doc, then sends `grant`.
    fn spawn_server_peer(
        mut side: tokio::io::DuplexStream,
        grant: Vec<u8>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let _client_nonce = read_frame(&mut side).await.unwrap();
            write_frame(&mut side, &nonce(0x77)).await.unwrap();
            write_frame(&mut side, b"server-doc").await.unwrap();
            let _client_doc = read_frame(&mut side).await.unwrap();
            write_frame(&mut side, &grant).await.unwrap();
        })
    }

    #[tokio::test]
    async fn client_installs_key_when_accepted_and_granted() {
        let (mut cli_side, srv_side) = duplex(16 * 1024);
        let server_pcr0 = pcr(0xAB);
        let mut grant = vec![TAG_GRANT];
        grant.extend_from_slice(&[0x42u8; 32]);
        let peer = spawn_server_peer(srv_side, grant);

        let v = FakeVerifier {
            pcr0: server_pcr0,
            nonce: Some(nonce(0x33).to_vec()),
            public_key: b"srv-point".to_vec(),
        };
        let attest = |_n: &[u8; NONCE_LEN], _s: &[u8]| b"client-doc".to_vec();
        let out = client_exchange(
            Channel {
                stream: &mut cli_side,
                my_nonce: &nonce(0x33),
                my_point: b"cli-point",
                peer_point: b"srv-point",
                verifier: &v,
                attest_fn: &attest,
            },
            AcceptInputs {
                kind: FetchKind::RootFromRoot,
                own_pcr0: &server_pcr0,
                baked_ancestors: &[],
            },
        )
        .await
        .unwrap();
        peer.await.unwrap();

        match out {
            ClientExchange::Installed(k) => assert_eq!(*k, [0x42u8; 32]),
            ClientExchange::Refused(r) => panic!("expected install, got {r:?}"),
        }
    }

    #[tokio::test]
    async fn client_refuses_and_keeps_no_key_on_key_mismatch() {
        // Attested key != server TLS point → KeyMismatch, grant bytes dropped.
        let (mut cli_side, srv_side) = duplex(16 * 1024);
        let mut grant = vec![TAG_GRANT];
        grant.extend_from_slice(&[0x42u8; 32]);
        let peer = spawn_server_peer(srv_side, grant);

        let v = FakeVerifier {
            pcr0: pcr(0xAB),
            nonce: Some(nonce(0x33).to_vec()),
            public_key: b"attested-other".to_vec(),
        };
        let attest = |_n: &[u8; NONCE_LEN], _s: &[u8]| b"client-doc".to_vec();
        let out = client_exchange(
            Channel {
                stream: &mut cli_side,
                my_nonce: &nonce(0x33),
                my_point: b"cli-point",
                peer_point: b"srv-point",
                verifier: &v,
                attest_fn: &attest,
            },
            AcceptInputs {
                kind: FetchKind::RootFromRoot,
                own_pcr0: &pcr(0xAB),
                baked_ancestors: &[],
            },
        )
        .await
        .unwrap();
        peer.await.unwrap();

        assert!(matches!(
            out,
            ClientExchange::Refused(ExchangeRefusal::KeyMismatch)
        ));
    }

    #[test]
    fn fresh_nonce_is_csprng_filled() {
        // The enclave passes NsmRng; tests use OsRng. Distinct draws differ.
        let a = fresh_nonce(&mut rand::rngs::OsRng);
        let b = fresh_nonce(&mut rand::rngs::OsRng);
        assert_ne!(a, b);
    }

    #[test]
    fn public_point_from_cert_returns_65_byte_uncompressed() {
        // The channel binding compares 65-byte SEC1 points, not SPKI DER.
        let cert = generate_ephemeral_cert().unwrap();
        assert_eq!(cert.public_point.len(), 65, "raw EC point, not SPKI DER");
        assert_eq!(cert.public_point[0], 0x04, "uncompressed point tag");
    }

    #[test]
    fn real_cert_point_binds_to_attestation_key() {
        // A real rcgen P-256 cert's point equals itself under check_peer_key —
        // the shape a hardware attestation's public_key actually carries.
        let cert = generate_ephemeral_cert().unwrap();
        let view = AttestationView::new(None, &cert.public_point);
        assert!(check_peer_key(&view, &cert.public_point).is_ok());
    }
}
