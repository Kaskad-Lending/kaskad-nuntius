//! Peer key fetch. The [`PeerSource`] seam is what the boot driver calls; the
//! real [`RatlsPeerSource`] runs the RA-TLS client leg (`run_client_handshake`)
//! against a sibling/parent enclave and installs the transferred key only when
//! the exchange's own policy accepted it. The seam keeps the driver's rules
//! testable without TLS or NSM.

use std::future::Future;

use crate::policy::FetchKind;
use alloy_primitives::Address;
use k256::ecdsa::SigningKey;

/// A key fetched and accepted from a peer, with its derived Eth address. The
/// `SigningKey` zeroizes on drop.
pub struct FetchedKey {
    pub address: Address,
    pub key: SigningKey,
}

impl FetchedKey {
    /// Build from raw transfer bytes, rejecting an invalid (e.g. zero) scalar.
    pub fn from_bytes(raw: &[u8; 32]) -> eyre::Result<Self> {
        let key = SigningKey::from_bytes(raw.into())
            .map_err(|_| eyre::eyre!("transferred key is not a valid secp256k1 scalar"))?;
        let address = crate::sig::address_from_key(key.verifying_key());
        Ok(Self { address, key })
    }
}

/// A bounded peer-fetch attempt failed before yielding an accepted key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchError {
    Timeout,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => f.write_str("peer fetch attempt timed out"),
        }
    }
}

impl std::error::Error for FetchError {}

/// One peer-fetch attempt against a single endpoint. `Ok(None)` = the peer
/// declined or was rejected by policy (try others / back off); `Err` = a
/// transport fault the driver logs and retries.
pub trait PeerSource {
    fn fetch(
        &self,
        endpoint: &str,
        kind: FetchKind,
    ) -> impl Future<Output = eyre::Result<Option<FetchedKey>>>;
}

#[cfg(target_os = "linux")]
pub use real::RatlsPeerSource;

#[cfg(target_os = "linux")]
mod real {
    use std::future::Future;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::policy::FetchKind;
    use crate::ratls::{
        client_config, crypto_provider, fresh_nonce, generate_ephemeral_cert, run_client_handshake,
        AcceptInputs, AttestFn, ClientExchange, Handshake, NsmPeerVerifier, PeerVerifier,
        NONCE_LEN,
    };
    use eyre::{eyre, Result};
    use nitro_common::nsm::Nsm;
    use nitro_common::rng::NsmRng;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_rustls::TlsConnector;
    use zeroize::Zeroize;

    use super::{FetchError, FetchedKey, PeerSource};

    /// In-enclave egress proxy (the crate's VSOCK forwarder). All peer traffic
    /// tunnels through it; only `lo` is up inside the enclave.
    const EGRESS_PROXY: &str = "127.0.0.1:5000";
    /// Default RA-TLS handover port on a peer's host ingress, appended when the
    /// host supplies a bare IP.
    const HANDOVER_PORT: u16 = 8443;
    /// One budget for proxy dial/CONNECT, TLS, attestation, and the key grant.
    const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

    /// Ensure `endpoint` carries an explicit port, defaulting to the handover port.
    fn with_default_port(endpoint: &str) -> String {
        if endpoint.contains(':') {
            endpoint.to_owned()
        } else {
            format!("{endpoint}:{HANDOVER_PORT}")
        }
    }

    /// Open a raw tunnel to `target` through the enclave's HTTP CONNECT egress
    /// proxy, returning the tunneled stream ready for the RA-TLS client leg.
    async fn connect_via_proxy<S>(
        connect: impl Future<Output = std::io::Result<S>>,
        target: &str,
    ) -> Result<S>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut tcp = connect.await?;
        let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        tcp.write_all(req.as_bytes()).await?;

        // Read only through the first CRLFCRLF: the proxy is transparent after the
        // response, so over-reading would swallow the peer's TLS bytes.
        let mut buf = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            if tcp.read(&mut byte).await? == 0 {
                return Err(eyre!("egress proxy closed before CONNECT response"));
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 8192 {
                return Err(eyre!("egress proxy CONNECT response too large"));
            }
        }
        // Status line is "HTTP/1.1 200 ..."; the second token is the code.
        let status_line = buf.split(|&b| b == b'\r').next().unwrap_or(&[]);
        let ok = std::str::from_utf8(status_line)
            .ok()
            .and_then(|l| l.split_whitespace().nth(1))
            == Some("200");
        if !ok {
            return Err(eyre!("egress proxy refused CONNECT"));
        }
        Ok(tcp)
    }

    /// Bound the entire network attempt; timeout drops its transport and secrets.
    async fn fetch_via_proxy<S, V, A>(
        connect: impl Future<Output = std::io::Result<S>>,
        target: &str,
        hs: Handshake<'_, V, A>,
        inputs: AcceptInputs<'_>,
    ) -> Result<Option<FetchedKey>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        V: PeerVerifier,
        A: AttestFn,
    {
        timeout(FETCH_TIMEOUT, async {
            let connector =
                TlsConnector::from(Arc::new(client_config(crypto_provider(), hs.my_cert)?));
            let tcp = connect_via_proxy(connect, target).await?;
            let server_name = ServerName::try_from("enclave.local")?;
            match run_client_handshake(&connector, server_name, tcp, hs, inputs).await? {
                ClientExchange::Installed(mut raw) => {
                    let fk = FetchedKey::from_bytes(&raw)?;
                    raw.zeroize();
                    Ok(Some(fk))
                }
                ClientExchange::Refused(_) => Ok(None),
            }
        })
        .await
        .map_err(|_| FetchError::Timeout)?
    }

    /// Production peer source: fresh ephemeral cert + NSM attestation per fetch,
    /// RA-TLS mutual auth, then install only an `Installed` exchange outcome.
    pub struct RatlsPeerSource {
        nsm: Nsm,
        own_pcr0: [u8; 48],
        baked_ancestors: Vec<[u8; 48]>,
    }

    impl RatlsPeerSource {
        pub fn new(nsm: Nsm, own_pcr0: [u8; 48], baked_ancestors: Vec<[u8; 48]>) -> Self {
            Self {
                nsm,
                own_pcr0,
                baked_ancestors,
            }
        }
    }

    impl PeerSource for RatlsPeerSource {
        async fn fetch(&self, endpoint: &str, kind: FetchKind) -> Result<Option<FetchedKey>> {
            let cert = generate_ephemeral_cert()?;

            let mut rng = NsmRng::new()?;
            let nonce = fresh_nonce(&mut rng);
            // Clock read per fetch, not once at construction: a long-lived source
            // must judge each peer cert's validity against the current time.
            let now_unix_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let verifier = NsmPeerVerifier { now_unix_secs };
            // My attestation answers the peer's nonce and binds my TLS point; a
            // failed NSM call yields an empty doc → the peer fails verification.
            let attest = |peer_nonce: &[u8; NONCE_LEN], my_point: &[u8]| -> Vec<u8> {
                self.nsm
                    .attestation(None, Some(peer_nonce.to_vec()), Some(my_point.to_vec()))
                    .unwrap_or_default()
            };

            let target = with_default_port(endpoint);
            let hs = Handshake {
                my_cert: &cert,
                my_nonce: &nonce,
                verifier: &verifier,
                attest_fn: &attest,
            };
            let inputs = AcceptInputs {
                kind,
                own_pcr0: &self.own_pcr0,
                baked_ancestors: &self.baked_ancestors,
            };

            fetch_via_proxy(TcpStream::connect(EGRESS_PROXY), &target, hs, inputs).await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::Cell;
        use std::future::{pending, poll_fn, ready};
        use std::io;
        use std::task::Poll;

        use crate::ratls::{server_config, EphemeralCert, VerifiedPeer};
        use tokio::io::{duplex, DuplexStream};
        use tokio::time::{sleep, Instant};
        use tokio_rustls::TlsAcceptor;

        const PCR0: [u8; 48] = [0xAB; 48];
        const KEY: [u8; 32] = [7; 32];
        const TARGET: &str = "peer.test:8443";
        const REQUEST: &[u8] = b"CONNECT peer.test:8443 HTTP/1.1\r\nHost: peer.test:8443\r\n\r\n";

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum Stall {
            ProxyResponse,
            Tls,
            Nonce,
            Attestation,
            Grant,
        }

        #[derive(Clone, Copy)]
        enum Reply {
            Stall(Stall),
            Grant([u8; 32]),
            Decline,
            ProxyRefused,
        }

        #[derive(Clone, Copy)]
        enum Proof {
            Valid,
            Invalid,
            WrongNonce,
            WrongPoint,
        }

        struct TestVerifier {
            pcr0: [u8; 48],
            point: Vec<u8>,
            proof: Proof,
            calls: Cell<usize>,
        }

        impl PeerVerifier for TestVerifier {
            fn verify(&self, doc: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<VerifiedPeer> {
                self.calls.set(self.calls.get() + 1);
                assert_eq!(doc, b"peer-doc");
                if matches!(self.proof, Proof::Invalid) {
                    return Err(eyre!("in-test attestation rejection"));
                }
                Ok(VerifiedPeer {
                    pcr0: self.pcr0,
                    nonce: Some(if matches!(self.proof, Proof::WrongNonce) {
                        vec![0; NONCE_LEN]
                    } else {
                        nonce.to_vec()
                    }),
                    public_key: if matches!(self.proof, Proof::WrongPoint) {
                        vec![4; 65]
                    } else {
                        self.point.clone()
                    },
                })
            }
        }

        struct Fixture {
            client_cert: EphemeralCert,
            server_cert: EphemeralCert,
            verifier: TestVerifier,
        }

        impl Fixture {
            fn new(pcr0: [u8; 48], proof: Proof) -> Self {
                let server_cert = generate_ephemeral_cert().unwrap();
                Self {
                    client_cert: generate_ephemeral_cert().unwrap(),
                    verifier: TestVerifier {
                        pcr0,
                        point: server_cert.public_point.clone(),
                        proof,
                        calls: Cell::new(0),
                    },
                    server_cert,
                }
            }

            async fn fetch<S>(
                &self,
                connect: impl Future<Output = io::Result<S>>,
                kind: FetchKind,
                ancestors: &[[u8; 48]],
            ) -> Result<Option<FetchedKey>>
            where
                S: AsyncRead + AsyncWrite + Unpin,
            {
                let nonce = [0x33; NONCE_LEN];
                let attest = |_: &[u8; NONCE_LEN], _: &[u8]| b"client-doc".to_vec();
                fetch_via_proxy(
                    connect,
                    TARGET,
                    Handshake {
                        my_cert: &self.client_cert,
                        my_nonce: &nonce,
                        verifier: &self.verifier,
                        attest_fn: &attest,
                    },
                    AcceptInputs {
                        kind,
                        own_pcr0: &PCR0,
                        baked_ancestors: ancestors,
                    },
                )
                .await
            }

            async fn exchange(
                &self,
                reply: Reply,
                kind: FetchKind,
                ancestors: &[[u8; 48]],
                proxy_delay: Duration,
            ) -> Result<Option<FetchedKey>> {
                let (client, server) = duplex(64 * 1024);
                let (result, ()) = tokio::join!(
                    self.fetch(ready(Ok(client)), kind, ancestors),
                    self.serve(server, reply, proxy_delay),
                );
                result
            }

            async fn root(&self, reply: Reply) -> Result<Option<FetchedKey>> {
                self.exchange(reply, FetchKind::RootFromRoot, &[], Duration::ZERO)
                    .await
            }

            async fn serve(&self, mut tcp: DuplexStream, reply: Reply, proxy_delay: Duration) {
                let mut request = vec![0; REQUEST.len()];
                tcp.read_exact(&mut request).await.unwrap();
                assert_eq!(request, REQUEST);
                if !proxy_delay.is_zero() {
                    sleep(proxy_delay).await;
                }
                if matches!(reply, Reply::Stall(Stall::ProxyResponse)) {
                    tcp.write_all(b"HTTP/1.1 200").await.unwrap();
                    disconnected(&mut tcp).await;
                    return;
                }
                if matches!(reply, Reply::ProxyRefused) {
                    tcp.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                        .await
                        .unwrap();
                    return;
                }
                tcp.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                if matches!(reply, Reply::Stall(Stall::Tls)) {
                    disconnected(&mut tcp).await;
                    return;
                }
                let acceptor = TlsAcceptor::from(Arc::new(
                    server_config(crypto_provider(), &self.server_cert).unwrap(),
                ));
                let mut tls = acceptor.accept(tcp).await.unwrap();
                assert_eq!(read_test_frame(&mut tls).await, [0x33; NONCE_LEN]);
                if matches!(reply, Reply::Stall(Stall::Nonce)) {
                    disconnected(&mut tls).await;
                    return;
                }
                write_test_frame(&mut tls, &[0x44; NONCE_LEN]).await;
                assert_eq!(read_test_frame(&mut tls).await, b"client-doc");
                if matches!(reply, Reply::Stall(Stall::Attestation)) {
                    disconnected(&mut tls).await;
                    return;
                }
                write_test_frame(&mut tls, b"peer-doc").await;
                match reply {
                    Reply::Stall(Stall::Grant) => {
                        tls.write_u32(33).await.unwrap();
                        tls.write_all(&[1]).await.unwrap();
                        tls.write_all(&KEY[..16]).await.unwrap();
                        tls.flush().await.unwrap();
                    }
                    Reply::Grant(key) => {
                        let mut grant = vec![1];
                        grant.extend_from_slice(&key);
                        write_test_frame(&mut tls, &grant).await;
                    }
                    Reply::Decline => write_test_frame(&mut tls, &[0]).await,
                    _ => unreachable!(),
                }
                disconnected(&mut tls).await;
            }
        }

        async fn read_test_frame<S: AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
            let len = stream.read_u32().await.unwrap() as usize;
            assert!(len <= 1024);
            let mut frame = vec![0; len];
            stream.read_exact(&mut frame).await.unwrap();
            frame
        }

        async fn write_test_frame<S: AsyncWrite + Unpin>(stream: &mut S, frame: &[u8]) {
            stream.write_u32(frame.len() as u32).await.unwrap();
            stream.write_all(frame).await.unwrap();
            stream.flush().await.unwrap();
        }

        async fn disconnected<S: AsyncRead + Unpin>(stream: &mut S) {
            let result = stream.read_to_end(&mut Vec::new()).await;
            if let Err(err) = result {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            }
        }

        fn assert_timeout(result: Result<Option<FetchedKey>>) {
            match result {
                Err(err) => {
                    assert_eq!(err.downcast_ref::<FetchError>(), Some(&FetchError::Timeout))
                }
                Ok(_) => panic!("stalled fetch must time out"),
            }
        }

        #[tokio::test(start_paused = true)]
        async fn stalled_proxy_dial_times_out_and_is_cancelled() {
            struct DropFlag<'a>(&'a Cell<bool>);
            impl Drop for DropFlag<'_> {
                fn drop(&mut self) {
                    self.0.set(true);
                }
            }
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let dropped = Cell::new(false);
            let connect = async {
                let _guard = DropFlag(&dropped);
                pending::<io::Result<DuplexStream>>().await
            };
            let start = Instant::now();
            assert_timeout(fixture.fetch(connect, FetchKind::RootFromRoot, &[]).await);
            assert_eq!(start.elapsed(), FETCH_TIMEOUT);
            assert!(dropped.get());
        }

        #[tokio::test(start_paused = true)]
        async fn stalled_connect_write_times_out_and_closes_transport() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let (client, mut server) = duplex(1);
            let start = Instant::now();
            assert_timeout(
                fixture
                    .fetch(ready(Ok(client)), FetchKind::RootFromRoot, &[])
                    .await,
            );
            assert_eq!(start.elapsed(), FETCH_TIMEOUT);
            let mut partial_request = Vec::new();
            server.read_to_end(&mut partial_request).await.unwrap();
            assert_eq!(partial_request, b"C");
        }

        #[tokio::test(start_paused = true)]
        async fn stalled_network_phases_time_out_and_close_transport() {
            for stage in [
                Stall::ProxyResponse,
                Stall::Tls,
                Stall::Nonce,
                Stall::Attestation,
                Stall::Grant,
            ] {
                let fixture = Fixture::new(PCR0, Proof::Valid);
                let start = Instant::now();
                assert_timeout(fixture.root(Reply::Stall(stage)).await);
                assert_eq!(start.elapsed(), FETCH_TIMEOUT, "{stage:?}");
                assert_eq!(
                    fixture.verifier.calls.get(),
                    usize::from(stage == Stall::Grant)
                );
            }
        }

        #[tokio::test(start_paused = true)]
        async fn later_phases_do_not_restart_the_attempt_budget() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let start = Instant::now();
            assert_timeout(
                fixture
                    .exchange(
                        Reply::Stall(Stall::Grant),
                        FetchKind::RootFromRoot,
                        &[],
                        FETCH_TIMEOUT * 2 / 3,
                    )
                    .await,
            );
            assert_eq!(start.elapsed(), FETCH_TIMEOUT);
            assert_eq!(fixture.verifier.calls.get(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn caller_cancellation_closes_transport_without_a_detached_attempt() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let (client, mut server) = duplex(1);
            let mut fetch =
                Box::pin(fixture.fetch(ready(Ok(client)), FetchKind::RootFromRoot, &[]));
            poll_fn(|cx| {
                assert!(fetch.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            drop(fetch);
            let mut partial_request = Vec::new();
            server.read_to_end(&mut partial_request).await.unwrap();
            assert_eq!(partial_request, b"C");
        }

        #[tokio::test(start_paused = true)]
        async fn immediate_transport_failure_is_not_classified_as_timeout() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let connect = ready(Err::<DuplexStream, _>(io::Error::from(
                io::ErrorKind::ConnectionRefused,
            )));
            let start = Instant::now();
            match fixture.fetch(connect, FetchKind::RootFromRoot, &[]).await {
                Err(err) => assert_eq!(
                    err.downcast_ref::<io::Error>().unwrap().kind(),
                    io::ErrorKind::ConnectionRefused
                ),
                Ok(_) => panic!("failed dial must not yield a key"),
            }
            assert_eq!(start.elapsed(), Duration::ZERO);
        }

        #[tokio::test(start_paused = true)]
        async fn accepted_peer_returns_the_transferred_key() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let fetched = fixture.root(Reply::Grant(KEY)).await.unwrap().unwrap();
            assert_eq!(&fetched.key.to_bytes()[..], KEY);
            assert_eq!(
                fetched.address,
                FetchedKey::from_bytes(&KEY).unwrap().address
            );
            assert_eq!(fixture.verifier.calls.get(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn attestation_and_channel_binding_failures_never_return_a_key() {
            for proof in [Proof::Invalid, Proof::WrongNonce, Proof::WrongPoint] {
                let fixture = Fixture::new(PCR0, proof);
                assert!(fixture.root(Reply::Grant(KEY)).await.unwrap().is_none());
                assert_eq!(fixture.verifier.calls.get(), 1);
            }
        }

        #[tokio::test(start_paused = true)]
        async fn rejected_attestation_cannot_stall_the_grant_drain() {
            let fixture = Fixture::new(PCR0, Proof::Invalid);
            let start = Instant::now();
            assert_timeout(fixture.root(Reply::Stall(Stall::Grant)).await);
            assert_eq!(start.elapsed(), FETCH_TIMEOUT);
            assert_eq!(fixture.verifier.calls.get(), 1);
        }

        #[tokio::test(start_paused = true)]
        async fn timeout_wrapper_preserves_all_client_pcr_policies() {
            for (kind, peer_pcr, ancestors, accepted) in [
                (FetchKind::RootFromRoot, PCR0, vec![], true),
                (FetchKind::RootFromRoot, [9; 48], vec![], false),
                (FetchKind::RootFromRoot, [9; 48], vec![[9; 48]], true),
                (FetchKind::BridgeFromBridge, PCR0, vec![], true),
                (FetchKind::BridgeFromBridge, [9; 48], vec![[9; 48]], false),
                (FetchKind::BridgeFromParent, PCR0, vec![], false),
                (FetchKind::BridgeFromParent, [9; 48], vec![[9; 48]], true),
            ] {
                let fixture = Fixture::new(peer_pcr, Proof::Valid);
                let result = fixture
                    .exchange(Reply::Grant(KEY), kind, &ancestors, Duration::ZERO)
                    .await
                    .unwrap();
                assert_eq!(result.is_some(), accepted, "{kind:?}");
            }
        }

        #[tokio::test(start_paused = true)]
        async fn invalid_transferred_scalar_is_an_error_not_a_timeout() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            match fixture.root(Reply::Grant([0; 32])).await {
                Err(err) => assert!(err.downcast_ref::<FetchError>().is_none()),
                Ok(_) => panic!("zero scalar must not be installed"),
            }
        }

        #[tokio::test(start_paused = true)]
        async fn sweep_reaches_good_peer_after_timeout_and_refusal() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let start = Instant::now();
            let mut fetched = Vec::new();
            for reply in [
                Reply::Stall(Stall::Grant),
                Reply::Decline,
                Reply::Grant(KEY),
            ] {
                if let Ok(Some(key)) = fixture.root(reply).await {
                    fetched.push(key);
                }
            }
            assert_eq!(fetched.len(), 1);
            assert_eq!(
                fetched[0].address,
                FetchedKey::from_bytes(&KEY).unwrap().address
            );
            assert_eq!(start.elapsed(), FETCH_TIMEOUT);
        }

        #[tokio::test(start_paused = true)]
        async fn all_failed_peer_sweep_finishes_without_a_key() {
            let fixture = Fixture::new(PCR0, Proof::Valid);
            let start = Instant::now();
            let mut faults = 0;
            for reply in [
                Reply::Stall(Stall::ProxyResponse),
                Reply::ProxyRefused,
                Reply::Decline,
                Reply::Stall(Stall::Grant),
            ] {
                match fixture.root(reply).await {
                    Ok(None) => {}
                    Err(_) => faults += 1,
                    Ok(Some(_)) => panic!("failed sweep must not produce a key"),
                }
            }
            assert_eq!(faults, 3);
            assert_eq!(start.elapsed(), FETCH_TIMEOUT * 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_derives_address_and_rejects_zero() {
        let fk = FetchedKey::from_bytes(&[7u8; 32]).unwrap();
        let expected = {
            let sk = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
            crate::sig::address_from_key(sk.verifying_key())
        };
        assert_eq!(fk.address, expected);
        assert!(
            FetchedKey::from_bytes(&[0u8; 32]).is_err(),
            "zero scalar is invalid"
        );
    }
}
