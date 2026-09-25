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
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::policy::FetchKind;
    use crate::ratls::{
        client_config, crypto_provider, fresh_nonce, generate_ephemeral_cert, run_client_handshake,
        AcceptInputs, ClientExchange, Handshake, NsmPeerVerifier, NONCE_LEN,
    };
    use eyre::{eyre, Result};
    use nitro_common::nsm::Nsm;
    use nitro_common::rng::NsmRng;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;
    use zeroize::Zeroize;

    use super::{FetchedKey, PeerSource};

    /// In-enclave egress proxy (the crate's VSOCK forwarder). All peer traffic
    /// tunnels through it; only `lo` is up inside the enclave.
    const EGRESS_PROXY: &str = "127.0.0.1:5000";
    /// Default RA-TLS handover port on a peer's host ingress, appended when the
    /// host supplies a bare IP.
    const HANDOVER_PORT: u16 = 8443;

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
    async fn connect_via_proxy(target: &str) -> Result<TcpStream> {
        let mut tcp = TcpStream::connect(EGRESS_PROXY).await?;
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
            let provider = crypto_provider();
            let cert = generate_ephemeral_cert()?;
            let connector = TlsConnector::from(Arc::new(client_config(provider, &cert)?));

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
            let tcp = connect_via_proxy(&target).await?;
            let server_name = ServerName::try_from("enclave.local")?;
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

            match run_client_handshake(&connector, server_name, tcp, hs, inputs).await? {
                ClientExchange::Installed(mut raw) => {
                    let fk = FetchedKey::from_bytes(&raw)?;
                    raw.zeroize(); // wipe the transferred scalar from this stack copy
                    Ok(Some(fk))
                }
                ClientExchange::Refused(_) => Ok(None),
            }
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
