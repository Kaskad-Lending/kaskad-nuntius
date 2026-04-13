use alloy_primitives::{B256, U256};
use eyre::Result;
use k256::ecdsa::{signature::Signer as K256Signer, Signature, SigningKey};
use sha3::{Digest, Keccak256};

/// Trait for signing oracle payloads.
/// MockSigner uses a local private key.
/// EnclaveSigner (future) will use TEE key management.
pub trait OracleSigner: Send + Sync {
    /// Sign a price update payload. Returns (signature_bytes, signer_address).
    fn sign_price_update(
        &self,
        asset_id: B256,
        price: U256,
        timestamp: u64,
        num_sources: u8,
        sources_hash: B256,
    ) -> Result<(Vec<u8>, [u8; 20])>;

    /// Get the signer's Ethereum address.
    fn address(&self) -> [u8; 20];

    /// Get the attestation document (if available).
    fn attestation_doc(&self) -> Option<Vec<u8>>;
}

/// Local signer for development/testing — private key from environment.
pub struct MockSigner {
    signing_key: SigningKey,
    address: [u8; 20],
}

impl MockSigner {
    pub fn new(private_key_hex: &str) -> Result<Self> {
        let key_bytes = hex::decode(private_key_hex.trim_start_matches("0x"))?;
        let signing_key = SigningKey::from_bytes((&key_bytes[..]).into())?;

        // Derive Ethereum address from public key
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..]; // skip 0x04 prefix
        let hash = Keccak256::digest(pubkey_uncompressed);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        Ok(Self {
            signing_key,
            address,
        })
    }

    /// Generate a random signer for testing.
    pub fn random() -> Self {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = &pubkey_bytes.as_bytes()[1..];
        let hash = Keccak256::digest(pubkey_uncompressed);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        Self {
            signing_key,
            address,
        }
    }
}

impl OracleSigner for MockSigner {
    fn sign_price_update(
        &self,
        asset_id: B256,
        price: U256,
        timestamp: u64,
        num_sources: u8,
        sources_hash: B256,
    ) -> Result<(Vec<u8>, [u8; 20])> {
        // Construct the message hash: keccak256(abi.encodePacked(...))
        // This matches the Solidity verification:
        //   keccak256(abi.encodePacked(assetId, price, timestamp, numSources, sourcesHash))
        // IMPORTANT: timestamp is uint256 in Solidity → 32 bytes, NOT u64 (8 bytes)
        let mut payload = Vec::new();
        payload.extend_from_slice(asset_id.as_slice()); // bytes32 → 32 bytes
        payload.extend_from_slice(&price.to_be_bytes::<32>()); // uint256 → 32 bytes
        payload.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>()); // uint256 → 32 bytes
        payload.extend_from_slice(&[num_sources]); // uint8   → 1 byte
        payload.extend_from_slice(sources_hash.as_slice()); // bytes32 → 32 bytes

        let message_hash = Keccak256::digest(&payload);

        // Ethereum signed message: "\x19Ethereum Signed Message:\n32" + hash
        let mut eth_message = Vec::new();
        eth_message.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        eth_message.extend_from_slice(&message_hash);
        let eth_hash = Keccak256::digest(&eth_message);

        // Sign
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&eth_hash)
            .map_err(|e| eyre::eyre!("signing failed: {}", e))?;

        // Encode as 65-byte (r, s, v) where v = recovery_id + 27
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recovery_id.to_byte() + 27);

        Ok((sig_bytes, self.address))
    }

    fn address(&self) -> [u8; 20] {
        self.address
    }

    fn attestation_doc(&self) -> Option<Vec<u8>> {
        None
    }
}

#[cfg(target_os = "linux")]
pub struct EnclaveSigner {
    signing_key: SigningKey,
    address: [u8; 20],
    /// Uncompressed public key bytes (65 bytes: 0x04 + X + Y).
    /// Kept so we can regenerate fresh attestation docs on demand.
    pubkey_bytes: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl EnclaveSigner {
    pub fn new() -> Result<Self> {
        // 1. Generate random ECDSA secp256k1 keypair
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let verifying_key = signing_key.verifying_key();

        // Output uncompressed public key (65 bytes): 0x04 + X + Y
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_slice = pubkey_bytes.as_bytes();

        let pubkey_uncompressed = &pubkey_slice[1..];
        let hash = Keccak256::digest(pubkey_uncompressed);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);

        // 2. Verify we can reach the NSM by issuing one attestation request.
        //    The result is discarded — /attestation endpoint regenerates on demand.
        let me = Self {
            signing_key,
            address,
            pubkey_bytes: pubkey_slice.to_vec(),
        };
        me.fresh_attestation_doc()?;

        Ok(me)
    }

    /// Generate a fresh attestation document via NSM. AWS Nitro leaf certs
    /// in the attestation chain live ~3 hours — callers must request a fresh
    /// doc close to when they'll use it on-chain.
    pub fn fresh_attestation_doc(&self) -> Result<Vec<u8>> {
        let fd = aws_nitro_enclaves_nsm_api::driver::nsm_init();
        if fd < 0 {
            return Err(eyre::eyre!("nsm_init failed: {}", fd));
        }

        let request = aws_nitro_enclaves_nsm_api::api::Request::Attestation {
            public_key: Some(self.pubkey_bytes.clone().into()),
            user_data: None,
            nonce: None,
        };

        let response = aws_nitro_enclaves_nsm_api::driver::nsm_process_request(fd, request);
        aws_nitro_enclaves_nsm_api::driver::nsm_exit(fd);

        match response {
            aws_nitro_enclaves_nsm_api::api::Response::Attestation { document } => Ok(document),
            aws_nitro_enclaves_nsm_api::api::Response::Error(err) => {
                Err(eyre::eyre!("NSM Attestation Error: {:?}", err))
            }
            _ => Err(eyre::eyre!("Unexpected NSM response")),
        }
    }
}

#[cfg(target_os = "linux")]
impl OracleSigner for EnclaveSigner {
    fn sign_price_update(
        &self,
        asset_id: B256,
        price: U256,
        timestamp: u64,
        num_sources: u8,
        sources_hash: B256,
    ) -> Result<(Vec<u8>, [u8; 20])> {
        // Construct the message hash: keccak256(abi.encodePacked(...))
        let mut payload = Vec::new();
        payload.extend_from_slice(asset_id.as_slice());
        payload.extend_from_slice(&price.to_be_bytes::<32>());
        payload.extend_from_slice(&U256::from(timestamp).to_be_bytes::<32>());
        payload.extend_from_slice(&[num_sources]);
        payload.extend_from_slice(sources_hash.as_slice());

        let message_hash = Keccak256::digest(&payload);

        // Ethereum signed message: "\x19Ethereum Signed Message:\n32" + hash
        let mut eth_message = Vec::new();
        eth_message.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        eth_message.extend_from_slice(&message_hash);
        let eth_hash = Keccak256::digest(&eth_message);

        // Sign
        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&eth_hash)
            .map_err(|e| eyre::eyre!("signing failed: {}", e))?;

        // Encode as 65-byte (r, s, v) where v = recovery_id + 27
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(&signature.to_bytes());
        sig_bytes.push(recovery_id.to_byte() + 27);

        Ok((sig_bytes, self.address))
    }

    fn address(&self) -> [u8; 20] {
        self.address
    }

    fn attestation_doc(&self) -> Option<Vec<u8>> {
        // Regenerate via NSM on every call — AWS Nitro leaf certs have ~3h TTL,
        // caching would hand out expired docs after a short while.
        match self.fresh_attestation_doc() {
            Ok(doc) => Some(doc),
            Err(e) => {
                tracing::warn!(error = %e, "NSM attestation request failed");
                None
            }
        }
    }
}
