use alloy_primitives::{Address, B256, U256, Bytes};
use alloy_sol_types::{sol, SolCall};
use eyre::Result;
use sha3::{Digest, Keccak256};

// Generate Rust bindings from the Solidity function signature
sol! {
    function updatePrice(
        bytes32 assetId,
        uint256 price,
        uint256 timestamp,
        uint8   numSources,
        bytes32 sourcesHash,
        bytes   signature
    ) external;
}

/// Publisher handles submitting signed price updates to the on-chain oracle contract.
pub struct Publisher {
    rpc_url: String,
    contract_address: Address,
    /// Private key for transaction signing (gas payer, NOT the oracle signer).
    /// In production, the enclave signs the price data, but the TX itself
    /// can be submitted by any funded account.
    tx_signer_key: String,
    client: reqwest::Client,
    chain_id: u64,
}

impl Publisher {
    pub fn new(rpc_url: String, contract_address: Address, tx_signer_key: String, chain_id: u64) -> Self {
        Self {
            rpc_url,
            contract_address,
            tx_signer_key,
            client: reqwest::Client::new(),
            chain_id,
        }
    }

    /// Encode the calldata for `updatePrice(...)`.
    pub fn encode_update_call(
        asset_id: B256,
        price: U256,
        timestamp: u64,
        num_sources: u8,
        sources_hash: B256,
        signature: Vec<u8>,
    ) -> Vec<u8> {
        let call = updatePriceCall {
            assetId: asset_id.into(),
            price,
            timestamp: U256::from(timestamp),
            numSources: num_sources,
            sourcesHash: sources_hash.into(),
            signature: signature.into(),
        };
        call.abi_encode()
    }

    /// Submit a price update transaction via JSON-RPC.
    /// Returns the transaction hash on success.
    pub async fn submit_price(
        &self,
        asset_id: B256,
        price: U256,
        timestamp: u64,
        num_sources: u8,
        sources_hash: B256,
        oracle_signature: Vec<u8>,
    ) -> Result<String> {
        let calldata = Self::encode_update_call(
            asset_id, price, timestamp, num_sources, sources_hash, oracle_signature,
        );

        // Get nonce
        let nonce = self.get_nonce().await?;

        // Get gas price
        let gas_price = self.get_gas_price().await?;

        // Build raw transaction
        let tx_signer_bytes = hex::decode(self.tx_signer_key.trim_start_matches("0x"))?;
        let signing_key = k256::ecdsa::SigningKey::from_bytes((&tx_signer_bytes[..]).into())?;

        // EIP-155 transaction encoding
        let gas_limit = 300_000u64; // generous for updatePrice

        // RLP encode: [nonce, gasPrice, gasLimit, to, value, data, chainId, 0, 0]
        let mut rlp_items: Vec<Vec<u8>> = vec![
            Self::rlp_encode_u64(nonce),
            Self::rlp_encode_u256(gas_price),
            Self::rlp_encode_u64(gas_limit),
            self.contract_address.to_vec(),
            vec![0x80], // value = 0
            Self::rlp_encode_bytes(&calldata),
            Self::rlp_encode_u64(self.chain_id),
            vec![0x80], // empty
            vec![0x80], // empty
        ];

        let unsigned_tx = Self::rlp_encode_list(&rlp_items);
        let tx_hash = Keccak256::digest(&unsigned_tx);

        // Sign
        let (sig, recovery_id) = signing_key
            .sign_prehash_recoverable(&tx_hash)
            .map_err(|e| eyre::eyre!("tx signing failed: {}", e))?;

        let v = recovery_id.to_byte() as u64 + 35 + 2 * self.chain_id;

        let sig_bytes = sig.to_bytes();
        let r = &sig_bytes[..32];
        let s = &sig_bytes[32..64];

        // Replace chainId, 0, 0 with v, r, s
        rlp_items[6] = Self::rlp_encode_u64(v);
        rlp_items[7] = Self::rlp_encode_bytes(r);
        rlp_items[8] = Self::rlp_encode_bytes(s);

        let signed_tx = Self::rlp_encode_list(&rlp_items);
        let raw_tx_hex = format!("0x{}", hex::encode(&signed_tx));

        // Send via eth_sendRawTransaction
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_sendRawTransaction",
                "params": [raw_tx_hex],
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(error) = result.get("error") {
            return Err(eyre::eyre!("RPC error: {}", error));
        }

        let tx_hash = result["result"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();

        tracing::info!(tx_hash = %tx_hash, "submitted price update TX");

        Ok(tx_hash)
    }

    // ─── JSON-RPC helpers ───────────────────────────────────────────

    async fn get_nonce(&self) -> Result<u64> {
        let verifying_key = k256::ecdsa::SigningKey::from_bytes(
            (&hex::decode(self.tx_signer_key.trim_start_matches("0x"))?[..]).into(),
        )?
        .verifying_key()
        .clone();

        let pubkey = verifying_key.to_encoded_point(false);
        let pubkey_bytes = &pubkey.as_bytes()[1..];
        let hash = Keccak256::digest(pubkey_bytes);
        let address = format!("0x{}", hex::encode(&hash[12..]));

        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_getTransactionCount",
                "params": [address, "latest"],
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = resp.json().await?;
        let nonce_hex = result["result"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("no nonce result"))?;

        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)?;
        Ok(nonce)
    }

    async fn get_gas_price(&self) -> Result<U256> {
        let resp = self
            .client
            .post(&self.rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": "eth_gasPrice",
                "params": [],
                "id": 1
            }))
            .send()
            .await?;

        let result: serde_json::Value = resp.json().await?;
        let price_hex = result["result"]
            .as_str()
            .ok_or_else(|| eyre::eyre!("no gas price result"))?;

        let price = u128::from_str_radix(price_hex.trim_start_matches("0x"), 16)?;
        Ok(U256::from(price))
    }

    // ─── RLP encoding helpers ───────────────────────────────────────

    fn rlp_encode_u64(val: u64) -> Vec<u8> {
        if val == 0 {
            return vec![0x80];
        }
        let bytes = val.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let significant = &bytes[start..];
        if significant.len() == 1 && significant[0] < 0x80 {
            significant.to_vec()
        } else {
            let mut result = vec![0x80 + significant.len() as u8];
            result.extend_from_slice(significant);
            result
        }
    }

    fn rlp_encode_u256(val: U256) -> Vec<u8> {
        let bytes = val.to_be_bytes::<32>();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
        let significant = &bytes[start..];
        if significant.is_empty() {
            return vec![0x80];
        }
        if significant.len() == 1 && significant[0] < 0x80 {
            significant.to_vec()
        } else {
            let mut result = vec![0x80 + significant.len() as u8];
            result.extend_from_slice(significant);
            result
        }
    }

    fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return vec![0x80];
        }
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        if data.len() < 56 {
            let mut result = vec![0x80 + data.len() as u8];
            result.extend_from_slice(data);
            result
        } else {
            let len_bytes = Self::rlp_encode_length_bytes(data.len());
            let mut result = vec![0xb7 + len_bytes.len() as u8];
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(data);
            result
        }
    }

    fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let payload: Vec<u8> = items.iter().flatten().copied().collect();
        if payload.len() < 56 {
            let mut result = vec![0xc0 + payload.len() as u8];
            result.extend_from_slice(&payload);
            result
        } else {
            let len_bytes = Self::rlp_encode_length_bytes(payload.len());
            let mut result = vec![0xf7 + len_bytes.len() as u8];
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(&payload);
            result
        }
    }

    fn rlp_encode_length_bytes(len: usize) -> Vec<u8> {
        let bytes = (len as u64).to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        bytes[start..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_update_call() {
        let asset_id = B256::ZERO;
        let price = U256::from(212926000000u64);
        let timestamp = 1710000000u64;
        let num_sources = 4u8;
        let sources_hash = B256::ZERO;
        let signature = vec![0u8; 65];

        let calldata = Publisher::encode_update_call(
            asset_id, price, timestamp, num_sources, sources_hash, signature,
        );

        // Should start with the function selector for updatePrice(...)
        assert!(calldata.len() > 4);
        // Function selector = first 4 bytes of keccak256("updatePrice(bytes32,uint256,uint256,uint8,bytes32,bytes)")
    }

    #[test]
    fn test_rlp_encode_u64() {
        assert_eq!(Publisher::rlp_encode_u64(0), vec![0x80]);
        assert_eq!(Publisher::rlp_encode_u64(1), vec![0x01]);
        assert_eq!(Publisher::rlp_encode_u64(127), vec![0x7f]);
        assert_eq!(Publisher::rlp_encode_u64(128), vec![0x81, 0x80]);
        assert_eq!(Publisher::rlp_encode_u64(256), vec![0x82, 0x01, 0x00]);
    }
}
