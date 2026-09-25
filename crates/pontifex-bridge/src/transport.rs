//! `ProxyTransport`: a [`keyex::chain::EthTransport`] backed by reqwest. In the
//! enclave the client egresses through the VSOCK→TCP CONNECT/SOCKS proxy on
//! 127.0.0.1:5000; this type is transport-agnostic and only builds/parses the
//! JSON-RPC envelope. The envelope logic is pure and unit-tested; the wire send
//! is a thin await.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};

use eyre::{bail, eyre, Result};
use keyex::chain::EthTransport;
use serde_json::{json, Value};

/// A JSON-RPC endpoint reached over an injected reqwest client.
pub struct ProxyTransport {
    client: reqwest::Client,
    url: String,
    id: AtomicU64,
}

impl ProxyTransport {
    pub fn new(client: reqwest::Client, url: impl Into<String>) -> Self {
        Self {
            client,
            url: url.into(),
            id: AtomicU64::new(1),
        }
    }
}

/// Build a JSON-RPC 2.0 request body.
fn build_rpc_body(id: u64, method: &str, params: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// Extract `result` from a JSON-RPC response, mapping a JSON-RPC `error` object
/// or a missing `result` to a coded failure.
fn parse_rpc_result(resp: Value) -> Result<Value> {
    if let Some(err) = resp.get("error").filter(|e| !e.is_null()) {
        let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
        bail!("json-rpc error {code}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| eyre!("json-rpc response has no result"))
}

impl EthTransport for ProxyTransport {
    fn rpc(&self, method: &str, params: Value) -> impl Future<Output = Result<Value>> {
        let id = self.id.fetch_add(1, Ordering::Relaxed);
        let body = build_rpc_body(id, method, &params);
        let req = self.client.post(&self.url).json(&body).send();
        async move {
            let resp = req.await?;
            if !resp.status().is_success() {
                bail!("rpc http status {}", resp.status());
            }
            parse_rpc_result(resp.json::<Value>().await?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_is_jsonrpc_2_0() {
        let b = build_rpc_body(7, "eth_call", &json!([{"to": "0x00"}, "latest"]));
        assert_eq!(b["jsonrpc"], "2.0");
        assert_eq!(b["id"], 7);
        assert_eq!(b["method"], "eth_call");
        assert_eq!(b["params"][1], "latest");
    }

    #[test]
    fn result_is_unwrapped() {
        let r =
            parse_rpc_result(json!({"jsonrpc": "2.0", "id": 1, "result": "0xdeadbeef"})).unwrap();
        assert_eq!(r, "0xdeadbeef");
    }

    #[test]
    fn error_object_is_a_failure() {
        let e = parse_rpc_result(json!({"error": {"code": -32000, "message": "boom"}}));
        assert!(e.is_err());
    }

    #[test]
    fn null_error_with_result_is_ok() {
        // Some nodes send `"error": null` alongside a real result.
        let r = parse_rpc_result(json!({"error": null, "result": "0x1"})).unwrap();
        assert_eq!(r, "0x1");
    }

    #[test]
    fn missing_result_is_a_failure() {
        assert!(parse_rpc_result(json!({"jsonrpc": "2.0", "id": 1})).is_err());
    }
}
