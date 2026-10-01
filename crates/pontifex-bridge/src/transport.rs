//! `ProxyTransport`: a [`keyex::chain::EthTransport`] backed by reqwest. In the
//! enclave the client egresses through the VSOCK→TCP CONNECT/SOCKS proxy on
//! 127.0.0.1:5000; this type is transport-agnostic and only builds/parses the
//! JSON-RPC envelope. The envelope logic is pure and unit-tested; the wire send
//! is a thin await.
//!
//! [`FailoverTransport`] spreads one read over the whole configured endpoint list:
//! a pruned node that cannot serve the pinned block must not wedge a claim.

use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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

/// Several JSON-RPC endpoints tried in order, sticky on the last one that
/// answered. Needed because RH's own node prunes state: it serves the
/// `finalized` header but not an `eth_call` at that height, so a single-endpoint
/// transport fails every registry read forever. Sticky (not round-robin) keeps a
/// multi-call read on one endpoint, so a lagging peer cannot fake a mismatch.
pub struct Failover<T> {
    endpoints: Vec<T>,
    sticky: AtomicUsize,
}

impl<T> Failover<T> {
    pub fn from_endpoints(endpoints: Vec<T>) -> Result<Self> {
        if endpoints.is_empty() {
            bail!("no RH RPC endpoints");
        }
        Ok(Self {
            endpoints,
            sticky: AtomicUsize::new(0),
        })
    }
}

impl Failover<ProxyTransport> {
    /// One endpoint per configured URL, sharing the proxied client's pool.
    pub fn new(client: reqwest::Client, urls: &[String]) -> Result<Self> {
        Self::from_endpoints(
            urls.iter()
                .map(|u| ProxyTransport::new(client.clone(), u.clone()))
                .collect(),
        )
    }
}

impl<T: EthTransport> EthTransport for Failover<T> {
    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let n = self.endpoints.len();
        let start = self.sticky.load(Ordering::Relaxed) % n;
        let mut last = None;
        for off in 0..n {
            let idx = (start + off) % n;
            match self.endpoints[idx].rpc(method, params.clone()).await {
                Ok(v) => {
                    if off != 0 {
                        self.sticky.store(idx, Ordering::Relaxed);
                    }
                    return Ok(v);
                }
                // Endpoint index only: the error text is remote-supplied and must
                // not reach host-readable enclave logs (R-8).
                Err(e) => {
                    tracing::warn!(endpoint = idx, "rh rpc endpoint failed");
                    last = Some(e);
                }
            }
        }
        Err(last.unwrap_or_else(|| eyre!("no RH RPC endpoints")))
    }
}

/// The RH-side transport: failover across every configured endpoint.
pub type FailoverTransport = Failover<ProxyTransport>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Endpoint stub: answers or fails, counting the calls it saw.
    struct Stub {
        up: bool,
        calls: AtomicUsize,
    }

    impl Stub {
        fn new(up: bool) -> Self {
            Self {
                up,
                calls: AtomicUsize::new(0),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }
    }

    impl EthTransport for Stub {
        fn rpc(&self, _method: &str, _params: Value) -> impl Future<Output = Result<Value>> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let up = self.up;
            async move {
                if up {
                    Ok(json!("0x1"))
                } else {
                    bail!("endpoint down")
                }
            }
        }
    }

    #[test]
    fn empty_endpoint_list_is_refused() {
        assert!(Failover::<Stub>::from_endpoints(vec![]).is_err());
    }

    #[tokio::test]
    async fn a_pruned_first_endpoint_falls_through_to_the_archive() {
        let f = Failover::from_endpoints(vec![Stub::new(false), Stub::new(true)]).unwrap();
        assert_eq!(f.rpc("eth_call", json!([])).await.unwrap(), json!("0x1"));
        assert_eq!(f.endpoints[0].calls(), 1);
        assert_eq!(f.endpoints[1].calls(), 1);
    }

    #[tokio::test]
    async fn the_working_endpoint_is_sticky_after_a_failover() {
        let f = Failover::from_endpoints(vec![Stub::new(false), Stub::new(true)]).unwrap();
        for _ in 0..3 {
            f.rpc("eth_call", json!([])).await.unwrap();
        }
        // The dead endpoint is paid for once, not once per read.
        assert_eq!(f.endpoints[0].calls(), 1);
        assert_eq!(f.endpoints[1].calls(), 3);
    }

    #[tokio::test]
    async fn all_endpoints_down_is_an_error() {
        let f = Failover::from_endpoints(vec![Stub::new(false), Stub::new(false)]).unwrap();
        assert!(f.rpc("eth_call", json!([])).await.is_err());
        assert_eq!(f.endpoints[0].calls(), 1);
        assert_eq!(f.endpoints[1].calls(), 1);
    }

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
