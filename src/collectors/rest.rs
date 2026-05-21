//! Shared `reqwest::Client` for REST snapshot bootstrap. When
//! `ENCLAVE_MODE` is set the client routes through `REST_PROXY`
//! (default `socks5h://127.0.0.1:5000`).

use once_cell::sync::Lazy;
use std::time::Duration;

fn enclave_mode() -> bool {
    std::env::var("ENCLAVE_MODE").is_ok()
}

fn rest_proxy_url() -> String {
    std::env::var("REST_PROXY").unwrap_or_else(|_| "socks5h://127.0.0.1:5000".to_string())
}

fn build_client() -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(60))
        .user_agent("glob-oracle-collector/1.0");

    if enclave_mode() {
        let url = rest_proxy_url();
        match reqwest::Proxy::all(&url) {
            Ok(p) => {
                tracing::info!(proxy = %url, "REST HTTP client routed through SOCKS5 proxy (enclave mode)");
                builder = builder.proxy(p);
            }
            Err(e) => {
                tracing::warn!(error = %e, proxy = %url, "bad REST_PROXY, going direct");
            }
        }
    }

    builder.build().expect("build reqwest client")
}

pub static HTTP: Lazy<reqwest::Client> = Lazy::new(build_client);

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialise across rest_proxy_default / _override / enclave_mode_detection
    // / build_client_works_in_host_mode -- they all touch shared env vars
    // (REST_PROXY, ENCLAVE_MODE) and cargo runs tests in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_env<T>(key: &str, val: Option<&str>, f: impl FnOnce() -> T) -> T {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = std::env::var(key).ok();
        match val {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        let out = f();
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
        out
    }

    #[test]
    fn rest_proxy_default() {
        with_env("REST_PROXY", None, || {
            assert_eq!(rest_proxy_url(), "socks5h://127.0.0.1:5000");
        });
    }

    #[test]
    fn rest_proxy_override() {
        with_env("REST_PROXY", Some("socks5://10.0.0.1:1080"), || {
            assert_eq!(rest_proxy_url(), "socks5://10.0.0.1:1080");
        });
    }

    #[test]
    fn enclave_mode_detection() {
        with_env("ENCLAVE_MODE", None, || {
            assert!(!enclave_mode());
        });
        with_env("ENCLAVE_MODE", Some("1"), || {
            assert!(enclave_mode());
        });
    }

    #[test]
    fn build_client_works_in_host_mode() {
        with_env("ENCLAVE_MODE", None, || {
            // Must not panic.
            let _client = build_client();
        });
    }
}
