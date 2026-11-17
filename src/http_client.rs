//! HTTP client of the price sources: allowlisted hosts, typed errors, one retry
//! inside the call deadline and a per-host pause after 403, 451, 429 or 418.
//! In enclave mode traffic goes through the local CONNECT bridge (port 5000)
//! and TLS terminates inside the enclave. An accepted response always carries
//! the server `Date`; the enclave never reads its own clock for signing
//! (audit C-3/H-9).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use chrono::DateTime;
use reqwest::header::{CONTENT_TYPE, DATE, RETRY_AFTER};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::time::Instant;

/// Response body cap (audit H-8); ticker bodies are a few KB.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;
/// Bytes of a non-2xx body kept for the error text.
const PREVIEW_BYTES: usize = 200;
const ENCLAVE_PROXY: &str = "http://127.0.0.1:5000";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const USER_AGENT: &str = "KaskadOracle/0.1";

/// Retry budget of one call. A retryable failure is retried only while its
/// pause plus `min_after_pause` still fits before the deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Bound on the whole call: every attempt and the pause between them.
    pub deadline: Duration,
    /// Wait before the retry; a retried 429 waits its `Retry-After` instead.
    pub pause: Duration,
    /// Time the retry must still have once its pause is over.
    pub min_after_pause: Duration,
    /// Longest `Retry-After` a 429 may carry and still be retried.
    pub max_retry_after: Duration,
    pub max_attempts: u32,
}

/// Policy of every GET; POST callers derive theirs from it.
pub const GET_POLICY: RetryPolicy = RetryPolicy {
    deadline: Duration::from_secs(10),
    pause: Duration::from_millis(250),
    min_after_pause: Duration::from_secs(1),
    max_retry_after: Duration::from_secs(1),
    max_attempts: 2,
};

/// How long a host gets no requests after a blocking or rate-limiting status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PausePolicy {
    pub unavailable_for_legal_reasons: Duration,
    pub forbidden: Duration,
    /// 429 or 418 without a usable `Retry-After`.
    pub rate_limited: Duration,
    /// Cap on a pause taken from `Retry-After`.
    pub max_rate_limited: Duration,
}

pub const HOST_PAUSES: PausePolicy = PausePolicy {
    unavailable_for_legal_reasons: Duration::from_secs(600),
    forbidden: Duration::from_secs(60),
    rate_limited: Duration::from_secs(30),
    max_rate_limited: Duration::from_secs(120),
};

/// Failure class; drives retry and pause decisions and the diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// HTTP 429 or 418.
    RateLimited,
    /// HTTP 403 or 451.
    Blocked,
    /// Any other 4xx.
    ClientError,
    /// 5xx.
    ServerError,
    /// The call deadline expired.
    Timeout,
    /// Connect, TLS or proxy refusal, or the connection cut before the response ended.
    Network,
    /// Unusable response: unexpected status, redirect loop, bad `Date`, oversized or non-JSON body.
    BadResponse,
    /// Invalid URL or host outside the allowlist; nothing was sent.
    Config,
    /// Host paused; nothing was sent.
    CoolingDown,
}

impl ErrorClass {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorClass::RateLimited => "rate_limited",
            ErrorClass::Blocked => "blocked",
            ErrorClass::ClientError => "client_error",
            ErrorClass::ServerError => "server_error",
            ErrorClass::Timeout => "timeout",
            ErrorClass::Network => "network",
            ErrorClass::BadResponse => "bad_response",
            ErrorClass::Config => "config",
            ErrorClass::CoolingDown => "cooling_down",
        }
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn status_class(code: u16) -> ErrorClass {
    match code {
        418 | 429 => ErrorClass::RateLimited,
        403 | 451 => ErrorClass::Blocked,
        400..=499 => ErrorClass::ClientError,
        500..=599 => ErrorClass::ServerError,
        _ => ErrorClass::BadResponse,
    }
}

/// Outcome of a failed attempt or call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpError {
    DisallowedHost,
    InvalidUrl {
        detail: String,
    },
    Connect {
        detail: String,
    },
    Timeout,
    /// Connection cut while the 2xx body was in flight.
    Transport {
        detail: String,
    },
    TooManyRedirects,
    /// Any non-2xx status; `retry_after` is already resolved against the response `Date`.
    Status {
        code: u16,
        retry_after: Option<Duration>,
        preview: String,
    },
    MissingDate,
    BadDate,
    BodyTooLarge,
    NotJson {
        detail: String,
    },
    CoolingDown {
        remaining: Duration,
        cause: ErrorClass,
    },
}

impl HttpError {
    pub fn class(&self) -> ErrorClass {
        match self {
            HttpError::DisallowedHost | HttpError::InvalidUrl { .. } => ErrorClass::Config,
            HttpError::Connect { .. } | HttpError::Transport { .. } => ErrorClass::Network,
            HttpError::Timeout => ErrorClass::Timeout,
            HttpError::Status { code, .. } => status_class(*code),
            HttpError::TooManyRedirects
            | HttpError::MissingDate
            | HttpError::BadDate
            | HttpError::BodyTooLarge
            | HttpError::NotJson { .. } => ErrorClass::BadResponse,
            HttpError::CoolingDown { .. } => ErrorClass::CoolingDown,
        }
    }

    /// Wait before a retry, or None when this outcome is final.
    fn retry_pause(&self, policy: &RetryPolicy) -> Option<Duration> {
        match self {
            HttpError::Connect { .. } | HttpError::Transport { .. } => Some(policy.pause),
            HttpError::Status {
                code: 408 | 425 | 500 | 502 | 503 | 504,
                ..
            } => Some(policy.pause),
            HttpError::Status {
                code: 429,
                retry_after: Some(wait),
                ..
            } if *wait <= policy.max_retry_after => Some(*wait),
            _ => None,
        }
    }

    /// Host pause this outcome starts, with the status that started it.
    fn host_pause(&self, pauses: &PausePolicy) -> Option<(u16, Duration)> {
        let HttpError::Status {
            code, retry_after, ..
        } = self
        else {
            return None;
        };
        let length = match code {
            451 => pauses.unavailable_for_legal_reasons,
            403 => pauses.forbidden,
            418 | 429 => retry_after.map_or(pauses.rate_limited, |wait| {
                wait.min(pauses.max_rate_limited)
            }),
            _ => return None,
        };
        Some((*code, length))
    }
}

/// A failed call: its host (never the path or query), the attempts that went
/// to the network and the outcome of the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestError {
    /// Empty when the URL has no host.
    pub host: String,
    pub attempts: u32,
    pub error: HttpError,
}

impl RequestError {
    pub fn class(&self) -> ErrorClass {
        self.error.class()
    }

    pub fn http_status(&self) -> Option<u16> {
        match self.error {
            HttpError::Status { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = &self.host;
        match &self.error {
            HttpError::DisallowedHost => write!(
                f,
                "disallowed host {host} (not in exchange_hostnames allowlist)"
            ),
            HttpError::InvalidUrl { detail } => write!(f, "invalid url: {detail}"),
            HttpError::Connect { detail } => write!(f, "connect to {host} failed: {detail}"),
            HttpError::Timeout => write!(f, "request to {host} timed out"),
            HttpError::Transport { detail } => write!(f, "connection to {host} cut: {detail}"),
            HttpError::TooManyRedirects => write!(f, "too many redirects from {host}"),
            HttpError::Status { code, preview, .. } => {
                let reason = reqwest::StatusCode::from_u16(*code)
                    .ok()
                    .and_then(|s| s.canonical_reason())
                    .unwrap_or("");
                write!(f, "HTTP {code} {reason} from {host}: {preview}")
            }
            HttpError::MissingDate => write!(f, "missing Date header from {host}"),
            HttpError::BadDate => write!(f, "bad Date header from {host}"),
            HttpError::BodyTooLarge => write!(
                f,
                "response body from {host} exceeds {MAX_RESPONSE_BYTES} bytes"
            ),
            HttpError::NotJson { detail } => write!(f, "non-JSON body from {host}: {detail}"),
            HttpError::CoolingDown { remaining, cause } => write!(
                f,
                "{host} paused for {:.1}s after {cause}",
                remaining.as_secs_f64()
            ),
        }
    }
}

impl std::error::Error for RequestError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Post,
}

/// One raw response, read no further than the body cap.
#[derive(Debug, Clone, Default)]
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) date: Option<String>,
    pub(crate) retry_after: Option<String>,
    pub(crate) body: Vec<u8>,
    /// The body was longer than `MAX_RESPONSE_BYTES`; `body` holds its start.
    pub(crate) oversized: bool,
}

/// One attempt on the wire: reqwest in production, a script in tests.
#[async_trait]
pub(crate) trait Exchange: Send + Sync {
    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<&'static [u8]>,
        timeout: Duration,
    ) -> Result<Reply, HttpError>;
}

struct ReqwestExchange {
    get: reqwest::Client,
    /// Never follows a redirect: the allowlist only vets the URL a request starts from.
    post: reqwest::Client,
}

#[async_trait]
impl Exchange for ReqwestExchange {
    async fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<&'static [u8]>,
        timeout: Duration,
    ) -> Result<Reply, HttpError> {
        let request = match method {
            Method::Get => self.get.get(url),
            Method::Post => self
                .post
                .post(url)
                .header(CONTENT_TYPE, "application/json")
                .body(body.unwrap_or_default()),
        };
        let mut resp = request
            .timeout(timeout)
            .send()
            .await
            .map_err(transport_error)?;
        let header = |name| {
            resp.headers()
                .get(name)
                .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        };
        let date = header(DATE);
        let retry_after = header(RETRY_AFTER);
        let status = resp.status();
        let (body, oversized) = read_capped(&mut resp, status.is_success()).await?;
        Ok(Reply {
            status: status.as_u16(),
            date,
            retry_after,
            body,
            oversized,
        })
    }
}

/// Reads the body up to the cap. A 2xx body cut short is a transport error;
/// for any other status the status decides, so a partial body is kept.
async fn read_capped(
    resp: &mut reqwest::Response,
    success: bool,
) -> Result<(Vec<u8>, bool), HttpError> {
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Ok((Vec::new(), true));
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                let room = MAX_RESPONSE_BYTES - body.len();
                if chunk.len() > room {
                    body.extend_from_slice(&chunk[..room]);
                    return Ok((body, true));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok((body, false)),
            Err(_) if !success => return Ok((body, false)),
            Err(e) => return Err(transport_error(e)),
        }
    }
}

/// Maps a reqwest failure; a refused CONNECT is a connect error.
fn transport_error(err: reqwest::Error) -> HttpError {
    let err = err.without_url();
    let detail = root_cause(&err);
    if err.is_builder() {
        HttpError::InvalidUrl { detail }
    } else if err.is_connect() {
        HttpError::Connect { detail }
    } else if err.is_timeout() {
        HttpError::Timeout
    } else if err.is_redirect() {
        HttpError::TooManyRedirects
    } else {
        HttpError::Transport { detail }
    }
}

fn root_cause(err: &(dyn std::error::Error + 'static)) -> String {
    let mut cause = err;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// Status first, then `Date`, the body cap and JSON.
fn interpret<T: DeserializeOwned>(reply: Reply) -> Result<(T, u64), HttpError> {
    let date = reply.date.as_deref().map(parse_http_date);
    if !(200..300).contains(&reply.status) {
        let retry_after = reply
            .retry_after
            .as_deref()
            .and_then(|v| parse_retry_after(v, date.flatten()));
        let preview = &reply.body[..reply.body.len().min(PREVIEW_BYTES)];
        return Err(HttpError::Status {
            code: reply.status,
            retry_after,
            preview: String::from_utf8_lossy(preview).into_owned(),
        });
    }
    let server_unix = match date {
        None => return Err(HttpError::MissingDate),
        Some(None) => return Err(HttpError::BadDate),
        Some(Some(unix)) => unix,
    };
    if reply.oversized {
        return Err(HttpError::BodyTooLarge);
    }
    let parsed = serde_json::from_slice(&reply.body).map_err(|e| HttpError::NotJson {
        detail: e.to_string(),
    })?;
    Ok((parsed, server_unix))
}

/// Unix seconds of an IMF-fixdate (RFC 2822) header; None unless positive.
fn parse_http_date(value: &str) -> Option<u64> {
    let unix = DateTime::parse_from_rfc2822(value.trim()).ok()?.timestamp();
    u64::try_from(unix).ok().filter(|t| *t > 0)
}

/// `Retry-After` as delay-seconds, or as an HTTP-date measured against the
/// `Date` of the same response; None when neither applies.
fn parse_retry_after(value: &str, date: Option<u64>) -> Option<Duration> {
    let value = value.trim();
    if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse().ok().map(Duration::from_secs);
    }
    let at = parse_http_date(value)?;
    Some(Duration::from_secs(at.saturating_sub(date?)))
}

/// A host pause: when it ends and the class that started it.
#[derive(Debug, Clone, Copy)]
struct Pause {
    until: Instant,
    cause: ErrorClass,
}

/// HTTP client shared by every source; clones share the host pauses.
#[derive(Clone)]
pub struct HttpClient {
    exchange: Arc<dyn Exchange>,
    /// From `config/assets.json → exchange_hostnames`, measured in PCR0. A
    /// request to any other host fails before a connection is opened
    /// (audit EXPLOIT-class CONNECT destination-allowlist).
    allowed_hosts: Vec<String>,
    /// Keyed by allowlisted hostname only, so bounded by the allowlist.
    pauses: Arc<Mutex<HashMap<String, Pause>>>,
}

fn build_client(proxy: Option<&str>, redirect: reqwest::redirect::Policy) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .timeout(GET_POLICY.deadline)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(redirect)
        .user_agent(USER_AGENT);
    if let Some(proxy) = proxy {
        // The host relays ciphertext only: TLS runs inside the enclave.
        let proxy =
            reqwest::Proxy::all(proxy).expect("Failed to configure enclave VSOCK proxy tunnel");
        builder = builder.proxy(proxy);
    }
    builder.build().expect("failed to create reqwest client")
}

impl HttpClient {
    pub fn new(enclave_mode: bool, allowed_hosts: Vec<String>) -> Self {
        Self::with_proxy(enclave_mode.then_some(ENCLAVE_PROXY), allowed_hosts)
    }

    fn with_proxy(proxy: Option<&str>, allowed_hosts: Vec<String>) -> Self {
        let exchange = ReqwestExchange {
            get: build_client(proxy, reqwest::redirect::Policy::limited(2)),
            post: build_client(proxy, reqwest::redirect::Policy::none()),
        };
        Self::with_exchange(Arc::new(exchange), allowed_hosts)
    }

    pub(crate) fn with_exchange(exchange: Arc<dyn Exchange>, allowed_hosts: Vec<String>) -> Self {
        Self {
            exchange,
            allowed_hosts,
            pauses: Arc::default(),
        }
    }

    /// GET under [`GET_POLICY`]: the parsed body and the server `Date` as unix seconds.
    pub async fn get_json_with_time<T: DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<(T, u64), RequestError> {
        self.call(Method::Get, url, None, &GET_POLICY).await
    }

    /// POST a JSON `body` under `policy`, never following a redirect. Same
    /// allowlist, body cap and `Date` rules as GET.
    pub async fn post_json_with_time<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &'static [u8],
        policy: &RetryPolicy,
    ) -> Result<(T, u64), RequestError> {
        self.call(Method::Post, url, Some(body), policy).await
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        url: &str,
        body: Option<&'static [u8]>,
        policy: &RetryPolicy,
    ) -> Result<(T, u64), RequestError> {
        let host = self.check_host(url)?;
        let deadline = Instant::now() + policy.deadline;
        let mut attempts = 0;
        let mut previous: Option<HttpError> = None;
        loop {
            if let Some(cooling) = self.cooling_down(&host) {
                return Err(RequestError {
                    host,
                    attempts,
                    error: previous.unwrap_or(cooling),
                });
            }
            attempts += 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            let sent = self.exchange.send(method, url, body, remaining);
            let error = match tokio::time::timeout(remaining, sent).await {
                Ok(Ok(reply)) => match interpret(reply) {
                    Ok(value) => {
                        self.lock_pauses().remove(&host);
                        return Ok(value);
                    }
                    Err(error) => error,
                },
                Ok(Err(error)) => error,
                Err(_) => HttpError::Timeout,
            };
            if let Some((_, length)) = error.host_pause(&HOST_PAUSES) {
                self.start_pause(&host, error.class(), length);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match error.retry_pause(policy) {
                Some(pause)
                    if attempts < policy.max_attempts && left >= pause + policy.min_after_pause =>
                {
                    tokio::time::sleep(pause).await;
                    previous = Some(error);
                }
                _ => {
                    return Err(RequestError {
                        host,
                        attempts,
                        error,
                    })
                }
            }
        }
    }

    /// Hostname allowlist gate, checked before any network call.
    fn check_host(&self, url: &str) -> Result<String, RequestError> {
        let refuse = |host: &str, error| RequestError {
            host: host.to_string(),
            attempts: 0,
            error,
        };
        let parsed = reqwest::Url::parse(url).map_err(|e| {
            refuse(
                "",
                HttpError::InvalidUrl {
                    detail: e.to_string(),
                },
            )
        })?;
        let host = parsed.host_str().ok_or_else(|| {
            refuse(
                "",
                HttpError::InvalidUrl {
                    detail: "no host".into(),
                },
            )
        })?;
        if !self.allowed_hosts.iter().any(|h| h == host) {
            return Err(refuse(host, HttpError::DisallowedHost));
        }
        Ok(host.to_string())
    }

    fn lock_pauses(&self) -> MutexGuard<'_, HashMap<String, Pause>> {
        self.pauses.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The pause still running for `host`; an expired one is dropped.
    fn cooling_down(&self, host: &str) -> Option<HttpError> {
        let now = Instant::now();
        let mut pauses = self.lock_pauses();
        let pause = *pauses.get(host)?;
        if now >= pause.until {
            pauses.remove(host);
            return None;
        }
        Some(HttpError::CoolingDown {
            remaining: pause.until - now,
            cause: pause.cause,
        })
    }

    fn start_pause(&self, host: &str, cause: ErrorClass, length: Duration) {
        if length.is_zero() {
            return;
        }
        let until = Instant::now() + length;
        self.lock_pauses()
            .insert(host.to_string(), Pause { until, cause });
    }
}

/// Scripted [`Exchange`] for tests that drive the retry and pause rules in
/// paused tokio time.
#[cfg(test)]
pub(crate) mod mock {
    use super::*;

    /// What one scripted attempt does.
    pub(crate) enum Step {
        Answer(Reply),
        Fail(HttpError),
        /// Never answers; only the call deadline ends it.
        Hang,
        /// Waits, then does the inner step.
        After(Duration, Box<Step>),
    }

    /// One attempt as the exchange received it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct Sent {
        pub(crate) method: Method,
        pub(crate) url: String,
        pub(crate) body: Option<&'static [u8]>,
        pub(crate) at: Instant,
    }

    type Plan = Box<dyn Fn(&str, usize) -> Step + Send + Sync>;

    /// Answers attempt `n` (0-based, counted per URL) with `plan(url, n)`.
    pub(crate) struct MockExchange {
        plan: Plan,
        sent: Mutex<Vec<Sent>>,
    }

    impl MockExchange {
        pub(crate) fn new(plan: impl Fn(&str, usize) -> Step + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Self {
                plan: Box::new(plan),
                sent: Mutex::default(),
            })
        }

        pub(crate) fn sent(&self) -> Vec<Sent> {
            self.sent.lock().unwrap().clone()
        }

        pub(crate) fn count(&self, url: &str) -> usize {
            self.sent().iter().filter(|s| s.url == url).count()
        }
    }

    #[async_trait]
    impl Exchange for MockExchange {
        async fn send(
            &self,
            method: Method,
            url: &str,
            body: Option<&'static [u8]>,
            _timeout: Duration,
        ) -> Result<Reply, HttpError> {
            let nth = {
                let mut sent = self.sent.lock().unwrap();
                let nth = sent.iter().filter(|s| s.url == url).count();
                sent.push(Sent {
                    method,
                    url: url.to_string(),
                    body,
                    at: Instant::now(),
                });
                nth
            };
            let mut step = (self.plan)(url, nth);
            loop {
                match step {
                    Step::After(wait, next) => {
                        tokio::time::sleep(wait).await;
                        step = *next;
                    }
                    Step::Answer(reply) => return Ok(reply),
                    Step::Fail(error) => return Err(error),
                    Step::Hang => std::future::pending::<()>().await,
                }
            }
        }
    }

    pub(crate) fn reply(status: u16, date: Option<&str>, body: &str) -> Reply {
        Reply {
            status,
            date: date.map(str::to_string),
            body: body.as_bytes().to_vec(),
            ..Reply::default()
        }
    }

    pub(crate) fn connect_error() -> HttpError {
        HttpError::Connect {
            detail: "Connection refused (os error 111)".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{connect_error, reply, MockExchange, Step};
    use super::*;
    use serde_json::Value;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const SERVER_DATE: &str = "Tue, 17 Nov 2026 12:00:00 GMT";
    const SERVER_UNIX: u64 = 1_794_916_800;
    const REDIRECT_PATH: &str = "/start";
    const TARGET_BODY: &str = r#"{"ok":true}"#;
    const HOST: &str = "api.example.com";
    const URL: &str = "https://api.example.com/ticker?symbol=BTCUSDT";
    const OTHER_URL: &str = "https://other.example.com/ticker";
    const RPC_LIKE: RetryPolicy = RetryPolicy {
        deadline: Duration::from_secs(4),
        ..GET_POLICY
    };

    /// One request as the test server received it.
    #[derive(Debug, Clone)]
    struct Seen {
        method: String,
        path: String,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;
    type Respond = Arc<dyn Fn(&Seen) -> Vec<u8> + Send + Sync>;

    /// Serves every request with `respond`; returns the base URL and the log.
    async fn serve_with(respond: Respond) -> (String, Log) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let log: Log = Arc::default();
        let server_log = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(answer(
                    stream,
                    Arc::clone(&respond),
                    Arc::clone(&server_log),
                ));
            }
        });
        (base, log)
    }

    /// `REDIRECT_PATH` answers `redirect_status` to `/next`; any other path 200 `TARGET_BODY`.
    async fn serve(redirect_status: &'static str) -> (String, Log) {
        serve_with(Arc::new(move |seen: &Seen| {
            let (status, location) = if seen.path == REDIRECT_PATH {
                (redirect_status, "Location: /next\r\n")
            } else {
                ("200 OK", "")
            };
            format!(
                "HTTP/1.1 {status}\r\nDate: {SERVER_DATE}\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{TARGET_BODY}",
                TARGET_BODY.len()
            )
            .into_bytes()
        }))
        .await
    }

    async fn read_head(stream: &mut TcpStream) -> (Vec<u8>, usize) {
        let mut buf = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the request head");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return (buf, i + 4);
            }
        }
    }

    async fn answer(mut stream: TcpStream, respond: Respond, log: Log) {
        let (buf, head_end) = read_head(&mut stream).await;
        let head = String::from_utf8(buf[..head_end].to_vec()).unwrap();
        let mut request_line = head.split("\r\n").next().unwrap().split(' ');
        let method = request_line.next().unwrap().to_string();
        let path = request_line.next().unwrap().to_string();
        let header = |name: &str| {
            head.split("\r\n").find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
            })
        };
        let content_length: usize = header("content-length").map_or(0, |v| v.parse().unwrap());
        let mut body = buf[head_end..].to_vec();
        while body.len() < content_length {
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0, "connection closed before the request body");
            body.extend_from_slice(&chunk[..n]);
        }
        let seen = Seen {
            method,
            path,
            content_type: header("content-type"),
            body,
        };
        let response = respond(&seen);
        log.lock().unwrap().push(seen);
        // The client may hang up early on an oversized body.
        if stream.write_all(&response).await.is_ok() {
            let _ = stream.shutdown().await;
        }
    }

    fn local_client() -> HttpClient {
        HttpClient::new(false, vec!["127.0.0.1".into()])
    }

    fn paths(log: &Log) -> Vec<String> {
        log.lock().unwrap().iter().map(|s| s.path.clone()).collect()
    }

    #[tokio::test]
    async fn post_never_follows_a_redirect() {
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "303 See Other",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            let (base, log) = serve(status).await;
            let err = local_client()
                .post_json_with_time::<Value>(&format!("{base}{REDIRECT_PATH}"), b"{}", &RPC_LIKE)
                .await
                .expect_err("a redirect must not be followed");
            assert!(err.to_string().contains(status), "{status}: {err}");
            assert_eq!(err.class(), ErrorClass::BadResponse, "{status}");
            assert_eq!(paths(&log), [REDIRECT_PATH], "{status}");
        }
    }

    #[tokio::test]
    async fn get_still_follows_a_redirect() {
        let (base, log) = serve("302 Found").await;
        let (body, server_time) = local_client()
            .get_json_with_time::<Value>(&format!("{base}{REDIRECT_PATH}"))
            .await
            .unwrap();
        assert_eq!(body, serde_json::json!({"ok": true}));
        assert_eq!(server_time, SERVER_UNIX);
        assert_eq!(paths(&log), [REDIRECT_PATH, "/next"]);
    }

    #[tokio::test]
    async fn post_sends_the_json_body_and_returns_the_date() {
        const SENT: &[u8] = br#"{"jsonrpc":"2.0","id":1}"#;
        let (base, log) = serve("307 Temporary Redirect").await;
        let (body, server_time) = local_client()
            .post_json_with_time::<Value>(&format!("{base}/rpc"), SENT, &RPC_LIKE)
            .await
            .unwrap();
        assert_eq!(body, serde_json::json!({"ok": true}));
        assert_eq!(server_time, SERVER_UNIX);
        let seen = log.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].method, "POST");
        assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
        assert_eq!(seen[0].body, SENT);
    }

    #[tokio::test]
    async fn allowlist_vets_the_host_and_post_keeps_the_path() {
        let bundled = crate::types::load_assets().unwrap().exchange_hostnames;
        HttpClient::new(false, bundled)
            .check_host("https://0xrpc.io/eth")
            .expect("0xrpc.io is allowlisted by host");
        let (base, log) = serve("307 Temporary Redirect").await;
        local_client()
            .post_json_with_time::<Value>(&format!("{base}/eth"), b"{}", &RPC_LIKE)
            .await
            .unwrap();
        assert_eq!(paths(&log), ["/eth"]);
    }

    #[tokio::test]
    async fn post_rejects_a_host_outside_the_allowlist() {
        let client = HttpClient::new(false, vec!["example.com".into()]);
        let err = client
            .post_json_with_time::<Value>("http://127.0.0.1:9/rpc", b"{}", &RPC_LIKE)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("disallowed host"), "{err}");
        assert_eq!((err.class(), err.attempts), (ErrorClass::Config, 0));
    }

    #[tokio::test]
    async fn post_honours_the_caller_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/rpc", listener.local_addr().unwrap());
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Keep the connection open without answering.
            let _ = held_tx.send(stream);
        });
        let short = RetryPolicy {
            deadline: Duration::from_millis(300),
            ..RPC_LIKE
        };
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            local_client().post_json_with_time::<Value>(&url, b"{}", &short),
        )
        .await
        .expect("the call deadline must fire before the guard");
        let err = outcome.unwrap_err();
        assert_eq!((err.class(), err.attempts), (ErrorClass::Timeout, 1));
        assert!(started.elapsed() < Duration::from_secs(4));
        drop(held_rx);
    }

    /// Answers `/status/<code>` with that status, no `Date` and a body of `/len/<n>` bytes.
    fn raw(status: &str, date: bool, content_length: bool, body_len: usize) -> Vec<u8> {
        let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
        if date {
            head.push_str(&format!("Date: {SERVER_DATE}\r\n"));
        }
        if content_length {
            head.push_str(&format!("Content-Length: {body_len}\r\n"));
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.resize(bytes.len() + body_len, b'x');
        bytes
    }

    #[tokio::test]
    async fn status_decides_before_date_and_the_cap_holds_for_every_status() {
        let over = MAX_RESPONSE_BYTES + 1;
        let cases: [(&str, Respond, ErrorClass, u32); 5] = [
            (
                "503 without Date",
                Arc::new(|_: &Seen| raw("503 Service Unavailable", false, true, 0)),
                ErrorClass::ServerError,
                2,
            ),
            (
                "503 with an oversized body",
                Arc::new(move |_: &Seen| raw("503 Service Unavailable", true, false, over)),
                ErrorClass::ServerError,
                2,
            ),
            (
                "404 with an oversized declared body",
                Arc::new(move |_: &Seen| raw("404 Not Found", false, true, over)),
                ErrorClass::ClientError,
                1,
            ),
            (
                "200 with an oversized streamed body",
                Arc::new(move |_: &Seen| raw("200 OK", true, false, over)),
                ErrorClass::BadResponse,
                1,
            ),
            (
                "200 without Date",
                Arc::new(|_: &Seen| raw("200 OK", false, true, 2)),
                ErrorClass::BadResponse,
                1,
            ),
        ];
        for (name, respond, class, attempts) in cases {
            let (base, log) = serve_with(respond).await;
            let err = local_client()
                .get_json_with_time::<Value>(&format!("{base}/x"))
                .await
                .unwrap_err();
            assert_eq!(
                (err.class(), err.attempts),
                (class, attempts),
                "{name}: {err}"
            );
            assert_eq!(log.lock().unwrap().len(), attempts as usize, "{name}");
        }
    }

    /// A CONNECT proxy that refuses every tunnel with `status`.
    async fn refusing_proxy(status: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let connects = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&connects);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let (head, _) = read_head(&mut stream).await;
                assert!(head.starts_with(b"CONNECT rpc.example.com:443 "));
                seen.fetch_add(1, Ordering::SeqCst);
                let reply = format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n");
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
        (proxy, connects)
    }

    #[tokio::test]
    async fn a_refused_connect_is_network_and_never_pauses_the_host() {
        for status in ["403 Forbidden", "429 Too Many Requests", "502 Bad Gateway"] {
            let (proxy, connects) = refusing_proxy(status).await;
            let client = HttpClient::with_proxy(Some(&proxy), vec!["rpc.example.com".into()]);
            for expected in [2, 4] {
                let err = client
                    .post_json_with_time::<Value>("https://rpc.example.com/", b"{}", &RPC_LIKE)
                    .await
                    .unwrap_err();
                assert_eq!(err.class(), ErrorClass::Network, "{status}: {err}");
                assert_eq!(err.http_status(), None, "{status}");
                assert_eq!(err.attempts, 2, "{status}");
                assert_eq!(connects.load(Ordering::SeqCst), expected, "{status}");
            }
        }
    }

    fn scripted(
        plan: impl Fn(&str, usize) -> Step + Send + Sync + 'static,
    ) -> (HttpClient, Arc<MockExchange>) {
        let exchange = MockExchange::new(plan);
        let hosts = vec![HOST.into(), "other.example.com".into()];
        (HttpClient::with_exchange(exchange.clone(), hosts), exchange)
    }

    fn ok() -> Step {
        Step::Answer(reply(200, Some(SERVER_DATE), TARGET_BODY))
    }

    fn status(code: u16) -> Step {
        Step::Answer(reply(code, Some(SERVER_DATE), ""))
    }

    fn rate_limited(retry_after: &str) -> Step {
        Step::Answer(Reply {
            retry_after: Some(retry_after.into()),
            ..reply(429, Some(SERVER_DATE), "")
        })
    }

    /// Builds the scripted first attempt of a case.
    type First = fn() -> Step;

    struct Case {
        name: &'static str,
        first: First,
        /// When the first attempt ends, from the start of the call.
        at: Duration,
        attempts: u32,
        /// Gap between the end of attempt 1 and the start of attempt 2.
        pause: Duration,
        /// None: the retry succeeds.
        class: Option<ErrorClass>,
    }

    const fn case(name: &'static str, first: First, attempts: u32) -> Case {
        Case {
            name,
            first,
            at: Duration::ZERO,
            attempts,
            pause: GET_POLICY.pause,
            class: None,
        }
    }

    const fn fails(mut c: Case, class: ErrorClass) -> Case {
        c.class = Some(class);
        c
    }

    const fn at(mut c: Case, millis: u64) -> Case {
        c.at = Duration::from_millis(millis);
        c
    }

    const fn paused(mut c: Case, millis: u64) -> Case {
        c.pause = Duration::from_millis(millis);
        c
    }

    #[tokio::test(start_paused = true)]
    async fn attempts_follow_the_condition_table() {
        use ErrorClass::*;
        let cases = [
            case("connect error", || Step::Fail(connect_error()), 2),
            case(
                "connection cut",
                || {
                    Step::Fail(HttpError::Transport {
                        detail: "unexpected EOF".into(),
                    })
                },
                2,
            ),
            case("HTTP 500", || status(500), 2),
            case("HTTP 502", || status(502), 2),
            case("HTTP 503", || status(503), 2),
            case("HTTP 504", || status(504), 2),
            case("HTTP 408", || status(408), 2),
            case("HTTP 425", || status(425), 2),
            case(
                "HTTP 503 without Date",
                || Step::Answer(reply(503, None, "")),
                2,
            ),
            paused(case("429 Retry-After 0", || rate_limited("0"), 2), 0),
            paused(case("429 Retry-After 1", || rate_limited("1"), 2), 1000),
            paused(
                case(
                    "429 Retry-After 1 s as HTTP-date",
                    || rate_limited("Tue, 17 Nov 2026 12:00:01 GMT"),
                    2,
                ),
                1000,
            ),
            fails(
                case("429 Retry-After 5", || rate_limited("5"), 1),
                RateLimited,
            ),
            fails(
                case("429 without Retry-After", || status(429), 1),
                RateLimited,
            ),
            fails(case("HTTP 418", || status(418), 1), RateLimited),
            fails(case("HTTP 403", || status(403), 1), Blocked),
            fails(case("HTTP 451", || status(451), 1), Blocked),
            fails(case("HTTP 400", || status(400), 1), ClientError),
            fails(case("HTTP 404", || status(404), 1), ClientError),
            fails(case("HTTP 501", || status(501), 1), ServerError),
            fails(case("HTTP 301", || status(301), 1), BadResponse),
            fails(
                case(
                    "200 without Date",
                    || Step::Answer(reply(200, None, TARGET_BODY)),
                    1,
                ),
                BadResponse,
            ),
            fails(
                case(
                    "200 with a bad Date",
                    || Step::Answer(reply(200, Some("yesterday"), TARGET_BODY)),
                    1,
                ),
                BadResponse,
            ),
            fails(
                case(
                    "200 oversized",
                    || {
                        Step::Answer(Reply {
                            oversized: true,
                            ..reply(200, Some(SERVER_DATE), TARGET_BODY)
                        })
                    },
                    1,
                ),
                BadResponse,
            ),
            fails(
                case(
                    "200 not JSON",
                    || Step::Answer(reply(200, Some(SERVER_DATE), "<html>")),
                    1,
                ),
                BadResponse,
            ),
            fails(
                case(
                    "too many redirects",
                    || Step::Fail(HttpError::TooManyRedirects),
                    1,
                ),
                BadResponse,
            ),
            fails(case("no answer", || Step::Hang, 1), Timeout),
            fails(
                at(
                    case(
                        "connect error with 1.24 s left",
                        || Step::Fail(connect_error()),
                        1,
                    ),
                    8_760,
                ),
                Network,
            ),
            at(
                case(
                    "connect error with 1.25 s left",
                    || Step::Fail(connect_error()),
                    2,
                ),
                8_750,
            ),
            fails(
                at(case("503 with 1 s left", || status(503), 1), 9_000),
                ServerError,
            ),
            fails(
                at(
                    paused(
                        case(
                            "429 Retry-After 1 with 1.99 s left",
                            || rate_limited("1"),
                            1,
                        ),
                        1000,
                    ),
                    8_010,
                ),
                RateLimited,
            ),
            at(
                paused(
                    case("429 Retry-After 1 with 2 s left", || rate_limited("1"), 2),
                    1000,
                ),
                8_000,
            ),
        ];
        for c in cases {
            let (first, at) = (c.first, c.at);
            let (client, exchange) = scripted(move |_, nth| match nth {
                0 => Step::After(at, Box::new(first())),
                _ => ok(),
            });
            let started = Instant::now();
            let outcome = client.get_json_with_time::<Value>(URL).await;
            let elapsed = started.elapsed();
            let sent = exchange.sent();
            assert_eq!(sent.len() as u32, c.attempts, "{}", c.name);
            assert!(elapsed <= GET_POLICY.deadline, "{}: {elapsed:?}", c.name);
            match (c.class, outcome) {
                (None, Ok((body, time))) => {
                    assert_eq!((body, time), (serde_json::json!({"ok": true}), SERVER_UNIX))
                }
                (Some(class), Err(err)) => {
                    assert_eq!(
                        (err.class(), err.attempts),
                        (class, c.attempts),
                        "{}",
                        c.name
                    )
                }
                (want, got) => panic!("{}: want {want:?}, got {got:?}", c.name),
            }
            if c.attempts == 2 {
                assert_eq!(sent[1].at - sent[0].at, c.at + c.pause, "{}", c.name);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_worst_case_call_never_outlasts_the_deadline() {
        let firsts: [First; 5] = [
            || Step::Fail(connect_error()),
            || status(503),
            || rate_limited("1"),
            || rate_limited("0"),
            || Step::Hang,
        ];
        for policy in [GET_POLICY, RPC_LIKE] {
            let step = Duration::from_millis(50);
            let mut at = Duration::ZERO;
            while at <= policy.deadline {
                for first in firsts {
                    let (client, _) = scripted(move |_, nth| match nth {
                        0 => Step::After(at, Box::new(first())),
                        _ => Step::Hang,
                    });
                    let started = Instant::now();
                    let _ = client
                        .post_json_with_time::<Value>(URL, b"{}", &policy)
                        .await
                        .unwrap_err();
                    let elapsed = started.elapsed();
                    assert!(elapsed <= policy.deadline, "{at:?}: {elapsed:?}");
                }
                at += step;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_pause_holds_back_its_host_until_it_expires() {
        let cases: [(&str, First, u64); 7] = [
            ("451", || status(451), 600),
            ("403", || status(403), 60),
            ("429 without Retry-After", || status(429), 30),
            ("418", || status(418), 30),
            ("429 Retry-After 5", || rate_limited("5"), 5),
            ("429 Retry-After 300", || rate_limited("300"), 120),
            (
                "429 Retry-After as HTTP-date",
                || rate_limited("Tue, 17 Nov 2026 12:00:45 GMT"),
                45,
            ),
        ];
        for (name, first, secs) in cases {
            let (client, exchange) = scripted(move |url, nth| match (url, nth) {
                (URL, 0) => first(),
                _ => ok(),
            });
            let started = Instant::now();
            let err = client.get_json_with_time::<Value>(URL).await.unwrap_err();
            assert_eq!(err.attempts, 1, "{name}");

            tokio::time::sleep_until(
                started + Duration::from_secs(secs) - Duration::from_millis(1),
            )
            .await;
            let held = client.get_json_with_time::<Value>(URL).await.unwrap_err();
            assert_eq!(
                (held.class(), held.attempts),
                (ErrorClass::CoolingDown, 0),
                "{name}"
            );
            assert_eq!(
                held.error,
                HttpError::CoolingDown {
                    remaining: Duration::from_millis(1),
                    cause: err.class()
                },
                "{name}"
            );
            assert_eq!(exchange.count(URL), 1, "{name}: nothing sent while paused");

            client
                .get_json_with_time::<Value>(OTHER_URL)
                .await
                .expect("another host is not paused");

            tokio::time::sleep_until(started + Duration::from_secs(secs)).await;
            client
                .get_json_with_time::<Value>(URL)
                .await
                .expect("requests resume once the pause ends");
            assert_eq!(exchange.count(URL), 2, "{name}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn statuses_outside_the_pause_list_never_pause() {
        for code in [400, 404, 408, 500, 503, 301] {
            let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let plan_failing = Arc::clone(&failing);
            let (client, exchange) = scripted(move |_, _| {
                if plan_failing.load(Ordering::SeqCst) {
                    status(code)
                } else {
                    ok()
                }
            });
            let first = client.get_json_with_time::<Value>(URL).await.unwrap_err();
            assert_eq!(first.http_status(), Some(code));
            failing.store(false, Ordering::SeqCst);
            let sent = exchange.count(URL);
            client
                .get_json_with_time::<Value>(URL)
                .await
                .expect("no pause");
            assert_eq!(exchange.count(URL), sent + 1, "{code}");
        }
    }

    #[test]
    fn retry_after_is_seconds_or_a_date_against_the_response_date() {
        let date = Some(SERVER_UNIX);
        let cases = [
            ("0", date, Some(0)),
            ("1", date, Some(1)),
            (" 120 ", date, Some(120)),
            ("Tue, 17 Nov 2026 12:00:30 GMT", date, Some(30)),
            ("Tue, 17 Nov 2026 11:59:00 GMT", date, Some(0)),
            ("Tue, 17 Nov 2026 12:00:30 GMT", None, None),
            ("-1", date, None),
            ("1.5", date, None),
            ("soon", date, None),
            ("", date, None),
            ("99999999999999999999999", date, None),
        ];
        for (value, date, secs) in cases {
            assert_eq!(
                parse_retry_after(value, date),
                secs.map(Duration::from_secs),
                "{value:?}"
            );
        }
    }

    #[test]
    fn error_text_names_the_host_but_never_the_path() {
        let err = RequestError {
            host: HOST.into(),
            attempts: 2,
            error: HttpError::Status {
                code: 503,
                retry_after: None,
                preview: "busy".into(),
            },
        };
        assert_eq!(
            err.to_string(),
            "HTTP 503 Service Unavailable from api.example.com: busy"
        );
        assert_eq!(err.http_status(), Some(503));
        let boxed: eyre::Report = err.clone().into();
        assert_eq!(boxed.downcast_ref::<RequestError>(), Some(&err));
    }
}
