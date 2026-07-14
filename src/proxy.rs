//! Operationally bounded reverse proxy for the Nix HTTP binary-cache protocol.
//!
//! The proxy verifies the configured upstream Ed25519 signature on `.narinfo`
//! metadata, replaces this proxy identity's prior signature pair, and re-serves
//! the metadata with both ordinary `Sig:` and experimental `Sig-PQC:` entries.
//! Small metadata is buffered behind strict limits because it must be parsed and
//! mutated. NAR objects are streamed while a concurrency permit remains held for
//! the lifetime of the response body.
//!
//! This remains a trust-translation prototype: it cannot upgrade a classical
//! upstream root of trust into a post-quantum origin root of trust.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path as AxumPath, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{Next, from_fn};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use futures_util::{StreamExt, TryStreamExt, stream};
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::keys::{self, SecretKey};
use crate::narinfo::{self, NarInfo};

/// Hard cap on the fixed-shape `nix-cache-info` document.
const MAX_CACHE_INFO_BYTES: usize = 4 * 1024;
/// Maximum accepted route-segment length before URL construction.
const MAX_PATH_SEGMENT_BYTES: usize = 255;
/// Nix's custom base32 alphabet used by 32-character store-path hashes.
const NIX_BASE32: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

const CACHE_CONTROL_METADATA: &str = "public, max-age=300";
const CACHE_CONTROL_NAR: &str = "public, max-age=31536000, immutable";
const CACHE_CONTROL_PRIVATE: &str = "no-store";

/// Operational limits for the network-facing proxy.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    /// Maximum number of requests whose handlers or response streams may be
    /// active at once. A NAR request holds its permit until EOF, body failure,
    /// client cancellation, or process shutdown.
    pub max_in_flight: usize,
    /// Maximum time a request may wait for an in-flight permit.
    pub queue_timeout: Duration,
    /// TCP/TLS connection deadline for upstream requests.
    pub connect_timeout: Duration,
    /// Whole-request deadline for small buffered metadata.
    pub metadata_total_timeout: Duration,
    /// Deadline for upstream NAR response headers.
    pub nar_header_timeout: Duration,
    /// Maximum idle interval between successive NAR body chunks.
    pub nar_chunk_idle_timeout: Duration,
    /// Optional maximum streamed NAR body size. `None` leaves the size
    /// unlimited while preserving concurrency and idle-time bounds.
    pub max_nar_bytes: Option<u64>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_in_flight: 128,
            queue_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(10),
            metadata_total_timeout: Duration::from_secs(30),
            nar_header_timeout: Duration::from_secs(30),
            nar_chunk_idle_timeout: Duration::from_secs(30),
            max_nar_bytes: None,
        }
    }
}

impl ProxyConfig {
    fn validate(&self) -> Result<()> {
        if self.max_in_flight == 0 {
            bail!("max_in_flight must be greater than zero");
        }
        for (name, value) in [
            ("queue_timeout", self.queue_timeout),
            ("connect_timeout", self.connect_timeout),
            ("metadata_total_timeout", self.metadata_total_timeout),
            ("nar_header_timeout", self.nar_header_timeout),
            ("nar_chunk_idle_timeout", self.nar_chunk_idle_timeout),
        ] {
            if value.is_zero() {
                bail!("{name} must be greater than zero");
            }
        }
        if self.max_nar_bytes == Some(0) {
            bail!("max_nar_bytes must be greater than zero when configured");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum RequestKind {
    CacheInfo,
    NarInfo,
    Nar,
    Readiness,
}

impl RequestKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::CacheInfo => "cache_info",
            Self::NarInfo => "narinfo",
            Self::Nar => "nar",
            Self::Readiness => "readiness",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RequestContext {
    id: u64,
    kind: RequestKind,
}

#[derive(Default)]
struct ProxyMetrics {
    requests_total: AtomicU64,
    requests_active: AtomicU64,
    requests_completed: AtomicU64,
    requests_failed: AtomicU64,
    requests_incomplete: AtomicU64,
    cache_info_requests: AtomicU64,
    narinfo_requests: AtomicU64,
    nar_requests: AtomicU64,
    readiness_checks: AtomicU64,
    overloaded_total: AtomicU64,
    invalid_requests_total: AtomicU64,
    upstream_failures_total: AtomicU64,
    signature_failures_total: AtomicU64,
    nar_stream_failures_total: AtomicU64,
    readiness_failures_total: AtomicU64,
    response_bytes_total: AtomicU64,
}

impl ProxyMetrics {
    fn record_kind(&self, kind: RequestKind) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        let counter = match kind {
            RequestKind::CacheInfo => &self.cache_info_requests,
            RequestKind::NarInfo => &self.narinfo_requests,
            RequestKind::Nar => &self.nar_requests,
            RequestKind::Readiness => &self.readiness_checks,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self) -> String {
        fn value(counter: &AtomicU64) -> u64 {
            counter.load(Ordering::Relaxed)
        }

        format!(
            concat!(
                "# HELP nix_pqc_proxy_up Whether the proxy process is running.\n",
                "# TYPE nix_pqc_proxy_up gauge\n",
                "nix_pqc_proxy_up 1\n",
                "# HELP nix_pqc_proxy_requests_total Requests admitted or refused by the proxy.\n",
                "# TYPE nix_pqc_proxy_requests_total counter\n",
                "nix_pqc_proxy_requests_total {}\n",
                "# TYPE nix_pqc_proxy_requests_active gauge\n",
                "nix_pqc_proxy_requests_active {}\n",
                "# TYPE nix_pqc_proxy_requests_completed_total counter\n",
                "nix_pqc_proxy_requests_completed_total {}\n",
                "# TYPE nix_pqc_proxy_requests_failed_total counter\n",
                "nix_pqc_proxy_requests_failed_total {}\n",
                "# TYPE nix_pqc_proxy_requests_incomplete_total counter\n",
                "nix_pqc_proxy_requests_incomplete_total {}\n",
                "# TYPE nix_pqc_proxy_cache_info_requests_total counter\n",
                "nix_pqc_proxy_cache_info_requests_total {}\n",
                "# TYPE nix_pqc_proxy_narinfo_requests_total counter\n",
                "nix_pqc_proxy_narinfo_requests_total {}\n",
                "# TYPE nix_pqc_proxy_nar_requests_total counter\n",
                "nix_pqc_proxy_nar_requests_total {}\n",
                "# TYPE nix_pqc_proxy_readiness_checks_total counter\n",
                "nix_pqc_proxy_readiness_checks_total {}\n",
                "# TYPE nix_pqc_proxy_overloaded_total counter\n",
                "nix_pqc_proxy_overloaded_total {}\n",
                "# TYPE nix_pqc_proxy_invalid_requests_total counter\n",
                "nix_pqc_proxy_invalid_requests_total {}\n",
                "# TYPE nix_pqc_proxy_upstream_failures_total counter\n",
                "nix_pqc_proxy_upstream_failures_total {}\n",
                "# TYPE nix_pqc_proxy_signature_failures_total counter\n",
                "nix_pqc_proxy_signature_failures_total {}\n",
                "# TYPE nix_pqc_proxy_nar_stream_failures_total counter\n",
                "nix_pqc_proxy_nar_stream_failures_total {}\n",
                "# TYPE nix_pqc_proxy_readiness_failures_total counter\n",
                "nix_pqc_proxy_readiness_failures_total {}\n",
                "# TYPE nix_pqc_proxy_response_bytes_total counter\n",
                "nix_pqc_proxy_response_bytes_total {}\n"
            ),
            value(&self.requests_total),
            value(&self.requests_active),
            value(&self.requests_completed),
            value(&self.requests_failed),
            value(&self.requests_incomplete),
            value(&self.cache_info_requests),
            value(&self.narinfo_requests),
            value(&self.nar_requests),
            value(&self.readiness_checks),
            value(&self.overloaded_total),
            value(&self.invalid_requests_total),
            value(&self.upstream_failures_total),
            value(&self.signature_failures_total),
            value(&self.nar_stream_failures_total),
            value(&self.readiness_failures_total),
            value(&self.response_bytes_total),
        )
    }
}

#[derive(Clone, Copy)]
enum UnfinalizedOutcome {
    Failed,
    Incomplete,
}

struct RequestGuard {
    _permit: OwnedSemaphorePermit,
    metrics: Arc<ProxyMetrics>,
    context: RequestContext,
    finalized: bool,
    unfinalized_outcome: UnfinalizedOutcome,
}

impl RequestGuard {
    fn streaming(mut self) -> Self {
        self.unfinalized_outcome = UnfinalizedOutcome::Incomplete;
        self
    }

    fn complete(mut self) {
        self.metrics
            .requests_completed
            .fetch_add(1, Ordering::Relaxed);
        self.finalized = true;
        emit_log("info", "request_complete", Some(self.context), None, None);
    }

    fn fail(mut self, code: &'static str) {
        self.metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
        self.finalized = true;
        emit_log(
            "warn",
            "request_failed",
            Some(self.context),
            Some(code),
            None,
        );
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.metrics.requests_active.fetch_sub(1, Ordering::Relaxed);
        if !self.finalized {
            match self.unfinalized_outcome {
                UnfinalizedOutcome::Failed => {
                    self.metrics.requests_failed.fetch_add(1, Ordering::Relaxed);
                    emit_log(
                        "warn",
                        "request_failed",
                        Some(self.context),
                        Some("handler_exited_without_success"),
                        None,
                    );
                }
                UnfinalizedOutcome::Incomplete => {
                    self.metrics
                        .requests_incomplete
                        .fetch_add(1, Ordering::Relaxed);
                    emit_log(
                        "warn",
                        "request_incomplete",
                        Some(self.context),
                        Some("response_cancelled"),
                        None,
                    );
                }
            }
        }
    }
}

struct ProxyState {
    upstream: reqwest::Url,
    upstream_pubkey: String,
    /// `None` when `--upstream-pubkey` was given without a `name:` prefix.
    upstream_key_name: Option<String>,
    secret: SecretKey,
    client: reqwest::Client,
    config: ProxyConfig,
    permits: Arc<Semaphore>,
    metrics: Arc<ProxyMetrics>,
    next_request_id: AtomicU64,
}

impl ProxyState {
    fn context(&self, kind: RequestKind) -> RequestContext {
        self.metrics.record_kind(kind);
        RequestContext {
            id: self.next_request_id.fetch_add(1, Ordering::Relaxed),
            kind,
        }
    }

    async fn acquire(self: &Arc<Self>, context: RequestContext) -> Result<RequestGuard, AppError> {
        let permit = tokio::time::timeout(
            self.config.queue_timeout,
            self.permits.clone().acquire_owned(),
        )
        .await;

        match permit {
            Ok(Ok(permit)) => {
                self.metrics.requests_active.fetch_add(1, Ordering::Relaxed);
                emit_log("info", "request_admitted", Some(context), None, None);
                Ok(RequestGuard {
                    _permit: permit,
                    metrics: Arc::clone(&self.metrics),
                    context,
                    finalized: false,
                    unfinalized_outcome: UnfinalizedOutcome::Failed,
                })
            }
            Ok(Err(_)) | Err(_) => {
                self.metrics
                    .overloaded_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(AppError::new(
                    Arc::clone(&self.metrics),
                    context,
                    StatusCode::SERVICE_UNAVAILABLE,
                    "proxy_overloaded",
                    anyhow!(
                        "request could not obtain an in-flight permit within {:?}",
                        self.config.queue_timeout
                    ),
                ))
            }
        }
    }

    fn bad_request(&self, context: RequestContext, error: anyhow::Error) -> AppError {
        self.metrics
            .invalid_requests_total
            .fetch_add(1, Ordering::Relaxed);
        AppError::new(
            Arc::clone(&self.metrics),
            context,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            error,
        )
    }

    fn upstream_error(&self, context: RequestContext, error: anyhow::Error) -> AppError {
        self.metrics
            .upstream_failures_total
            .fetch_add(1, Ordering::Relaxed);
        AppError::new(
            Arc::clone(&self.metrics),
            context,
            StatusCode::BAD_GATEWAY,
            "upstream_failure",
            error,
        )
    }

    fn verification_error(&self, context: RequestContext, error: anyhow::Error) -> AppError {
        self.metrics
            .signature_failures_total
            .fetch_add(1, Ordering::Relaxed);
        AppError::new(
            Arc::clone(&self.metrics),
            context,
            StatusCode::BAD_GATEWAY,
            "upstream_signature_rejected",
            error,
        )
    }
}

#[derive(Serialize)]
struct LogRecord<'a> {
    level: &'a str,
    event: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_kind: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<&'a str>,
}

fn emit_log(
    level: &'static str,
    event: &'static str,
    context: Option<RequestContext>,
    code: Option<&'static str>,
    detail: Option<&str>,
) {
    let record = LogRecord {
        level,
        event,
        request_id: context.map(|value| value.id),
        request_kind: context.map(|value| value.kind.as_str()),
        code,
        detail,
    };
    match serde_json::to_string(&record) {
        Ok(line) => eprintln!("{line}"),
        Err(_) => eprintln!(r#"{{"level":"error","event":"log_encoding_failed"}}"#),
    }
}

struct AppError {
    _metrics: Arc<ProxyMetrics>,
    context: RequestContext,
    status: StatusCode,
    code: &'static str,
    _error: anyhow::Error,
}

impl AppError {
    fn new(
        metrics: Arc<ProxyMetrics>,
        context: RequestContext,
        status: StatusCode,
        code: &'static str,
        error: anyhow::Error,
    ) -> Self {
        Self {
            _metrics: metrics,
            context,
            status,
            code,
            _error: error,
        }
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
    request_id: u64,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        emit_log(
            "error",
            "request_refused",
            Some(self.context),
            Some(self.code),
            None,
        );
        let body = serde_json::to_string(&ErrorResponse {
            error: self.code,
            request_id: self.context.id,
        })
        .unwrap_or_else(|_| {
            format!(
                r#"{{"error":"internal_encoding_failure","request_id":{}}}"#,
                self.context.id
            )
        });
        let mut response = (
            self.status,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, CACHE_CONTROL_PRIVATE),
            ],
            body,
        )
            .into_response();
        if let Ok(value) = HeaderValue::from_str(&self.context.id.to_string()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        if self.code == "proxy_overloaded" {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}

struct FetchedMetadata {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Read an HTTP response body up to `cap` bytes, erroring rather than
/// truncating. The Content-Length precheck is only an optimization; the
/// streaming cap remains authoritative when the header is absent or false.
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<(HeaderMap, Vec<u8>)> {
    if let Some(length) = resp.content_length() {
        if length > cap as u64 {
            bail!("upstream response Content-Length {length} exceeded the {cap}-byte cap");
        }
    }

    let headers = resp.headers().clone();
    let mut body_stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = body_stream.try_next().await? {
        buf.extend_from_slice(&chunk);
        if buf.len() > cap {
            bail!("upstream response body exceeded the {cap}-byte cap");
        }
    }
    Ok((headers, buf))
}

async fn fetch_capped_raw(
    state: &ProxyState,
    url: reqwest::Url,
    cap: usize,
) -> Result<FetchedMetadata> {
    tokio::time::timeout(state.config.metadata_total_timeout, async {
        let response = state.client.get(url).send().await?;
        let status =
            StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let (headers, body) = read_capped(response, cap).await?;
        Ok::<_, anyhow::Error>(FetchedMetadata {
            status,
            headers,
            body,
        })
    })
    .await
    .map_err(|_| {
        anyhow!(
            "upstream metadata request timed out after {:?}",
            state.config.metadata_total_timeout
        )
    })?
}

fn parse_upstream_base(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).context("parsing upstream URL")?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("upstream URL scheme must be http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("upstream URL must not contain user-info credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("upstream URL must not contain a query or fragment");
    }
    if url.host_str().is_none() {
        bail!("upstream URL must contain a host");
    }
    Ok(url)
}

fn upstream_url(base: &reqwest::Url, segments: &[&str]) -> Result<reqwest::Url> {
    let mut url = base.clone();
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| anyhow!("upstream URL cannot be used as a hierarchical base"))?;
        path.pop_if_empty();
        for segment in segments {
            path.push(segment);
        }
    }
    Ok(url)
}

fn validate_narinfo_hash(hash: &str) -> Result<()> {
    if hash.len() != 32 || !hash.bytes().all(|byte| NIX_BASE32.contains(&byte)) {
        bail!("narinfo hash must be exactly 32 lowercase Nix-base32 characters");
    }
    Ok(())
}

fn validate_nar_file(file: &str) -> Result<()> {
    if file.is_empty() || file.len() > MAX_PATH_SEGMENT_BYTES {
        bail!("NAR filename must contain 1..={MAX_PATH_SEGMENT_BYTES} bytes");
    }
    if matches!(file, "." | "..") {
        bail!("NAR filename must not be a URL dot-segment");
    }
    if !file
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        bail!("NAR filename contains characters outside the allowed URL-segment alphabet");
    }
    Ok(())
}

fn validate_narinfo_download_url(raw: &str) -> Result<()> {
    let file = raw
        .strip_prefix("nar/")
        .ok_or_else(|| anyhow!("narinfo URL must be relative and start with 'nar/'"))?;
    if file.contains('/') {
        bail!("narinfo URL must contain exactly one NAR filename segment");
    }
    validate_nar_file(file)
}

fn validate_content_type(headers: &HeaderMap, resource: &str) -> Result<()> {
    let Some(value) = headers.get(header::CONTENT_TYPE) else {
        return Ok(());
    };
    let value = value
        .to_str()
        .context("upstream Content-Type was not valid ASCII")?
        .to_ascii_lowercase();
    if value.starts_with("text/html") || value.starts_with("application/xhtml") {
        bail!("upstream returned HTML content for {resource}");
    }
    Ok(())
}

fn validate_cache_info(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("nix-cache-info is not valid UTF-8")?;
    if text.bytes().any(|byte| byte == 0 || byte == b'\r') {
        bail!("nix-cache-info contains forbidden control characters");
    }

    let mut store_dir = None;
    let mut seen_want_mass_query = false;
    let mut seen_priority = false;
    for line in text.lines().filter(|line| !line.is_empty()) {
        let Some((name, value)) = line.split_once(':') else {
            bail!("nix-cache-info line is missing ':' separator");
        };
        let value = value.trim();
        match name {
            "StoreDir" => {
                if store_dir.is_some() {
                    bail!("nix-cache-info contains duplicate StoreDir fields");
                }
                if !value.starts_with('/') || value.contains("..") {
                    bail!("nix-cache-info StoreDir must be an absolute normalized path");
                }
                store_dir = Some(value);
            }
            "WantMassQuery" => {
                if seen_want_mass_query {
                    bail!("nix-cache-info contains duplicate WantMassQuery fields");
                }
                seen_want_mass_query = true;
                if !matches!(value, "0" | "1") {
                    bail!("nix-cache-info WantMassQuery must be 0 or 1");
                }
            }
            "Priority" => {
                if seen_priority {
                    bail!("nix-cache-info contains duplicate Priority fields");
                }
                seen_priority = true;
                value
                    .parse::<i32>()
                    .context("nix-cache-info Priority must be an integer")?;
            }
            _ => {}
        }
    }
    if store_dir.is_none() {
        bail!("nix-cache-info is missing StoreDir");
    }
    Ok(())
}

fn plain_response(status: StatusCode, body: &'static str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, CACHE_CONTROL_PRIVATE),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response()
}

async fn reject_request_bodies(request: Request<Body>, next: Next) -> Response {
    let has_content_length = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > 0);
    let has_transfer_encoding = request.headers().contains_key(header::TRANSFER_ENCODING);
    if has_content_length || has_transfer_encoding {
        return plain_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request bodies are not accepted by this read-only proxy\n",
        );
    }
    next.run(request).await
}

/// CLI entry point with the default operational limits.
pub async fn run(
    upstream: String,
    upstream_pubkey: String,
    key_path: PathBuf,
    listen: String,
) -> Result<()> {
    run_with_config(
        upstream,
        upstream_pubkey,
        key_path,
        listen,
        ProxyConfig::default(),
    )
    .await
}

/// CLI entry point with explicit operational limits.
pub async fn run_with_config(
    upstream: String,
    upstream_pubkey: String,
    key_path: PathBuf,
    listen: String,
    config: ProxyConfig,
) -> Result<()> {
    config.validate()?;
    let secret = SecretKey::load(&key_path)?;
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let local_addr = listener.local_addr()?;

    println!("nix-pqc-cache-proxy: signing as '{}'", secret.name);
    println!("nix-pqc-cache-proxy: upstream configured");
    println!("nix-pqc-cache-proxy: listening on http://{local_addr}");
    println!(
        "nix-pqc-cache-proxy: max in-flight = {}, queue timeout = {:?}",
        config.max_in_flight, config.queue_timeout
    );
    println!(
        "  point nix at it with: --extra-substituters http://{local_addr} --extra-trusted-public-keys '{}:{}'",
        secret.name,
        base64::engine::general_purpose::STANDARD.encode(secret.public().keys.ed25519)
    );

    serve_with_config_and_shutdown(
        listener,
        upstream,
        upstream_pubkey,
        secret,
        config,
        shutdown_signal(),
    )
    .await
}

/// Serve with default limits and no internally generated shutdown signal.
/// Tests commonly abort the returned task when their fixture ends.
pub async fn serve(
    listener: tokio::net::TcpListener,
    upstream: String,
    upstream_pubkey: String,
    secret: SecretKey,
) -> Result<()> {
    serve_with_config(
        listener,
        upstream,
        upstream_pubkey,
        secret,
        ProxyConfig::default(),
    )
    .await
}

/// Serve with explicit limits and no internally generated shutdown signal.
pub async fn serve_with_config(
    listener: tokio::net::TcpListener,
    upstream: String,
    upstream_pubkey: String,
    secret: SecretKey,
    config: ProxyConfig,
) -> Result<()> {
    serve_with_config_and_shutdown(
        listener,
        upstream,
        upstream_pubkey,
        secret,
        config,
        std::future::pending(),
    )
    .await
}

/// Serve with explicit limits and a caller-provided graceful-shutdown future.
/// Once the future resolves, axum stops accepting connections and drains
/// admitted handlers/streams before returning.
pub async fn serve_with_config_and_shutdown<F>(
    listener: tokio::net::TcpListener,
    upstream: String,
    upstream_pubkey: String,
    secret: SecretKey,
    config: ProxyConfig,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    config.validate()?;
    let upstream = parse_upstream_base(&upstream)?;
    let (upstream_key_name, upstream_pubkey) = {
        let (name, key) = keys::parse_named_pubkey(&upstream_pubkey);
        (name.map(String::from), key.to_string())
    };
    if upstream_key_name.is_none() {
        emit_log(
            "warn",
            "name_blind_upstream_key",
            None,
            Some("missing_key_name"),
            Some("upstream public key has no name prefix; signature identity is not name-bound"),
        );
    }

    let client = reqwest::Client::builder()
        .connect_timeout(config.connect_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let state = Arc::new(ProxyState {
        upstream,
        upstream_pubkey,
        upstream_key_name,
        secret,
        client,
        permits: Arc::new(Semaphore::new(config.max_in_flight)),
        metrics: Arc::new(ProxyMetrics::default()),
        next_request_id: AtomicU64::new(1),
        config,
    });

    let app = Router::new()
        .route("/healthz", get(handle_health))
        .route("/readyz", get(handle_ready))
        .route("/metrics", get(handle_metrics))
        .route("/nix-cache-info", get(handle_cache_info))
        // axum 0.8 forbids mixing a literal suffix with a parameter in one
        // path segment, so this captures the whole filename and validates the
        // suffix/hash inside the handler.
        .route("/{filename}", get(handle_narinfo))
        .route("/nar/{file}", get(handle_nar))
        .layer(DefaultBodyLimit::max(0))
        .layer(from_fn(reject_request_bodies))
        .with_state(state);

    emit_log("info", "proxy_ready", None, None, None);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    emit_log("info", "proxy_stopped", None, None, None);
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            emit_log(
                "error",
                "shutdown_signal_error",
                None,
                Some("ctrl_c_registration_failed"),
                Some(&error.to_string()),
            );
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                emit_log(
                    "error",
                    "shutdown_signal_error",
                    None,
                    Some("sigterm_registration_failed"),
                    Some(&error.to_string()),
                );
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    emit_log("info", "shutdown_requested", None, None, None);
}

async fn handle_health() -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, CACHE_CONTROL_PRIVATE),
        ],
        r#"{"status":"ok"}"#,
    )
        .into_response()
}

async fn handle_metrics(State(state): State<Arc<ProxyState>>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; version=0.0.4"),
            (header::CACHE_CONTROL, CACHE_CONTROL_PRIVATE),
        ],
        state.metrics.render(),
    )
        .into_response()
}

async fn handle_ready(State(state): State<Arc<ProxyState>>) -> Response {
    let context = state.context(RequestKind::Readiness);
    let guard = match state.acquire(context).await {
        Ok(guard) => guard,
        Err(error) => return error.into_response(),
    };
    let url = match upstream_url(&state.upstream, &["nix-cache-info"]) {
        Ok(url) => url,
        Err(error) => {
            state
                .metrics
                .readiness_failures_total
                .fetch_add(1, Ordering::Relaxed);
            guard.fail("invalid_upstream_base");
            return state.upstream_error(context, error).into_response();
        }
    };
    let result = fetch_capped_raw(&state, url, MAX_CACHE_INFO_BYTES).await;
    match result {
        Ok(fetched)
            if fetched.status.is_success()
                && validate_content_type(&fetched.headers, "nix-cache-info").is_ok()
                && validate_cache_info(&fetched.body).is_ok() =>
        {
            guard.complete();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, CACHE_CONTROL_PRIVATE),
                ],
                r#"{"status":"ready"}"#,
            )
                .into_response()
        }
        Ok(fetched) => {
            state
                .metrics
                .readiness_failures_total
                .fetch_add(1, Ordering::Relaxed);
            guard.fail("upstream_not_ready");
            AppError::new(
                Arc::clone(&state.metrics),
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_not_ready",
                anyhow!(
                    "readiness probe rejected upstream response with status {}",
                    fetched.status
                ),
            )
            .into_response()
        }
        Err(error) => {
            state
                .metrics
                .readiness_failures_total
                .fetch_add(1, Ordering::Relaxed);
            guard.fail("upstream_not_ready");
            AppError::new(
                Arc::clone(&state.metrics),
                context,
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_not_ready",
                error,
            )
            .into_response()
        }
    }
}

async fn handle_cache_info(State(state): State<Arc<ProxyState>>) -> Result<Response, AppError> {
    let context = state.context(RequestKind::CacheInfo);
    let guard = state.acquire(context).await?;
    let url = upstream_url(&state.upstream, &["nix-cache-info"])
        .map_err(|error| state.upstream_error(context, error))?;
    let fetched = fetch_capped_raw(&state, url, MAX_CACHE_INFO_BYTES)
        .await
        .map_err(|error| state.upstream_error(context, error))?;

    if fetched.status == StatusCode::NOT_FOUND {
        guard.complete();
        return Ok(plain_response(
            StatusCode::NOT_FOUND,
            "upstream cache info not found\n",
        ));
    }
    if !fetched.status.is_success() {
        return Err(state.upstream_error(
            context,
            anyhow!("upstream nix-cache-info returned {}", fetched.status),
        ));
    }
    validate_content_type(&fetched.headers, "nix-cache-info")
        .and_then(|_| validate_cache_info(&fetched.body))
        .map_err(|error| state.upstream_error(context, error))?;

    state
        .metrics
        .response_bytes_total
        .fetch_add(fetched.body.len() as u64, Ordering::Relaxed);
    guard.complete();
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/x-nix-cache-info"),
            (header::CACHE_CONTROL, CACHE_CONTROL_METADATA),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        fetched.body,
    )
        .into_response())
}

async fn handle_narinfo(
    State(state): State<Arc<ProxyState>>,
    AxumPath(filename): AxumPath<String>,
) -> Result<Response, AppError> {
    let context = state.context(RequestKind::NarInfo);
    let Some(hash) = filename.strip_suffix(".narinfo") else {
        return Ok(plain_response(
            StatusCode::NOT_FOUND,
            "not a narinfo request\n",
        ));
    };
    validate_narinfo_hash(hash).map_err(|error| state.bad_request(context, error))?;
    let guard = state.acquire(context).await?;
    let narinfo_filename = format!("{hash}.narinfo");
    let url = upstream_url(&state.upstream, &[&narinfo_filename])
        .map_err(|error| state.upstream_error(context, error))?;
    let fetched = fetch_capped_raw(&state, url, narinfo::MAX_NARINFO_BYTES)
        .await
        .map_err(|error| state.upstream_error(context, error))?;

    if fetched.status == StatusCode::NOT_FOUND {
        guard.complete();
        return Ok(plain_response(
            StatusCode::NOT_FOUND,
            "upstream narinfo not found\n",
        ));
    }
    if !fetched.status.is_success() {
        return Err(state.upstream_error(
            context,
            anyhow!("upstream narinfo returned {}", fetched.status),
        ));
    }
    validate_content_type(&fetched.headers, "narinfo")
        .map_err(|error| state.upstream_error(context, error))?;
    let text = String::from_utf8(fetched.body)
        .context("upstream narinfo is not valid UTF-8")
        .map_err(|error| state.upstream_error(context, error))?;
    let mut info = NarInfo::parse(&text).map_err(|error| state.upstream_error(context, error))?;
    validate_narinfo_download_url(&info.url)
        .map_err(|error| state.upstream_error(context, error))?;
    let fingerprint = info
        .fingerprint()
        .map_err(|error| state.upstream_error(context, error))?;

    narinfo::verify_any_ed25519_sig(
        &fingerprint,
        &info.sigs,
        state.upstream_key_name.as_deref(),
        &state.upstream_pubkey,
    )
    .context("upstream Sig did not verify against the configured upstream key")
    .map_err(|error| state.verification_error(context, error))?;

    replace_proxy_signatures(&mut info, &fingerprint, &state.secret)
        .map_err(|error| state.upstream_error(context, error))?;
    let body = info.to_text();
    state
        .metrics
        .response_bytes_total
        .fetch_add(body.len() as u64, Ordering::Relaxed);
    guard.complete();

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/x-nix-narinfo"),
            (header::CACHE_CONTROL, CACHE_CONTROL_METADATA),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        body,
    )
        .into_response())
}

struct NarStreamState {
    upstream: futures_util::stream::BoxStream<'static, reqwest::Result<Bytes>>,
    guard: Option<RequestGuard>,
    metrics: Arc<ProxyMetrics>,
    context: RequestContext,
    bytes_seen: u64,
    max_bytes: Option<u64>,
    idle_timeout: Duration,
}

async fn handle_nar(
    State(state): State<Arc<ProxyState>>,
    AxumPath(file): AxumPath<String>,
) -> Result<Response, AppError> {
    let context = state.context(RequestKind::Nar);
    validate_nar_file(&file).map_err(|error| state.bad_request(context, error))?;
    let guard = state.acquire(context).await?;
    let url = upstream_url(&state.upstream, &["nar", &file])
        .map_err(|error| state.upstream_error(context, error))?;
    let response = tokio::time::timeout(
        state.config.nar_header_timeout,
        state.client.get(url).send(),
    )
    .await
    .map_err(|_| {
        state.upstream_error(
            context,
            anyhow!(
                "upstream NAR headers timed out after {:?}",
                state.config.nar_header_timeout
            ),
        )
    })?
    .map_err(|error| state.upstream_error(context, error.into()))?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if status == StatusCode::NOT_FOUND {
        guard.complete();
        return Ok(plain_response(
            StatusCode::NOT_FOUND,
            "upstream NAR not found\n",
        ));
    }
    if !status.is_success() {
        return Err(state.upstream_error(context, anyhow!("upstream NAR returned {status}")));
    }
    validate_content_type(response.headers(), "NAR")
        .map_err(|error| state.upstream_error(context, error))?;

    let content_length = response.content_length();
    if let (Some(limit), Some(length)) = (state.config.max_nar_bytes, content_length) {
        if length > limit {
            return Err(state.upstream_error(
                context,
                anyhow!("upstream NAR Content-Length {length} exceeded configured limit {limit}"),
            ));
        }
    }

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("application/octet-stream"));
    let upstream = response.bytes_stream().boxed();
    let stream_state = NarStreamState {
        upstream,
        guard: Some(guard.streaming()),
        metrics: Arc::clone(&state.metrics),
        context,
        bytes_seen: 0,
        max_bytes: state.config.max_nar_bytes,
        idle_timeout: state.config.nar_chunk_idle_timeout,
    };
    let body_stream = stream::unfold(Some(stream_state), |state| async move {
        let mut state = state?;
        match tokio::time::timeout(state.idle_timeout, state.upstream.try_next()).await {
            Ok(Ok(Some(chunk))) => {
                let next_bytes = state.bytes_seen.saturating_add(chunk.len() as u64);
                if state.max_bytes.is_some_and(|limit| next_bytes > limit) {
                    state
                        .metrics
                        .nar_stream_failures_total
                        .fetch_add(1, Ordering::Relaxed);
                    if let Some(guard) = state.guard.take() {
                        guard.fail("nar_size_limit_exceeded");
                    }
                    return Some((
                        Err(std::io::Error::other(
                            "upstream NAR exceeded the configured streaming size limit",
                        )),
                        None,
                    ));
                }
                state.bytes_seen = next_bytes;
                state
                    .metrics
                    .response_bytes_total
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                Some((Ok::<_, std::io::Error>(chunk), Some(state)))
            }
            Ok(Ok(None)) => {
                if let Some(guard) = state.guard.take() {
                    guard.complete();
                }
                None
            }
            Ok(Err(error)) => {
                state
                    .metrics
                    .nar_stream_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                emit_log(
                    "error",
                    "nar_stream_failed",
                    Some(state.context),
                    Some("upstream_body_error"),
                    None,
                );
                if let Some(guard) = state.guard.take() {
                    guard.fail("upstream_body_error");
                }
                Some((Err(std::io::Error::other(error)), None))
            }
            Err(_) => {
                state
                    .metrics
                    .nar_stream_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                emit_log(
                    "error",
                    "nar_stream_failed",
                    Some(state.context),
                    Some("upstream_body_idle_timeout"),
                    None,
                );
                if let Some(guard) = state.guard.take() {
                    guard.fail("upstream_body_idle_timeout");
                }
                Some((
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "upstream NAR body made no progress for {:?}",
                            state.idle_timeout
                        ),
                    )),
                    None,
                ))
            }
        }
    });
    let body = Body::from_stream(body_stream);
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL_NAR),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Some(length) = content_length {
        if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
            response.headers_mut().insert(header::CONTENT_LENGTH, value);
        }
    }
    // Make it explicit that range requests are not forwarded by this
    // prototype rather than accidentally advertising upstream capability.
    response.headers_mut().remove(header::ACCEPT_RANGES);
    Ok(response)
}

/// Replace this proxy key's prior signatures rather than accumulating another
/// pair on every pass through the same proxy or signing chain.
fn replace_proxy_signatures(
    info: &mut NarInfo,
    fingerprint: &str,
    secret: &SecretKey,
) -> Result<()> {
    let signature = secret.signer.sign(fingerprint.as_bytes());
    let ed25519 = base64::engine::general_purpose::STANDARD.encode(signature.ed25519);
    info.replace_signature_pair(
        &secret.name,
        format!("{}:{ed25519}", secret.name),
        keys::encode_sig_pqc(&secret.name, &signature.ml_dsa),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_info() -> NarInfo {
        NarInfo {
            store_path: "/nix/store/00000000000000000000000000000000-demo".to_string(),
            url: "nar/demo.nar".to_string(),
            compression: "none".to_string(),
            nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
            nar_size: 1,
            ..Default::default()
        }
    }

    #[test]
    fn proxy_resigning_is_idempotent_for_its_own_key() {
        let secret = SecretKey::generate("proxy-1");
        let mut info = minimal_info();
        let fingerprint = info.fingerprint().unwrap();

        replace_proxy_signatures(&mut info, &fingerprint, &secret).unwrap();
        replace_proxy_signatures(&mut info, &fingerprint, &secret).unwrap();

        let prefix = "proxy-1:";
        assert_eq!(
            info.sigs
                .iter()
                .filter(|entry| entry.starts_with(prefix))
                .count(),
            1
        );
        assert_eq!(
            info.sig_pqc
                .iter()
                .filter(|entry| entry.starts_with(prefix))
                .count(),
            1
        );
        keys::verify_hybrid(&info, &fingerprint, "proxy-1", &secret.public().keys).unwrap();
    }

    #[test]
    fn upstream_url_rejects_credentials_queries_and_fragments() {
        for invalid in [
            "ftp://cache.example",
            "https://user:pass@cache.example",
            "https://cache.example?x=1",
            "https://cache.example#fragment",
        ] {
            assert!(parse_upstream_base(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn upstream_url_preserves_configured_base_path_without_string_injection() {
        let base = parse_upstream_base("https://cache.example/prefix").unwrap();
        let url = upstream_url(&base, &["nar", "abc.nar.xz"]).unwrap();
        assert_eq!(url.as_str(), "https://cache.example/prefix/nar/abc.nar.xz");
    }

    #[test]
    fn request_path_validation_is_strict() {
        assert!(validate_narinfo_hash("00000000000000000000000000000000").is_ok());
        assert!(validate_narinfo_hash("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").is_err());
        assert!(validate_narinfo_hash("short").is_err());
        assert!(validate_nar_file("abc.nar.xz").is_ok());
        assert!(validate_nar_file("../escape").is_err());
        assert!(validate_nar_file("..").is_err());
        assert!(validate_nar_file("file?query").is_err());
        assert!(validate_narinfo_download_url("nar/abc.nar.xz").is_ok());
        assert!(validate_narinfo_download_url("https://other.example/abc.nar").is_err());
        assert!(validate_narinfo_download_url("nar/nested/abc.nar").is_err());
    }

    #[test]
    fn cache_info_validation_fails_closed() {
        assert!(validate_cache_info(b"StoreDir: /nix/store\nWantMassQuery: 1\n").is_ok());
        assert!(validate_cache_info(b"WantMassQuery: 1\n").is_err());
        assert!(validate_cache_info(b"StoreDir: relative\n").is_err());
        assert!(validate_cache_info(b"StoreDir: /nix/store\r\n").is_err());
        assert!(validate_cache_info(b"StoreDir: /nix/store\nStoreDir: /other\n").is_err());
    }

    #[test]
    fn configuration_rejects_zero_limits() {
        assert!(
            ProxyConfig {
                max_in_flight: 0,
                ..ProxyConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ProxyConfig {
                queue_timeout: Duration::ZERO,
                ..ProxyConfig::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            ProxyConfig {
                max_nar_bytes: Some(0),
                ..ProxyConfig::default()
            }
            .validate()
            .is_err()
        );
    }
}
