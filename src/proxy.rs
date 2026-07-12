//! A minimal reverse proxy speaking the Nix HTTP binary-cache protocol.
//!
//! Fetches `.narinfo`/`nix-cache-info`/NAR bytes from a real upstream
//! substituter, verifies the upstream's classical Ed25519 `Sig:`, and
//! re-serves the narinfo augmented with OUR hybrid `Sig-PQC:` line (and our
//! own classical `Sig:`, so a client can trust this proxy's key alone).
//!
//! Scope note: this does not make the upstream itself PQC-signed — it's a
//! local trust-translation boundary. `.narinfo` text is small (a few KB even
//! dual-signed) and is buffered/parsed in memory, which is unavoidable since
//! we mutate it before re-serving. NAR bytes are NOT buffered — they can be
//! gigabytes for a real store path, so `handle_nar` streams the upstream
//! response body straight through instead of loading it whole.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use axum::Router;
use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use futures_util::TryStreamExt;

use crate::keys::{self, SecretKey};
use crate::narinfo::{self, NarInfo};

/// Hard cap on a fetched `.narinfo` body. Real narinfo (even hybrid dual-
/// signed: classical sig ~100B + ML-DSA-65 sig ~4.4KB base64-encoded) is a
/// few KB; this is generous headroom, not a tight fit. Enforced while
/// streaming (not only after full buffering) so a malicious or compromised
/// upstream can't force unbounded memory use before we ever look at the
/// content.
const MAX_NARINFO_BYTES: usize = 64 * 1024;

/// Hard cap on the (tiny, fixed-shape) `nix-cache-info` document.
const MAX_CACHE_INFO_BYTES: usize = 4 * 1024;

struct ProxyState {
    upstream: String,
    upstream_pubkey: String,
    /// `None` when `--upstream-pubkey` was given without a `name:` prefix —
    /// degrades to name-blind matching (see `keys::parse_named_pubkey`).
    upstream_key_name: Option<String>,
    secret: SecretKey,
    client: reqwest::Client,
}

/// Read an HTTP response body up to `cap` bytes, erroring (not truncating)
/// if it's exceeded — a truncated narinfo would fail to parse anyway, and
/// silently truncating is worse than a clear error for a security-relevant
/// boundary. Streams rather than trusting `Content-Length`, which a
/// malicious/misbehaving upstream could simply omit or lie about.
async fn read_capped(resp: reqwest::Response, cap: usize) -> Result<Vec<u8>> {
    let mut stream = resp.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.try_next().await? {
        buf.extend_from_slice(&chunk);
        if buf.len() > cap {
            bail!("upstream response body exceeded the {cap}-byte cap");
        }
    }
    Ok(buf)
}

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_GATEWAY,
            format!("proxy error: {:#}", self.0),
        )
            .into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

/// CLI entry point: loads the key, binds `listen`, prints connection info,
/// then hands off to [`serve`].
pub async fn run(
    upstream: String,
    upstream_pubkey: String,
    key_path: PathBuf,
    listen: String,
) -> Result<()> {
    let secret = SecretKey::load(&key_path)?;
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    let local_addr = listener.local_addr()?;

    println!("nix-pqc-cache-proxy: signing as '{}'", secret.name);
    println!("nix-pqc-cache-proxy: upstream = {upstream}");
    println!("nix-pqc-cache-proxy: listening on http://{local_addr}");
    println!(
        "  point nix at it with: --extra-substituters http://{local_addr} --extra-trusted-public-keys '{}:{}'",
        secret.name,
        base64::engine::general_purpose::STANDARD.encode(secret.public().keys.ed25519)
    );

    serve(listener, upstream, upstream_pubkey, secret).await
}

/// Build the router and serve it on an already-bound listener. Split out
/// from [`run`] so tests can bind an ephemeral port (`127.0.0.1:0`), read
/// back the real address via `listener.local_addr()`, and hand a live
/// `SecretKey` straight in — without needing a CLI-facing key file or
/// waiting on `run`'s startup printing.
pub async fn serve(
    listener: tokio::net::TcpListener,
    upstream: String,
    upstream_pubkey: String,
    secret: SecretKey,
) -> Result<()> {
    let (upstream_key_name, upstream_pubkey) = {
        let (name, key) = keys::parse_named_pubkey(&upstream_pubkey);
        (name.map(String::from), key.to_string())
    };
    if upstream_key_name.is_none() {
        eprintln!(
            "warning: --upstream-pubkey has no 'name:' prefix; matching any Sig: entry's name \
             (not enforcing key-name identity, unlike real Nix's trusted-public-keys)"
        );
    }
    // Without a timeout, a hung or slow upstream would leave a request (and
    // the client waiting on it) stuck indefinitely.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let state = Arc::new(ProxyState {
        upstream,
        upstream_pubkey,
        upstream_key_name,
        secret,
        client,
    });

    let app = Router::new()
        .route("/nix-cache-info", get(handle_cache_info))
        // axum 0.8 forbids mixing a literal suffix with a param in one path
        // segment ("/{hash}.narinfo" panics at router build time), so this
        // captures the whole segment and splits the ".narinfo" suffix in the
        // handler instead. Static routes (like /nix-cache-info above) still
        // take priority over this dynamic one.
        .route("/{filename}", get(handle_narinfo))
        .route("/nar/{file}", get(handle_nar))
        .with_state(state);

    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_cache_info(State(state): State<Arc<ProxyState>>) -> Result<Response, AppError> {
    let url = format!("{}/nix-cache-info", state.upstream);
    let resp = state.client.get(&url).send().await?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = read_capped(resp, MAX_CACHE_INFO_BYTES).await?;
    Ok((status, bytes).into_response())
}

async fn handle_narinfo(
    State(state): State<Arc<ProxyState>>,
    AxumPath(filename): AxumPath<String>,
) -> Result<Response, AppError> {
    let Some(hash) = filename.strip_suffix(".narinfo") else {
        return Ok((StatusCode::NOT_FOUND, "not a narinfo request").into_response());
    };
    let url = format!("{}/{hash}.narinfo", state.upstream);
    let resp = state.client.get(&url).send().await?;
    if !resp.status().is_success() {
        return Ok((StatusCode::NOT_FOUND, "upstream narinfo not found").into_response());
    }
    let bytes = read_capped(resp, MAX_NARINFO_BYTES).await?;
    let text = String::from_utf8(bytes).context("upstream narinfo is not valid UTF-8")?;
    let mut info = NarInfo::parse(&text)?;
    let fingerprint = info.fingerprint()?;

    // Verify the upstream's existing signature before we vouch for it further.
    let verified = info.sigs.iter().any(|s| {
        narinfo::verify_ed25519_sig(
            &fingerprint,
            s,
            state.upstream_key_name.as_deref(),
            &state.upstream_pubkey,
        )
        .is_ok()
    });
    if !verified {
        return Err(AppError(anyhow!(
            "upstream Sig did not verify against the configured upstream_pubkey for {hash}"
        )));
    }

    // Re-sign: add our own classical Sig (so a client can trust this proxy's
    // key alone) plus the hybrid Sig-PQC line.
    let sig = state.secret.signer.sign(fingerprint.as_bytes());
    let ed_b64 = base64::engine::general_purpose::STANDARD.encode(sig.ed25519);
    info.sigs.push(format!("{}:{}", state.secret.name, ed_b64));
    info.sig_pqc
        .push(keys::encode_sig_pqc(&state.secret.name, &sig.ml_dsa));

    Ok((
        StatusCode::OK,
        [("content-type", "text/x-nix-narinfo")],
        info.to_text(),
    )
        .into_response())
}

async fn handle_nar(
    State(state): State<Arc<ProxyState>>,
    AxumPath(file): AxumPath<String>,
) -> Result<Response, AppError> {
    let url = format!("{}/nar/{file}", state.upstream);
    let resp = state.client.get(&url).send().await?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    // NAR files can be gigabytes (a real store path's compressed archive) —
    // stream chunks straight from upstream to the client instead of
    // buffering the whole body, unlike the narinfo handler above (which
    // must buffer, since it parses and mutates the text before re-serving).
    let stream = resp.bytes_stream().map_err(std::io::Error::other);
    let body = Body::from_stream(stream);
    Ok((status, [("content-type", content_type)], body).into_response())
}
