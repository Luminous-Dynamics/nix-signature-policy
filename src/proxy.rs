//! A minimal reverse proxy speaking the Nix HTTP binary-cache protocol.
//!
//! Fetches `.narinfo`/`nix-cache-info`/NAR bytes from a real upstream
//! substituter, verifies the upstream's classical Ed25519 `Sig:`, and
//! re-serves the narinfo augmented with OUR hybrid `Sig-PQC:` line (and our
//! own classical `Sig:`, so a client can trust this proxy's key alone).
//!
//! Scope note: this does not make the upstream itself PQC-signed — it's a
//! local trust-translation boundary. NAR bytes and narinfo text are buffered
//! fully in memory, which is fine for a prototype/demo and not how a
//! production proxy would handle large store paths.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;

use crate::keys::{self, SecretKey};
use crate::narinfo::{self, NarInfo};

struct ProxyState {
    upstream: String,
    upstream_pubkey: String,
    secret: SecretKey,
    client: reqwest::Client,
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

pub async fn run(
    upstream: String,
    upstream_pubkey: String,
    key_path: PathBuf,
    listen: String,
) -> Result<()> {
    let secret = SecretKey::load(&key_path)?;
    let upstream_pubkey = keys::strip_key_name(&upstream_pubkey).to_string();
    let client = reqwest::Client::builder().build()?;

    println!("nix-pqc-cache-proxy: signing as '{}'", secret.name);
    println!("nix-pqc-cache-proxy: upstream = {upstream}");
    println!("nix-pqc-cache-proxy: listening on http://{listen}");
    println!(
        "  point nix at it with: --extra-substituters http://{listen} --extra-trusted-public-keys '{}:{}'",
        secret.name,
        base64::engine::general_purpose::STANDARD.encode(secret.public().keys.ed25519)
    );

    let state = Arc::new(ProxyState {
        upstream,
        upstream_pubkey,
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

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_cache_info(State(state): State<Arc<ProxyState>>) -> Result<Response, AppError> {
    let url = format!("{}/nix-cache-info", state.upstream);
    let resp = state.client.get(&url).send().await?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let bytes = resp.bytes().await?;
    Ok((status, bytes.to_vec()).into_response())
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
    let text = resp.text().await?;
    let mut info = NarInfo::parse(&text)?;
    let fingerprint = info.fingerprint()?;

    // Verify the upstream's existing signature before we vouch for it further.
    let verified = info
        .sigs
        .iter()
        .any(|s| narinfo::verify_ed25519_sig(&fingerprint, s, &state.upstream_pubkey).is_ok());
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
        .push(keys::encode_sig_pqc(&state.secret.name, &sig));

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
    let bytes = resp.bytes().await?;
    Ok((status, [("content-type", content_type)], bytes.to_vec()).into_response())
}
