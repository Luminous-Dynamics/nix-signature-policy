//! Hermetic end-to-end proxy tests: an in-process fake upstream binary cache
//! plus our real proxy in front of it, talked to over real HTTP sockets on
//! ephemeral ports — no network access and no real `nix` binary required, so
//! these run in default `cargo test` and stay fast/deterministic.
//!
//! For the full real-`nix` proof (build a real package, `nix copy` through
//! the proxy, `nix store verify` it) see `tests/real_nix_e2e.rs`, which is
//! `#[ignore]`d because it needs `nix` + network.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path as AxumPath, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{StreamExt, stream};
use rand::RngCore;
use tokio::sync::{Notify, oneshot};

use nix_pqc_cache_proxy::keys::SecretKey;
use nix_pqc_cache_proxy::narinfo::{self, NarInfo};
use nix_pqc_cache_proxy::proxy::ProxyConfig;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// A fake upstream binary cache: one narinfo, dual-referencable by hash, plus
/// arbitrary NAR bytes, all served over real HTTP on an OS-assigned port.
struct FakeUpstream {
    addr: std::net::SocketAddr,
    signing_key: SigningKey,
    hash: String,
    nar_bytes: Vec<u8>,
}

#[derive(Clone)]
struct UpstreamState {
    hash: String,
    narinfo_text: String,
    nar_bytes: Arc<Vec<u8>>,
}

async fn upstream_cache_info() -> &'static str {
    "StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n"
}

async fn upstream_narinfo(
    State(state): State<UpstreamState>,
    AxumPath(filename): AxumPath<String>,
) -> impl IntoResponse {
    if filename == format!("{}.narinfo", state.hash) {
        (axum::http::StatusCode::OK, state.narinfo_text.clone())
    } else {
        (axum::http::StatusCode::NOT_FOUND, String::new())
    }
}

async fn upstream_nar(State(state): State<UpstreamState>) -> Vec<u8> {
    state.nar_bytes.as_ref().clone()
}

async fn spawn_fake_upstream(nar_size: usize) -> FakeUpstream {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);

    // Deterministic pseudo-random NAR payload — big enough to meaningfully
    // exercise streaming (not just a couple of bytes), byte-comparable
    // without stashing a literal blob in the test.
    let nar_bytes: Vec<u8> = (0..nar_size).map(|i| (i % 251) as u8).collect();

    let hash = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(); // fake but well-formed-looking
    let mut info = NarInfo {
        store_path: format!("/nix/store/{hash}-fake-pkg-1.0"),
        url: "nar/fake.nar".to_string(),
        compression: "none".to_string(),
        nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
        nar_size: nar_bytes.len() as u64,
        ..Default::default()
    };
    let fingerprint = info.fingerprint().unwrap();
    let sig = signing_key.sign(fingerprint.as_bytes());
    info.sigs
        .push(format!("fake-upstream-1:{}", B64.encode(sig.to_bytes())));

    let state = UpstreamState {
        hash: hash.clone(),
        narinfo_text: info.to_text(),
        nar_bytes: Arc::new(nar_bytes.clone()),
    };
    let app = Router::new()
        .route("/nix-cache-info", get(upstream_cache_info))
        .route("/{filename}", get(upstream_narinfo))
        .route("/nar/{file}", get(upstream_nar))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    FakeUpstream {
        addr,
        signing_key,
        hash,
        nar_bytes,
    }
}

async fn spawn_proxy_for_url(
    upstream_url: String,
    upstream_pubkey: String,
    config: ProxyConfig,
) -> (std::net::SocketAddr, SecretKey) {
    let secret = SecretKey::generate("test-proxy-1");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    // We only need `secret` for signing inside the spawned proxy task; retain
    // an equivalent caller-side key for verifying the response signatures.
    let secret_bytes = secret.signer.to_bytes();
    tokio::spawn(nix_pqc_cache_proxy::proxy::serve_with_config(
        listener,
        upstream_url,
        upstream_pubkey,
        secret,
        config,
    ));

    let secret_for_caller = SecretKey {
        name: "test-proxy-1".to_string(),
        signer: nix_pqc_cache_proxy::hybrid::HybridSigner::from_bytes(&secret_bytes).unwrap(),
    };
    (proxy_addr, secret_for_caller)
}

async fn spawn_our_proxy(
    upstream: &FakeUpstream,
    upstream_pubkey_override: Option<&str>,
) -> (std::net::SocketAddr, SecretKey) {
    let upstream_pubkey = upstream_pubkey_override
        .map(String::from)
        .unwrap_or_else(|| B64.encode(upstream.signing_key.verifying_key().to_bytes()));
    spawn_proxy_for_url(
        format!("http://{}", upstream.addr),
        upstream_pubkey,
        ProxyConfig::default(),
    )
    .await
}

// Wait for a TCP listener to actually accept connections before the test's
// first request — `tokio::spawn` doesn't guarantee the server is ready yet.
async fn wait_until_up(addr: std::net::SocketAddr) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("server at {addr} never came up");
}

#[tokio::test]
async fn proxy_augments_narinfo_with_hybrid_signature() {
    let upstream = spawn_fake_upstream(64).await;
    wait_until_up(upstream.addr).await;
    let (proxy_addr, secret) = spawn_our_proxy(&upstream, None).await;
    wait_until_up(proxy_addr).await;

    let client = reqwest::Client::new();
    let text = client
        .get(format!("http://{proxy_addr}/{}.narinfo", upstream.hash))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    let info = NarInfo::parse(&text).unwrap();
    let fingerprint = info.fingerprint().unwrap();

    // Original upstream Sig is preserved (backward compatible: a client
    // trusting only the upstream's key still trusts this response).
    assert_eq!(info.sigs.len(), 2, "expected upstream Sig + our added Sig");
    let upstream_pk_b64 = B64.encode(upstream.signing_key.verifying_key().to_bytes());
    assert!(info.sigs.iter().any(|s| {
        narinfo::verify_ed25519_sig(&fingerprint, s, Some("fake-upstream-1"), &upstream_pk_b64)
            .is_ok()
    }));

    // Our own classical Sig verifies too.
    let our_pk_b64 = B64.encode(secret.public().keys.ed25519);
    assert!(info.sigs.iter().any(|s| {
        narinfo::verify_ed25519_sig(&fingerprint, s, Some("test-proxy-1"), &our_pk_b64).is_ok()
    }));

    // The hybrid Sig-PQC line is present (carrying ONLY the ML-DSA half) and,
    // paired with the same-keyname Sig: line above, verifies as a hybrid pair.
    assert_eq!(info.sig_pqc.len(), 1);
    let (name, algorithm, _ml_dsa) =
        nix_pqc_cache_proxy::keys::decode_sig_pqc(&info.sig_pqc[0]).unwrap();
    assert_eq!(name, "test-proxy-1");
    assert_eq!(
        algorithm,
        nix_pqc_cache_proxy::keys::SigPqcAlgorithm::MlDsa65
    );
    nix_pqc_cache_proxy::keys::verify_hybrid(&info, &fingerprint, &name, &secret.public().keys)
        .expect("hybrid signature must verify");
}

#[tokio::test]
async fn proxy_rejects_when_upstream_signature_does_not_verify() {
    let upstream = spawn_fake_upstream(64).await;
    wait_until_up(upstream.addr).await;
    // Wrong pubkey: 32 zero bytes, will never match the real upstream sig.
    let wrong_pubkey = B64.encode([0u8; 32]);
    let (proxy_addr, _secret) = spawn_our_proxy(&upstream, Some(&wrong_pubkey)).await;
    wait_until_up(proxy_addr).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{proxy_addr}/{}.narinfo", upstream.hash))
        .send()
        .await
        .unwrap();
    assert!(
        !resp.status().is_success(),
        "proxy must fail closed when it can't verify the upstream signature"
    );
}

#[tokio::test]
async fn proxy_streams_nar_bytes_correctly() {
    // 5MB — big enough that a naive full-buffer implementation would still
    // "work" for this test, but this exercises the actual streaming path
    // end-to-end and confirms the bytes survive intact through both hops.
    let nar_size = 5 * 1024 * 1024;
    let upstream = spawn_fake_upstream(nar_size).await;
    wait_until_up(upstream.addr).await;
    let (proxy_addr, _secret) = spawn_our_proxy(&upstream, None).await;
    wait_until_up(proxy_addr).await;

    let client = reqwest::Client::new();
    let bytes = client
        .get(format!("http://{proxy_addr}/nar/fake.nar"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();

    assert_eq!(bytes.len(), nar_size);
    assert_eq!(bytes.as_ref(), upstream.nar_bytes.as_slice());
}

#[tokio::test]
async fn proxy_passes_through_nix_cache_info() {
    let upstream = spawn_fake_upstream(16).await;
    wait_until_up(upstream.addr).await;
    let (proxy_addr, _secret) = spawn_our_proxy(&upstream, None).await;
    wait_until_up(proxy_addr).await;

    let client = reqwest::Client::new();
    let text = client
        .get(format!("http://{proxy_addr}/nix-cache-info"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("StoreDir: /nix/store"));
}

async fn spawn_custom_upstream(app: Router) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    wait_until_up(addr).await;
    addr
}

fn test_upstream_pubkey() -> String {
    B64.encode([0u8; 32])
}

#[tokio::test]
async fn health_readiness_and_metrics_are_operationally_useful() {
    let upstream = spawn_fake_upstream(16).await;
    wait_until_up(upstream.addr).await;
    let (proxy_addr, _) = spawn_our_proxy(&upstream, None).await;
    wait_until_up(proxy_addr).await;
    let client = reqwest::Client::new();

    let health = client
        .get(format!("http://{proxy_addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    assert_eq!(health.headers()["cache-control"], "no-store");

    let ready = client
        .get(format!("http://{proxy_addr}/readyz"))
        .send()
        .await
        .unwrap();
    assert_eq!(ready.status(), reqwest::StatusCode::OK);

    let metrics = client
        .get(format!("http://{proxy_addr}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("nix_pqc_proxy_up 1"));
    assert!(metrics.contains("nix_pqc_proxy_readiness_checks_total 1"));
}

#[tokio::test]
async fn read_only_routes_reject_request_bodies() {
    let upstream = spawn_fake_upstream(16).await;
    wait_until_up(upstream.addr).await;
    let (proxy_addr, _) = spawn_our_proxy(&upstream, None).await;
    wait_until_up(proxy_addr).await;

    let response = reqwest::Client::new()
        .get(format!("http://{proxy_addr}/healthz"))
        .body("unexpected")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("request bodies are not accepted")
    );
}

#[tokio::test]
async fn bounded_queue_refuses_excess_concurrency() {
    #[derive(Clone)]
    struct SlowState {
        started: Arc<Notify>,
        release: Arc<Notify>,
    }

    async fn slow_cache_info(State(state): State<SlowState>) -> &'static str {
        state.started.notify_one();
        state.release.notified().await;
        "StoreDir: /nix/store\nWantMassQuery: 1\n"
    }

    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let upstream_addr = spawn_custom_upstream(
        Router::new()
            .route("/nix-cache-info", get(slow_cache_info))
            .with_state(SlowState {
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            }),
    )
    .await;
    let config = ProxyConfig {
        max_in_flight: 1,
        queue_timeout: Duration::from_millis(25),
        ..ProxyConfig::default()
    };
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        test_upstream_pubkey(),
        config,
    )
    .await;
    wait_until_up(proxy_addr).await;

    let client = reqwest::Client::new();
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .get(format!("http://{proxy_addr}/nix-cache-info"))
            .send()
            .await
            .unwrap()
    });
    started.notified().await;
    let second = client
        .get(format!("http://{proxy_addr}/nix-cache-info"))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(second.headers()["retry-after"], "1");
    assert!(second.headers().contains_key("x-request-id"));
    assert!(second.text().await.unwrap().contains("proxy_overloaded"));
    release.notify_one();
    assert_eq!(first.await.unwrap().status(), reqwest::StatusCode::OK);

    let metrics = client
        .get(format!("http://{proxy_addr}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("nix_pqc_proxy_overloaded_total 1"));
}

#[tokio::test]
async fn oversized_metadata_and_redirects_fail_closed() {
    async fn oversized() -> String {
        "x".repeat(5 * 1024)
    }
    async fn redirect() -> impl IntoResponse {
        (
            axum::http::StatusCode::FOUND,
            [(axum::http::header::LOCATION, "http://127.0.0.1:1/elsewhere")],
            "redirect",
        )
    }

    for app in [
        Router::new().route("/nix-cache-info", get(oversized)),
        Router::new().route("/nix-cache-info", get(redirect)),
    ] {
        let upstream_addr = spawn_custom_upstream(app).await;
        let (proxy_addr, _) = spawn_proxy_for_url(
            format!("http://{upstream_addr}"),
            test_upstream_pubkey(),
            ProxyConfig::default(),
        )
        .await;
        wait_until_up(proxy_addr).await;
        let response = reqwest::get(format!("http://{proxy_addr}/nix-cache-info"))
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    }
}

#[tokio::test]
async fn readiness_fails_when_cache_info_is_malformed() {
    async fn malformed() -> &'static str {
        "WantMassQuery: 1\n"
    }
    let upstream_addr =
        spawn_custom_upstream(Router::new().route("/nix-cache-info", get(malformed))).await;
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        test_upstream_pubkey(),
        ProxyConfig::default(),
    )
    .await;
    wait_until_up(proxy_addr).await;

    let response = reqwest::get(format!("http://{proxy_addr}/readyz"))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("upstream_not_ready")
    );
}

#[tokio::test]
async fn narinfo_download_url_cannot_escape_the_proxy_namespace() {
    async fn serve_narinfo(State(text): State<String>) -> String {
        text
    }

    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let hash = "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
    let mut info = NarInfo {
        store_path: format!("/nix/store/{hash}-escape-attempt"),
        url: "https://other.example/escape.nar".to_string(),
        compression: "none".to_string(),
        nar_hash: "sha256:0000000000000000000000000000000000000000000000000000".to_string(),
        nar_size: 1,
        ..Default::default()
    };
    let fingerprint = info.fingerprint().unwrap();
    let signature = signing_key.sign(fingerprint.as_bytes());
    info.sigs.push(format!(
        "escape-upstream-1:{}",
        B64.encode(signature.to_bytes())
    ));

    let upstream_addr = spawn_custom_upstream(
        Router::new()
            .route("/{filename}", get(serve_narinfo))
            .with_state(info.to_text()),
    )
    .await;
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        format!(
            "escape-upstream-1:{}",
            B64.encode(signing_key.verifying_key().to_bytes())
        ),
        ProxyConfig::default(),
    )
    .await;
    wait_until_up(proxy_addr).await;

    let response = reqwest::get(format!("http://{proxy_addr}/{hash}.narinfo"))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert!(response.text().await.unwrap().contains("upstream_failure"));
}

#[tokio::test]
async fn invalid_nar_route_input_is_rejected_before_upstream_fetch() {
    let upstream = spawn_fake_upstream(16).await;
    wait_until_up(upstream.addr).await;
    let (proxy_addr, _) = spawn_our_proxy(&upstream, None).await;
    wait_until_up(proxy_addr).await;

    let response = reqwest::get(format!("http://{proxy_addr}/nar/file%3Fquery"))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(response.text().await.unwrap().contains("invalid_request"));
}

#[tokio::test]
async fn interrupted_nar_stream_surfaces_a_body_error_and_releases_capacity() {
    async fn interrupted() -> Response {
        let chunks = stream::unfold(0, |state| async move {
            match state {
                0 => Some((Ok::<Bytes, std::io::Error>(Bytes::from_static(b"first")), 1)),
                1 => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Some((
                        Err(std::io::Error::other("injected upstream body failure")),
                        2,
                    ))
                }
                _ => None,
            }
        });
        Response::new(Body::from_stream(chunks))
    }
    let upstream_addr =
        spawn_custom_upstream(Router::new().route("/nar/fault.nar", get(interrupted))).await;
    let config = ProxyConfig {
        max_in_flight: 1,
        ..ProxyConfig::default()
    };
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        test_upstream_pubkey(),
        config,
    )
    .await;
    wait_until_up(proxy_addr).await;

    let response = reqwest::get(format!("http://{proxy_addr}/nar/fault.nar"))
        .await
        .unwrap();
    assert!(response.bytes().await.is_err());

    // The NAR stream's permit must be released after the body failure.
    let health = reqwest::get(format!("http://{proxy_addr}/healthz"))
        .await
        .unwrap();
    assert_eq!(health.status(), reqwest::StatusCode::OK);
    let metrics = reqwest::get(format!("http://{proxy_addr}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(metrics.contains("nix_pqc_proxy_nar_stream_failures_total 1"));
    assert!(metrics.contains("nix_pqc_proxy_requests_failed_total 1"));
    assert!(metrics.contains("nix_pqc_proxy_requests_active 0"));
}

#[tokio::test]
async fn stalled_nar_stream_hits_the_idle_deadline() {
    async fn stalled() -> Response {
        let stream =
            stream::once(async { Ok::<Bytes, std::io::Error>(Bytes::from_static(b"first")) })
                .chain(stream::pending());
        Response::new(Body::from_stream(stream))
    }
    let upstream_addr =
        spawn_custom_upstream(Router::new().route("/nar/stalled.nar", get(stalled))).await;
    let config = ProxyConfig {
        nar_chunk_idle_timeout: Duration::from_millis(30),
        ..ProxyConfig::default()
    };
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        test_upstream_pubkey(),
        config,
    )
    .await;
    wait_until_up(proxy_addr).await;

    let response = reqwest::get(format!("http://{proxy_addr}/nar/stalled.nar"))
        .await
        .unwrap();
    assert!(response.bytes().await.is_err());
}

#[tokio::test]
async fn configured_nar_size_limit_is_enforced_from_headers_and_streaming() {
    async fn declared_large() -> Response {
        Response::builder()
            .header(axum::http::header::CONTENT_LENGTH, "128")
            .body(Body::from(vec![0u8; 128]))
            .unwrap()
    }
    let upstream_addr =
        spawn_custom_upstream(Router::new().route("/nar/declared.nar", get(declared_large))).await;
    let config = ProxyConfig {
        max_nar_bytes: Some(64),
        ..ProxyConfig::default()
    };
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        test_upstream_pubkey(),
        config.clone(),
    )
    .await;
    wait_until_up(proxy_addr).await;
    let response = reqwest::get(format!("http://{proxy_addr}/nar/declared.nar"))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);

    async fn undeclared_large() -> Response {
        let chunks = stream::iter(vec![
            Ok::<Bytes, std::io::Error>(Bytes::from(vec![1u8; 40])),
            Ok(Bytes::from(vec![2u8; 40])),
        ]);
        Response::new(Body::from_stream(chunks))
    }
    let upstream_addr =
        spawn_custom_upstream(Router::new().route("/nar/streamed.nar", get(undeclared_large)))
            .await;
    let (proxy_addr, _) = spawn_proxy_for_url(
        format!("http://{upstream_addr}"),
        test_upstream_pubkey(),
        config,
    )
    .await;
    wait_until_up(proxy_addr).await;
    let response = reqwest::get(format!("http://{proxy_addr}/nar/streamed.nar"))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.bytes().await.is_err());
}

#[tokio::test]
async fn graceful_shutdown_stops_accepting_and_returns_cleanly() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let secret = SecretKey::generate("test-proxy-1");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let task = tokio::spawn(nix_pqc_cache_proxy::proxy::serve_with_config_and_shutdown(
        listener,
        "http://127.0.0.1:9".to_string(),
        test_upstream_pubkey(),
        secret,
        ProxyConfig::default(),
        async move {
            let _ = shutdown_rx.await;
        },
    ));
    wait_until_up(proxy_addr).await;
    assert_eq!(
        reqwest::get(format!("http://{proxy_addr}/healthz"))
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::OK
    );

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("proxy did not drain promptly")
        .expect("proxy task panicked")
        .expect("proxy returned an error");
}
