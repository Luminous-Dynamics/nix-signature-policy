//! Hermetic end-to-end proxy tests: an in-process fake upstream binary cache
//! plus our real proxy in front of it, talked to over real HTTP sockets on
//! ephemeral ports — no network access and no real `nix` binary required, so
//! these run in default `cargo test` and stay fast/deterministic.
//!
//! For the full real-`nix` proof (build a real package, `nix copy` through
//! the proxy, `nix store verify` it) see `tests/real_nix_e2e.rs`, which is
//! `#[ignore]`d because it needs `nix` + network.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path as AxumPath, State};
use axum::response::IntoResponse;
use axum::routing::get;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;

use nix_pqc_cache_proxy::keys::SecretKey;
use nix_pqc_cache_proxy::narinfo::{self, NarInfo};

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

async fn spawn_our_proxy(
    upstream: &FakeUpstream,
    upstream_pubkey_override: Option<&str>,
) -> (std::net::SocketAddr, SecretKey) {
    let secret = SecretKey::generate("test-proxy-1");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();

    let upstream_url = format!("http://{}", upstream.addr);
    let upstream_pubkey = upstream_pubkey_override
        .map(String::from)
        .unwrap_or_else(|| B64.encode(upstream.signing_key.verifying_key().to_bytes()));

    // We only need `secret` for signing inside the spawned proxy task; the
    // caller gets a fresh handle via `SecretKey::generate` again is wasteful,
    // so instead we return a second copy loaded from the same bytes.
    let secret_bytes = secret.signer.to_bytes();
    tokio::spawn(nix_pqc_cache_proxy::proxy::serve(
        listener,
        upstream_url,
        upstream_pubkey,
        secret,
    ));

    let secret_for_caller = SecretKey {
        name: "test-proxy-1".to_string(),
        signer: nix_pqc_cache_proxy::hybrid::HybridSigner::from_bytes(&secret_bytes).unwrap(),
    };
    (proxy_addr, secret_for_caller)
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
