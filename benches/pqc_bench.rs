//! Sign/verify/parse cost benchmarks. Sizes are already measured by hand
//! (see README: the Sig-PQC: line alone adds ~4.4KB/narinfo, dominated by
//! the 3309-byte ML-DSA-65 signature base64-inflated ~4/3x); this bench
//! covers latency instead.

use criterion::{Criterion, criterion_group, criterion_main};

use nix_pqc_cache_proxy::keys::SecretKey;
use nix_pqc_cache_proxy::narinfo::NarInfo;

/// Real narinfo fields (same fixture as `narinfo.rs`'s own tests — fetched
/// 2026-07-10 from cache.nixos.org for bash-5.2p37) rather than a fabricated
/// one, so the bench measures realistic field sizes.
fn sample_narinfo() -> NarInfo {
    NarInfo {
        store_path: "/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
        url: "nar/08lg95m879r3yarkg6ndjg3db9an3bzg5ha9iba2vd8hfrw06q93.nar.xz".to_string(),
        compression: "xz".to_string(),
        nar_hash: "sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48".to_string(),
        nar_size: 1654112,
        references: vec![
            "00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
        ],
        ..Default::default()
    }
}

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("hybrid_keygen", |b| {
        b.iter(|| SecretKey::generate("bench-key"))
    });
}

fn bench_sign(c: &mut Criterion) {
    let key = SecretKey::generate("bench-key");
    let fingerprint = sample_narinfo().fingerprint().unwrap();
    c.bench_function("hybrid_sign_fingerprint", |b| {
        b.iter(|| key.signer.sign(fingerprint.as_bytes()))
    });
}

fn bench_verify(c: &mut Criterion) {
    let key = SecretKey::generate("bench-key");
    let fingerprint = sample_narinfo().fingerprint().unwrap();
    let sig = key.signer.sign(fingerprint.as_bytes());
    let verifying_keys = key.public().keys;
    c.bench_function("hybrid_verify", |b| {
        b.iter(|| {
            nix_pqc_cache_proxy::hybrid::verify(&verifying_keys, fingerprint.as_bytes(), &sig)
                .unwrap()
        })
    });
}

fn bench_sig_pqc_encode(c: &mut Criterion) {
    let key = SecretKey::generate("bench-key");
    let fingerprint = sample_narinfo().fingerprint().unwrap();
    let sig = key.signer.sign(fingerprint.as_bytes());
    c.bench_function("sig_pqc_encode", |b| {
        b.iter(|| nix_pqc_cache_proxy::keys::encode_sig_pqc("bench-key", &sig.ml_dsa))
    });
}

fn bench_narinfo_parse(c: &mut Criterion) {
    let text = sample_narinfo().to_text();
    c.bench_function("narinfo_parse", |b| {
        b.iter(|| NarInfo::parse(&text).unwrap())
    });
}

fn bench_narinfo_to_text(c: &mut Criterion) {
    let info = sample_narinfo();
    c.bench_function("narinfo_to_text", |b| b.iter(|| info.to_text()));
}

criterion_group!(
    benches,
    bench_keygen,
    bench_sign,
    bench_verify,
    bench_sig_pqc_encode,
    bench_narinfo_parse,
    bench_narinfo_to_text,
);
criterion_main!(benches);
