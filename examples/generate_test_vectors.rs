//! Generates the JSON test-vector suite in `test-vectors/` from real
//! signatures produced by this crate — so an independent implementation of
//! the RFC's wire format (a different language, a `tvix` patch, whatever)
//! can check itself against known-good and known-bad cases without reading
//! or trusting this crate's source.
//!
//! Signing is randomized (both Ed25519 nonces via RustCrypto and especially
//! ML-DSA's internal randomness), so vectors capture a fixed
//! signature-and-expected-result pair rather than being "recompute this
//! exact signature from the key" — the useful direction for an independent
//! verifier to check compatibility.
//!
//! Run with: `cargo run --example generate_test_vectors`

use std::fs;
use std::path::Path;

use base64::Engine;
use nix_pqc_cache_proxy::keys::{self, SecretKey};
use nix_pqc_cache_proxy::narinfo::NarInfo;
use serde_json::json;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors");
    fs::create_dir_all(&dir).unwrap();

    write_fingerprint_vectors(&dir);
    write_signature_vectors(&dir);

    println!("wrote test vectors to {}", dir.display());
}

fn write_fingerprint_vectors(dir: &Path) {
    let with_refs = NarInfo {
        store_path: "/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
        nar_hash: "sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48".to_string(),
        nar_size: 1654112,
        references: vec![
            "00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
        ],
        ..Default::default()
    };
    write_fingerprint_vector(
        dir,
        "fingerprint-001-with-references",
        "Real narinfo (bash-5.2p37, fetched from cache.nixos.org 2026-07-10) \
         with two references, one of them a self-reference. Verified \
         separately (see narinfo.rs tests) to match Nix's own \
         ValidPathInfo::fingerprint() by successfully checking the real \
         cache.nixos.org Ed25519 signature against it.",
        &with_refs,
    );

    let no_refs = NarInfo {
        store_path: "/nix/store/aasbksznz37vw5pb26wq86209q5cmza8-xgcc-15.2.0-libgcc".to_string(),
        nar_hash: "sha256:0f3gg73cybjfnzlav06r5ndr4711wv2gjkgk2s0lghp2h3cy6db7".to_string(),
        nar_size: 279624,
        references: vec![],
        ..Default::default()
    };
    write_fingerprint_vector(
        dir,
        "fingerprint-002-no-references",
        "Zero-reference case. Real Nix narinfo emits 'References: ' (colon, \
         space, nothing) for a path with no references -- the trailing \
         space is significant and a naive parser that trims trailing \
         whitespace before splitting on ': ' will fail to parse this line \
         at all (a real bug this prototype hit and fixed).",
        &no_refs,
    );
}

fn write_fingerprint_vector(dir: &Path, name: &str, description: &str, info: &NarInfo) {
    let fingerprint = info.fingerprint().unwrap();
    let vector = json!({
        "description": description,
        "narinfo_fields": {
            "store_path": info.store_path,
            "nar_hash": info.nar_hash,
            "nar_size": info.nar_size,
            "references": info.references,
        },
        "expected_fingerprint": fingerprint,
    });
    write_json(dir, name, &vector);
}

fn write_signature_vectors(dir: &Path) {
    let key = SecretKey::generate("test-vector-key-1");
    let info = NarInfo {
        store_path: "/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
        nar_hash: "sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48".to_string(),
        nar_size: 1654112,
        references: vec![
            "00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
        ],
        ..Default::default()
    };
    let fingerprint = info.fingerprint().unwrap();
    let sig = key.signer.sign(fingerprint.as_bytes());

    let ed25519_b64 = B64.encode(sig.ed25519);
    let sig_line_value = format!("{}:{}", key.name, ed25519_b64);
    let sig_pqc_line_value = keys::encode_sig_pqc(&key.name, &sig.ml_dsa);

    let ed25519_pub_b64 = B64.encode(key.public().keys.ed25519);
    let ml_dsa_pub_b64 = B64.encode(&key.public().keys.ml_dsa);

    write_signature_vector(
        dir,
        "sig-pqc-001-valid",
        "A correctly hybrid-signed narinfo: both the Sig: and Sig-PQC: \
         lines verify against the published keys, and Sig-PQC: carries \
         only the ML-DSA-65 signature (tag byte + signature bytes), not a \
         duplicate of the Ed25519 signature already in Sig:.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        Some(&sig_line_value),
        &sig_pqc_line_value,
        true,
    );

    let mut corrupted_pqc = sig_pqc_line_value.clone();
    {
        let mid = corrupted_pqc.len() - 10;
        let bytes = unsafe { corrupted_pqc.as_bytes_mut() };
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    }
    write_signature_vector(
        dir,
        "sig-pqc-002-invalid-ml-dsa",
        "Sig: is untouched and still verifies classically on its own; \
         Sig-PQC:'s ML-DSA bytes are corrupted, so the hybrid check must \
         fail even though the classical half alone is fine.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        Some(&sig_line_value),
        &corrupted_pqc,
        false,
    );

    let unknown_tag_pqc = {
        let (name_part, b64_part) = sig_pqc_line_value.split_once(':').unwrap();
        let mut raw = B64.decode(b64_part).unwrap();
        raw[0] = 99; // no implementation of this scheme defines tag 99
        format!("{name_part}:{}", B64.encode(&raw))
    };
    write_signature_vector(
        dir,
        "sig-pqc-003-unknown-algorithm-tag",
        "Sig-PQC:'s leading algorithm-tag byte is set to 99, which this \
         scheme does not define. A conformant implementation must reject \
         this entry rather than guess at its meaning -- this is the whole \
         point of the tag byte existing.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        Some(&sig_line_value),
        &unknown_tag_pqc,
        false,
    );

    write_signature_vector(
        dir,
        "sig-pqc-004-missing-classical-pairing",
        "Sig-PQC: is present and well-formed, but there is no Sig: line \
         for the same key name at all. The hybrid check must fail closed \
         -- a missing classical half is not vacuously fine just because \
         the PQC half is present and valid.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        None,
        &sig_pqc_line_value,
        false,
    );
}

#[allow(clippy::too_many_arguments)]
fn write_signature_vector(
    dir: &Path,
    name: &str,
    description: &str,
    info: &NarInfo,
    fingerprint: &str,
    keyname: &str,
    ed25519_pubkey_b64: &str,
    ml_dsa_pubkey_b64: &str,
    sig_line_value: Option<&str>,
    sig_pqc_line_value: &str,
    hybrid_valid: bool,
) {
    let vector = json!({
        "description": description,
        "narinfo_fields": {
            "store_path": info.store_path,
            "nar_hash": info.nar_hash,
            "nar_size": info.nar_size,
            "references": info.references,
        },
        "fingerprint": fingerprint,
        "keyname": keyname,
        "ed25519_public_key_b64": ed25519_pubkey_b64,
        "ml_dsa_65_public_key_b64": ml_dsa_pubkey_b64,
        "sig_line": sig_line_value.map(|v| format!("Sig: {v}")),
        "sig_pqc_line": format!("Sig-PQC: {sig_pqc_line_value}"),
        "expected": {
            "hybrid_valid": hybrid_valid,
        },
    });
    write_json(dir, name, &vector);
}

fn write_json(dir: &Path, name: &str, value: &serde_json::Value) {
    let path = dir.join(format!("{name}.json"));
    fs::write(&path, serde_json::to_string_pretty(value).unwrap() + "\n").unwrap();
    println!("  {}", path.display());
}
