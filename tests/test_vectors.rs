//! Runs `test-vectors/*.json` (see `examples/generate_test_vectors.rs`)
//! against this crate's own implementation, so a future change to the
//! fingerprint algorithm or hybrid-verify logic that silently disagrees
//! with the committed vectors fails CI, not just a manual re-check.

use std::fs;
use std::path::Path;

use base64::Engine;
use serde_json::Value;

use nix_pqc_cache_proxy::keys::{self, verify_hybrid};
use nix_pqc_cache_proxy::narinfo::NarInfo;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors")
}

fn load(name: &str) -> Value {
    let text = fs::read_to_string(vectors_dir().join(format!("{name}.json")))
        .unwrap_or_else(|e| panic!("reading {name}.json: {e}"));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {name}.json: {e}"))
}

fn narinfo_from_fields(fields: &Value) -> NarInfo {
    NarInfo {
        store_path: fields["store_path"].as_str().unwrap().to_string(),
        nar_hash: fields["nar_hash"].as_str().unwrap().to_string(),
        nar_size: fields["nar_size"].as_u64().unwrap(),
        references: fields["references"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect(),
        ..Default::default()
    }
}

#[test]
fn fingerprint_vectors_match() {
    for name in [
        "fingerprint-001-with-references",
        "fingerprint-002-no-references",
        "fingerprint-003-shuffled-references",
        "fingerprint-004-duplicate-references",
    ] {
        let vector = load(name);
        let info = narinfo_from_fields(&vector["narinfo_fields"]);
        let expected = vector["expected_fingerprint"].as_str().unwrap();
        assert_eq!(
            info.fingerprint().unwrap(),
            expected,
            "vector {name} fingerprint mismatch"
        );
    }
}

#[test]
fn shuffled_references_vector_matches_canonical_vector() {
    // Belt-and-suspenders on top of fingerprint_vectors_match: the
    // shuffled-order vector's expected fingerprint must be IDENTICAL to
    // the canonically-ordered vector's, not just internally self-consistent.
    let canonical = load("fingerprint-001-with-references");
    let shuffled = load("fingerprint-003-shuffled-references");
    assert_ne!(
        canonical["narinfo_fields"]["references"], shuffled["narinfo_fields"]["references"],
        "the vectors should actually differ in input order"
    );
    assert_eq!(
        canonical["expected_fingerprint"], shuffled["expected_fingerprint"],
        "shuffled reference order must not change the fingerprint"
    );
}

#[test]
fn duplicate_references_vector_matches_canonical_vector() {
    let canonical = load("fingerprint-001-with-references");
    let duplicated = load("fingerprint-004-duplicate-references");
    assert_ne!(
        canonical["narinfo_fields"]["references"], duplicated["narinfo_fields"]["references"],
        "the duplicate-reference vector must exercise a distinct input"
    );
    assert_eq!(
        canonical["expected_fingerprint"], duplicated["expected_fingerprint"],
        "duplicate references must not change StorePathSet fingerprint semantics"
    );
}

fn strip_prefix_all(lines: &Value, prefix: &str) -> Vec<String> {
    lines
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap()
                .strip_prefix(prefix)
                .unwrap()
                .to_string()
        })
        .collect()
}

fn run_signature_vector(name: &str) {
    let vector = load(name);
    let info = narinfo_from_fields(&vector["narinfo_fields"]);
    let fingerprint = vector["fingerprint"].as_str().unwrap();
    assert_eq!(
        info.fingerprint().unwrap(),
        fingerprint,
        "vector {name} fingerprint drifted"
    );

    let keyname = vector["keyname"].as_str().unwrap();
    let ed25519 = B64
        .decode(vector["ed25519_public_key_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let ml_dsa = B64
        .decode(vector["ml_dsa_65_public_key_b64"].as_str().unwrap())
        .unwrap();
    let keys = nix_pqc_cache_proxy::hybrid::HybridVerifyingKeys { ed25519, ml_dsa };

    let mut info = info;
    info.sigs = strip_prefix_all(&vector["sig_lines"], "Sig: ");
    info.sig_pqc = strip_prefix_all(&vector["sig_pqc_lines"], "Sig-PQC: ");

    let expected_hybrid_valid = vector["expected"]["hybrid_valid"].as_bool().unwrap();
    let actual = verify_hybrid(&info, fingerprint, keyname, &keys).is_ok();
    assert_eq!(
        actual, expected_hybrid_valid,
        "vector {name}: expected hybrid_valid={expected_hybrid_valid}, got {actual}"
    );
}

#[test]
fn sig_pqc_valid_vector() {
    run_signature_vector("sig-pqc-001-valid");
}

#[test]
fn sig_pqc_invalid_ml_dsa_vector() {
    run_signature_vector("sig-pqc-002-invalid-ml-dsa");
}

#[test]
fn sig_pqc_unknown_algorithm_tag_vector() {
    run_signature_vector("sig-pqc-003-unknown-algorithm-tag");
}

#[test]
fn sig_pqc_missing_classical_pairing_vector() {
    run_signature_vector("sig-pqc-004-missing-classical-pairing");
}

#[test]
fn sig_pqc_duplicate_invalid_first_valid_second_vector() {
    run_signature_vector("sig-pqc-005-duplicate-invalid-first-valid-second");
}

#[test]
fn sig_pqc_malformed_base64_vector() {
    run_signature_vector("sig-pqc-006-malformed-base64");
}

#[test]
fn sig_pqc_wrong_size_ml_dsa_signature_vector() {
    run_signature_vector("sig-pqc-007-wrong-size-ml-dsa-signature");
}

#[test]
fn sig_pqc_unknown_tag_then_valid_vector() {
    run_signature_vector("sig-pqc-008-unknown-tag-then-valid");
}

#[test]
fn decode_sig_pqc_rejects_unknown_tag_vector() {
    // Belt-and-suspenders: confirm the decode step itself (not just
    // verify_hybrid) rejects the unknown-tag vector, matching the RFC's
    // claim that an unrecognized algorithm tag is "rejected cleanly."
    let vector = load("sig-pqc-003-unknown-algorithm-tag");
    let sig_pqc_line = vector["sig_pqc_lines"][0]
        .as_str()
        .unwrap()
        .strip_prefix("Sig-PQC: ")
        .unwrap();
    assert!(keys::decode_sig_pqc(sig_pqc_line).is_err());
}

#[test]
fn decode_sig_pqc_rejects_malformed_base64_vector() {
    let vector = load("sig-pqc-006-malformed-base64");
    let sig_pqc_line = vector["sig_pqc_lines"][0]
        .as_str()
        .unwrap()
        .strip_prefix("Sig-PQC: ")
        .unwrap();
    assert!(keys::decode_sig_pqc(sig_pqc_line).is_err());
}

#[test]
fn decode_sig_pqc_rejects_wrong_size_vector() {
    let vector = load("sig-pqc-007-wrong-size-ml-dsa-signature");
    let sig_pqc_line = vector["sig_pqc_lines"][0]
        .as_str()
        .unwrap()
        .strip_prefix("Sig-PQC: ")
        .unwrap();
    let err = keys::decode_sig_pqc(sig_pqc_line).unwrap_err();
    assert!(err.to_string().contains("expected exactly"));
}
