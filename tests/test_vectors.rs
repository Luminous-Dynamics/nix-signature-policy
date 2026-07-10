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
    let keys = mycelix_crypto::hybrid_sig::HybridVerifyingKeys { ed25519, ml_dsa };

    let mut info = info;
    if let Some(sig_line) = vector["sig_line"].as_str() {
        info.sigs
            .push(sig_line.strip_prefix("Sig: ").unwrap().to_string());
    }
    let sig_pqc_line = vector["sig_pqc_line"].as_str().unwrap();
    info.sig_pqc
        .push(sig_pqc_line.strip_prefix("Sig-PQC: ").unwrap().to_string());

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
fn decode_sig_pqc_rejects_unknown_tag_vector() {
    // Belt-and-suspenders: confirm the decode step itself (not just
    // verify_hybrid) rejects the unknown-tag vector, matching the RFC's
    // claim that an unrecognized algorithm tag is "rejected cleanly."
    let vector = load("sig-pqc-003-unknown-algorithm-tag");
    let sig_pqc_line = vector["sig_pqc_line"]
        .as_str()
        .unwrap()
        .strip_prefix("Sig-PQC: ")
        .unwrap();
    assert!(keys::decode_sig_pqc(sig_pqc_line).is_err());
}
