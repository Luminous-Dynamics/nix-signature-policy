//! Real-fixture interoperability tests for `raw_evidence.rs`.
//!
//! Complements `src/raw_evidence.rs`'s own unit tests (which cover the
//! per-outcome matrix -- valid/invalid/malformed, both encodings, unknown
//! key/algorithm, duplicate registry names, oversized batches -- using
//! self-generated crypto for speed and determinism). This file's job is
//! specifically what those unit tests cannot do: exercise the adapter
//! against **real bytes produced by a real, independently-built Nix**
//! (`DeterminateSystems/nix-src#449`, commit
//! `6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6`), captured in
//! `tests/fixtures/determinate-nix-449/` -- see that directory's
//! `PROVENANCE.md` for the exact commands and build record.

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use nix_signature_policy::narinfo::NarInfo;
use nix_signature_policy::policy::VerificationOutcome;
use nix_signature_policy::raw_evidence::{
    PublicKeyEncoding, RawEvidenceError, VerificationKeyEntry, verify_raw_evidence,
};

fn fixture_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/determinate-nix-449")
        .join(relative)
}

fn read_fixture(relative: &str) -> String {
    fs::read_to_string(fixture_path(relative))
        .unwrap_or_else(|e| panic!("reading fixture {relative}: {e}"))
}

/// A real `key-name:base64` line as emitted by `nix key
/// convert-secret-to-public`, with no surrounding whitespace.
fn public_key_line(relative: &str) -> (String, String) {
    let line = read_fixture(relative);
    let (name, b64) = line
        .trim()
        .split_once(':')
        .unwrap_or_else(|| panic!("{relative} is not a valid key-name:base64 line"));
    (name.to_string(), b64.to_string())
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Real `.narinfo` from `nix copy --to file://...`, and the two real
/// verification keys, each under its own distinct key name (the pattern
/// confirmed to actually work -- see "same-name collision" tests below for
/// the pattern confirmed NOT to work in real Nix today).
struct DistinctNameFixture {
    narinfo: NarInfo,
    ed25519_key: VerificationKeyEntry,
    ml_dsa_65_key: VerificationKeyEntry,
}

fn load_distinct_name_fixture() -> DistinctNameFixture {
    let narinfo_text = read_fixture("interop-fixture-2.narinfo");
    let narinfo = NarInfo::parse(&narinfo_text).expect("parse real narinfo");

    let (ed_name, ed_b64) = public_key_line("verification-key-ed25519.pub");
    let (ml_name, ml_b64) = public_key_line("verification-key-ml-dsa-65-spki-der.pub");

    DistinctNameFixture {
        narinfo,
        ed25519_key: VerificationKeyEntry {
            key_name: ed_name,
            algorithm: "ed25519".to_string(),
            encoding: PublicKeyEncoding::Raw,
            public_key_base64: ed_b64,
        },
        ml_dsa_65_key: VerificationKeyEntry {
            key_name: ml_name,
            algorithm: "ml-dsa-65".to_string(),
            encoding: PublicKeyEncoding::SpkiDer,
            public_key_base64: ml_b64,
        },
    }
}

#[test]
fn real_narinfo_fingerprint_matches_known_value() {
    let fixture = load_distinct_name_fixture();
    let fingerprint = fixture.narinfo.fingerprint().expect("fingerprint");
    assert_eq!(
        fingerprint,
        "1;/nix/store/31ahsdff5bd9pk77n2avvys6zdxbrknh-interop-fixture-2;\
         sha256:17w50rmznwp0qfq5k8x0987j3i6sw5ryjp52qcrr0jpf7gsf35qb;128;"
    );
}

#[test]
fn real_determinate_ed25519_and_ml_dsa_65_both_verify_with_distinct_key_names() {
    let fixture = load_distinct_name_fixture();
    let fingerprint = fixture.narinfo.fingerprint().expect("fingerprint");
    let registry = [fixture.ed25519_key.clone(), fixture.ml_dsa_65_key.clone()];

    let candidates =
        verify_raw_evidence(fingerprint.as_bytes(), &fixture.narinfo.sigs, &registry).unwrap();

    assert_eq!(
        candidates.len(),
        2,
        "narinfo should carry exactly 2 Sig: lines"
    );
    for candidate in &candidates {
        assert_eq!(
            candidate.verification,
            VerificationOutcome::Valid,
            "candidate {candidate:?} should verify against real Determinate Nix signatures"
        );
    }
    let algorithms: std::collections::BTreeSet<_> =
        candidates.iter().map(|c| c.algorithm.as_str()).collect();
    assert_eq!(
        algorithms,
        ["ed25519", "ml-dsa-65"].into_iter().collect(),
        "both algorithms should resolve from the registry, never from the wire entry itself"
    );
}

#[test]
fn real_determinate_signature_tampering_is_invalid_not_malformed() {
    let fixture = load_distinct_name_fixture();
    let fingerprint = fixture.narinfo.fingerprint().expect("fingerprint");

    // Take the real ed25519 Sig: entry and flip one byte of the decoded
    // signature -- proves real crypto (not just self-generated fixtures)
    // rejects tampering, rather than merely accepting anything that parses.
    let real_entry = fixture
        .narinfo
        .sigs
        .iter()
        .find(|s| s.starts_with(&format!("{}:", fixture.ed25519_key.key_name)))
        .expect("real ed25519 Sig: entry present")
        .clone();
    let (name, sig_b64) = real_entry.split_once(':').unwrap();
    let mut sig_bytes = b64_decode(sig_b64);
    sig_bytes[0] ^= 0xFF;
    let tampered_entry = format!("{name}:{}", b64_encode(&sig_bytes));

    let registry = [fixture.ed25519_key.clone()];
    let candidates =
        verify_raw_evidence(fingerprint.as_bytes(), &[tampered_entry], &registry).unwrap();

    assert_eq!(candidates[0].verification, VerificationOutcome::Invalid);
}

#[test]
fn real_determinate_mixed_batch_bad_entries_never_block_the_valid_one() {
    // The "row 10" scenario, corrected for the real wire format: real
    // narinfo Sig: entries never carry an algorithm tag, so there is no
    // "unknown algorithm tag" to place directly on an entry. The
    // equivalent realistic failure modes are (a) a raw signature
    // referencing a verification-key record whose configured algorithm is
    // unsupported, and (b) an unregistered key name -- both must produce a
    // deterministic Malformed observation, never panic, and never prevent
    // a different, genuinely valid entry in the same batch from verifying.
    let fixture = load_distinct_name_fixture();
    let fingerprint = fixture.narinfo.fingerprint().expect("fingerprint");

    let real_ed25519_entry = fixture
        .narinfo
        .sigs
        .iter()
        .find(|s| s.starts_with(&format!("{}:", fixture.ed25519_key.key_name)))
        .expect("real ed25519 Sig: entry present")
        .clone();

    let unsupported_algorithm_key = VerificationKeyEntry {
        key_name: "unsupported-algo-key".to_string(),
        algorithm: "sphincs+".to_string(), // not dispatched by verify_against_key
        encoding: PublicKeyEncoding::Raw,
        public_key_base64: b64_encode(&[0u8; 32]),
    };
    let unsupported_algorithm_entry = format!(
        "{}:{}",
        unsupported_algorithm_key.key_name,
        b64_encode(&[0u8; 64])
    );
    let unregistered_key_entry = format!("nobody-registered-this-name:{}", b64_encode(&[0u8; 64]));

    let registry = [fixture.ed25519_key.clone(), unsupported_algorithm_key];
    let entries = [
        real_ed25519_entry,
        unsupported_algorithm_entry,
        unregistered_key_entry,
    ];

    let candidates = verify_raw_evidence(fingerprint.as_bytes(), &entries, &registry).unwrap();
    assert_eq!(candidates.len(), 3);
    assert_eq!(
        candidates[0].verification,
        VerificationOutcome::Valid,
        "the real valid entry must not be affected by the other two malformed entries"
    );
    assert_eq!(candidates[1].verification, VerificationOutcome::Malformed);
    assert_eq!(candidates[2].verification, VerificationOutcome::Malformed);
}

// --- Same-name collision: a real, reproducible Nix limitation ---
//
// See tests/fixtures/determinate-nix-449/PROVENANCE.md's "Same-name
// collision" section: signing one store path with an Ed25519 key and an
// ML-DSA-65 key that share the *identical* `--key-name` produces a narinfo
// real Nix itself cannot correctly dual-trust (`nix store verify
// --sigs-needed 2` fails, deterministically, regardless of argument
// order). These tests show this adapter handles that same input two ways:
// reject the ambiguous configuration outright (preferred), or -- if only
// one of the two same-named keys ends up registered, mirroring what real
// Nix effectively does internally -- fail safe rather than silently
// mis-verify a signature under the wrong algorithm.

fn load_same_name_collision_keys() -> (String, VerificationKeyEntry, VerificationKeyEntry) {
    let (ed_name, ed_b64) = public_key_line("same-name-collision/ed25519.pub");
    let (ml_name, ml_b64) = public_key_line("same-name-collision/ml-dsa-65-spki-der.pub");
    assert_eq!(
        ed_name, ml_name,
        "fixture is specifically the same-name case"
    );

    let ed_key = VerificationKeyEntry {
        key_name: ed_name.clone(),
        algorithm: "ed25519".to_string(),
        encoding: PublicKeyEncoding::Raw,
        public_key_base64: ed_b64,
    };
    let ml_key = VerificationKeyEntry {
        key_name: ml_name,
        algorithm: "ml-dsa-65".to_string(),
        encoding: PublicKeyEncoding::SpkiDer,
        public_key_base64: ml_b64,
    };
    (ed_name, ed_key, ml_key)
}

fn load_same_name_collision_signatures() -> (String, String) {
    let json_text = read_fixture("same-name-collision/pathinfo.json");
    let json: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    let entry = json.as_object().unwrap().values().next().unwrap();
    let sigs: Vec<String> = entry["signatures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(sigs.len(), 2);

    // Distinguish which is which by decoded length (64 = Ed25519, 3309 =
    // ML-DSA-65) -- the same disambiguation real Nix itself effectively
    // relies on internally, since the key-name string alone cannot tell
    // them apart (see PROVENANCE.md).
    let mut ed25519_entry = None;
    let mut ml_dsa_entry = None;
    for sig in sigs {
        let (_, b64) = sig.split_once(':').unwrap();
        match b64_decode(b64).len() {
            64 => ed25519_entry = Some(sig),
            3309 => ml_dsa_entry = Some(sig),
            other => panic!("unexpected decoded signature length {other}"),
        }
    }
    (ed25519_entry.unwrap(), ml_dsa_entry.unwrap())
}

#[test]
fn same_name_collision_registry_is_rejected_as_duplicate_config() {
    let (_, ed_key, ml_key) = load_same_name_collision_keys();
    let registry = [ed_key, ml_key.clone()];

    let result = verify_raw_evidence(b"irrelevant fingerprint", &[], &registry);
    assert_eq!(
        result.unwrap_err(),
        RawEvidenceError::DuplicateVerificationKeyName(ml_key.key_name)
    );
}

#[test]
fn same_name_collision_with_only_ed25519_key_registered_ml_dsa_entry_fails_safe() {
    // Mirrors what real Nix effectively does when both keys share a name
    // (only one survives internally) -- except here it's an explicit
    // adapter-level registry choice, not a silent internal collision. The
    // property under test: the ML-DSA-65 entry (3309 real bytes) run
    // through Ed25519 dispatch (which requires an exact 64-byte signature)
    // must fail safe as Malformed -- never panic, never silently succeed,
    // and never be confused with the registered key's own algorithm. No
    // real .narinfo was exported for this fixture (only pathinfo.json --
    // see PROVENANCE.md), so a fixed placeholder message is used; the
    // Ed25519 entry's exact outcome (Invalid, since it won't verify
    // against a message it wasn't signed over) is incidental, only the
    // ML-DSA entry's Malformed outcome is the point of this test.
    let (_, ed_key, _) = load_same_name_collision_keys();
    let (ed25519_entry, ml_dsa_entry) = load_same_name_collision_signatures();

    let registry = [ed_key];
    let entries = [ed25519_entry, ml_dsa_entry];
    let candidates = verify_raw_evidence(b"any fixed message", &entries, &registry).unwrap();

    assert_eq!(candidates.len(), 2);
    assert_eq!(
        candidates[0].verification,
        VerificationOutcome::Invalid,
        "real 64-byte Ed25519 signature over the wrong message: cryptographically \
         impossible to accidentally verify, so this must be Invalid"
    );
    assert_eq!(
        candidates[1].verification,
        VerificationOutcome::Malformed,
        "real 3309-byte ML-DSA-65 signature dispatched through the single \
         registered Ed25519 key: wrong length, must fail safe as Malformed, \
         never silently accepted under the wrong algorithm"
    );
}
