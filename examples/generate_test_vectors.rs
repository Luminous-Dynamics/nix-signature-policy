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
use nix_signature_policy::keys::{self, SecretKey};
use nix_signature_policy::narinfo::NarInfo;
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

fn sample_narinfo() -> NarInfo {
    NarInfo {
        store_path: "/nix/store/00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
        nar_hash: "sha256:0hbgkq56i09xjh7jkm3z1lwgbrhwazkyab7mw108m0fp0f59dj48".to_string(),
        nar_size: 1654112,
        references: vec![
            "00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
        ],
        ..Default::default()
    }
}

fn write_fingerprint_vectors(dir: &Path) {
    write_fingerprint_vector(
        dir,
        "fingerprint-001-with-references",
        "Real narinfo (bash-5.2p37, fetched from cache.nixos.org 2026-07-10) \
         with two references, one of them a self-reference, already in \
         canonical (sorted) order. Verified separately (see narinfo.rs \
         tests) to match Nix's own ValidPathInfo::fingerprint() by \
         successfully checking the real cache.nixos.org Ed25519 signature \
         against it.",
        &sample_narinfo(),
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

    // Real Nix stores references in a std::set<StorePath> (sorted by plain
    // string comparison on the basename) and always computes the
    // fingerprint from that canonical order -- verified directly against
    // src/libstore/include/nix/store/path-info.hh, which documents
    // ValidPathInfo::fingerprint() as using "the sorted references". A
    // narinfo whose References: text happens to list them in a different
    // order must still produce the IDENTICAL fingerprint. This was a real,
    // previously-untested gap in this prototype: every prior fixture
    // happened to already be canonically ordered.
    let shuffled = NarInfo {
        references: vec![
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
            "00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
        ],
        ..sample_narinfo()
    };
    let canonical_fp = sample_narinfo().fingerprint().unwrap();
    let shuffled_fp = shuffled.fingerprint().unwrap();
    assert_eq!(
        canonical_fp, shuffled_fp,
        "generator's own sanity check: shuffled references must still produce the canonical fingerprint"
    );
    write_fingerprint_vector(
        dir,
        "fingerprint-003-shuffled-references",
        "Same narinfo as fingerprint-001, but References: lists the same \
         two paths in the OPPOSITE order. expected_fingerprint is \
         identical to fingerprint-001's -- a conformant implementation \
         must canonicalize (sort) references before computing the \
         fingerprint, not trust the narinfo text's order.",
        &shuffled,
    );

    let duplicated = NarInfo {
        references: vec![
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
            "00zrahbb32nzawrmv9sjxn36h7qk9vrs-bash-5.2p37".to_string(),
            "q4wq65gl3r8fy746v9bbwgx4gzn0r2kl-glibc-2.40-66".to_string(),
        ],
        ..sample_narinfo()
    };
    assert_eq!(
        canonical_fp,
        duplicated.fingerprint().unwrap(),
        "duplicate references must collapse to StorePathSet semantics"
    );
    write_fingerprint_vector(
        dir,
        "fingerprint-004-duplicate-references",
        "Same logical reference set as fingerprint-001, but one reference \
         is repeated and the input order is shuffled. A conformant \
         implementation must model Nix's StorePathSet semantics: sort and \
         deduplicate before fingerprinting.",
        &duplicated,
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
    let info = sample_narinfo();
    let fingerprint = info.fingerprint().unwrap();
    let sig = key.signer.sign(fingerprint.as_bytes());

    let sig_line = format!("{}:{}", key.name, B64.encode(sig.ed25519));
    let sig_pqc_line = keys::encode_sig_pqc(&key.name, &sig.ml_dsa);

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
        std::slice::from_ref(&sig_line),
        std::slice::from_ref(&sig_pqc_line),
        true,
    );

    let corrupted_pqc = flip_a_char(&sig_pqc_line);
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
        std::slice::from_ref(&sig_line),
        std::slice::from_ref(&corrupted_pqc),
        false,
    );

    let unknown_tag_pqc = set_tag_byte(&sig_pqc_line, 99);
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
        std::slice::from_ref(&sig_line),
        std::slice::from_ref(&unknown_tag_pqc),
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
        &[],
        std::slice::from_ref(&sig_pqc_line),
        false,
    );

    write_signature_vector(
        dir,
        "sig-pqc-005-duplicate-invalid-first-valid-second",
        "TWO Sig-PQC: entries under the same key name: the first is \
         corrupted, the second is genuinely valid (and two Sig: entries, \
         same pattern). A first-match-only implementation would wrongly \
         reject this narinfo; a conformant one tries every same-keyname \
         Sig:/Sig-PQC: pairing and succeeds if ANY pair verifies -- \
         matching Nix's own any-of-N-signatures trust model.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        &[flip_ed25519_byte(&sig_line), sig_line.clone()],
        &[corrupted_pqc.clone(), sig_pqc_line.clone()],
        true,
    );

    let malformed_base64 = format!("{}:{}", key.name, "not-valid-base64!!!@@@###");
    write_signature_vector(
        dir,
        "sig-pqc-006-malformed-base64",
        "Sig-PQC:'s value is not valid base64 at all (as opposed to \
         well-formed-but-wrong-length or wrong-tag). Must be rejected at \
         decode time with a clean error, not panic or silently treat it \
         as empty.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        std::slice::from_ref(&sig_line),
        &[malformed_base64],
        false,
    );

    let mut truncated_ml_dsa = sig.ml_dsa.clone();
    truncated_ml_dsa.truncate(100); // real ML-DSA-65 signatures are 3309 bytes
    let wrong_size_pqc = keys::encode_sig_pqc(&key.name, &truncated_ml_dsa);
    write_signature_vector(
        dir,
        "sig-pqc-007-wrong-size-ml-dsa-signature",
        "Sig-PQC:'s tag byte and base64 are both well-formed, but the \
         ML-DSA payload is truncated to 100 bytes instead of the real \
         ML-DSA-65 length of 3309 bytes. Must be rejected at the codec \
         boundary (decode_sig_pqc) with a specific length-mismatch error, \
         not deferred silently to the crypto backend.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        std::slice::from_ref(&sig_line),
        &[wrong_size_pqc],
        false,
    );

    write_signature_vector(
        dir,
        "sig-pqc-008-unknown-tag-then-valid",
        "TWO Sig-PQC: entries under the same key name: the first carries \
         an algorithm tag (250) this scheme does not define (simulating a \
         future algorithm an older implementation wouldn't recognize), the \
         second is genuinely valid ML-DSA-65. The unrecognized-tag entry \
         must be skipped as a failed candidate, not abort verification of \
         the rest of the list -- this is the crux of forward compatibility.",
        &info,
        &fingerprint,
        &key.name,
        &ed25519_pub_b64,
        &ml_dsa_pub_b64,
        std::slice::from_ref(&sig_line),
        &[set_tag_byte(&sig_pqc_line, 250), sig_pqc_line.clone()],
        true,
    );
}

/// Flip one base64 character well past any header bytes, preserving decoded
/// length -- corrupts content without changing size.
fn flip_a_char(line: &str) -> String {
    let mut s = line.to_string();
    let mid = s.len() - 10;
    let bytes = unsafe { s.as_bytes_mut() };
    bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
    s
}

/// Flip the first byte of a `Sig:` line's raw Ed25519 signature (not the
/// key name prefix), preserving length.
fn flip_ed25519_byte(sig_line: &str) -> String {
    let (name, b64) = sig_line.split_once(':').unwrap();
    let mut raw = B64.decode(b64).unwrap();
    raw[0] ^= 0xFF;
    format!("{name}:{}", B64.encode(raw))
}

/// Overwrite a `Sig-PQC:` line's leading algorithm-tag byte.
fn set_tag_byte(sig_pqc_line: &str, tag: u8) -> String {
    let (name, b64) = sig_pqc_line.split_once(':').unwrap();
    let mut raw = B64.decode(b64).unwrap();
    raw[0] = tag;
    format!("{name}:{}", B64.encode(raw))
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
    sig_lines: &[String],
    sig_pqc_lines: &[String],
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
        "sig_lines": sig_lines.iter().map(|v| format!("Sig: {v}")).collect::<Vec<_>>(),
        "sig_pqc_lines": sig_pqc_lines.iter().map(|v| format!("Sig-PQC: {v}")).collect::<Vec<_>>(),
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
