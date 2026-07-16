#![no_main]

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::policy::VerificationOutcome;
use nix_signature_policy::raw_evidence::{
    MAX_RAW_SIGNATURE_ENTRIES, MAX_VERIFICATION_KEYS, PublicKeyEncoding, RawEvidenceError,
    VerificationKeyEntry, verify_raw_evidence,
};

// Real bytes captured from a real, independently-built Nix
// (DeterminateSystems/nix-src#449, commit
// 6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6) -- see
// tests/fixtures/determinate-nix-449/PROVENANCE.md. Embedded via
// `include_str!` so this harness can never drift from the committed
// fixtures it's meant to be grounded in. Used as an always-present,
// known-good baseline: the point of this harness isn't just "does it
// crash" but "can fuzz-derived garbage ever suppress a genuinely valid
// real-world signature" -- a property that needs a real valid signature
// present in every run to even be testable.
const REAL_NARINFO: &str =
    include_str!("../../tests/fixtures/determinate-nix-449/interop-fixture-2.narinfo");
const REAL_ED25519_PUB_LINE: &str =
    include_str!("../../tests/fixtures/determinate-nix-449/verification-key-ed25519.pub");
const REAL_ML_DSA_65_PUB_LINE: &str = include_str!(
    "../../tests/fixtures/determinate-nix-449/verification-key-ml-dsa-65-spki-der.pub"
);
const REAL_FINGERPRINT: &[u8] = b"1;/nix/store/31ahsdff5bd9pk77n2avvys6zdxbrknh-interop-fixture-2;\
sha256:17w50rmznwp0qfq5k8x0987j3i6sw5ryjp52qcrr0jpf7gsf35qb;128;";

fn real_ed25519_entry() -> String {
    REAL_NARINFO
        .lines()
        .find_map(|line| line.strip_prefix("Sig: interop-cache-ed25519:"))
        .map(|b64| format!("interop-cache-ed25519:{b64}"))
        .expect("real narinfo fixture must carry the ed25519 Sig: line")
}

fn real_ml_dsa_65_entry() -> String {
    REAL_NARINFO
        .lines()
        .find_map(|line| line.strip_prefix("Sig: interop-cache-mldsa65:"))
        .map(|b64| format!("interop-cache-mldsa65:{b64}"))
        .expect("real narinfo fixture must carry the ml-dsa-65 Sig: line")
}

fn key_line_b64(line: &str) -> String {
    line.trim()
        .split_once(':')
        .expect("fixture key line must be name:base64")
        .1
        .to_string()
}

fn real_ed25519_key() -> VerificationKeyEntry {
    VerificationKeyEntry {
        key_name: "interop-cache-ed25519".to_string(),
        algorithm: "ed25519".to_string(),
        encoding: PublicKeyEncoding::Raw,
        public_key_base64: key_line_b64(REAL_ED25519_PUB_LINE),
    }
}

fn real_ml_dsa_65_key() -> VerificationKeyEntry {
    VerificationKeyEntry {
        key_name: "interop-cache-mldsa65".to_string(),
        algorithm: "ml-dsa-65".to_string(),
        encoding: PublicKeyEncoding::SpkiDer,
        public_key_base64: key_line_b64(REAL_ML_DSA_65_PUB_LINE),
    }
}

/// A tiny deterministic byte cursor over the fuzz input, used to derive
/// bounded, varied-but-reproducible structured data -- same style already
/// used by policy_evaluator.rs / policy_adapters.rs in this fuzz suite.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn byte(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn slice(&mut self, len: usize) -> &'a [u8] {
        let start = self.pos.min(self.data.len());
        let end = (start + len).min(self.data.len());
        self.pos = end;
        &self.data[start..end]
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("real SPKI fixture must be valid base64")
}

/// Derive a bounded, varied "noise" signature entry + matching (or
/// deliberately mismatching) verification-key entry from a few fuzz
/// bytes. Covers: malformed base64, wrong-length raw keys, corrupted SPKI
/// (bit-flipped OID region), unregistered key names, unsupported
/// algorithm tags.
fn derive_noise(cursor: &mut Cursor, index: usize) -> (String, VerificationKeyEntry) {
    let control = cursor.byte();
    let key_name = format!("fuzz-key-{index}");

    let algorithm = match control % 4 {
        0 => "ed25519",
        1 => "ml-dsa-65",
        2 => "sphincs+", // deliberately unsupported
        _ => "",         // deliberately empty/malformed
    };

    let (encoding, public_key_base64) = match control / 4 % 3 {
        0 => (PublicKeyEncoding::Raw, b64(cursor.slice(8))),
        1 => {
            // Corrupt a real SPKI blob at a byte offset inside its
            // algorithm-identifier/OID region (bytes 4..17 per
            // PROVENANCE.md's DER breakdown) -- usually produces a wrong
            // or malformed OID, exercising decode_ml_dsa_65_spki's
            // rejection path without hand-maintaining a second real SPKI
            // fixture. Decodes to real DER bytes first: mutating the
            // base64 *text* instead (an earlier version of this harness
            // did exactly that) doesn't correspond to any specific
            // decoded-byte offset, since base64 is a 6-bits-per-character
            // encoding -- one flipped character can smear across two
            // adjacent decoded bytes at a boundary this offset math never
            // accounted for.
            let mut corrupted = b64_decode(&key_line_b64(REAL_ML_DSA_65_PUB_LINE));
            if !corrupted.is_empty() {
                let offset = (4 + (cursor.byte() as usize % 13)) % corrupted.len();
                let flip = cursor.byte().max(1);
                if let Some(byte) = corrupted.get_mut(offset) {
                    *byte ^= flip;
                }
            }
            (PublicKeyEncoding::SpkiDer, b64(&corrupted))
        }
        _ => (PublicKeyEncoding::SpkiDer, b64(cursor.slice(6))), // too short to be valid SPKI
    };

    let signature_base64 = match control / 12 % 2 {
        0 => b64(cursor.slice(16)),
        _ => "not valid base64!!!".to_string(), // deliberately malformed
    };

    let entry_key_name = if control / 24 % 2 == 0 {
        key_name.clone() // will have a matching (if odd) registry entry
    } else {
        format!("unregistered-{index}") // deliberately no matching key
    };

    (
        format!("{entry_key_name}:{signature_base64}"),
        VerificationKeyEntry {
            key_name,
            algorithm: algorithm.to_string(),
            encoding,
            public_key_base64,
        },
    )
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let mode = cursor.byte() % 4;
    let noise_count = (cursor.byte() % 8) as usize;

    let mut signatures = vec![real_ed25519_entry(), real_ml_dsa_65_entry()];
    let mut verification_keys = vec![real_ed25519_key(), real_ml_dsa_65_key()];

    for i in 0..noise_count {
        let (entry, key) = derive_noise(&mut cursor, i);
        signatures.push(entry);
        verification_keys.push(key);
    }

    match mode {
        // Forced registry key-name collision: must fail as a
        // deterministic, whole-batch configuration error, never guessed
        // or silently resolved to one of the two.
        1 => {
            let mut colliding = real_ed25519_key();
            colliding.key_name = "interop-cache-mldsa65".to_string(); // collides with the real ML-DSA key's name
            verification_keys.push(colliding);

            let first = verify_raw_evidence(REAL_FINGERPRINT, &signatures, &verification_keys);
            let second = verify_raw_evidence(REAL_FINGERPRINT, &signatures, &verification_keys);
            assert_eq!(first, second, "must be deterministic");
            assert!(matches!(
                first,
                Err(RawEvidenceError::DuplicateVerificationKeyName(_))
            ));
        }
        // Forced over-bound batches: bounds must be enforced before any
        // expensive cryptographic work runs (proven by this branch never
        // hanging/timing out under the fuzzer, since the synthetic
        // vectors below are cheap to build but would be expensive to
        // actually verify one-by-one if the bound check were skipped).
        2 => {
            let oversized_signatures: Vec<String> = (0..MAX_RAW_SIGNATURE_ENTRIES + 1)
                .map(|i| format!("k{i}:{}", b64(&[0u8; 8])))
                .collect();
            let result =
                verify_raw_evidence(REAL_FINGERPRINT, &oversized_signatures, &verification_keys);
            assert_eq!(result, Err(RawEvidenceError::TooManyEntries));
        }
        3 => {
            let oversized_keys: Vec<VerificationKeyEntry> = (0..MAX_VERIFICATION_KEYS + 1)
                .map(|i| VerificationKeyEntry {
                    key_name: format!("k{i}"),
                    algorithm: "ed25519".to_string(),
                    encoding: PublicKeyEncoding::Raw,
                    public_key_base64: b64(&[0u8; 8]),
                })
                .collect();
            let result = verify_raw_evidence(REAL_FINGERPRINT, &signatures, &oversized_keys);
            assert_eq!(result, Err(RawEvidenceError::TooManyVerificationKeys));
        }
        // Ordinary mixed batch: real valid signatures alongside
        // fuzz-derived noise. The core invariant: no amount of malformed,
        // unknown, or unsupported noise may ever suppress or alter the
        // outcome of the two genuinely valid real entries.
        _ => {
            let first = verify_raw_evidence(REAL_FINGERPRINT, &signatures, &verification_keys);
            let second = verify_raw_evidence(REAL_FINGERPRINT, &signatures, &verification_keys);
            assert_eq!(first, second, "must be deterministic");

            let Ok(candidates) = first else {
                // Only reachable if noise happened to also collide two
                // registry key names -- itself a valid, already-covered
                // outcome (see mode 1); nothing further to assert here.
                return;
            };

            let real_ed25519 = candidates
                .iter()
                .find(|c| c.key_name == "interop-cache-ed25519" && c.algorithm == "ed25519")
                .expect("real ed25519 candidate must always be present");
            let real_ml_dsa = candidates
                .iter()
                .find(|c| c.key_name == "interop-cache-mldsa65" && c.algorithm == "ml-dsa-65")
                .expect("real ml-dsa-65 candidate must always be present");

            assert_eq!(
                real_ed25519.verification,
                VerificationOutcome::Valid,
                "real ed25519 signature must stay Valid regardless of surrounding noise"
            );
            assert_eq!(
                real_ml_dsa.verification,
                VerificationOutcome::Valid,
                "real ml-dsa-65 signature must stay Valid regardless of surrounding noise"
            );
        }
    }
});
