//! A provisional adapter: raw, literal narinfo `Sig:` entries
//! (`"keyname:base64"`, exactly Nix's real on-wire format -- see
//! [`crate::narinfo::parse_sig_entry`]) plus a canonical fingerprint,
//! verified into normalized [`SignatureCandidate`]s that the frozen
//! `core-v1` evaluator can consume unmodified.
//!
//! # Why this exists
//!
//! `core-v1`'s [`SignatureCandidate`] requires `verification:
//! VerificationOutcome` as caller-supplied input -- by design, `core-v1` is
//! representation-neutral and never touches raw cryptographic bytes (see
//! `policy_adapters.rs`'s own header comment: *"adapters consume fixture
//! observations, not untrusted production bytes... production wire parsers
//! remain responsible for... cryptographic verification"*). That means
//! `core-v1`/`nix-signature-authorize` alone is a **verified-observation
//! consumer**, not a **raw-evidence processor**: something upstream of it
//! must already have checked each signature before it reaches the
//! evaluator.
//!
//! Today's Nix cannot supply verified ML-DSA observations itself -- that
//! needs `NixOS/nix#15926` (or equivalent) to land first. This module is
//! the bridge for *current* Nix: it takes exactly what a real `.narinfo`
//! already carries and verifies each entry itself using this crate's own
//! vendored, algorithm-specific primitives
//! ([`crate::hybrid::verify_ed25519_only`], [`crate::hybrid::verify_ml_dsa_only`]),
//! and only then constructs [`SignatureCandidate`]s. `core-v1` itself is
//! never modified by this module.
//!
//! # No algorithm tag on the wire, by design
//!
//! Real narinfo `Sig:` entries are `"keyname:base64"` and nothing else --
//! confirmed directly against a real Determinate Nix build (see
//! `tests/fixtures/determinate-nix-449/`). There is no per-entry algorithm
//! field, and a raw signature entry cannot self-declare one: **the
//! [`VerificationKeyEntry`] registry -- trusted local configuration, not
//! wire input -- is the sole source of truth for which algorithm a claimed
//! key name means.** [`RawSignatureEntry`] therefore only carries a key
//! name and signature bytes, exactly like real `Sig:` lines.
//!
//! This is also why [`verify_raw_evidence`] requires **unique key names**
//! in `verification_keys`: real Nix cannot even reliably trust two
//! different algorithms sharing one key name today (confirmed empirically
//! -- `nix store verify --sigs-needed 2` fails, deterministically and
//! order-independently, when an Ed25519 and an ML-DSA-65 key are both
//! registered under the same name; see
//! `tests/fixtures/determinate-nix-449/PROVENANCE.md`'s "Same-name
//! collision" section). Requiring one verification key per name keeps
//! dispatch deterministic and mirrors that real-world constraint rather
//! than inventing a same-name multi-algorithm trust model Nix itself
//! doesn't support. Two keys for one *identity* (e.g. one publisher's
//! Ed25519 and ML-DSA-65 keys) should use two distinct key names, mapped
//! to the same identity/authority in policy metadata one layer up.
//!
//! # Stability
//!
//! Provisional, not part of `core-v1`. See `docs/RAW_EVIDENCE_ADAPTER.md`.
//! A future Nix with native multi-algorithm verification could supply
//! verified observations directly and skip this adapter entirely.

use std::collections::HashSet;

use ml_dsa::pkcs8::SubjectPublicKeyInfoRef;
use ml_dsa::{MlDsa65, VerifyingKey as MlVerifyingKey};
use sha2::{Digest, Sha256};

use crate::hybrid::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, ML_DSA_65_PUBLIC_KEY_LEN,
    ML_DSA_65_SIGNATURE_LEN, verify_ed25519_only, verify_ml_dsa_only,
};
use crate::narinfo::parse_sig_entry;
use crate::policy::{AlgorithmId, SignatureCandidate, VerificationOutcome};

/// Maximum raw signature entries accepted before verification, mirroring
/// `core-v1`'s existing bounds so this adapter cannot be used to smuggle in
/// unbounded work ahead of the evaluator's own limits.
pub const MAX_RAW_SIGNATURE_ENTRIES: usize = 128;

/// Bound on the diagnostic "claimed key name" text kept for an entry that
/// fails to parse even as `"name:base64"` -- purely for bounded, readable
/// diagnostics; never used for trust (see [`verify_one`]'s doc).
const MAX_CLAIMED_KEY_NAME_CHARS: usize = 128;

/// A raw, literal narinfo `Sig:` entry: `"keyname:base64"`, byte-for-byte
/// what a real `.narinfo` carries. No verification has happened yet; this
/// is untrusted input. Parsed with [`crate::narinfo::parse_sig_entry`].
pub type RawSignatureEntry = String;

/// How a [`VerificationKeyEntry`]'s public key bytes are encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PublicKeyEncoding {
    /// Fixed-length raw key bytes: this crate's own generated format
    /// ([`crate::hybrid::HybridSigner`]) and Ed25519's on-wire form
    /// (confirmed unwrapped from real Determinate Nix output too).
    Raw,
    /// X.509 SubjectPublicKeyInfo DER, observed from real
    /// `nix key convert-secret-to-public --key-type ml-dsa-65` output
    /// (Determinate Nix, OpenSSL-backed). Parsed with real ASN.1/SPKI
    /// decoding (`ml_dsa::pkcs8`), not a hand-rolled byte-offset strip.
    SpkiDer,
}

/// One trusted verification key: the sole source of truth for "what public
/// key, algorithm, and encoding does this key name mean." A signature
/// entry can *claim* any key name; it cannot assign itself an algorithm or
/// a public key -- only entries matching a registry key by name are ever
/// handed to a verifier, and the algorithm used is always the registry's,
/// never inferred from the wire bytes.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationKeyEntry {
    pub key_name: String,
    pub algorithm: AlgorithmId,
    pub encoding: PublicKeyEncoding,
    /// Base64-encoded key bytes in `encoding`'s form, matching
    /// `Sig:` lines' own base64 convention.
    pub public_key_base64: String,
}

/// Closed set of ways raw-evidence verification can fail before or during
/// dispatch. Distinct from [`VerificationOutcome::Malformed`], which is a
/// *per-signature* outcome fed into the evaluator; these are adapter-level
/// failures that refuse the whole request rather than one candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawEvidenceError {
    /// More entries than [`MAX_RAW_SIGNATURE_ENTRIES`] were supplied.
    TooManyEntries,
    /// `verification_keys` had two entries sharing a `key_name`. Rejected
    /// as invalid configuration rather than guessed at dispatch time --
    /// see the module doc's "no algorithm tag on the wire" section for why
    /// this must be deterministic up front.
    DuplicateVerificationKeyName(String),
}

/// Verify each `signatures` entry against `verification_keys` for the
/// given `fingerprint`, producing normalized [`SignatureCandidate`]s ready
/// for the unmodified `core-v1` evaluator. Never trusts a `verification`
/// value from the input -- every outcome is computed here. `signatures`
/// are literal `"keyname:base64"` narinfo `Sig:` entries.
pub fn verify_raw_evidence(
    fingerprint: &[u8],
    signatures: &[RawSignatureEntry],
    verification_keys: &[VerificationKeyEntry],
) -> Result<Vec<SignatureCandidate>, RawEvidenceError> {
    if signatures.len() > MAX_RAW_SIGNATURE_ENTRIES {
        return Err(RawEvidenceError::TooManyEntries);
    }

    let mut seen_names = HashSet::with_capacity(verification_keys.len());
    for key in verification_keys {
        if !seen_names.insert(key.key_name.as_str()) {
            return Err(RawEvidenceError::DuplicateVerificationKeyName(
                key.key_name.clone(),
            ));
        }
    }

    let candidates = signatures
        .iter()
        .map(|entry| verify_one(fingerprint, entry, verification_keys))
        .collect();
    Ok(candidates)
}

fn verify_one(
    fingerprint: &[u8],
    raw_entry: &str,
    verification_keys: &[VerificationKeyEntry],
) -> SignatureCandidate {
    let signature_id = signature_id(raw_entry);

    // A raw entry that doesn't even parse as "name:base64" has no key name
    // to resolve; keep a bounded, best-effort diagnostic label. This is
    // never a trust decision -- core-v1's evaluator drops every Malformed
    // candidate before it ever looks at key_name/algorithm (verified
    // directly against `policy.rs`'s evaluation loop).
    let (key_name, sig_bytes) = match parse_sig_entry(raw_entry) {
        Ok(parsed) => parsed,
        Err(_) => {
            return SignatureCandidate {
                key_name: claimed_key_name(raw_entry),
                algorithm: AlgorithmId::new(),
                signature_id,
                verification: VerificationOutcome::Malformed,
            };
        }
    };

    // The registry is the sole source of trust for which algorithm and
    // public key a claimed key name resolves to -- a wire entry cannot
    // assign itself either (see module doc).
    let matching_key = verification_keys
        .iter()
        .find(|key| key.key_name == key_name);

    let (algorithm, verification) = match matching_key {
        None => (AlgorithmId::new(), VerificationOutcome::Malformed),
        Some(key) => (
            key.algorithm.clone(),
            verify_against_key(key, fingerprint, &sig_bytes),
        ),
    };

    SignatureCandidate {
        key_name,
        algorithm,
        signature_id,
        verification,
    }
}

/// Decode `key`'s public key per its declared encoding, then dispatch to
/// the algorithm-specific verifier. Unknown algorithms, unsupported
/// encoding/algorithm pairs, and wrong-length keys/signatures are
/// `Malformed`, not a hard error -- matching the existing crate-wide
/// pattern (`keys::verify_hybrid`) that a malformed or unrecognized
/// candidate is dropped, never a reason to abort evaluation of a
/// different, valid candidate.
fn verify_against_key(
    key: &VerificationKeyEntry,
    message: &[u8],
    signature: &[u8],
) -> VerificationOutcome {
    let Some(encoded_public_key) = base64_decode(&key.public_key_base64) else {
        return VerificationOutcome::Malformed;
    };

    let raw_public_key = match (key.algorithm.as_str(), key.encoding) {
        (_, PublicKeyEncoding::Raw) => encoded_public_key,
        ("ml-dsa-65", PublicKeyEncoding::SpkiDer) => {
            match decode_ml_dsa_65_spki(&encoded_public_key) {
                Ok(raw) => raw,
                Err(()) => return VerificationOutcome::Malformed,
            }
        }
        // No other algorithm's SPKI-DER form is recognized today -- reject
        // explicitly rather than guess at an unobserved encoding.
        (_, PublicKeyEncoding::SpkiDer) => return VerificationOutcome::Malformed,
    };

    match key.algorithm.as_str() {
        "ed25519" => {
            let (Ok(public_key), Ok(sig)) = (
                <&[u8; ED25519_PUBLIC_KEY_LEN]>::try_from(raw_public_key.as_slice()),
                <&[u8; ED25519_SIGNATURE_LEN]>::try_from(signature),
            ) else {
                return VerificationOutcome::Malformed;
            };
            match verify_ed25519_only(public_key, message, sig) {
                Ok(()) => VerificationOutcome::Valid,
                Err(_) => VerificationOutcome::Invalid,
            }
        }
        "ml-dsa-65" => {
            if raw_public_key.len() != ML_DSA_65_PUBLIC_KEY_LEN
                || signature.len() != ML_DSA_65_SIGNATURE_LEN
            {
                return VerificationOutcome::Malformed;
            }
            match verify_ml_dsa_only(&raw_public_key, message, signature) {
                Ok(()) => VerificationOutcome::Valid,
                Err(_) => VerificationOutcome::Invalid,
            }
        }
        _ => VerificationOutcome::Malformed,
    }
}

/// Decode an ML-DSA-65 X.509 SubjectPublicKeyInfo DER blob into the raw
/// 1952-byte FIPS-204 key, using real ASN.1/SPKI parsing from the
/// `pkcs8`/`der`/`spki` crates `ml-dsa` itself already depends on (zero
/// new dependencies) -- not a hand-rolled fixed-offset byte slice. This
/// validates the ASN.1 structure, asserts the algorithm OID is exactly
/// ML-DSA-65, and rejects anything with trailing or malformed data via
/// `SubjectPublicKeyInfoRef`'s own strict DER decode.
fn decode_ml_dsa_65_spki(der_bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let spki = SubjectPublicKeyInfoRef::try_from(der_bytes).map_err(|_| ())?;
    let verifying_key = MlVerifyingKey::<MlDsa65>::try_from(spki).map_err(|_| ())?;
    Ok(verifying_key.encode().as_slice().to_vec())
}

/// Stable, content-addressed identity for a signature's raw bytes: exact
/// duplicates (byte-identical entry) share this ID, matching
/// `SignatureCandidate::signature_id`'s documented contract.
fn signature_id(raw_entry: &str) -> String {
    format!("{:x}", Sha256::digest(raw_entry.as_bytes()))
}

/// Best-effort, bounded label for an entry that couldn't even be split
/// into `(name, base64)` -- diagnostics only, see [`verify_one`].
fn claimed_key_name(raw_entry: &str) -> String {
    let name = raw_entry.split(':').next().unwrap_or(raw_entry);
    name.chars().take(MAX_CLAIMED_KEY_NAME_CHARS).collect()
}

fn base64_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::HybridSigner;

    fn key(
        name: &str,
        algorithm: &str,
        encoding: PublicKeyEncoding,
        public_key: &[u8],
    ) -> VerificationKeyEntry {
        VerificationKeyEntry {
            key_name: name.to_string(),
            algorithm: algorithm.to_string(),
            encoding,
            public_key_base64: b64(public_key),
        }
    }

    fn raw_key(name: &str, algorithm: &str, public_key: &[u8]) -> VerificationKeyEntry {
        key(name, algorithm, PublicKeyEncoding::Raw, public_key)
    }

    fn entry(name: &str, signature_base64: &str) -> RawSignatureEntry {
        format!("{name}:{signature_base64}")
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn valid_ed25519_signature_verifies() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let sig = signer.sign(message);

        let registry = [raw_key("cache", "ed25519", &keys.ed25519)];
        let entries = [entry("cache", &b64(&sig.ed25519))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].algorithm, "ed25519");
        assert_eq!(candidates[0].verification, VerificationOutcome::Valid);
    }

    #[test]
    fn valid_ml_dsa_signature_verifies_raw_encoding() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let sig = signer.sign(message);

        let registry = [raw_key("cache", "ml-dsa-65", &keys.ml_dsa)];
        let entries = [entry("cache", &b64(&sig.ml_dsa))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].verification, VerificationOutcome::Valid);
    }

    #[test]
    fn valid_ml_dsa_signature_verifies_spki_der_encoding() {
        use ml_dsa::pkcs8::EncodePublicKey as _;
        use ml_dsa::signature::{Keypair as _, Signer as _};
        use ml_dsa::{Generate as _, MlDsa65, SigningKey as MlSigningKey};

        let signing_key = MlSigningKey::<MlDsa65>::generate();
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let sig = signing_key.sign(message);

        let spki_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("encode SPKI DER")
            .to_vec();

        let registry = [key(
            "cache",
            "ml-dsa-65",
            PublicKeyEncoding::SpkiDer,
            &spki_der,
        )];
        let entries = [entry("cache", &b64(sig.encode().as_slice()))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].verification, VerificationOutcome::Valid);
    }

    #[test]
    fn spki_der_with_trailing_bytes_is_rejected() {
        use ml_dsa::pkcs8::EncodePublicKey as _;
        use ml_dsa::signature::{Keypair as _, Signer as _};
        use ml_dsa::{Generate as _, MlDsa65, SigningKey as MlSigningKey};

        let signing_key = MlSigningKey::<MlDsa65>::generate();
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let sig = signing_key.sign(message);

        let mut spki_der = signing_key
            .verifying_key()
            .to_public_key_der()
            .expect("encode SPKI DER")
            .to_vec();
        spki_der.push(0xAA); // trailing garbage byte after the valid DER structure

        let registry = [key(
            "cache",
            "ml-dsa-65",
            PublicKeyEncoding::SpkiDer,
            &spki_der,
        )];
        let entries = [entry("cache", &b64(sig.encode().as_slice()))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].verification, VerificationOutcome::Malformed);
    }

    #[test]
    fn spki_der_with_wrong_algorithm_oid_is_rejected() {
        use ml_dsa::pkcs8::EncodePublicKey as _;
        use ml_dsa::signature::Keypair as _;
        use ml_dsa::{Generate as _, MlDsa44, SigningKey as MlSigningKey};

        // A structurally valid SPKI DER blob, but for the wrong ML-DSA
        // parameter set (44, not 65) -- the OID assertion inside
        // decode_ml_dsa_65_spki (via ml_dsa's own SPKI TryFrom impl) must
        // catch this, not just a length check.
        let wrong_algo_key = MlSigningKey::<MlDsa44>::generate();
        let spki_der = wrong_algo_key
            .verifying_key()
            .to_public_key_der()
            .expect("encode SPKI DER")
            .to_vec();

        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let registry = [key(
            "cache",
            "ml-dsa-65",
            PublicKeyEncoding::SpkiDer,
            &spki_der,
        )];
        let entries = [entry("cache", &b64(&[0u8; ML_DSA_65_SIGNATURE_LEN]))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].verification, VerificationOutcome::Malformed);
    }

    #[test]
    fn tampered_signature_is_invalid_not_malformed() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let sig = signer.sign(message);
        let mut tampered = sig.ed25519;
        tampered[0] ^= 0xff;

        let registry = [raw_key("cache", "ed25519", &keys.ed25519)];
        let entries = [entry("cache", &b64(&tampered))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].verification, VerificationOutcome::Invalid);
    }

    #[test]
    fn signature_over_wrong_fingerprint_is_invalid() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let signed_message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let different_message = b"1;/nix/store/different;sha256:xyz;99;";
        let sig = signer.sign(signed_message);

        let registry = [raw_key("cache", "ed25519", &keys.ed25519)];
        let entries = [entry("cache", &b64(&sig.ed25519))];

        let candidates = verify_raw_evidence(different_message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].verification, VerificationOutcome::Invalid);
    }

    #[test]
    fn unknown_key_name_is_malformed_not_a_hard_error() {
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let entries = [entry("unregistered", &b64(&[0u8; 64]))];

        let candidates = verify_raw_evidence(message, &entries, &[]).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].verification, VerificationOutcome::Malformed);
    }

    #[test]
    fn unknown_algorithm_is_malformed() {
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";

        let registry = [raw_key("cache", "sphincs+", &[0u8; 32])];
        let entries = [entry("cache", &b64(&[0u8; 64]))];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].verification, VerificationOutcome::Malformed);
    }

    #[test]
    fn malformed_base64_is_malformed() {
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let registry = [raw_key("cache", "ed25519", &[0u8; ED25519_PUBLIC_KEY_LEN])];
        let entries = [entry("cache", "not valid base64!!!")];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].verification, VerificationOutcome::Malformed);
    }

    #[test]
    fn unparseable_entry_is_malformed_with_bounded_diagnostic_name() {
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        // No ':' separator at all -- can't even extract a claimed key name/base64.
        let entries = ["not-a-sig-entry-at-all".to_string()];

        let candidates = verify_raw_evidence(message, &entries, &[]).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].verification, VerificationOutcome::Malformed);
        assert_eq!(candidates[0].key_name, "not-a-sig-entry-at-all");
    }

    #[test]
    fn duplicate_signature_bytes_share_signature_id() {
        let signer = HybridSigner::generate();
        let keys = signer.verifying_keys();
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let sig = signer.sign(message);
        let encoded = b64(&sig.ed25519);

        let registry = [raw_key("cache", "ed25519", &keys.ed25519)];
        let entries = [entry("cache", &encoded), entry("cache", &encoded)];

        let candidates = verify_raw_evidence(message, &entries, &registry).unwrap();
        assert_eq!(candidates[0].signature_id, candidates[1].signature_id);
    }

    #[test]
    fn too_many_entries_is_rejected() {
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let entries: Vec<_> = (0..MAX_RAW_SIGNATURE_ENTRIES + 1)
            .map(|i| entry(&format!("key-{i}"), &b64(&[0u8; 64])))
            .collect();

        let result = verify_raw_evidence(message, &entries, &[]);
        assert_eq!(result.unwrap_err(), RawEvidenceError::TooManyEntries);
    }

    #[test]
    fn duplicate_verification_key_name_is_rejected_as_config_error() {
        let message = b"1;/nix/store/abc-foo;sha256:def;120;";
        let registry = [
            raw_key("cache", "ed25519", &[0u8; ED25519_PUBLIC_KEY_LEN]),
            key("cache", "ml-dsa-65", PublicKeyEncoding::SpkiDer, &[0u8; 64]),
        ];
        let entries: [RawSignatureEntry; 0] = [];

        let result = verify_raw_evidence(message, &entries, &registry);
        assert_eq!(
            result.unwrap_err(),
            RawEvidenceError::DuplicateVerificationKeyName("cache".to_string())
        );
    }

    // Real Determinate Nix (nix-src#449) interoperability -- against the
    // committed fixtures in tests/fixtures/determinate-nix-449/, including
    // the DER-wrapped ML-DSA-65 key -- lives in tests/raw_evidence_interop.rs,
    // not here, since it reads fixture files from disk.
}
