use std::fs;
use std::path::Path;

use nix_signature_policy::conformance::load_case;
use nix_signature_policy::evidence::{
    AttestationStatus, EvidenceBundle, EvidenceFailureCode, EvidenceVerificationOptions,
    SourceBindingStatus, bundle_from_conformance_case, to_pretty_json, verify_bundle,
};
use nix_signature_policy::keys::SecretKey;

const VECTOR: &str = "policy-vectors/adapter-parity/semantic-hybrid-valid.json";

#[test]
fn committed_vector_exports_and_replays_offline() {
    let path = Path::new(VECTOR);
    let bytes = fs::read(path).unwrap();
    let case = load_case(path).unwrap();
    let bundle = bundle_from_conformance_case(&case, VECTOR, &bytes, None).unwrap();

    let serialized = to_pretty_json(&bundle).unwrap();
    let reparsed: EvidenceBundle = serde_json::from_str(&serialized).unwrap();
    assert_eq!(bundle, reparsed);

    let report = verify_bundle(
        &reparsed,
        EvidenceVerificationOptions {
            source_artifact: Some(&bytes),
            require_source_artifact: true,
            ..EvidenceVerificationOptions::default()
        },
    );
    assert!(report.success, "{report:#?}");
    assert_eq!(report.source_binding, SourceBindingStatus::Valid);
    assert_eq!(report.attestation, AttestationStatus::Absent);
}

#[test]
fn source_binding_detects_the_wrong_vector() {
    let path = Path::new(VECTOR);
    let bytes = fs::read(path).unwrap();
    let case = load_case(path).unwrap();
    let bundle = bundle_from_conformance_case(&case, VECTOR, &bytes, None).unwrap();

    let report = verify_bundle(
        &bundle,
        EvidenceVerificationOptions {
            source_artifact: Some(b"different source bytes"),
            require_source_artifact: true,
            ..EvidenceVerificationOptions::default()
        },
    );
    assert!(!report.success);
    assert_eq!(report.source_binding, SourceBindingStatus::Mismatch);
    assert!(
        report
            .failure_codes
            .contains(&EvidenceFailureCode::SourceArtifactMismatch)
    );
}

#[test]
fn hybrid_attestation_is_bound_to_the_payload_digest() {
    let path = Path::new(VECTOR);
    let bytes = fs::read(path).unwrap();
    let case = load_case(path).unwrap();
    let signer = SecretKey::generate("evidence-1");
    let trusted = signer.public();
    let mut bundle = bundle_from_conformance_case(&case, VECTOR, &bytes, Some(&signer)).unwrap();

    let valid = verify_bundle(
        &bundle,
        EvidenceVerificationOptions {
            trusted_attestation_key: Some(&trusted),
            require_attestation: true,
            ..EvidenceVerificationOptions::default()
        },
    );
    assert!(valid.success, "{valid:#?}");

    let replacement = if bundle.payload_sha256.starts_with('0') {
        "1"
    } else {
        "0"
    };
    bundle.payload_sha256.replace_range(0..1, replacement);
    let invalid = verify_bundle(
        &bundle,
        EvidenceVerificationOptions {
            trusted_attestation_key: Some(&trusted),
            require_attestation: true,
            ..EvidenceVerificationOptions::default()
        },
    );
    assert!(!invalid.success);
    assert!(
        invalid
            .failure_codes
            .contains(&EvidenceFailureCode::InvalidPayloadDigest)
    );
}
