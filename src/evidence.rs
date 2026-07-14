//! Deterministic, replayable policy-decision evidence bundles.
//!
//! An evidence bundle records the exact normalized policy inputs and resulting
//! decision, binds them with a SHA-256 payload digest, and may carry an optional
//! hybrid Ed25519+ML-DSA-65 producer attestation. The offline verifier never
//! trusts the serialized decision: it canonicalizes the inputs, re-runs the
//! policy evaluator, and requires the recomputed decision to match exactly.
//!
//! # Assurance boundary
//!
//! Version 1 is a **policy replay** format. Candidate cryptographic verification
//! outcomes are inputs to the bundle; the verifier does not re-parse original
//! wire signatures or independently repeat their cryptographic verification.
//! An optional producer attestation authenticates who emitted the evidence, but
//! cannot make a dishonest producer's candidate observations true. Future
//! evidence kinds may add transport-specific cryptographic replay material.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::conformance::ConformanceCase;
use crate::hybrid::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, HybridSignature, HybridVerifyingKeys,
    ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN,
};
use crate::keys::{PublicKey, SecretKey};
use crate::policy::{
    EvaluationContext, PolicyDecision, SignatureCandidate, SignaturePolicy, TrustedKey,
    canonicalize_policy, evaluate_policy_with_context,
};

/// Current evidence envelope and payload schema version.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;
/// Defensive maximum accepted evidence-file size.
pub const MAX_EVIDENCE_BYTES: u64 = 8 * 1024 * 1024;
/// Domain separator for optional producer attestations.
const ATTESTATION_DOMAIN: &[u8] = b"nix-pqc-cache-proxy/policy-evidence/v1\0";
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// The level of assurance carried by this evidence format.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAssurance {
    /// Re-evaluates normalized policy inputs but trusts candidate verification
    /// outcomes as observations supplied by the producer.
    PolicyReplay,
}

/// Stable description of the implementation that produced the bundle.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProducer {
    pub implementation: String,
    pub version: String,
}

/// Binding to the source artifact from which the policy evidence was derived.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSource {
    pub kind: String,
    pub identifier: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub adapter: String,
}

/// Canonical policy-decision payload covered by `payload_sha256`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidencePayload {
    pub schema_version: u32,
    pub assurance: EvidenceAssurance,
    pub producer: EvidenceProducer,
    pub source: EvidenceSource,
    pub evaluation_time: i64,
    /// Highest policy epoch committed by the verifier when this evidence was produced.
    pub minimum_policy_epoch: u64,
    pub policy: SignaturePolicy,
    pub trusted_keys: Vec<TrustedKey>,
    pub candidates: Vec<SignatureCandidate>,
    pub decision: PolicyDecision,
}

/// Optional hybrid attestation over the canonical payload digest.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAttestation {
    pub algorithm: String,
    pub key_name: String,
    pub ed25519_public_key_base64: String,
    pub ml_dsa_65_public_key_base64: String,
    pub ed25519_signature_base64: String,
    pub ml_dsa_65_signature_base64: String,
}

/// Self-contained evidence envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    pub bundle_schema_version: u32,
    pub payload_sha256: String,
    pub payload: EvidencePayload,
    #[serde(default)]
    pub attestation: Option<EvidenceAttestation>,
}

/// Machine-readable offline-verification failure codes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFailureCode {
    UnsupportedSchema,
    InvalidPayloadStructure,
    InvalidPayloadDigest,
    NonCanonicalPayload,
    DecisionMismatch,
    MissingAttestation,
    InvalidAttestation,
    UntrustedAttestation,
    MissingSourceArtifact,
    SourceArtifactMismatch,
}

/// Status of an optional source-artifact binding check.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SourceBindingStatus {
    NotChecked,
    Valid,
    Missing,
    Mismatch,
}

/// Status of an optional producer attestation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AttestationStatus {
    Absent,
    ValidSelfContained,
    ValidTrusted,
    Invalid,
    Untrusted,
}

/// Complete result of offline evidence verification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVerificationReport {
    pub report_schema_version: u32,
    pub success: bool,
    pub payload_structure_valid: bool,
    pub payload_digest_valid: bool,
    pub payload_is_canonical: bool,
    pub decision_reproduced: bool,
    pub source_binding: SourceBindingStatus,
    pub attestation: AttestationStatus,
    pub failure_codes: BTreeSet<EvidenceFailureCode>,
    pub recomputed_decision: PolicyDecision,
}

/// Options controlling offline evidence verification.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvidenceVerificationOptions<'a> {
    pub trusted_attestation_key: Option<&'a PublicKey>,
    pub source_artifact: Option<&'a [u8]>,
    pub require_attestation: bool,
    pub require_source_artifact: bool,
}

/// Build deterministic evidence from one conformance vector.
///
/// The vector's transport adapter is normalized before it enters the payload.
/// Policy clauses, group requirements, trusted keys, and candidates are then
/// sorted into a canonical order and the decision is recomputed over that
/// order. Repeated calls with the same source identifier, case bytes, and
/// policy inputs produce an identical payload and payload digest. Optional
/// attestation bytes are outside that digest and follow the signing
/// implementation's determinism guarantees.
pub fn bundle_from_conformance_case(
    case: &ConformanceCase,
    source_identifier: impl Into<String>,
    source_bytes: &[u8],
    signing_key: Option<&SecretKey>,
) -> Result<EvidenceBundle> {
    let candidates = case.input.normalize(&case.trusted_keys);
    let source = EvidenceSource {
        kind: "policy_conformance_vector".into(),
        identifier: source_identifier.into(),
        sha256: sha256_hex(source_bytes),
        size_bytes: source_bytes
            .len()
            .try_into()
            .map_err(|_| anyhow!("source artifact length does not fit in u64"))?,
        adapter: case.input.adapter_name().into(),
    };

    build_bundle(
        source,
        case.evaluation_time,
        case.minimum_policy_epoch,
        case.policy.clone(),
        case.trusted_keys.clone(),
        candidates,
        signing_key,
    )
}

/// Build an evidence bundle from already-normalized policy inputs.
pub fn build_bundle(
    source: EvidenceSource,
    evaluation_time: i64,
    minimum_policy_epoch: u64,
    mut policy: SignaturePolicy,
    mut trusted_keys: Vec<TrustedKey>,
    mut candidates: Vec<SignatureCandidate>,
    signing_key: Option<&SecretKey>,
) -> Result<EvidenceBundle> {
    canonicalize_policy(&mut policy);
    canonicalize_trusted_keys(&mut trusted_keys);
    canonicalize_candidates(&mut candidates);

    let decision = evaluate_policy_with_context(
        &policy,
        &trusted_keys,
        &candidates,
        EvaluationContext {
            evaluation_time,
            minimum_policy_epoch,
        },
    );
    let payload = EvidencePayload {
        schema_version: EVIDENCE_SCHEMA_VERSION,
        assurance: EvidenceAssurance::PolicyReplay,
        producer: EvidenceProducer {
            implementation: env!("CARGO_PKG_NAME").into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
        source,
        evaluation_time,
        minimum_policy_epoch,
        policy,
        trusted_keys,
        candidates,
        decision,
    };
    validate_payload_structure(&payload)?;
    let payload_sha256 = payload_digest_hex(&payload)?;
    let attestation = signing_key
        .map(|key| create_attestation(key, &payload_sha256))
        .transpose()?;

    Ok(EvidenceBundle {
        bundle_schema_version: EVIDENCE_SCHEMA_VERSION,
        payload_sha256,
        payload,
        attestation,
    })
}

/// Read one strict evidence bundle from disk.
pub fn load_bundle(path: &Path) -> Result<EvidenceBundle> {
    let metadata =
        fs::metadata(path).with_context(|| format!("reading evidence metadata {path:?}"))?;
    if metadata.len() > MAX_EVIDENCE_BYTES {
        bail!(
            "evidence bundle {path:?} is {} bytes, limit is {MAX_EVIDENCE_BYTES}",
            metadata.len()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("reading evidence bundle {path:?}"))?;
    parse_bundle(&bytes).with_context(|| format!("parsing evidence bundle {path:?}"))
}

/// Parse one strict evidence bundle from bytes.
pub fn parse_bundle(bytes: &[u8]) -> Result<EvidenceBundle> {
    if bytes.len() > MAX_EVIDENCE_BYTES as usize {
        bail!(
            "evidence bundle is {} bytes, limit is {MAX_EVIDENCE_BYTES}",
            bytes.len()
        );
    }
    serde_json::from_slice(bytes).context("parsing evidence bundle JSON")
}

/// Serialize a bundle as stable, human-reviewable JSON.
pub fn to_pretty_json(bundle: &EvidenceBundle) -> Result<String> {
    let mut text = serde_json::to_string_pretty(bundle)?;
    text.push('\n');
    Ok(text)
}

/// Verify a bundle's digest, canonical form, policy decision, optional source
/// binding, and optional hybrid producer attestation.
pub fn verify_bundle(
    bundle: &EvidenceBundle,
    options: EvidenceVerificationOptions<'_>,
) -> EvidenceVerificationReport {
    let mut failure_codes = BTreeSet::new();

    let schema_supported = bundle.bundle_schema_version == EVIDENCE_SCHEMA_VERSION
        && bundle.payload.schema_version == EVIDENCE_SCHEMA_VERSION;
    if !schema_supported {
        failure_codes.insert(EvidenceFailureCode::UnsupportedSchema);
    }

    let payload_structure_valid = validate_payload_structure(&bundle.payload).is_ok();
    if !payload_structure_valid {
        failure_codes.insert(EvidenceFailureCode::InvalidPayloadStructure);
    }

    let payload_digest_valid = payload_digest_hex(&bundle.payload)
        .is_ok_and(|digest| constant_time_eq(digest.as_bytes(), bundle.payload_sha256.as_bytes()));
    if !payload_digest_valid {
        failure_codes.insert(EvidenceFailureCode::InvalidPayloadDigest);
    }

    let canonical_payload = canonicalized_payload(&bundle.payload);
    let payload_is_canonical = canonical_payload == bundle.payload;
    if !payload_is_canonical {
        failure_codes.insert(EvidenceFailureCode::NonCanonicalPayload);
    }

    let recomputed_decision = evaluate_policy_with_context(
        &canonical_payload.policy,
        &canonical_payload.trusted_keys,
        &canonical_payload.candidates,
        EvaluationContext {
            evaluation_time: canonical_payload.evaluation_time,
            minimum_policy_epoch: canonical_payload.minimum_policy_epoch,
        },
    );
    let decision_reproduced = recomputed_decision == bundle.payload.decision;
    if !decision_reproduced {
        failure_codes.insert(EvidenceFailureCode::DecisionMismatch);
    }

    let source_binding = match options.source_artifact {
        Some(bytes) => {
            let size_matches = u64::try_from(bytes.len())
                .is_ok_and(|length| length == bundle.payload.source.size_bytes);
            let digest_matches = constant_time_eq(
                sha256_hex(bytes).as_bytes(),
                bundle.payload.source.sha256.as_bytes(),
            );
            if size_matches && digest_matches {
                SourceBindingStatus::Valid
            } else {
                failure_codes.insert(EvidenceFailureCode::SourceArtifactMismatch);
                SourceBindingStatus::Mismatch
            }
        }
        None if options.require_source_artifact => {
            failure_codes.insert(EvidenceFailureCode::MissingSourceArtifact);
            SourceBindingStatus::Missing
        }
        None => SourceBindingStatus::NotChecked,
    };

    let attestation = verify_attestation(
        bundle.attestation.as_ref(),
        &bundle.payload_sha256,
        options.trusted_attestation_key,
        options.require_attestation,
        &mut failure_codes,
    );

    EvidenceVerificationReport {
        report_schema_version: 1,
        success: schema_supported
            && payload_structure_valid
            && payload_digest_valid
            && payload_is_canonical
            && decision_reproduced
            && !matches!(
                source_binding,
                SourceBindingStatus::Missing | SourceBindingStatus::Mismatch
            )
            && !matches!(
                attestation,
                AttestationStatus::Invalid | AttestationStatus::Untrusted
            )
            && failure_codes.is_empty(),
        payload_structure_valid,
        payload_digest_valid,
        payload_is_canonical,
        decision_reproduced,
        source_binding,
        attestation,
        failure_codes,
        recomputed_decision,
    }
}

fn verify_attestation(
    attestation: Option<&EvidenceAttestation>,
    payload_sha256: &str,
    trusted_key: Option<&PublicKey>,
    require_attestation: bool,
    failure_codes: &mut BTreeSet<EvidenceFailureCode>,
) -> AttestationStatus {
    let Some(attestation) = attestation else {
        if require_attestation || trusted_key.is_some() {
            failure_codes.insert(EvidenceFailureCode::MissingAttestation);
        }
        return AttestationStatus::Absent;
    };

    let verified = decode_and_verify_attestation(attestation, payload_sha256);
    let Ok((keys, _signature)) = verified else {
        failure_codes.insert(EvidenceFailureCode::InvalidAttestation);
        return AttestationStatus::Invalid;
    };

    if let Some(trusted) = trusted_key {
        if trusted.name != attestation.key_name
            || trusted.keys.ed25519 != keys.ed25519
            || trusted.keys.ml_dsa != keys.ml_dsa
        {
            failure_codes.insert(EvidenceFailureCode::UntrustedAttestation);
            return AttestationStatus::Untrusted;
        }
        AttestationStatus::ValidTrusted
    } else {
        AttestationStatus::ValidSelfContained
    }
}

fn create_attestation(key: &SecretKey, payload_sha256: &str) -> Result<EvidenceAttestation> {
    crate::keys::validate_key_name(&key.name).context("evidence signing key name is invalid")?;
    let digest = decode_sha256_hex(payload_sha256)?;
    let message = attestation_message(&key.name, &digest);
    let signature = key.signer.sign(&message);
    let public = key.public();
    Ok(EvidenceAttestation {
        algorithm: "ed25519+ml-dsa-65".into(),
        key_name: key.name.clone(),
        ed25519_public_key_base64: B64.encode(public.keys.ed25519),
        ml_dsa_65_public_key_base64: B64.encode(public.keys.ml_dsa),
        ed25519_signature_base64: B64.encode(signature.ed25519),
        ml_dsa_65_signature_base64: B64.encode(signature.ml_dsa),
    })
}

fn decode_and_verify_attestation(
    attestation: &EvidenceAttestation,
    payload_sha256: &str,
) -> Result<(HybridVerifyingKeys, HybridSignature)> {
    if attestation.algorithm != "ed25519+ml-dsa-65" {
        bail!("unsupported evidence attestation algorithm");
    }
    crate::keys::validate_key_name(&attestation.key_name)
        .context("evidence attestation key name is invalid")?;

    let ed_key = B64
        .decode(&attestation.ed25519_public_key_base64)
        .context("decoding evidence Ed25519 public key")?;
    let ed25519: [u8; ED25519_PUBLIC_KEY_LEN] = ed_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("evidence Ed25519 public key has wrong length"))?;
    let ml_dsa = B64
        .decode(&attestation.ml_dsa_65_public_key_base64)
        .context("decoding evidence ML-DSA public key")?;
    if ml_dsa.len() != ML_DSA_65_PUBLIC_KEY_LEN {
        bail!("evidence ML-DSA public key has wrong length");
    }

    let ed_sig = B64
        .decode(&attestation.ed25519_signature_base64)
        .context("decoding evidence Ed25519 signature")?;
    let ed25519_signature: [u8; ED25519_SIGNATURE_LEN] = ed_sig
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("evidence Ed25519 signature has wrong length"))?;
    let ml_dsa_signature = B64
        .decode(&attestation.ml_dsa_65_signature_base64)
        .context("decoding evidence ML-DSA signature")?;
    if ml_dsa_signature.len() != ML_DSA_65_SIGNATURE_LEN {
        bail!("evidence ML-DSA signature has wrong length");
    }

    let keys = HybridVerifyingKeys { ed25519, ml_dsa };
    let signature = HybridSignature {
        ed25519: ed25519_signature,
        ml_dsa: ml_dsa_signature,
    };
    let digest = decode_sha256_hex(payload_sha256)?;
    crate::hybrid::verify(
        &keys,
        &attestation_message(&attestation.key_name, &digest),
        &signature,
    )
    .context("verifying evidence hybrid attestation")?;
    Ok((keys, signature))
}

fn canonicalized_payload(payload: &EvidencePayload) -> EvidencePayload {
    let mut canonical = payload.clone();
    canonicalize_policy(&mut canonical.policy);
    canonicalize_trusted_keys(&mut canonical.trusted_keys);
    canonicalize_candidates(&mut canonical.candidates);
    canonical.decision = evaluate_policy_with_context(
        &canonical.policy,
        &canonical.trusted_keys,
        &canonical.candidates,
        EvaluationContext {
            evaluation_time: canonical.evaluation_time,
            minimum_policy_epoch: canonical.minimum_policy_epoch,
        },
    );
    canonical
}

fn canonicalize_trusted_keys(keys: &mut [TrustedKey]) {
    keys.sort_by(|left, right| {
        (
            left.key_id.as_str(),
            left.key_name.as_str(),
            left.algorithm.as_str(),
            left.signer_identity.as_str(),
            left.authority.as_str(),
            left.custody_domain.as_str(),
        )
            .cmp(&(
                right.key_id.as_str(),
                right.key_name.as_str(),
                right.algorithm.as_str(),
                right.signer_identity.as_str(),
                right.authority.as_str(),
                right.custody_domain.as_str(),
            ))
    });
}

fn canonicalize_candidates(candidates: &mut [SignatureCandidate]) {
    candidates.sort_by(|left, right| {
        (
            left.key_name.as_str(),
            left.algorithm.as_str(),
            left.signature_id.as_str(),
            left.verification,
        )
            .cmp(&(
                right.key_name.as_str(),
                right.algorithm.as_str(),
                right.signature_id.as_str(),
                right.verification,
            ))
    });
}

fn validate_payload_structure(payload: &EvidencePayload) -> Result<()> {
    if payload.producer.implementation.trim().is_empty()
        || payload.producer.version.trim().is_empty()
    {
        bail!("evidence producer implementation and version must be non-empty");
    }
    validate_payload_source(&payload.source)
}

fn validate_payload_source(source: &EvidenceSource) -> Result<()> {
    if source.kind.trim().is_empty()
        || source.identifier.trim().is_empty()
        || source.adapter.trim().is_empty()
    {
        bail!("evidence source kind, identifier, and adapter must be non-empty");
    }
    decode_sha256_hex(&source.sha256).context("evidence source has invalid SHA-256 digest")?;
    if source.sha256.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("evidence source SHA-256 digest must use lowercase hexadecimal");
    }
    Ok(())
}

fn payload_digest_hex(payload: &EvidencePayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload).context("serializing canonical evidence payload")?;
    Ok(sha256_hex(&bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    encode_hex(&digest)
}

fn decode_sha256_hex(text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("expected exactly 64 hexadecimal SHA-256 characters");
    }
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        out[index] = (high << 4) | low;
    }
    Ok(out)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => bail!("invalid hexadecimal character"),
    }
}

fn attestation_message(key_name: &str, digest: &[u8; 32]) -> Vec<u8> {
    let key_name_bytes = key_name.as_bytes();
    let key_name_len = u32::try_from(key_name_bytes.len())
        .expect("validated evidence key names are bounded to 128 bytes");
    let mut message = Vec::with_capacity(
        ATTESTATION_DOMAIN.len() + std::mem::size_of::<u32>() + key_name_bytes.len() + digest.len(),
    );
    message.extend_from_slice(ATTESTATION_DOMAIN);
    message.extend_from_slice(&key_name_len.to_be_bytes());
    message.extend_from_slice(key_name_bytes);
    message.extend_from_slice(digest);
    message
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (left, right)| {
            difference | (*left ^ *right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::policy::{
        AlgorithmDefinition, Decision, FamilyDefinition, FamilyStatus, GroupDefinition,
        GroupPredicate, GroupRequirement, PolicyClause, SignatureCandidate, VerificationOutcome,
    };

    fn requirement(group: &str) -> GroupRequirement {
        GroupRequirement {
            group: group.into(),
            min_distinct_identities: 1,
            min_distinct_families: 0,
            min_distinct_authorities: 0,
            min_distinct_custody_domains: 0,
        }
    }

    fn test_inputs() -> (
        EvidenceSource,
        SignaturePolicy,
        Vec<TrustedKey>,
        Vec<SignatureCandidate>,
    ) {
        let source_bytes = b"fixture";
        let source = EvidenceSource {
            kind: "test_fixture".into(),
            identifier: "fixture.json".into(),
            sha256: sha256_hex(source_bytes),
            size_bytes: source_bytes.len() as u64,
            adapter: "semantic".into(),
        };
        let policy = SignaturePolicy {
            policy_id: "hybrid".into(),
            version: 1,
            epoch: 1,
            previous_policy_hash: None,
            active_from: None,
            expires_at: None,
            max_signature_observations: 128,
            max_signature_candidates: 32,
            family_registry: vec![
                FamilyDefinition {
                    family: "elliptic_curve".into(),
                    status: FamilyStatus::Enabled,
                },
                FamilyDefinition {
                    family: "lattice".into(),
                    status: FamilyStatus::Enabled,
                },
            ],
            algorithm_registry: vec![
                AlgorithmDefinition {
                    algorithm: "ml-dsa-65".into(),
                    family: "lattice".into(),
                    assurance_class: "post_quantum".into(),
                },
                AlgorithmDefinition {
                    algorithm: "ed25519".into(),
                    family: "elliptic_curve".into(),
                    assurance_class: "classical".into(),
                },
            ],
            group_definitions: vec![
                GroupDefinition {
                    group: "post-quantum".into(),
                    predicate: GroupPredicate {
                        allowed_assurance_classes: BTreeSet::from(["post_quantum".into()]),
                        ..GroupPredicate::default()
                    },
                },
                GroupDefinition {
                    group: "classical".into(),
                    predicate: GroupPredicate {
                        allowed_assurance_classes: BTreeSet::from(["classical".into()]),
                        ..GroupPredicate::default()
                    },
                },
            ],
            accept_if_any: vec![PolicyClause {
                clause_id: "required".into(),
                required_groups: vec![requirement("post-quantum"), requirement("classical")],
                relations: Vec::new(),
                active_from: None,
                active_until: None,
            }],
        };
        let trusted = vec![
            TrustedKey {
                key_id: "pq".into(),
                key_name: "cache".into(),
                signer_identity: "owner".into(),
                algorithm: "ml-dsa-65".into(),
                roles: BTreeSet::from(["cache-signing".into()]),
                authority: "owner".into(),
                custody_domain: "pq-domain".into(),
                revoked: false,
                valid_from: None,
                valid_until: None,
            },
            TrustedKey {
                key_id: "ed".into(),
                key_name: "cache".into(),
                signer_identity: "owner".into(),
                algorithm: "ed25519".into(),
                roles: BTreeSet::from(["cache-signing".into()]),
                authority: "owner".into(),
                custody_domain: "ed-domain".into(),
                revoked: false,
                valid_from: None,
                valid_until: None,
            },
        ];
        let candidates = vec![
            SignatureCandidate {
                key_name: "cache".into(),
                algorithm: "ml-dsa-65".into(),
                signature_id: "pq-sig".into(),
                verification: VerificationOutcome::Valid,
            },
            SignatureCandidate {
                key_name: "cache".into(),
                algorithm: "ed25519".into(),
                signature_id: "ed-sig".into(),
                verification: VerificationOutcome::Valid,
            },
        ];
        (source, policy, trusted, candidates)
    }

    #[test]
    fn repeated_unsigned_builds_are_byte_identical() {
        let (source, policy, trusted, candidates) = test_inputs();
        let first = build_bundle(
            source.clone(),
            0,
            0,
            policy.clone(),
            trusted.clone(),
            candidates.clone(),
            None,
        )
        .unwrap();
        let second = build_bundle(source, 0, 0, policy, trusted, candidates, None).unwrap();
        assert_eq!(
            to_pretty_json(&first).unwrap(),
            to_pretty_json(&second).unwrap()
        );
        assert_eq!(first.payload.decision.decision, Decision::Accept);
    }

    #[test]
    fn offline_verifier_rejects_a_tampered_decision() {
        let (source, policy, trusted, candidates) = test_inputs();
        let mut bundle = build_bundle(source, 0, 0, policy, trusted, candidates, None).unwrap();
        bundle.payload.decision.decision = Decision::Refuse;
        bundle.payload_sha256 = payload_digest_hex(&bundle.payload).unwrap();

        let report = verify_bundle(&bundle, EvidenceVerificationOptions::default());
        assert!(!report.success);
        assert!(
            report
                .failure_codes
                .contains(&EvidenceFailureCode::NonCanonicalPayload)
        );
        assert!(
            report
                .failure_codes
                .contains(&EvidenceFailureCode::DecisionMismatch)
        );
    }

    #[test]
    fn signed_bundle_verifies_against_the_expected_key() {
        let signer = SecretKey::generate("evidence-1");
        let trusted = signer.public();
        let (source, policy, trusted_keys, candidates) = test_inputs();
        let bundle = build_bundle(
            source,
            0,
            0,
            policy,
            trusted_keys,
            candidates,
            Some(&signer),
        )
        .unwrap();

        let report = verify_bundle(
            &bundle,
            EvidenceVerificationOptions {
                trusted_attestation_key: Some(&trusted),
                source_artifact: Some(b"fixture"),
                require_attestation: true,
                require_source_artifact: true,
            },
        );
        assert!(report.success);
        assert_eq!(report.attestation, AttestationStatus::ValidTrusted);
        assert_eq!(report.source_binding, SourceBindingStatus::Valid);
    }

    #[test]
    fn attestation_key_name_is_covered_by_the_signature() {
        let signer = SecretKey::generate("evidence-1");
        let (source, policy, trusted_keys, candidates) = test_inputs();
        let mut bundle = build_bundle(
            source,
            0,
            0,
            policy,
            trusted_keys,
            candidates,
            Some(&signer),
        )
        .unwrap();
        bundle.attestation.as_mut().unwrap().key_name = "renamed-1".into();

        let report = verify_bundle(
            &bundle,
            EvidenceVerificationOptions {
                require_attestation: true,
                ..EvidenceVerificationOptions::default()
            },
        );
        assert!(!report.success);
        assert_eq!(report.attestation, AttestationStatus::Invalid);
    }

    #[test]
    fn wrong_attestation_trust_anchor_is_rejected() {
        let signer = SecretKey::generate("evidence-1");
        let wrong = SecretKey::generate("evidence-2").public();
        let (source, policy, trusted_keys, candidates) = test_inputs();
        let bundle = build_bundle(
            source,
            0,
            0,
            policy,
            trusted_keys,
            candidates,
            Some(&signer),
        )
        .unwrap();

        let report = verify_bundle(
            &bundle,
            EvidenceVerificationOptions {
                trusted_attestation_key: Some(&wrong),
                require_attestation: true,
                ..EvidenceVerificationOptions::default()
            },
        );
        assert!(!report.success);
        assert_eq!(report.attestation, AttestationStatus::Untrusted);
    }
}
