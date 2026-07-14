//! Compact trust-admission receipts.
//!
//! Receipts are deterministic audit records derived from the normalized Nix
//! integration request. They are intentionally smaller than policy-replay
//! evidence bundles: a receipt explains a decision and binds its policy, but
//! does not contain enough input material to independently re-run cryptographic
//! verification or policy evaluation.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::commitment::{CommitmentDomain, commitment_sha256};

use crate::integration::{
    AdmissionDecision, AdmissionReasonCode, AuthorizationRequest, BuiltInDecision, EnforcementMode,
    authorize,
};
use crate::policy::{FamilyId, IdentityId, ReasonCode, canonical_policy_sha256};
use crate::registry::{RegistryReasonCode, canonical_registry_sha256};

/// Current compact receipt schema version.
pub const TRUST_RECEIPT_SCHEMA_VERSION: u32 = 2;

/// Artifact identity covered by a receipt.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReceiptArtifact {
    /// Usually a Nix store path, narinfo URL, or another stable artifact ID.
    pub identifier: String,
    /// SHA-256 of the canonical fingerprint admitted by the verifier.
    pub canonical_fingerprint_sha256: String,
    /// Optional NAR hash copied from the authenticated metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nar_hash: Option<String>,
}

/// Canonical receipt payload covered by `payload_sha256`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustReceiptPayload {
    pub schema_version: u32,
    pub artifact: ReceiptArtifact,
    pub decision_time: i64,
    pub minimum_policy_epoch: u64,
    pub minimum_registry_epoch: u64,
    pub enforcement_mode: EnforcementMode,
    pub built_in_decision: BuiltInDecision,
    pub decision: AdmissionDecision,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_epoch: u64,
    pub policy_sha256: String,
    pub registry_id: String,
    pub registry_epoch: u64,
    pub registry_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub satisfied_clause: Option<String>,
    pub qualifying_identities: BTreeSet<IdentityId>,
    pub qualifying_families: BTreeSet<FamilyId>,
    pub qualifying_authorities: BTreeSet<String>,
    pub qualifying_custody_domains: BTreeSet<String>,
    pub policy_reason_codes: BTreeSet<ReasonCode>,
    pub admission_reason_codes: BTreeSet<AdmissionReasonCode>,
    pub registry_reason_codes: BTreeSet<RegistryReasonCode>,
}

/// Self-checking compact trust receipt.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustReceipt {
    pub receipt_schema_version: u32,
    pub payload_sha256: String,
    pub payload: TrustReceiptPayload,
}

/// Build a deterministic receipt by evaluating the normalized authorization
/// request and extracting the selected clause's witnesses.
pub fn build_trust_receipt(
    request: &AuthorizationRequest,
    artifact: ReceiptArtifact,
) -> Result<TrustReceipt> {
    validate_artifact(&artifact)?;
    let response = authorize(request);
    let policy_sha256 = canonical_policy_sha256(&request.policy)
        .context("hashing canonical authorization policy")?;
    let registry_sha256 = canonical_registry_sha256(&request.trust_registry)
        .context("hashing canonical trusted-key registry")?;

    let mut qualifying_identities = BTreeSet::new();
    let mut qualifying_families = BTreeSet::new();
    let mut qualifying_authorities = BTreeSet::new();
    let mut qualifying_custody_domains = BTreeSet::new();
    if let Some(clause_id) = &response.policy_decision.satisfied_clause {
        if let Some(clause) = response
            .policy_decision
            .clause_evaluations
            .iter()
            .find(|clause| &clause.clause_id == clause_id)
        {
            for group in &clause.groups {
                qualifying_identities.extend(group.signer_identities.iter().cloned());
                qualifying_families.extend(group.families.iter().cloned());
                qualifying_authorities.extend(group.authorities.iter().cloned());
                qualifying_custody_domains.extend(group.custody_domains.iter().cloned());
            }
        }
    }

    let payload = TrustReceiptPayload {
        schema_version: TRUST_RECEIPT_SCHEMA_VERSION,
        artifact,
        decision_time: request.evaluation_context.evaluation_time,
        minimum_policy_epoch: request.evaluation_context.minimum_policy_epoch,
        minimum_registry_epoch: request.evaluation_context.minimum_registry_epoch,
        enforcement_mode: request.enforcement_mode,
        built_in_decision: request.built_in_decision,
        decision: response.decision,
        policy_id: response.policy_decision.policy_id,
        policy_version: response.policy_decision.policy_version,
        policy_epoch: response.policy_decision.policy_epoch,
        policy_sha256,
        registry_id: response.registry_decision.registry_id,
        registry_epoch: response.registry_decision.registry_epoch,
        registry_sha256,
        satisfied_clause: response.policy_decision.satisfied_clause,
        qualifying_identities,
        qualifying_families,
        qualifying_authorities,
        qualifying_custody_domains,
        policy_reason_codes: response.policy_decision.reason_codes,
        admission_reason_codes: response.reason_codes,
        registry_reason_codes: response.registry_decision.reason_codes,
    };
    let payload_sha256 = payload_sha256(&payload)?;
    Ok(TrustReceipt {
        receipt_schema_version: TRUST_RECEIPT_SCHEMA_VERSION,
        payload_sha256,
        payload,
    })
}

/// Verify schema consistency, artifact digest syntax, and the receipt payload
/// digest. This verifies receipt integrity, not the original signatures.
pub fn verify_trust_receipt(receipt: &TrustReceipt) -> Result<()> {
    if receipt.receipt_schema_version != TRUST_RECEIPT_SCHEMA_VERSION
        || receipt.payload.schema_version != TRUST_RECEIPT_SCHEMA_VERSION
    {
        bail!("unsupported trust receipt schema version");
    }
    validate_artifact(&receipt.payload.artifact)?;
    if !is_lower_sha256(&receipt.payload.policy_sha256) {
        bail!("receipt policy_sha256 is not a lowercase SHA-256 digest");
    }
    if !is_lower_sha256(&receipt.payload.registry_sha256) {
        bail!("receipt registry_sha256 is not a lowercase SHA-256 digest");
    }
    if receipt.payload.registry_id.trim().is_empty() || receipt.payload.registry_epoch == 0 {
        bail!("receipt registry commitment is invalid");
    }
    let expected = payload_sha256(&receipt.payload)?;
    if expected != receipt.payload_sha256 {
        bail!("trust receipt payload digest mismatch");
    }
    Ok(())
}

/// Human-readable one-line explanation suitable for CLI and logs.
pub fn explain_trust_receipt(receipt: &TrustReceipt) -> Result<String> {
    verify_trust_receipt(receipt)?;
    let clause = receipt
        .payload
        .satisfied_clause
        .as_deref()
        .unwrap_or("none");
    Ok(format!(
        "{:?}: {} under policy {} v{} epoch {} and registry {} epoch {} ({:?}, clause {}, families [{}], identities [{}])",
        receipt.payload.decision,
        receipt.payload.artifact.identifier,
        receipt.payload.policy_id,
        receipt.payload.policy_version,
        receipt.payload.policy_epoch,
        receipt.payload.registry_id,
        receipt.payload.registry_epoch,
        receipt.payload.enforcement_mode,
        clause,
        receipt
            .payload
            .qualifying_families
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        receipt
            .payload
            .qualifying_identities
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
    ))
}

pub fn parse_trust_receipt(bytes: &[u8]) -> Result<TrustReceipt> {
    serde_json::from_slice(bytes).context("parsing trust receipt JSON")
}

pub fn to_pretty_json(receipt: &TrustReceipt) -> Result<String> {
    let mut text = serde_json::to_string_pretty(receipt)?;
    text.push('\n');
    Ok(text)
}

fn validate_artifact(artifact: &ReceiptArtifact) -> Result<()> {
    if artifact.identifier.trim().is_empty() {
        bail!("receipt artifact identifier is empty");
    }
    if !is_lower_sha256(&artifact.canonical_fingerprint_sha256) {
        bail!("canonical_fingerprint_sha256 is not a lowercase SHA-256 digest");
    }
    if artifact.nar_hash.as_deref().is_some_and(str::is_empty) {
        bail!("nar_hash must be omitted rather than empty");
    }
    Ok(())
}

fn payload_sha256(payload: &TrustReceiptPayload) -> Result<String> {
    let bytes = serde_json::to_vec(payload).context("serializing trust receipt payload")?;
    Ok(commitment_sha256(CommitmentDomain::ReceiptPayload, &bytes))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::integration::{
        AuthorizationRequest, BuiltInDecision, EnforcementMode, INTEGRATION_CONTRACT_VERSION,
        SerializableEvaluationContext,
    };
    use crate::policy::{
        AlgorithmDefinition, FamilyDefinition, FamilyStatus, GroupDefinition, GroupPredicate,
        GroupRequirement, PolicyClause, SignatureCandidate, SignaturePolicy, TrustedKey,
        VerificationOutcome,
    };
    use crate::registry::TrustRegistry;

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            contract_version: INTEGRATION_CONTRACT_VERSION,
            enforcement_mode: EnforcementMode::Authoritative,
            built_in_decision: BuiltInDecision::Accept,
            evaluation_context: SerializableEvaluationContext {
                evaluation_time: 100,
                minimum_policy_epoch: 1,
                minimum_registry_epoch: 1,
            },
            policy: SignaturePolicy {
                policy_id: "receipt-policy".into(),
                version: 1,
                epoch: 1,
                previous_policy_hash: None,
                active_from: None,
                expires_at: None,
                max_signature_observations: 128,
                max_signature_candidates: 32,
                family_registry: vec![FamilyDefinition {
                    family: "hash_based".into(),
                    status: FamilyStatus::Enabled,
                }],
                algorithm_registry: vec![AlgorithmDefinition {
                    algorithm: "slh-dsa-128s".into(),
                    family: "hash_based".into(),
                    assurance_class: "post_quantum".into(),
                }],
                group_definitions: vec![GroupDefinition {
                    group: "post-quantum".into(),
                    predicate: GroupPredicate {
                        allowed_assurance_classes: BTreeSet::from(["post_quantum".into()]),
                        ..GroupPredicate::default()
                    },
                }],
                accept_if_any: vec![PolicyClause {
                    clause_id: "required".into(),
                    required_groups: vec![GroupRequirement {
                        group: "post-quantum".into(),
                        min_distinct_identities: 1,
                        min_distinct_families: 1,
                        min_distinct_authorities: 0,
                        min_distinct_custody_domains: 0,
                    }],
                    relations: Vec::new(),
                    active_from: None,
                    active_until: None,
                }],
            },
            trust_registry: TrustRegistry {
                registry_id: "receipt-cache-keys".into(),
                epoch: 1,
                previous_registry_hash: None,
                trusted_keys: vec![TrustedKey {
                    key_id: "hash".into(),
                    key_name: "cache".into(),
                    signer_identity: "cache-owner".into(),
                    algorithm: "slh-dsa-128s".into(),
                    roles: BTreeSet::new(),
                    authority: "cache-owner".into(),
                    custody_domain: "offline-hsm".into(),
                    revoked: false,
                    valid_from: None,
                    valid_until: None,
                }],
            },
            candidates: vec![SignatureCandidate {
                key_name: "cache".into(),
                algorithm: "slh-dsa-128s".into(),
                signature_id: "hash-good".into(),
                verification: VerificationOutcome::Valid,
            }],
        }
    }

    fn artifact() -> ReceiptArtifact {
        ReceiptArtifact {
            identifier: "/nix/store/example-system".into(),
            canonical_fingerprint_sha256: "11".repeat(32),
            nar_hash: Some("sha256:example".into()),
        }
    }

    #[test]
    fn receipt_records_policy_and_qualifying_family() {
        let receipt = build_trust_receipt(&request(), artifact()).unwrap();
        verify_trust_receipt(&receipt).unwrap();
        assert_eq!(receipt.payload.decision, AdmissionDecision::Accept);
        assert!(receipt.payload.qualifying_families.contains("hash_based"));
        assert!(
            receipt
                .payload
                .qualifying_identities
                .contains("cache-owner")
        );
    }

    #[test]
    fn tampered_receipt_is_refused() {
        let mut receipt = build_trust_receipt(&request(), artifact()).unwrap();
        receipt.payload.policy_epoch = 2;
        assert!(verify_trust_receipt(&receipt).is_err());
    }

    #[test]
    fn repeated_receipts_are_deterministic() {
        let first = build_trust_receipt(&request(), artifact()).unwrap();
        let second = build_trust_receipt(&request(), artifact()).unwrap();
        assert_eq!(first, second);
    }
}
