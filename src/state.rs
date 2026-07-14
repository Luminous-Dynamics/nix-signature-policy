//! Persistent local rollback checkpoint for policy and trusted-key registry state.
//!
//! A monotonic epoch protects a client only when the client remembers the
//! highest state it has accepted. This module provides a small, deterministic,
//! self-checking file format rather than requiring a general database.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::commitment::{CommitmentDomain, commitment_sha256};

use crate::integration::{
    AuthorizationRequest, INTEGRATION_CONTRACT_VERSION, SerializableEvaluationContext,
};
use crate::policy::{canonical_policy_sha256, validate_policy_structure};
use crate::registry::{RegistryDecisionValue, canonical_registry_sha256, evaluate_trust_registry};

pub const TRUST_STATE_SCHEMA_VERSION: u32 = 1;

/// Highest locally committed trust state for one deployment domain.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustStateEntry {
    pub policy_id: String,
    pub policy_epoch: u64,
    pub policy_sha256: String,
    pub registry_id: String,
    pub registry_epoch: u64,
    pub registry_sha256: String,
}

/// Canonical payload protected by `payload_sha256`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustStatePayload {
    pub schema_version: u32,
    pub domains: BTreeMap<String, TrustStateEntry>,
}

/// Self-checking local state file.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustStateFile {
    pub state_schema_version: u32,
    pub payload_sha256: String,
    pub payload: TrustStatePayload,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrustStateError {
    #[error("trust domain is empty")]
    EmptyDomain,
    #[error("authorization request uses unsupported contract version {0}")]
    UnsupportedContractVersion(u32),
    #[error("authorization policy or trusted-key metadata is invalid")]
    InvalidPolicy,
    #[error("trusted-key registry is invalid")]
    InvalidRegistry,
    #[error("policy domain changed from {previous:?} to {next:?}")]
    PolicyDomainChanged { previous: String, next: String },
    #[error("registry domain changed from {previous:?} to {next:?}")]
    RegistryDomainChanged { previous: String, next: String },
    #[error("{component} epoch rolled back from {previous} to {next}")]
    EpochRollback {
        component: &'static str,
        previous: u64,
        next: u64,
    },
    #[error("{component} epoch {epoch} was reused with a different commitment")]
    SameEpochCommitmentChanged { component: &'static str, epoch: u64 },
    #[error(
        "{component} checkpoint must advance exactly one epoch; previous {previous}, next {next}"
    )]
    NonContiguousAdvance {
        component: &'static str,
        previous: u64,
        next: u64,
    },
    #[error("{component} successor does not bind the committed predecessor")]
    PredecessorMismatch { component: &'static str },
    #[error("neither policy nor registry advanced")]
    NoStateAdvance,
    #[error("trust-state file is invalid: {0}")]
    InvalidState(String),
    #[error("serializing canonical trust state failed: {0}")]
    Serialization(String),
}

/// Build a new state file containing one deployment domain.
pub fn initialize_trust_state(
    domain: &str,
    request: &AuthorizationRequest,
) -> Result<TrustStateFile, TrustStateError> {
    let entry = entry_from_request(request)?;
    let mut domains = BTreeMap::new();
    if domain.trim().is_empty() {
        return Err(TrustStateError::EmptyDomain);
    }
    domains.insert(domain.to_string(), entry);
    build_state_file(TrustStatePayload {
        schema_version: TRUST_STATE_SCHEMA_VERSION,
        domains,
    })
}

/// Advance one deployment domain by exactly one linked policy and/or registry
/// epoch. Unchanged components retain the same epoch and commitment.
pub fn advance_trust_state(
    state: &TrustStateFile,
    domain: &str,
    request: &AuthorizationRequest,
) -> Result<TrustStateFile, TrustStateError> {
    verify_trust_state(state)?;
    if domain.trim().is_empty() {
        return Err(TrustStateError::EmptyDomain);
    }
    let next = entry_from_request(request)?;
    let mut payload = state.payload.clone();
    if let Some(previous) = payload.domains.get(domain) {
        if previous.policy_id != next.policy_id {
            return Err(TrustStateError::PolicyDomainChanged {
                previous: previous.policy_id.clone(),
                next: next.policy_id.clone(),
            });
        }
        if previous.registry_id != next.registry_id {
            return Err(TrustStateError::RegistryDomainChanged {
                previous: previous.registry_id.clone(),
                next: next.registry_id.clone(),
            });
        }
        let policy_advanced = validate_component_advance(
            "policy",
            previous.policy_epoch,
            &previous.policy_sha256,
            next.policy_epoch,
            &next.policy_sha256,
            request.policy.previous_policy_hash.as_deref(),
        )?;
        let registry_advanced = validate_component_advance(
            "registry",
            previous.registry_epoch,
            &previous.registry_sha256,
            next.registry_epoch,
            &next.registry_sha256,
            request.trust_registry.previous_registry_hash.as_deref(),
        )?;
        if !policy_advanced && !registry_advanced {
            return Err(TrustStateError::NoStateAdvance);
        }
    }
    payload.domains.insert(domain.to_string(), next);
    build_state_file(payload)
}

/// Copy committed minimum epochs into an authorization request.
pub fn apply_trust_state(
    state: &TrustStateFile,
    domain: &str,
    request: &mut AuthorizationRequest,
) -> Result<(), TrustStateError> {
    verify_trust_state(state)?;
    let entry = state
        .payload
        .domains
        .get(domain)
        .ok_or_else(|| TrustStateError::InvalidState(format!("unknown domain {domain:?}")))?;
    if entry.policy_id != request.policy.policy_id {
        return Err(TrustStateError::PolicyDomainChanged {
            previous: entry.policy_id.clone(),
            next: request.policy.policy_id.clone(),
        });
    }
    if entry.registry_id != request.trust_registry.registry_id {
        return Err(TrustStateError::RegistryDomainChanged {
            previous: entry.registry_id.clone(),
            next: request.trust_registry.registry_id.clone(),
        });
    }
    request.evaluation_context.minimum_policy_epoch = entry.policy_epoch;
    request.evaluation_context.minimum_registry_epoch = entry.registry_epoch;
    Ok(())
}

/// Verify schema, digest, domain names, and commitment syntax.
pub fn verify_trust_state(state: &TrustStateFile) -> Result<(), TrustStateError> {
    if state.state_schema_version != TRUST_STATE_SCHEMA_VERSION
        || state.payload.schema_version != TRUST_STATE_SCHEMA_VERSION
    {
        return Err(TrustStateError::InvalidState(
            "unsupported schema version".into(),
        ));
    }
    if state.payload.domains.is_empty() {
        return Err(TrustStateError::InvalidState(
            "state contains no domains".into(),
        ));
    }
    for (domain, entry) in &state.payload.domains {
        if domain.trim().is_empty()
            || entry.policy_id.trim().is_empty()
            || entry.registry_id.trim().is_empty()
            || entry.policy_epoch == 0
            || entry.registry_epoch == 0
            || !is_lower_sha256(&entry.policy_sha256)
            || !is_lower_sha256(&entry.registry_sha256)
        {
            return Err(TrustStateError::InvalidState(format!(
                "invalid checkpoint for domain {domain:?}"
            )));
        }
    }
    let expected = payload_sha256(&state.payload)
        .map_err(|error| TrustStateError::Serialization(error.to_string()))?;
    if expected != state.payload_sha256 {
        return Err(TrustStateError::InvalidState(
            "payload digest mismatch".into(),
        ));
    }
    Ok(())
}

pub fn parse_trust_state(bytes: &[u8]) -> Result<TrustStateFile> {
    serde_json::from_slice(bytes).context("parsing trust-state JSON")
}

pub fn trust_state_to_pretty_json(state: &TrustStateFile) -> Result<String> {
    verify_trust_state(state).map_err(anyhow::Error::new)?;
    let mut text = serde_json::to_string_pretty(state)?;
    text.push('\n');
    Ok(text)
}

fn entry_from_request(request: &AuthorizationRequest) -> Result<TrustStateEntry, TrustStateError> {
    if request.contract_version != INTEGRATION_CONTRACT_VERSION {
        return Err(TrustStateError::UnsupportedContractVersion(
            request.contract_version,
        ));
    }
    if !validate_policy_structure(&request.policy, &request.trust_registry.trusted_keys) {
        return Err(TrustStateError::InvalidPolicy);
    }
    if evaluate_trust_registry(&request.trust_registry, 0).decision != RegistryDecisionValue::Accept
    {
        return Err(TrustStateError::InvalidRegistry);
    }
    let policy_sha256 = canonical_policy_sha256(&request.policy)
        .map_err(|error| TrustStateError::Serialization(error.to_string()))?;
    let registry_sha256 = canonical_registry_sha256(&request.trust_registry)
        .map_err(|error| TrustStateError::Serialization(error.to_string()))?;
    Ok(TrustStateEntry {
        policy_id: request.policy.policy_id.clone(),
        policy_epoch: request.policy.epoch,
        policy_sha256,
        registry_id: request.trust_registry.registry_id.clone(),
        registry_epoch: request.trust_registry.epoch,
        registry_sha256,
    })
}

fn validate_component_advance(
    component: &'static str,
    previous_epoch: u64,
    previous_hash: &str,
    next_epoch: u64,
    next_hash: &str,
    next_predecessor: Option<&str>,
) -> Result<bool, TrustStateError> {
    if next_epoch < previous_epoch {
        return Err(TrustStateError::EpochRollback {
            component,
            previous: previous_epoch,
            next: next_epoch,
        });
    }
    if next_epoch == previous_epoch {
        if next_hash != previous_hash {
            return Err(TrustStateError::SameEpochCommitmentChanged {
                component,
                epoch: next_epoch,
            });
        }
        return Ok(false);
    }
    if next_epoch != previous_epoch + 1 {
        return Err(TrustStateError::NonContiguousAdvance {
            component,
            previous: previous_epoch,
            next: next_epoch,
        });
    }
    if next_predecessor != Some(previous_hash) {
        return Err(TrustStateError::PredecessorMismatch { component });
    }
    Ok(true)
}

fn build_state_file(payload: TrustStatePayload) -> Result<TrustStateFile, TrustStateError> {
    let payload_sha256 = payload_sha256(&payload)
        .map_err(|error| TrustStateError::Serialization(error.to_string()))?;
    Ok(TrustStateFile {
        state_schema_version: TRUST_STATE_SCHEMA_VERSION,
        payload_sha256,
        payload,
    })
}

fn payload_sha256(payload: &TrustStatePayload) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(payload)?;
    Ok(commitment_sha256(
        CommitmentDomain::TrustStatePayload,
        &bytes,
    ))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Create a context containing only the checkpoint's committed minima.
pub fn committed_context(
    entry: &TrustStateEntry,
    evaluation_time: i64,
) -> SerializableEvaluationContext {
    SerializableEvaluationContext {
        evaluation_time,
        minimum_policy_epoch: entry.policy_epoch,
        minimum_registry_epoch: entry.registry_epoch,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::integration::{BuiltInDecision, EnforcementMode, INTEGRATION_CONTRACT_VERSION};
    use crate::policy::{
        AlgorithmDefinition, FamilyDefinition, FamilyStatus, GroupDefinition, GroupPredicate,
        GroupRequirement, PolicyClause, SignaturePolicy, TrustedKey,
    };
    use crate::registry::{TrustRegistry, canonical_registry_sha256};

    fn request() -> AuthorizationRequest {
        let key = TrustedKey {
            key_id: "release".into(),
            key_name: "cache".into(),
            signer_identity: "owner".into(),
            algorithm: "ed25519".into(),
            roles: BTreeSet::new(),
            authority: "owner".into(),
            custody_domain: "offline".into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        };
        AuthorizationRequest {
            contract_version: INTEGRATION_CONTRACT_VERSION,
            enforcement_mode: EnforcementMode::Authoritative,
            built_in_decision: BuiltInDecision::NotEvaluated,
            evaluation_context: SerializableEvaluationContext::default(),
            policy: SignaturePolicy {
                policy_id: "cache-policy".into(),
                version: 1,
                epoch: 1,
                previous_policy_hash: None,
                active_from: None,
                expires_at: None,
                max_signature_observations: 128,
                max_signature_candidates: 32,
                family_registry: vec![FamilyDefinition {
                    family: "elliptic_curve".into(),
                    status: FamilyStatus::Enabled,
                }],
                algorithm_registry: vec![AlgorithmDefinition {
                    algorithm: "ed25519".into(),
                    family: "elliptic_curve".into(),
                    assurance_class: "classical".into(),
                }],
                group_definitions: vec![GroupDefinition {
                    group: "release".into(),
                    predicate: GroupPredicate {
                        match_all: true,
                        ..GroupPredicate::default()
                    },
                }],
                accept_if_any: vec![PolicyClause {
                    clause_id: "release".into(),
                    required_groups: vec![GroupRequirement {
                        group: "release".into(),
                        min_distinct_identities: 1,
                        min_distinct_families: 0,
                        min_distinct_authorities: 0,
                        min_distinct_custody_domains: 0,
                    }],
                    relations: Vec::new(),
                    active_from: None,
                    active_until: None,
                }],
            },
            trust_registry: TrustRegistry {
                registry_id: "cache-keys".into(),
                epoch: 1,
                previous_registry_hash: None,
                trusted_keys: vec![key],
            },
            candidates: Vec::new(),
        }
    }

    #[test]
    fn initialized_state_applies_committed_minima() {
        let request = request();
        let state = initialize_trust_state("cache.example", &request).unwrap();
        verify_trust_state(&state).unwrap();
        let mut later = request.clone();
        apply_trust_state(&state, "cache.example", &mut later).unwrap();
        assert_eq!(later.evaluation_context.minimum_policy_epoch, 1);
        assert_eq!(later.evaluation_context.minimum_registry_epoch, 1);
    }

    #[test]
    fn linked_registry_successor_advances() {
        let request = request();
        let state = initialize_trust_state("cache.example", &request).unwrap();
        let mut next = request.clone();
        next.trust_registry.epoch = 2;
        next.trust_registry.previous_registry_hash =
            Some(canonical_registry_sha256(&request.trust_registry).unwrap());
        let advanced = advance_trust_state(&state, "cache.example", &next).unwrap();
        assert_eq!(advanced.payload.domains["cache.example"].registry_epoch, 2);
    }

    #[test]
    fn epoch_jump_requires_intermediate_chain_objects() {
        let request = request();
        let state = initialize_trust_state("cache.example", &request).unwrap();
        let mut next = request.clone();
        next.policy.epoch = 3;
        next.policy.previous_policy_hash = Some("00".repeat(32));
        assert!(matches!(
            advance_trust_state(&state, "cache.example", &next),
            Err(TrustStateError::NonContiguousAdvance { .. })
        ));
    }

    #[test]
    fn tampered_state_digest_is_refused() {
        let request = request();
        let mut state = initialize_trust_state("cache.example", &request).unwrap();
        state
            .payload
            .domains
            .get_mut("cache.example")
            .unwrap()
            .policy_epoch = 2;
        assert!(verify_trust_state(&state).is_err());
    }
}
