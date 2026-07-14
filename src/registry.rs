//! Versioned trusted-key registry commitments.
//!
//! The policy evaluator still consumes a slice of trusted keys. This module
//! gives that slice an independent identity, monotonic epoch, predecessor hash,
//! and deterministic commitment so key enrollment and revocation cannot be
//! rolled back merely by replaying an older request.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::commitment::{CommitmentDomain, commitment_sha256};

use crate::policy::TrustedKey;

/// Versioned collection of trusted verification keys.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustRegistry {
    pub registry_id: String,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_registry_hash: Option<String>,
    pub trusted_keys: Vec<TrustedKey>,
}

/// Stable registry-evaluation value.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RegistryDecisionValue {
    Accept,
    Refuse,
}

/// Stable registry refusal or warning codes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RegistryReasonCode {
    InvalidRegistry,
    RegistryRollback,
}

/// Deterministic registry validation result.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryDecision {
    pub registry_id: String,
    pub registry_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_sha256: Option<String>,
    pub decision: RegistryDecisionValue,
    pub reason_codes: std::collections::BTreeSet<RegistryReasonCode>,
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryTransitionError {
    #[error("trust registry domain changed from {previous:?} to {next:?}")]
    RegistryDomainChanged { previous: String, next: String },
    #[error("trust registry epoch did not advance: previous {previous}, next {next}")]
    EpochDidNotAdvance { previous: u64, next: u64 },
    #[error("successor trust registry is missing previous_registry_hash")]
    MissingPreviousRegistryHash,
    #[error("successor trust registry predecessor hash mismatch")]
    PreviousRegistryHashMismatch { expected: String, actual: String },
    #[error("serializing canonical trust registry failed: {0}")]
    Serialization(String),
}

/// Sort semantically unordered key records before hashing or persistence.
pub fn canonicalize_trust_registry(registry: &mut TrustRegistry) {
    registry.trusted_keys.sort_by(|left, right| {
        (
            left.key_id.as_str(),
            left.key_name.as_str(),
            left.algorithm.as_str(),
        )
            .cmp(&(
                right.key_id.as_str(),
                right.key_name.as_str(),
                right.algorithm.as_str(),
            ))
    });
}

/// SHA-256 of the canonical JSON registry representation.
pub fn canonical_registry_sha256(registry: &TrustRegistry) -> Result<String, serde_json::Error> {
    let mut canonical = registry.clone();
    canonicalize_trust_registry(&mut canonical);
    let bytes = serde_json::to_vec(&canonical)?;
    Ok(commitment_sha256(CommitmentDomain::Registry, &bytes))
}

/// Validate registry structure and committed minimum epoch.
pub fn evaluate_trust_registry(
    registry: &TrustRegistry,
    minimum_registry_epoch: u64,
) -> RegistryDecision {
    let mut reason_codes = std::collections::BTreeSet::new();
    let structurally_valid = registry_is_well_formed(registry);
    if !structurally_valid {
        reason_codes.insert(RegistryReasonCode::InvalidRegistry);
    }
    if registry.epoch < minimum_registry_epoch {
        reason_codes.insert(RegistryReasonCode::RegistryRollback);
    }
    let registry_sha256 = canonical_registry_sha256(registry).ok();
    if registry_sha256.is_none() {
        reason_codes.insert(RegistryReasonCode::InvalidRegistry);
    }
    RegistryDecision {
        registry_id: registry.registry_id.clone(),
        registry_epoch: registry.epoch,
        registry_sha256,
        decision: if reason_codes.is_empty() {
            RegistryDecisionValue::Accept
        } else {
            RegistryDecisionValue::Refuse
        },
        reason_codes,
    }
}

/// Validate an append-only registry-chain transition.
pub fn validate_registry_transition(
    previous: &TrustRegistry,
    next: &TrustRegistry,
) -> Result<(), RegistryTransitionError> {
    if previous.registry_id != next.registry_id {
        return Err(RegistryTransitionError::RegistryDomainChanged {
            previous: previous.registry_id.clone(),
            next: next.registry_id.clone(),
        });
    }
    if next.epoch <= previous.epoch {
        return Err(RegistryTransitionError::EpochDidNotAdvance {
            previous: previous.epoch,
            next: next.epoch,
        });
    }
    let expected = canonical_registry_sha256(previous)
        .map_err(|error| RegistryTransitionError::Serialization(error.to_string()))?;
    let actual = next
        .previous_registry_hash
        .clone()
        .ok_or(RegistryTransitionError::MissingPreviousRegistryHash)?;
    if actual != expected {
        return Err(RegistryTransitionError::PreviousRegistryHashMismatch { expected, actual });
    }
    Ok(())
}

fn registry_is_well_formed(registry: &TrustRegistry) -> bool {
    if registry.registry_id.trim().is_empty()
        || registry.epoch == 0
        || registry
            .previous_registry_hash
            .as_deref()
            .is_some_and(|hash| !is_lower_sha256(hash))
    {
        return false;
    }

    let mut key_ids = HashSet::new();
    let mut wire_keys = HashSet::new();
    for key in &registry.trusted_keys {
        if key.key_id.trim().is_empty()
            || key.key_name.trim().is_empty()
            || key.signer_identity.trim().is_empty()
            || key.algorithm.trim().is_empty()
            || key.authority.trim().is_empty()
            || key.custody_domain.trim().is_empty()
            || key.roles.iter().any(|role| role.trim().is_empty())
            || !key_ids.insert(key.key_id.as_str())
            || !wire_keys.insert((key.key_name.as_str(), key.algorithm.as_str()))
            || key
                .valid_from
                .zip(key.valid_until)
                .is_some_and(|(start, end)| start >= end)
        {
            return false;
        }
    }
    true
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

    fn key(id: &str) -> TrustedKey {
        TrustedKey {
            key_id: id.into(),
            key_name: id.into(),
            signer_identity: "owner".into(),
            algorithm: "ed25519".into(),
            roles: BTreeSet::new(),
            authority: "owner".into(),
            custody_domain: id.into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        }
    }

    fn registry() -> TrustRegistry {
        TrustRegistry {
            registry_id: "cache-keys".into(),
            epoch: 1,
            previous_registry_hash: None,
            trusted_keys: vec![key("a"), key("b")],
        }
    }

    #[test]
    fn canonical_hash_ignores_key_order() {
        let first = registry();
        let mut second = first.clone();
        second.trusted_keys.reverse();
        assert_eq!(
            canonical_registry_sha256(&first).unwrap(),
            canonical_registry_sha256(&second).unwrap()
        );
    }

    #[test]
    fn duplicate_wire_key_is_invalid() {
        let mut duplicate = registry();
        duplicate.trusted_keys[1].key_name = duplicate.trusted_keys[0].key_name.clone();
        duplicate.trusted_keys[1].algorithm = duplicate.trusted_keys[0].algorithm.clone();
        let decision = evaluate_trust_registry(&duplicate, 0);
        assert_eq!(decision.decision, RegistryDecisionValue::Refuse);
        assert!(
            decision
                .reason_codes
                .contains(&RegistryReasonCode::InvalidRegistry)
        );
    }

    #[test]
    fn committed_epoch_refuses_registry_rollback() {
        let decision = evaluate_trust_registry(&registry(), 2);
        assert_eq!(decision.decision, RegistryDecisionValue::Refuse);
        assert!(
            decision
                .reason_codes
                .contains(&RegistryReasonCode::RegistryRollback)
        );
    }

    #[test]
    fn transition_binds_predecessor() {
        let previous = registry();
        let mut next = previous.clone();
        next.epoch = 2;
        next.previous_registry_hash = Some(canonical_registry_sha256(&previous).unwrap());
        assert_eq!(validate_registry_transition(&previous, &next), Ok(()));
    }
}
