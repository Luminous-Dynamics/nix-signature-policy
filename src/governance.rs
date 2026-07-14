//! Authorization of policy and trusted-key registry transitions.
//!
//! Hash chaining and monotonic epochs prevent rollback, but they do not answer
//! who is allowed to advance trust state. This module consumes endorsements
//! that have already been cryptographically verified and requires an explicit,
//! bounded governance rule before a transition may be committed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::commitment::{CommitmentDomain, commitment_sha256};
use crate::policy::{
    SignaturePolicy, VerificationOutcome, canonical_policy_sha256, validate_policy_transition,
};
use crate::registry::{TrustRegistry, canonical_registry_sha256, validate_registry_transition};

pub const TRANSITION_GOVERNANCE_VERSION: u32 = 1;
pub const DEFAULT_MAX_TRANSITION_ENDORSEMENTS: usize = 64;
pub const MAX_TRANSITION_ENDORSEMENTS: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionComponent {
    Policy,
    Registry,
}

/// Canonical object endorsed by transition authorities.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionTarget {
    pub governance_version: u32,
    pub component: TransitionComponent,
    pub domain_id: String,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub previous_sha256: String,
    pub next_sha256: String,
}

/// Small threshold rule for authorizing one transition.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionRule {
    pub rule_id: String,
    pub required_role: String,
    #[serde(default)]
    pub min_distinct_identities: usize,
    #[serde(default)]
    pub min_distinct_families: usize,
    #[serde(default)]
    pub min_distinct_authorities: usize,
    #[serde(default)]
    pub forbidden_families: BTreeSet<String>,
    #[serde(default = "default_max_endorsements")]
    pub max_endorsements: usize,
}

fn default_max_endorsements() -> usize {
    DEFAULT_MAX_TRANSITION_ENDORSEMENTS
}

/// Verified endorsement over the canonical transition target commitment.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionEndorsement {
    pub endorsement_id: String,
    pub signer_identity: String,
    pub family: String,
    pub authority: String,
    #[serde(default)]
    pub roles: BTreeSet<String>,
    pub target_sha256: String,
    pub verification: VerificationOutcome,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransitionDecisionValue {
    Accept,
    Refuse,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum TransitionReasonCode {
    InvalidTarget,
    InvalidRule,
    TooManyEndorsements,
    DuplicateEndorsement,
    ConflictingEndorsement,
    InvalidEndorsement,
    WrongTarget,
    MissingRequiredRole,
    ForbiddenFamily,
    InsufficientIdentities,
    InsufficientFamilies,
    InsufficientAuthorities,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransitionAuthorizationDecision {
    pub decision: TransitionDecisionValue,
    pub transition_sha256: Option<String>,
    pub eligible_endorsement_count: usize,
    pub distinct_identity_count: usize,
    pub distinct_family_count: usize,
    pub distinct_authority_count: usize,
    pub reason_codes: BTreeSet<TransitionReasonCode>,
}

/// Compute the domain-separated commitment that transition endorsements bind.
pub fn canonical_transition_sha256(target: &TransitionTarget) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(target)?;
    Ok(commitment_sha256(CommitmentDomain::Transition, &bytes))
}

/// Construct and chain-validate a policy transition target.
pub fn policy_transition_target(
    previous: &SignaturePolicy,
    next: &SignaturePolicy,
) -> Result<TransitionTarget, String> {
    validate_policy_transition(previous, next).map_err(|error| error.to_string())?;
    Ok(TransitionTarget {
        governance_version: TRANSITION_GOVERNANCE_VERSION,
        component: TransitionComponent::Policy,
        domain_id: previous.policy_id.clone(),
        previous_epoch: previous.epoch,
        next_epoch: next.epoch,
        previous_sha256: canonical_policy_sha256(previous).map_err(|error| error.to_string())?,
        next_sha256: canonical_policy_sha256(next).map_err(|error| error.to_string())?,
    })
}

/// Construct and chain-validate a trusted-key registry transition target.
pub fn registry_transition_target(
    previous: &TrustRegistry,
    next: &TrustRegistry,
) -> Result<TransitionTarget, String> {
    validate_registry_transition(previous, next).map_err(|error| error.to_string())?;
    Ok(TransitionTarget {
        governance_version: TRANSITION_GOVERNANCE_VERSION,
        component: TransitionComponent::Registry,
        domain_id: previous.registry_id.clone(),
        previous_epoch: previous.epoch,
        next_epoch: next.epoch,
        previous_sha256: canonical_registry_sha256(previous).map_err(|error| error.to_string())?,
        next_sha256: canonical_registry_sha256(next).map_err(|error| error.to_string())?,
    })
}

/// Evaluate verified transition endorsements against one bounded governance rule.
pub fn authorize_transition(
    target: &TransitionTarget,
    rule: &TransitionRule,
    endorsements: &[TransitionEndorsement],
) -> TransitionAuthorizationDecision {
    let transition_sha256 = canonical_transition_sha256(target).ok();
    let mut reason_codes = BTreeSet::new();
    if !target_is_well_formed(target) || transition_sha256.is_none() {
        reason_codes.insert(TransitionReasonCode::InvalidTarget);
    }
    if !rule_is_well_formed(rule) {
        reason_codes.insert(TransitionReasonCode::InvalidRule);
    }
    if endorsements.len() > rule.max_endorsements.min(MAX_TRANSITION_ENDORSEMENTS) {
        reason_codes.insert(TransitionReasonCode::TooManyEndorsements);
    }
    if !reason_codes.is_empty() {
        return refusal(transition_sha256, reason_codes);
    }

    let expected_target = transition_sha256
        .as_deref()
        .expect("validated transition commitment exists");
    let mut unique: BTreeMap<&str, &TransitionEndorsement> = BTreeMap::new();
    let mut conflict = false;
    for endorsement in endorsements {
        match unique.get(endorsement.endorsement_id.as_str()) {
            None => {
                unique.insert(endorsement.endorsement_id.as_str(), endorsement);
            }
            Some(previous) if *previous == endorsement => {
                reason_codes.insert(TransitionReasonCode::DuplicateEndorsement);
            }
            Some(_) => {
                conflict = true;
                reason_codes.insert(TransitionReasonCode::ConflictingEndorsement);
            }
        }
    }
    if conflict {
        return refusal(transition_sha256, reason_codes);
    }

    let mut identities = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut authorities = BTreeSet::new();
    let mut eligible_endorsement_count = 0;
    for endorsement in unique.values() {
        if endorsement.verification != VerificationOutcome::Valid {
            reason_codes.insert(TransitionReasonCode::InvalidEndorsement);
            continue;
        }
        if endorsement.target_sha256 != expected_target {
            reason_codes.insert(TransitionReasonCode::WrongTarget);
            continue;
        }
        if !endorsement.roles.contains(&rule.required_role) {
            reason_codes.insert(TransitionReasonCode::MissingRequiredRole);
            continue;
        }
        if rule.forbidden_families.contains(&endorsement.family) {
            reason_codes.insert(TransitionReasonCode::ForbiddenFamily);
            continue;
        }
        if endorsement.endorsement_id.trim().is_empty()
            || endorsement.signer_identity.trim().is_empty()
            || endorsement.family.trim().is_empty()
            || endorsement.authority.trim().is_empty()
        {
            reason_codes.insert(TransitionReasonCode::InvalidEndorsement);
            continue;
        }
        eligible_endorsement_count += 1;
        identities.insert(endorsement.signer_identity.clone());
        families.insert(endorsement.family.clone());
        authorities.insert(endorsement.authority.clone());
    }

    if identities.len() < rule.min_distinct_identities {
        reason_codes.insert(TransitionReasonCode::InsufficientIdentities);
    }
    if families.len() < rule.min_distinct_families {
        reason_codes.insert(TransitionReasonCode::InsufficientFamilies);
    }
    if authorities.len() < rule.min_distinct_authorities {
        reason_codes.insert(TransitionReasonCode::InsufficientAuthorities);
    }

    let blocking = reason_codes
        .iter()
        .any(|code| !matches!(code, TransitionReasonCode::DuplicateEndorsement));
    TransitionAuthorizationDecision {
        decision: if blocking {
            TransitionDecisionValue::Refuse
        } else {
            TransitionDecisionValue::Accept
        },
        transition_sha256,
        eligible_endorsement_count,
        distinct_identity_count: identities.len(),
        distinct_family_count: families.len(),
        distinct_authority_count: authorities.len(),
        reason_codes,
    }
}

fn refusal(
    transition_sha256: Option<String>,
    reason_codes: BTreeSet<TransitionReasonCode>,
) -> TransitionAuthorizationDecision {
    TransitionAuthorizationDecision {
        decision: TransitionDecisionValue::Refuse,
        transition_sha256,
        eligible_endorsement_count: 0,
        distinct_identity_count: 0,
        distinct_family_count: 0,
        distinct_authority_count: 0,
        reason_codes,
    }
}

fn target_is_well_formed(target: &TransitionTarget) -> bool {
    target.governance_version == TRANSITION_GOVERNANCE_VERSION
        && !target.domain_id.trim().is_empty()
        && target.previous_epoch > 0
        && target.next_epoch == target.previous_epoch + 1
        && is_lower_sha256(&target.previous_sha256)
        && is_lower_sha256(&target.next_sha256)
        && target.previous_sha256 != target.next_sha256
}

fn rule_is_well_formed(rule: &TransitionRule) -> bool {
    let threshold = rule.min_distinct_identities > 0
        || rule.min_distinct_families > 0
        || rule.min_distinct_authorities > 0;
    !rule.rule_id.trim().is_empty()
        && !rule.required_role.trim().is_empty()
        && threshold
        && rule.max_endorsements > 0
        && rule.max_endorsements <= MAX_TRANSITION_ENDORSEMENTS
        && rule
            .forbidden_families
            .iter()
            .all(|family| !family.trim().is_empty())
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> TransitionTarget {
        TransitionTarget {
            governance_version: 1,
            component: TransitionComponent::Policy,
            domain_id: "cache-policy".into(),
            previous_epoch: 7,
            next_epoch: 8,
            previous_sha256: "11".repeat(32),
            next_sha256: "22".repeat(32),
        }
    }

    fn rule() -> TransitionRule {
        TransitionRule {
            rule_id: "two-family-recovery".into(),
            required_role: "policy-root".into(),
            min_distinct_identities: 2,
            min_distinct_families: 2,
            min_distinct_authorities: 2,
            forbidden_families: BTreeSet::from(["lattice".into()]),
            max_endorsements: 8,
        }
    }

    fn endorsement(
        id: &str,
        identity: &str,
        family: &str,
        authority: &str,
        target_sha256: &str,
    ) -> TransitionEndorsement {
        TransitionEndorsement {
            endorsement_id: id.into(),
            signer_identity: identity.into(),
            family: family.into(),
            authority: authority.into(),
            roles: BTreeSet::from(["policy-root".into()]),
            target_sha256: target_sha256.into(),
            verification: VerificationOutcome::Valid,
        }
    }

    #[test]
    fn two_unaffected_families_can_authorize_recovery() {
        let target = target();
        let digest = canonical_transition_sha256(&target).unwrap();
        let endorsements = vec![
            endorsement("a", "root-a", "elliptic_curve", "org-a", &digest),
            endorsement("b", "root-b", "hash_based", "org-b", &digest),
        ];
        let decision = authorize_transition(&target, &rule(), &endorsements);
        assert_eq!(decision.decision, TransitionDecisionValue::Accept);
        assert_eq!(decision.distinct_family_count, 2);
    }

    #[test]
    fn broken_family_cannot_authorize_its_own_replacement() {
        let target = target();
        let digest = canonical_transition_sha256(&target).unwrap();
        let endorsements = vec![
            endorsement("a", "root-a", "elliptic_curve", "org-a", &digest),
            endorsement("b", "root-b", "lattice", "org-b", &digest),
        ];
        let decision = authorize_transition(&target, &rule(), &endorsements);
        assert_eq!(decision.decision, TransitionDecisionValue::Refuse);
        assert!(
            decision
                .reason_codes
                .contains(&TransitionReasonCode::ForbiddenFamily)
        );
    }

    #[test]
    fn endorsement_is_bound_to_exact_transition() {
        let target = target();
        let decision = authorize_transition(
            &target,
            &rule(),
            &[
                endorsement("a", "root-a", "elliptic_curve", "org-a", &"33".repeat(32)),
                endorsement("b", "root-b", "hash_based", "org-b", &"33".repeat(32)),
            ],
        );
        assert_eq!(decision.decision, TransitionDecisionValue::Refuse);
        assert!(
            decision
                .reason_codes
                .contains(&TransitionReasonCode::WrongTarget)
        );
    }
}
