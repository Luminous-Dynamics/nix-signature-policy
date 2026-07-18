//! Minimal integration contract between Nix's existing signature verifier and
//! the representation-neutral authorization policy engine.
//!
//! The essential security property is that an authoritative policy cannot be
//! bypassed by a permissive built-in `any-valid` result. Callers select the
//! enforcement mode explicitly and receive a deterministic final admission
//! decision together with both component decisions.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::policy::{
    Decision, EvaluationContext, PolicyDecision, SignatureCandidate, SignaturePolicy,
    evaluate_policy_with_context,
};
use crate::registry::{
    RegistryDecision, RegistryDecisionValue, TrustRegistry, evaluate_trust_registry,
};

/// Version of the normalized integration request/response contract.
pub const INTEGRATION_CONTRACT_VERSION: u32 = 2;

/// Result produced by Nix's existing built-in trust path.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BuiltInDecision {
    /// At least one signature satisfied the configured built-in trust rule.
    Accept,
    /// The built-in verifier ran and did not authorize the artifact.
    Refuse,
    /// The built-in path was intentionally not evaluated.
    NotEvaluated,
}

/// How built-in trust and composed authorization policy are combined.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Preserve existing Nix behavior; policy is evaluated only for evidence.
    Legacy,
    /// Either built-in trust or policy may authorize. Suitable for observation,
    /// never for mandatory hybrid enforcement.
    Supplemental,
    /// The composed policy owns the final decision. Built-in acceptance cannot
    /// bypass a policy refusal.
    Authoritative,
    /// Both built-in trust and the composed policy must authorize.
    Conjunctive,
}

/// Stable final admission value.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDecision {
    Accept,
    Refuse,
}

/// Stable explanation codes for the integration boundary.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionReasonCode {
    UnsupportedContractVersion,
    BuiltInAccepted,
    BuiltInRefused,
    BuiltInNotEvaluated,
    PolicyAccepted,
    PolicyRefused,
    SupplementalPathAccepted,
    AuthoritativePolicyRequired,
    ConjunctiveRequirementFailed,
    RegistryAccepted,
    RegistryRefused,
    RegistryRequired,
}

/// Normalized request supplied after wire parsing and cryptographic verification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRequest {
    pub contract_version: u32,
    pub enforcement_mode: EnforcementMode,
    pub built_in_decision: BuiltInDecision,
    pub evaluation_context: SerializableEvaluationContext,
    pub policy: SignaturePolicy,
    pub trust_registry: TrustRegistry,
    pub candidates: Vec<SignatureCandidate>,
}

/// Serializable form of [`EvaluationContext`]. Carried on the wire inside
/// [`AuthorizationRequest`] -- see [`EvaluationContext::evaluation_time`]'s
/// doc comment (`crate::policy`) for the field's authority model
/// (caller-authoritative, never altered by a helper this crate invokes)
/// and boundary conventions; that documentation is not duplicated here.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SerializableEvaluationContext {
    pub evaluation_time: i64,
    #[serde(default)]
    pub minimum_policy_epoch: u64,
    #[serde(default)]
    pub minimum_registry_epoch: u64,
}

impl From<SerializableEvaluationContext> for EvaluationContext {
    fn from(value: SerializableEvaluationContext) -> Self {
        Self {
            evaluation_time: value.evaluation_time,
            minimum_policy_epoch: value.minimum_policy_epoch,
        }
    }
}

/// Deterministic integration response suitable for logging or admission receipts.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResponse {
    pub contract_version: u32,
    pub enforcement_mode: EnforcementMode,
    pub decision: AdmissionDecision,
    pub built_in_decision: BuiltInDecision,
    pub policy_decision: PolicyDecision,
    pub registry_decision: RegistryDecision,
    pub reason_codes: BTreeSet<AdmissionReasonCode>,
}

/// Evaluate policy and combine it with the existing Nix trust path according to
/// an explicit enforcement mode.
pub fn authorize(request: &AuthorizationRequest) -> AuthorizationResponse {
    let registry_decision = evaluate_trust_registry(
        &request.trust_registry,
        request.evaluation_context.minimum_registry_epoch,
    );
    let policy_decision = evaluate_policy_with_context(
        &request.policy,
        &request.trust_registry.trusted_keys,
        &request.candidates,
        request.evaluation_context.into(),
    );
    let contract_supported = request.contract_version == INTEGRATION_CONTRACT_VERSION;
    let registry_accepts = registry_decision.decision == RegistryDecisionValue::Accept;
    let built_in_accepts = request.built_in_decision == BuiltInDecision::Accept;
    let policy_accepts = policy_decision.decision == Decision::Accept;

    let mut reason_codes = BTreeSet::new();
    if !contract_supported {
        reason_codes.insert(AdmissionReasonCode::UnsupportedContractVersion);
    }
    reason_codes.insert(match request.built_in_decision {
        BuiltInDecision::Accept => AdmissionReasonCode::BuiltInAccepted,
        BuiltInDecision::Refuse => AdmissionReasonCode::BuiltInRefused,
        BuiltInDecision::NotEvaluated => AdmissionReasonCode::BuiltInNotEvaluated,
    });
    reason_codes.insert(if policy_accepts {
        AdmissionReasonCode::PolicyAccepted
    } else {
        AdmissionReasonCode::PolicyRefused
    });
    reason_codes.insert(if registry_accepts {
        AdmissionReasonCode::RegistryAccepted
    } else {
        AdmissionReasonCode::RegistryRefused
    });
    reason_codes.insert(AdmissionReasonCode::RegistryRequired);

    // `registry_accepts` (trust-registry epoch/rollback validity) only
    // gates the *policy* path, never the built-in path -- a registry
    // rollback or invalidation must not be able to veto Nix's own
    // built-in trust result. Legacy mode in particular is documented
    // ("Preserve existing Nix behavior; policy is evaluated only for
    // evidence") to be exactly Nix's built-in decision and nothing else;
    // a prior version of this function unconditionally ANDed
    // `registry_accepts` into every mode's final decision, so an invalid
    // or rolled-back registry could refuse admission even in Legacy mode
    // despite Legacy never consulting the registry for its own decision.
    // `contract_supported` remains a genuine cross-cutting gate in every
    // mode -- an unsupported wire-contract version means this function
    // cannot trust its own interpretation of the rest of the request,
    // which is a protocol-safety concern independent of enforcement mode.
    let registry_gated_policy_accepts = registry_accepts && policy_accepts;

    let mode_accepts = match request.enforcement_mode {
        EnforcementMode::Legacy => built_in_accepts,
        EnforcementMode::Supplemental => {
            let accepted = built_in_accepts || registry_gated_policy_accepts;
            if accepted {
                reason_codes.insert(AdmissionReasonCode::SupplementalPathAccepted);
            }
            accepted
        }
        EnforcementMode::Authoritative => {
            reason_codes.insert(AdmissionReasonCode::AuthoritativePolicyRequired);
            registry_gated_policy_accepts
        }
        EnforcementMode::Conjunctive => {
            let accepted = built_in_accepts && registry_gated_policy_accepts;
            if !accepted {
                reason_codes.insert(AdmissionReasonCode::ConjunctiveRequirementFailed);
            }
            accepted
        }
    };

    let accepts = contract_supported && mode_accepts;

    AuthorizationResponse {
        contract_version: INTEGRATION_CONTRACT_VERSION,
        enforcement_mode: request.enforcement_mode,
        decision: if accepts {
            AdmissionDecision::Accept
        } else {
            AdmissionDecision::Refuse
        },
        built_in_decision: request.built_in_decision,
        policy_decision,
        registry_decision,
        reason_codes,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::policy::{
        AlgorithmDefinition, FamilyDefinition, FamilyStatus, GroupDefinition, GroupPredicate,
        GroupRequirement, PolicyClause, TrustedKey, VerificationOutcome,
    };
    use crate::registry::TrustRegistry;

    fn request(
        mode: EnforcementMode,
        built_in: BuiltInDecision,
        include_pq: bool,
    ) -> AuthorizationRequest {
        let policy = SignaturePolicy {
            policy_id: "integration-hybrid".into(),
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
                    algorithm: "ed25519".into(),
                    family: "elliptic_curve".into(),
                    assurance_class: "classical".into(),
                },
                AlgorithmDefinition {
                    algorithm: "ml-dsa-65".into(),
                    family: "lattice".into(),
                    assurance_class: "post_quantum".into(),
                },
            ],
            group_definitions: vec![
                GroupDefinition {
                    group: "classical".into(),
                    predicate: GroupPredicate {
                        allowed_assurance_classes: BTreeSet::from(["classical".into()]),
                        ..GroupPredicate::default()
                    },
                },
                GroupDefinition {
                    group: "post-quantum".into(),
                    predicate: GroupPredicate {
                        allowed_assurance_classes: BTreeSet::from(["post_quantum".into()]),
                        ..GroupPredicate::default()
                    },
                },
            ],
            accept_if_any: vec![PolicyClause {
                clause_id: "required".into(),
                required_groups: vec![
                    GroupRequirement {
                        group: "classical".into(),
                        min_distinct_identities: 1,
                        min_distinct_families: 0,
                        min_distinct_authorities: 0,
                        min_distinct_custody_domains: 0,
                    },
                    GroupRequirement {
                        group: "post-quantum".into(),
                        min_distinct_identities: 1,
                        min_distinct_families: 0,
                        min_distinct_authorities: 0,
                        min_distinct_custody_domains: 0,
                    },
                ],
                relations: Vec::new(),
                active_from: None,
                active_until: None,
            }],
        };
        let trusted_keys = vec![
            TrustedKey {
                key_id: "ed".into(),
                key_name: "cache".into(),
                signer_identity: "owner".into(),
                algorithm: "ed25519".into(),
                roles: BTreeSet::new(),
                authority: "owner".into(),
                custody_domain: "ed".into(),
                revoked: false,
                valid_from: None,
                valid_until: None,
            },
            TrustedKey {
                key_id: "pq".into(),
                key_name: "cache".into(),
                signer_identity: "owner".into(),
                algorithm: "ml-dsa-65".into(),
                roles: BTreeSet::new(),
                authority: "owner".into(),
                custody_domain: "pq".into(),
                revoked: false,
                valid_from: None,
                valid_until: None,
            },
        ];
        let mut candidates = vec![SignatureCandidate {
            key_name: "cache".into(),
            algorithm: "ed25519".into(),
            signature_id: "ed-good".into(),
            verification: VerificationOutcome::Valid,
        }];
        if include_pq {
            candidates.push(SignatureCandidate {
                key_name: "cache".into(),
                algorithm: "ml-dsa-65".into(),
                signature_id: "pq-good".into(),
                verification: VerificationOutcome::Valid,
            });
        }
        AuthorizationRequest {
            contract_version: INTEGRATION_CONTRACT_VERSION,
            enforcement_mode: mode,
            built_in_decision: built_in,
            evaluation_context: SerializableEvaluationContext {
                evaluation_time: 0,
                minimum_policy_epoch: 0,
                minimum_registry_epoch: 0,
            },
            policy,
            trust_registry: TrustRegistry {
                registry_id: "integration-cache-keys".into(),
                epoch: 1,
                previous_registry_hash: None,
                trusted_keys,
            },
            candidates,
        }
    }

    #[test]
    fn unsupported_contract_version_fails_closed() {
        let mut unsupported = request(EnforcementMode::Legacy, BuiltInDecision::Accept, true);
        unsupported.contract_version = INTEGRATION_CONTRACT_VERSION + 1;
        let response = authorize(&unsupported);
        assert_eq!(response.decision, AdmissionDecision::Refuse);
        assert!(
            response
                .reason_codes
                .contains(&AdmissionReasonCode::UnsupportedContractVersion)
        );
    }

    #[test]
    fn authoritative_mode_cannot_be_bypassed_by_builtin_acceptance() {
        let response = authorize(&request(
            EnforcementMode::Authoritative,
            BuiltInDecision::Accept,
            false,
        ));
        assert_eq!(response.decision, AdmissionDecision::Refuse);
        assert_eq!(response.policy_decision.decision, Decision::Refuse);
    }

    #[test]
    fn supplemental_mode_preserves_compatibility_but_is_not_mandatory_policy() {
        let response = authorize(&request(
            EnforcementMode::Supplemental,
            BuiltInDecision::Accept,
            false,
        ));
        assert_eq!(response.decision, AdmissionDecision::Accept);
        assert!(
            response
                .reason_codes
                .contains(&AdmissionReasonCode::SupplementalPathAccepted)
        );
    }

    #[test]
    fn conjunctive_mode_requires_both_paths() {
        let refused = authorize(&request(
            EnforcementMode::Conjunctive,
            BuiltInDecision::Refuse,
            true,
        ));
        assert_eq!(refused.decision, AdmissionDecision::Refuse);

        let accepted = authorize(&request(
            EnforcementMode::Conjunctive,
            BuiltInDecision::Accept,
            true,
        ));
        assert_eq!(accepted.decision, AdmissionDecision::Accept);
    }
    #[test]
    fn registry_rollback_refuses_even_when_policy_and_builtin_accept() {
        let mut request = request(
            EnforcementMode::Authoritative,
            BuiltInDecision::Accept,
            true,
        );
        request.evaluation_context.minimum_registry_epoch = 2;
        let response = authorize(&request);
        assert_eq!(response.decision, AdmissionDecision::Refuse);
        assert_eq!(
            response.registry_decision.decision,
            RegistryDecisionValue::Refuse
        );
        assert!(
            response
                .reason_codes
                .contains(&AdmissionReasonCode::RegistryRefused)
        );
    }

    /// Regression for the bug an external review found: a prior version
    /// of `authorize()` ANDed `registry_accepts` into every mode's final
    /// decision, so a rolled-back or invalid trust registry could refuse
    /// admission even in Legacy mode -- despite Legacy mode's own doc
    /// comment stating it preserves existing Nix behavior and evaluates
    /// policy "only for evidence." A misconfigured or stale external
    /// registry must never be able to veto Nix's own built-in trust
    /// result when the built-in path is the only one Legacy mode
    /// actually uses.
    #[test]
    fn legacy_mode_ignores_registry_rollback() {
        let mut request = request(EnforcementMode::Legacy, BuiltInDecision::Accept, true);
        request.evaluation_context.minimum_registry_epoch = 2;
        let response = authorize(&request);
        assert_eq!(response.decision, AdmissionDecision::Accept);
        // The rollback is still visible for observability -- it just
        // doesn't gate Legacy mode's decision.
        assert_eq!(
            response.registry_decision.decision,
            RegistryDecisionValue::Refuse
        );
        assert!(
            response
                .reason_codes
                .contains(&AdmissionReasonCode::RegistryRefused)
        );
    }

    /// The other half of the same fix: in Supplemental mode, when the
    /// built-in path itself refuses, a rolled-back registry must still
    /// prevent the policy path from independently authorizing --
    /// `registry_accepts` guards the policy path, it just must not guard
    /// the built-in path (covered above).
    #[test]
    fn supplemental_mode_policy_path_is_still_registry_gated() {
        let mut request = request(EnforcementMode::Supplemental, BuiltInDecision::Refuse, true);
        request.evaluation_context.minimum_registry_epoch = 2;
        let response = authorize(&request);
        assert_eq!(response.decision, AdmissionDecision::Refuse);
        assert_eq!(response.policy_decision.decision, Decision::Accept);
        assert_eq!(
            response.registry_decision.decision,
            RegistryDecisionValue::Refuse
        );
    }
}
