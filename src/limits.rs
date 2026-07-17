//! Explicit resource profile for policy and registry evaluation.
//!
//! Signature observations were bounded from the beginning, but policy shape is
//! also attacker- or operator-controlled at an integration boundary. These
//! limits make worst-case memory and traversal costs reviewable without tying
//! acceptance to wall-clock timing on one machine.

use serde::{Deserialize, Serialize};

use crate::policy::{SignaturePolicy, TrustedKey};

pub const RESOURCE_PROFILE_ID: &str = "resource-v1";
pub const RESOURCE_PROFILE_VERSION: u32 = 1;
pub const MAX_POLICY_FAMILIES: usize = 64;
pub const MAX_POLICY_ALGORITHMS: usize = 256;
pub const MAX_POLICY_GROUPS: usize = 128;
pub const MAX_POLICY_CLAUSES: usize = 128;
pub const MAX_REQUIREMENTS_PER_CLAUSE: usize = 64;
pub const MAX_RELATIONS_PER_CLAUSE: usize = 64;
pub const MAX_GROUPS_PER_RELATION: usize = 16;
pub const MAX_TRUSTED_KEYS: usize = 4096;
pub const MAX_ROLES_PER_KEY: usize = 64;
pub const MAX_PREDICATE_VALUES: usize = 256;
pub const MAX_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyComplexity {
    pub family_count: usize,
    pub algorithm_count: usize,
    pub group_count: usize,
    pub clause_count: usize,
    pub requirement_count: usize,
    pub relation_count: usize,
    pub relation_group_reference_count: usize,
    pub trusted_key_count: usize,
    pub maximum_roles_per_key: usize,
    pub maximum_predicate_values: usize,
    pub maximum_identifier_bytes: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ResourceLimitViolation {
    TooManyFamilies,
    TooManyAlgorithms,
    TooManyGroups,
    TooManyClauses,
    TooManyRequirementsInClause,
    TooManyRelationsInClause,
    TooManyGroupsInRelation,
    TooManyTrustedKeys,
    TooManyRolesOnKey,
    TooManyPredicateValues,
    IdentifierTooLong,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvaluationWorkEstimate {
    pub raw_observations: usize,
    pub bounded_unique_candidates: usize,
    pub key_resolution_units: u64,
    pub group_membership_units: u64,
    pub requirement_units: u64,
    pub relation_units: u64,
    pub total_work_units: u64,
}

pub fn analyze_policy_complexity(
    policy: &SignaturePolicy,
    trusted_keys: &[TrustedKey],
) -> PolicyComplexity {
    let requirement_count = policy
        .accept_if_any
        .iter()
        .map(|clause| clause.required_groups.len())
        .sum();
    let relation_count = policy
        .accept_if_any
        .iter()
        .map(|clause| clause.relations.len())
        .sum();
    let relation_group_reference_count = policy
        .accept_if_any
        .iter()
        .flat_map(|clause| &clause.relations)
        .map(|relation| relation.groups.len())
        .sum();
    let maximum_roles_per_key = trusted_keys
        .iter()
        .map(|key| key.roles.len())
        .max()
        .unwrap_or(0);
    let maximum_predicate_values = policy
        .group_definitions
        .iter()
        .map(|definition| {
            let predicate = &definition.predicate;
            predicate.allowed_algorithms.len()
                + predicate.allowed_families.len()
                + predicate.allowed_assurance_classes.len()
                + predicate.required_roles.len()
                + predicate.allowed_authorities.len()
                + predicate.allowed_custody_domains.len()
        })
        .max()
        .unwrap_or(0);
    let maximum_identifier_bytes = identifiers(policy, trusted_keys)
        .map(str::len)
        .max()
        .unwrap_or(0);

    PolicyComplexity {
        family_count: policy.family_registry.len(),
        algorithm_count: policy.algorithm_registry.len(),
        group_count: policy.group_definitions.len(),
        clause_count: policy.accept_if_any.len(),
        requirement_count,
        relation_count,
        relation_group_reference_count,
        trusted_key_count: trusted_keys.len(),
        maximum_roles_per_key,
        maximum_predicate_values,
        maximum_identifier_bytes,
    }
}

pub fn resource_limit_violations(
    policy: &SignaturePolicy,
    trusted_keys: &[TrustedKey],
) -> Vec<ResourceLimitViolation> {
    let complexity = analyze_policy_complexity(policy, trusted_keys);
    let mut violations = Vec::new();
    if complexity.family_count > MAX_POLICY_FAMILIES {
        violations.push(ResourceLimitViolation::TooManyFamilies);
    }
    if complexity.algorithm_count > MAX_POLICY_ALGORITHMS {
        violations.push(ResourceLimitViolation::TooManyAlgorithms);
    }
    if complexity.group_count > MAX_POLICY_GROUPS {
        violations.push(ResourceLimitViolation::TooManyGroups);
    }
    if complexity.clause_count > MAX_POLICY_CLAUSES {
        violations.push(ResourceLimitViolation::TooManyClauses);
    }
    if policy
        .accept_if_any
        .iter()
        .any(|clause| clause.required_groups.len() > MAX_REQUIREMENTS_PER_CLAUSE)
    {
        violations.push(ResourceLimitViolation::TooManyRequirementsInClause);
    }
    if policy
        .accept_if_any
        .iter()
        .any(|clause| clause.relations.len() > MAX_RELATIONS_PER_CLAUSE)
    {
        violations.push(ResourceLimitViolation::TooManyRelationsInClause);
    }
    if policy
        .accept_if_any
        .iter()
        .flat_map(|clause| &clause.relations)
        .any(|relation| relation.groups.len() > MAX_GROUPS_PER_RELATION)
    {
        violations.push(ResourceLimitViolation::TooManyGroupsInRelation);
    }
    if complexity.trusted_key_count > MAX_TRUSTED_KEYS {
        violations.push(ResourceLimitViolation::TooManyTrustedKeys);
    }
    if complexity.maximum_roles_per_key > MAX_ROLES_PER_KEY {
        violations.push(ResourceLimitViolation::TooManyRolesOnKey);
    }
    if complexity.maximum_predicate_values > MAX_PREDICATE_VALUES {
        violations.push(ResourceLimitViolation::TooManyPredicateValues);
    }
    if complexity.maximum_identifier_bytes > MAX_IDENTIFIER_BYTES {
        violations.push(ResourceLimitViolation::IdentifierTooLong);
    }
    violations.sort();
    violations.dedup();
    violations
}

pub fn policy_within_resource_limits(
    policy: &SignaturePolicy,
    trusted_keys: &[TrustedKey],
) -> bool {
    resource_limit_violations(policy, trusted_keys).is_empty()
}

/// Conservative implementation-independent work units for one evaluation.
///
/// These units are not elapsed time. They expose how input dimensions compose
/// so deployments can compare policies and reject unexpectedly expensive
/// configurations before enabling them.
pub fn estimate_evaluation_work(
    policy: &SignaturePolicy,
    trusted_key_count: usize,
    raw_observations: usize,
) -> EvaluationWorkEstimate {
    let bounded_unique_candidates = raw_observations.min(policy.max_signature_candidates);
    let key_resolution_units = bounded_unique_candidates as u64;
    let group_membership_units =
        saturating_product(bounded_unique_candidates, policy.group_definitions.len());
    let requirement_units = policy
        .accept_if_any
        .iter()
        .map(|clause| clause.required_groups.len() as u64)
        .sum();
    // distinct_relation_witnesses() (src/policy.rs) evaluates each
    // relation via Kuhn's-algorithm bipartite matching between the
    // relation's groups and the candidate values observed for them --
    // worst case O(groups * edges), where edges are bounded by
    // groups * bounded_unique_candidates (each group's value set can
    // hold at most one entry per observed candidate). Counting only
    // group references here (as a prior version of this function did)
    // silently assumed O(groups) relation cost, which understated the
    // real -- now polynomial, not exponential, but not free -- cost of
    // evaluating a relation once real candidate counts are involved.
    let relation_units = policy
        .accept_if_any
        .iter()
        .flat_map(|clause| &clause.relations)
        .map(|relation| {
            let group_count = relation.groups.len() as u64;
            group_count
                .saturating_mul(group_count)
                .saturating_mul(bounded_unique_candidates as u64)
        })
        .sum();
    let registry_units = trusted_key_count as u64;
    let total_work_units = (raw_observations as u64)
        .saturating_add(key_resolution_units)
        .saturating_add(group_membership_units)
        .saturating_add(requirement_units)
        .saturating_add(relation_units)
        .saturating_add(registry_units);
    EvaluationWorkEstimate {
        raw_observations,
        bounded_unique_candidates,
        key_resolution_units,
        group_membership_units,
        requirement_units,
        relation_units,
        total_work_units,
    }
}

fn saturating_product(left: usize, right: usize) -> u64 {
    (left as u64).saturating_mul(right as u64)
}

fn identifiers<'a>(
    policy: &'a SignaturePolicy,
    trusted_keys: &'a [TrustedKey],
) -> impl Iterator<Item = &'a str> {
    let policy_ids = std::iter::once(policy.policy_id.as_str())
        .chain(
            policy
                .family_registry
                .iter()
                .map(|item| item.family.as_str()),
        )
        .chain(policy.algorithm_registry.iter().flat_map(|item| {
            [
                item.algorithm.as_str(),
                item.family.as_str(),
                item.assurance_class.as_str(),
            ]
        }))
        .chain(policy.group_definitions.iter().flat_map(|item| {
            std::iter::once(item.group.as_str())
                .chain(item.predicate.allowed_algorithms.iter().map(String::as_str))
                .chain(item.predicate.allowed_families.iter().map(String::as_str))
                .chain(
                    item.predicate
                        .allowed_assurance_classes
                        .iter()
                        .map(String::as_str),
                )
                .chain(item.predicate.required_roles.iter().map(String::as_str))
                .chain(
                    item.predicate
                        .allowed_authorities
                        .iter()
                        .map(String::as_str),
                )
                .chain(
                    item.predicate
                        .allowed_custody_domains
                        .iter()
                        .map(String::as_str),
                )
        }))
        .chain(policy.accept_if_any.iter().flat_map(|clause| {
            std::iter::once(clause.clause_id.as_str())
                .chain(
                    clause
                        .required_groups
                        .iter()
                        .map(|item| item.group.as_str()),
                )
                .chain(clause.relations.iter().flat_map(|relation| {
                    std::iter::once(relation.relation_id.as_str())
                        .chain(relation.groups.iter().map(String::as_str))
                }))
        }));
    let key_ids = trusted_keys.iter().flat_map(|key| {
        [
            key.key_id.as_str(),
            key.key_name.as_str(),
            key.signer_identity.as_str(),
            key.algorithm.as_str(),
            key.authority.as_str(),
            key.custody_domain.as_str(),
        ]
        .into_iter()
        .chain(key.roles.iter().map(String::as_str))
    });
    policy_ids.chain(key_ids)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::policy::{
        AlgorithmDefinition, FamilyDefinition, FamilyStatus, GroupDefinition, GroupPredicate,
        GroupRequirement, PolicyClause,
    };

    fn policy() -> SignaturePolicy {
        SignaturePolicy {
            policy_id: "bounded".into(),
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
        }
    }

    #[test]
    fn ordinary_policy_is_within_profile() {
        assert!(resource_limit_violations(&policy(), &[]).is_empty());
    }

    #[test]
    fn identifier_limit_is_explicit() {
        let mut oversized = policy();
        oversized.policy_id = "x".repeat(MAX_IDENTIFIER_BYTES + 1);
        assert_eq!(
            resource_limit_violations(&oversized, &[]),
            vec![ResourceLimitViolation::IdentifierTooLong]
        );
    }

    #[test]
    fn work_estimate_composes_dimensions() {
        let estimate = estimate_evaluation_work(&policy(), 2, 3);
        assert_eq!(estimate.raw_observations, 3);
        assert_eq!(estimate.bounded_unique_candidates, 3);
        assert_eq!(estimate.group_membership_units, 3);
        assert_eq!(estimate.requirement_units, 1);
        assert!(estimate.total_work_units >= 12);
    }

    #[test]
    fn relation_units_scale_with_groups_and_observed_candidates() {
        use crate::policy::{GroupRelation, RelationAttribute, RelationMode};

        let mut with_relation = policy();
        with_relation.accept_if_any[0]
            .relations
            .push(GroupRelation {
                relation_id: "distinct-owners".into(),
                attribute: RelationAttribute::Identity,
                mode: RelationMode::Distinct,
                groups: vec!["release".into(), "release".into(), "release".into()],
            });

        // group_count = 3, bounded_unique_candidates = min(raw_observations, 32).
        let estimate = estimate_evaluation_work(&with_relation, 2, 5);
        assert_eq!(estimate.bounded_unique_candidates, 5);
        assert_eq!(estimate.relation_units, 3 * 3 * 5);

        // A relation-free policy still reports zero relation cost.
        assert_eq!(estimate_evaluation_work(&policy(), 2, 5).relation_units, 0);
    }

    #[test]
    fn excessive_roles_are_rejected() {
        let key = TrustedKey {
            key_id: "key".into(),
            key_name: "cache".into(),
            signer_identity: "owner".into(),
            algorithm: "ed25519".into(),
            roles: (0..=MAX_ROLES_PER_KEY)
                .map(|index| format!("role-{index}"))
                .collect::<BTreeSet<_>>(),
            authority: "owner".into(),
            custody_domain: "offline".into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        };
        assert_eq!(
            resource_limit_violations(&policy(), &[key]),
            vec![ResourceLimitViolation::TooManyRolesOnKey]
        );
    }
}
