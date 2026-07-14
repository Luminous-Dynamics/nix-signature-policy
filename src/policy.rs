//! Representation-neutral signature authorization policy.
//!
//! This module deliberately starts *after* wire parsing and cryptographic
//! verification. Adapters normalize transport-specific signature observations
//! into [`SignatureCandidate`] values; this evaluator then decides whether the
//! verified, trusted candidates satisfy an explicit, typed authorization policy.
//!
//! Algorithm family and assurance metadata come from the policy's algorithm
//! registry, not from key-controlled group labels. This prevents a trusted key
//! record from silently declaring a classical algorithm to be post-quantum.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Current machine-readable conformance schema version.
pub const POLICY_VECTOR_SCHEMA_VERSION: u32 = 2;
/// Default cap on raw signature observations before deduplication.
pub const DEFAULT_MAX_SIGNATURE_OBSERVATIONS: usize = 128;
/// Default cap on unique signature candidates after deduplication.
pub const DEFAULT_MAX_SIGNATURE_CANDIDATES: usize = 32;
/// Defensive upper bound for a vector-supplied raw observation cap.
pub const MAX_CONFIGURABLE_SIGNATURE_OBSERVATIONS: usize = 16_384;
/// Defensive upper bound for a vector-supplied unique candidate cap.
pub const MAX_CONFIGURABLE_SIGNATURE_CANDIDATES: usize = 4096;

fn default_max_signature_observations() -> usize {
    DEFAULT_MAX_SIGNATURE_OBSERVATIONS
}

fn default_max_signature_candidates() -> usize {
    DEFAULT_MAX_SIGNATURE_CANDIDATES
}

/// Stable identifier for a signature algorithm.
pub type AlgorithmId = String;
/// Stable identifier for a cryptographic family.
pub type FamilyId = String;
/// Stable identifier for a broad assurance class, such as `classical` or
/// `post_quantum`.
pub type AssuranceClassId = String;
/// Stable identifier for a policy-defined signer group.
pub type GroupId = String;
/// Stable identifier for a logical signer identity.
pub type IdentityId = String;
/// Stable identifier for an authorization role.
pub type RoleId = String;
/// Stable identifier for an organizational or administrative authority.
pub type AuthorityId = String;
/// Stable identifier for a key-custody or failure domain.
pub type CustodyDomainId = String;

/// Lifecycle state for one cryptographic family.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FamilyStatus {
    /// Signatures from the family may authorize artifacts normally.
    #[default]
    Enabled,
    /// Signatures are observed and reported but cannot satisfy authorization.
    ObserveOnly,
    /// Signatures remain eligible while emitting an explicit warning.
    Deprecated,
    /// Signatures are ineligible because the family is considered compromised
    /// or administratively prohibited.
    Forbidden,
}

/// Policy-owned lifecycle metadata for one cryptographic family.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FamilyDefinition {
    pub family: FamilyId,
    #[serde(default)]
    pub status: FamilyStatus,
}

fn default_policy_epoch() -> u64 {
    1
}

/// Policy-owned metadata for one signature algorithm.
///
/// Family and assurance classification are derived through this registry. A
/// trusted key names only its algorithm and cannot independently relabel that
/// algorithm into a stronger assurance class.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlgorithmDefinition {
    pub algorithm: AlgorithmId,
    pub family: FamilyId,
    pub assurance_class: AssuranceClassId,
}

/// A trusted verification key and its non-cryptographic authorization
/// attributes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    /// Vector-local stable identifier used by the semantic adapter.
    pub key_id: String,
    /// Name carried by or selected for the wire signature.
    pub key_name: String,
    /// Logical identity used for distinct-signer and binding constraints.
    pub signer_identity: IdentityId,
    /// Algorithm identifier resolved through [`SignaturePolicy::algorithm_registry`].
    pub algorithm: AlgorithmId,
    /// Roles assigned by trusted local configuration.
    #[serde(default)]
    pub roles: BTreeSet<RoleId>,
    /// Organizational or administrative authority represented by this key.
    pub authority: AuthorityId,
    /// Key-custody or implementation failure domain.
    pub custody_domain: CustodyDomainId,
    /// Whether the key has been revoked at the evaluation boundary.
    #[serde(default)]
    pub revoked: bool,
    /// Inclusive lower timestamp bound, represented as fixture-defined seconds.
    #[serde(default)]
    pub valid_from: Option<i64>,
    /// Exclusive upper timestamp bound, represented as fixture-defined seconds.
    #[serde(default)]
    pub valid_until: Option<i64>,
}

/// Typed predicate used to derive group membership from trusted metadata.
///
/// Every non-empty allow-list is conjunctive with every other allow-list. All
/// `required_roles` must be present. A deliberately unconstrained group must set
/// `match_all` instead of relying on an accidentally empty predicate.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupPredicate {
    #[serde(default)]
    pub match_all: bool,
    #[serde(default)]
    pub allowed_algorithms: BTreeSet<AlgorithmId>,
    #[serde(default)]
    pub allowed_families: BTreeSet<FamilyId>,
    #[serde(default)]
    pub allowed_assurance_classes: BTreeSet<AssuranceClassId>,
    #[serde(default)]
    pub required_roles: BTreeSet<RoleId>,
    #[serde(default)]
    pub allowed_authorities: BTreeSet<AuthorityId>,
    #[serde(default)]
    pub allowed_custody_domains: BTreeSet<CustodyDomainId>,
}

impl GroupPredicate {
    fn matches(&self, key: &TrustedKey, algorithm: &AlgorithmDefinition) -> bool {
        self.match_all
            || ((!self.allowed_algorithms.is_empty()
                || !self.allowed_families.is_empty()
                || !self.allowed_assurance_classes.is_empty()
                || !self.required_roles.is_empty()
                || !self.allowed_authorities.is_empty()
                || !self.allowed_custody_domains.is_empty())
                && (self.allowed_algorithms.is_empty()
                    || self.allowed_algorithms.contains(&algorithm.algorithm))
                && (self.allowed_families.is_empty()
                    || self.allowed_families.contains(&algorithm.family))
                && (self.allowed_assurance_classes.is_empty()
                    || self
                        .allowed_assurance_classes
                        .contains(&algorithm.assurance_class))
                && self.required_roles.is_subset(&key.roles)
                && (self.allowed_authorities.is_empty()
                    || self.allowed_authorities.contains(&key.authority))
                && (self.allowed_custody_domains.is_empty()
                    || self.allowed_custody_domains.contains(&key.custody_domain)))
    }

    fn is_well_formed(&self) -> bool {
        let constrained = !self.allowed_algorithms.is_empty()
            || !self.allowed_families.is_empty()
            || !self.allowed_assurance_classes.is_empty()
            || !self.required_roles.is_empty()
            || !self.allowed_authorities.is_empty()
            || !self.allowed_custody_domains.is_empty();
        if self.match_all {
            !constrained
        } else {
            constrained
        }
    }
}

/// One named, policy-derived signer group.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupDefinition {
    pub group: GroupId,
    pub predicate: GroupPredicate,
}

fn default_zero() -> usize {
    0
}

/// One group threshold inside a policy clause.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupRequirement {
    pub group: GroupId,
    /// Required number of distinct logical signer identities.
    #[serde(default = "default_zero")]
    pub min_distinct_identities: usize,
    /// Required number of distinct cryptographic families.
    #[serde(default = "default_zero")]
    pub min_distinct_families: usize,
    /// Required number of distinct administrative authorities.
    #[serde(default = "default_zero")]
    pub min_distinct_authorities: usize,
    /// Required number of distinct key-custody domains.
    #[serde(default = "default_zero")]
    pub min_distinct_custody_domains: usize,
}

/// Attribute selected by a cross-group relational constraint.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RelationAttribute {
    Identity,
    Family,
    Authority,
    CustodyDomain,
}

/// Relationship required across named groups.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum RelationMode {
    /// At least one attribute value must be present in every named group.
    Same,
    /// There must be an injective assignment of one attribute value per group.
    Distinct,
}

/// A bounded relational constraint across signer groups.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupRelation {
    pub relation_id: String,
    pub attribute: RelationAttribute,
    pub mode: RelationMode,
    pub groups: Vec<GroupId>,
}

/// A conjunction of group requirements and relational constraints.
///
/// Every requirement in a clause must be satisfied. A policy may contain
/// multiple clauses; satisfying any one clause accepts the input. This remains
/// a small, non-Turing-complete disjunctive-normal-form policy model.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyClause {
    pub clause_id: String,
    pub required_groups: Vec<GroupRequirement>,
    #[serde(default)]
    pub relations: Vec<GroupRelation>,
    /// Inclusive clause activation boundary.
    #[serde(default)]
    pub active_from: Option<i64>,
    /// Exclusive clause deactivation boundary.
    #[serde(default)]
    pub active_until: Option<i64>,
}

/// Representation-neutral authorization policy.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignaturePolicy {
    pub policy_id: String,
    pub version: u32,
    /// Monotonic anti-rollback epoch for this policy domain.
    #[serde(default = "default_policy_epoch")]
    pub epoch: u64,
    /// SHA-256 of the canonical preceding policy, when this is a successor.
    #[serde(default)]
    pub previous_policy_hash: Option<String>,
    /// Inclusive policy activation boundary.
    #[serde(default)]
    pub active_from: Option<i64>,
    /// Exclusive policy expiry boundary.
    #[serde(default)]
    pub expires_at: Option<i64>,
    #[serde(default = "default_max_signature_observations")]
    pub max_signature_observations: usize,
    #[serde(default = "default_max_signature_candidates")]
    pub max_signature_candidates: usize,
    pub family_registry: Vec<FamilyDefinition>,
    pub algorithm_registry: Vec<AlgorithmDefinition>,
    pub group_definitions: Vec<GroupDefinition>,
    /// Any active satisfied clause accepts; all requirements inside a clause are ANDed.
    pub accept_if_any: Vec<PolicyClause>,
}

/// External state required for rollback-safe policy evaluation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvaluationContext {
    pub evaluation_time: i64,
    /// Highest policy epoch already committed for this policy domain.
    pub minimum_policy_epoch: u64,
}

/// Failure returned when validating a signed policy-chain transition.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyTransitionError {
    #[error("policy domain changed from {previous:?} to {next:?}")]
    PolicyDomainChanged { previous: String, next: String },
    #[error("policy epoch did not advance: previous={previous}, next={next}")]
    EpochDidNotAdvance { previous: u64, next: u64 },
    #[error("successor policy is missing previous_policy_hash")]
    MissingPreviousPolicyHash,
    #[error("successor policy references {actual}, expected {expected}")]
    PreviousPolicyHashMismatch { expected: String, actual: String },
    #[error("canonical policy serialization failed: {0}")]
    Serialization(String),
}

/// Result of cryptographic verification performed before policy evaluation.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    Valid,
    Invalid,
    Malformed,
}

/// Transport-neutral signature observation consumed by the evaluator.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignatureCandidate {
    pub key_name: String,
    pub algorithm: AlgorithmId,
    /// Opaque identity of the signature bytes. Exact duplicates share this ID.
    pub signature_id: String,
    pub verification: VerificationOutcome,
}

/// Stable decision value used by vectors and reports.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Accept,
    Refuse,
}

/// Stable diagnostic/refusal codes.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    InvalidPolicy,
    PolicyRollback,
    PolicyNotActive,
    PolicyExpired,
    NoActiveClause,
    TooManyObservations,
    TooManyCandidates,
    DuplicateCandidate,
    ConflictingCandidate,
    UnknownKey,
    AlgorithmMismatch,
    InvalidSignature,
    MalformedSignature,
    RevokedKey,
    NotYetValidKey,
    ExpiredKey,
    ObserveOnlyFamily,
    DeprecatedFamily,
    ForbiddenFamily,
    MissingRequiredGroup,
    MissingRequiredRelation,
}

/// Candidate-level diagnostic suitable for machine-readable evidence.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CandidateDiagnostic {
    pub key_name: String,
    pub algorithm: AlgorithmId,
    pub signature_id: String,
    pub code: ReasonCode,
}

/// Per-group observation for one policy clause.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GroupObservation {
    pub group: GroupId,
    pub required_identities: usize,
    pub observed_identities: usize,
    pub signer_identities: Vec<IdentityId>,
    pub required_families: usize,
    pub observed_families: usize,
    pub families: Vec<FamilyId>,
    pub required_authorities: usize,
    pub observed_authorities: usize,
    pub authorities: Vec<AuthorityId>,
    pub required_custody_domains: usize,
    pub observed_custody_domains: usize,
    pub custody_domains: Vec<CustodyDomainId>,
}

/// One deterministic witness for a satisfied relation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelationWitness {
    pub group: GroupId,
    pub value: String,
}

/// Evaluation of one relational constraint.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RelationEvaluation {
    pub relation_id: String,
    pub attribute: RelationAttribute,
    pub mode: RelationMode,
    pub satisfied: bool,
    pub witnesses: Vec<RelationWitness>,
}

/// Evaluation of one conjunction clause.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClauseEvaluation {
    pub clause_id: String,
    pub active: bool,
    pub satisfied: bool,
    pub groups: Vec<GroupObservation>,
    pub relations: Vec<RelationEvaluation>,
}

/// Complete deterministic policy decision.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_epoch: u64,
    pub satisfied_clause: Option<String>,
    pub raw_candidate_count: usize,
    pub unique_candidate_count: usize,
    pub eligible_candidate_count: usize,
    pub reason_codes: BTreeSet<ReasonCode>,
    pub candidate_diagnostics: Vec<CandidateDiagnostic>,
    pub clause_evaluations: Vec<ClauseEvaluation>,
}

impl PolicyDecision {
    fn refusal(policy: &SignaturePolicy, code: ReasonCode, raw_candidate_count: usize) -> Self {
        Self {
            decision: Decision::Refuse,
            policy_id: policy.policy_id.clone(),
            policy_version: policy.version,
            policy_epoch: policy.epoch,
            satisfied_clause: None,
            raw_candidate_count,
            unique_candidate_count: 0,
            eligible_candidate_count: 0,
            reason_codes: BTreeSet::from([code]),
            candidate_diagnostics: Vec::new(),
            clause_evaluations: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct GroupMember {
    signer_identity: IdentityId,
    family: FamilyId,
    authority: AuthorityId,
    custody_domain: CustodyDomainId,
}

/// Evaluate normalized signature candidates against an explicit policy.
///
/// `evaluation_time` is an integer fixture clock. Production adapters may map
/// Unix time or a signed policy epoch into this field; the evaluator only
/// requires a consistent ordering.
pub fn evaluate_policy(
    policy: &SignaturePolicy,
    trusted_keys: &[TrustedKey],
    candidates: &[SignatureCandidate],
    evaluation_time: i64,
) -> PolicyDecision {
    evaluate_policy_with_context(
        policy,
        trusted_keys,
        candidates,
        EvaluationContext {
            evaluation_time,
            minimum_policy_epoch: 0,
        },
    )
}

/// Evaluate with explicit anti-rollback and activation context.
pub fn evaluate_policy_with_context(
    policy: &SignaturePolicy,
    trusted_keys: &[TrustedKey],
    candidates: &[SignatureCandidate],
    context: EvaluationContext,
) -> PolicyDecision {
    if !policy_is_well_formed(policy, trusted_keys) {
        return PolicyDecision::refusal(policy, ReasonCode::InvalidPolicy, candidates.len());
    }
    if policy.epoch < context.minimum_policy_epoch {
        return PolicyDecision::refusal(policy, ReasonCode::PolicyRollback, candidates.len());
    }
    if policy
        .active_from
        .is_some_and(|active_from| context.evaluation_time < active_from)
    {
        return PolicyDecision::refusal(policy, ReasonCode::PolicyNotActive, candidates.len());
    }
    if policy
        .expires_at
        .is_some_and(|expires_at| context.evaluation_time >= expires_at)
    {
        return PolicyDecision::refusal(policy, ReasonCode::PolicyExpired, candidates.len());
    }

    let evaluation_time = context.evaluation_time;
    if candidates.len() > policy.max_signature_observations {
        return PolicyDecision::refusal(policy, ReasonCode::TooManyObservations, candidates.len());
    }

    let mut diagnostics = Vec::new();
    let mut reason_codes = BTreeSet::new();
    let mut unique_candidates = BTreeMap::new();
    let mut has_conflict = false;

    for candidate in candidates {
        let identity = (
            candidate.key_name.clone(),
            candidate.algorithm.clone(),
            candidate.signature_id.clone(),
        );
        match unique_candidates.entry(identity) {
            Entry::Vacant(entry) => {
                entry.insert(candidate.verification);
            }
            Entry::Occupied(entry) if *entry.get() == candidate.verification => {
                reason_codes.insert(ReasonCode::DuplicateCandidate);
                diagnostics.push(candidate_diagnostic(
                    candidate,
                    ReasonCode::DuplicateCandidate,
                ));
            }
            Entry::Occupied(_) => {
                has_conflict = true;
                reason_codes.insert(ReasonCode::ConflictingCandidate);
                diagnostics.push(candidate_diagnostic(
                    candidate,
                    ReasonCode::ConflictingCandidate,
                ));
            }
        }
    }

    if has_conflict {
        sort_candidate_diagnostics(&mut diagnostics);
        return PolicyDecision {
            decision: Decision::Refuse,
            policy_id: policy.policy_id.clone(),
            policy_version: policy.version,
            policy_epoch: policy.epoch,
            satisfied_clause: None,
            raw_candidate_count: candidates.len(),
            unique_candidate_count: unique_candidates.len(),
            eligible_candidate_count: 0,
            reason_codes,
            candidate_diagnostics: diagnostics,
            clause_evaluations: Vec::new(),
        };
    }

    if unique_candidates.len() > policy.max_signature_candidates {
        reason_codes.insert(ReasonCode::TooManyCandidates);
        sort_candidate_diagnostics(&mut diagnostics);
        return PolicyDecision {
            decision: Decision::Refuse,
            policy_id: policy.policy_id.clone(),
            policy_version: policy.version,
            policy_epoch: policy.epoch,
            satisfied_clause: None,
            raw_candidate_count: candidates.len(),
            unique_candidate_count: unique_candidates.len(),
            eligible_candidate_count: 0,
            reason_codes,
            candidate_diagnostics: diagnostics,
            clause_evaluations: Vec::new(),
        };
    }

    let families: HashMap<&str, &FamilyDefinition> = policy
        .family_registry
        .iter()
        .map(|definition| (definition.family.as_str(), definition))
        .collect();
    let algorithms: HashMap<&str, &AlgorithmDefinition> = policy
        .algorithm_registry
        .iter()
        .map(|definition| (definition.algorithm.as_str(), definition))
        .collect();
    let mut keys_by_name: HashMap<&str, Vec<&TrustedKey>> = HashMap::new();
    for key in trusted_keys {
        keys_by_name.entry(&key.key_name).or_default().push(key);
    }

    let mut group_members: BTreeMap<&str, BTreeSet<GroupMember>> = policy
        .group_definitions
        .iter()
        .map(|definition| (definition.group.as_str(), BTreeSet::new()))
        .collect();
    let mut eligible_candidate_count = 0;

    for ((key_name, algorithm, signature_id), verification) in &unique_candidates {
        let candidate = SignatureCandidate {
            key_name: key_name.clone(),
            algorithm: algorithm.clone(),
            signature_id: signature_id.clone(),
            verification: *verification,
        };
        let verification_code = match candidate.verification {
            VerificationOutcome::Valid => None,
            VerificationOutcome::Invalid => Some(ReasonCode::InvalidSignature),
            VerificationOutcome::Malformed => Some(ReasonCode::MalformedSignature),
        };
        if let Some(code) = verification_code {
            reason_codes.insert(code);
            diagnostics.push(candidate_diagnostic(&candidate, code));
            continue;
        }

        let Some(named_keys) = keys_by_name.get(candidate.key_name.as_str()) else {
            reason_codes.insert(ReasonCode::UnknownKey);
            diagnostics.push(candidate_diagnostic(&candidate, ReasonCode::UnknownKey));
            continue;
        };

        let Some(key) = named_keys
            .iter()
            .copied()
            .find(|key| key.algorithm == candidate.algorithm)
        else {
            reason_codes.insert(ReasonCode::AlgorithmMismatch);
            diagnostics.push(candidate_diagnostic(
                &candidate,
                ReasonCode::AlgorithmMismatch,
            ));
            continue;
        };

        let status_code = if key.revoked {
            Some(ReasonCode::RevokedKey)
        } else if key
            .valid_from
            .is_some_and(|valid_from| evaluation_time < valid_from)
        {
            Some(ReasonCode::NotYetValidKey)
        } else if key
            .valid_until
            .is_some_and(|valid_until| evaluation_time >= valid_until)
        {
            Some(ReasonCode::ExpiredKey)
        } else {
            None
        };
        if let Some(code) = status_code {
            reason_codes.insert(code);
            diagnostics.push(candidate_diagnostic(&candidate, code));
            continue;
        }

        let Some(algorithm_definition) = algorithms.get(key.algorithm.as_str()).copied() else {
            // A well-formed policy requires this mapping. Keep the branch
            // fail-closed in case future callers bypass validation.
            reason_codes.insert(ReasonCode::InvalidPolicy);
            diagnostics.push(candidate_diagnostic(&candidate, ReasonCode::InvalidPolicy));
            continue;
        };
        let Some(family_definition) = families.get(algorithm_definition.family.as_str()).copied()
        else {
            reason_codes.insert(ReasonCode::InvalidPolicy);
            diagnostics.push(candidate_diagnostic(&candidate, ReasonCode::InvalidPolicy));
            continue;
        };
        match family_definition.status {
            FamilyStatus::Enabled => {}
            FamilyStatus::ObserveOnly => {
                reason_codes.insert(ReasonCode::ObserveOnlyFamily);
                diagnostics.push(candidate_diagnostic(
                    &candidate,
                    ReasonCode::ObserveOnlyFamily,
                ));
                continue;
            }
            FamilyStatus::Deprecated => {
                reason_codes.insert(ReasonCode::DeprecatedFamily);
                diagnostics.push(candidate_diagnostic(
                    &candidate,
                    ReasonCode::DeprecatedFamily,
                ));
            }
            FamilyStatus::Forbidden => {
                reason_codes.insert(ReasonCode::ForbiddenFamily);
                diagnostics.push(candidate_diagnostic(
                    &candidate,
                    ReasonCode::ForbiddenFamily,
                ));
                continue;
            }
        }

        eligible_candidate_count += 1;
        let member = GroupMember {
            signer_identity: key.signer_identity.clone(),
            family: algorithm_definition.family.clone(),
            authority: key.authority.clone(),
            custody_domain: key.custody_domain.clone(),
        };
        for definition in &policy.group_definitions {
            if definition.predicate.matches(key, algorithm_definition) {
                group_members
                    .entry(definition.group.as_str())
                    .or_default()
                    .insert(member.clone());
            }
        }
    }

    let mut clause_evaluations = Vec::with_capacity(policy.accept_if_any.len());
    let mut satisfied_clause = None;

    let mut active_clause_count = 0;
    for clause in &policy.accept_if_any {
        let active = clause
            .active_from
            .is_none_or(|active_from| evaluation_time >= active_from)
            && clause
                .active_until
                .is_none_or(|active_until| evaluation_time < active_until);
        if active {
            active_clause_count += 1;
        }
        let mut groups = Vec::with_capacity(clause.required_groups.len());
        let mut clause_satisfied = active;

        for requirement in &clause.required_groups {
            let members = group_members
                .get(requirement.group.as_str())
                .cloned()
                .unwrap_or_default();
            let signer_identities = distinct_member_values(&members, RelationAttribute::Identity);
            let families = distinct_member_values(&members, RelationAttribute::Family);
            let authorities = distinct_member_values(&members, RelationAttribute::Authority);
            let custody_domains =
                distinct_member_values(&members, RelationAttribute::CustodyDomain);

            let group_satisfied = signer_identities.len() >= requirement.min_distinct_identities
                && families.len() >= requirement.min_distinct_families
                && authorities.len() >= requirement.min_distinct_authorities
                && custody_domains.len() >= requirement.min_distinct_custody_domains;
            clause_satisfied &= group_satisfied;
            groups.push(GroupObservation {
                group: requirement.group.clone(),
                required_identities: requirement.min_distinct_identities,
                observed_identities: signer_identities.len(),
                signer_identities: signer_identities.into_iter().collect(),
                required_families: requirement.min_distinct_families,
                observed_families: families.len(),
                families: families.into_iter().collect(),
                required_authorities: requirement.min_distinct_authorities,
                observed_authorities: authorities.len(),
                authorities: authorities.into_iter().collect(),
                required_custody_domains: requirement.min_distinct_custody_domains,
                observed_custody_domains: custody_domains.len(),
                custody_domains: custody_domains.into_iter().collect(),
            });
        }

        let mut relations = Vec::with_capacity(clause.relations.len());
        for relation in &clause.relations {
            let evaluation = evaluate_relation(relation, &group_members);
            clause_satisfied &= evaluation.satisfied;
            relations.push(evaluation);
        }

        if clause_satisfied && satisfied_clause.is_none() {
            satisfied_clause = Some(clause.clause_id.clone());
        }
        clause_evaluations.push(ClauseEvaluation {
            clause_id: clause.clause_id.clone(),
            active,
            satisfied: clause_satisfied,
            groups,
            relations,
        });
    }

    let decision = if satisfied_clause.is_some() {
        Decision::Accept
    } else if active_clause_count == 0 {
        reason_codes.insert(ReasonCode::NoActiveClause);
        Decision::Refuse
    } else {
        let has_failed_relation = clause_evaluations
            .iter()
            .filter(|clause| clause.active)
            .flat_map(|clause| &clause.relations)
            .any(|relation| !relation.satisfied);
        if has_failed_relation {
            reason_codes.insert(ReasonCode::MissingRequiredRelation);
        }
        reason_codes.insert(ReasonCode::MissingRequiredGroup);
        Decision::Refuse
    };

    sort_candidate_diagnostics(&mut diagnostics);

    PolicyDecision {
        decision,
        policy_id: policy.policy_id.clone(),
        policy_version: policy.version,
        policy_epoch: policy.epoch,
        satisfied_clause,
        raw_candidate_count: candidates.len(),
        unique_candidate_count: unique_candidates.len(),
        eligible_candidate_count,
        reason_codes,
        candidate_diagnostics: diagnostics,
        clause_evaluations,
    }
}

fn distinct_member_values(
    members: &BTreeSet<GroupMember>,
    attribute: RelationAttribute,
) -> BTreeSet<String> {
    members
        .iter()
        .map(|member| member_value(member, attribute).to_string())
        .collect()
}

fn member_value(member: &GroupMember, attribute: RelationAttribute) -> &str {
    match attribute {
        RelationAttribute::Identity => &member.signer_identity,
        RelationAttribute::Family => &member.family,
        RelationAttribute::Authority => &member.authority,
        RelationAttribute::CustodyDomain => &member.custody_domain,
    }
}

fn evaluate_relation(
    relation: &GroupRelation,
    group_members: &BTreeMap<&str, BTreeSet<GroupMember>>,
) -> RelationEvaluation {
    let groups: Vec<(String, BTreeSet<String>)> = relation
        .groups
        .iter()
        .map(|group| {
            let values = group_members
                .get(group.as_str())
                .map(|members| distinct_member_values(members, relation.attribute))
                .unwrap_or_default();
            (group.clone(), values)
        })
        .collect();

    let witnesses = match relation.mode {
        RelationMode::Same => same_relation_witnesses(&groups),
        RelationMode::Distinct => distinct_relation_witnesses(&groups),
    };
    RelationEvaluation {
        relation_id: relation.relation_id.clone(),
        attribute: relation.attribute,
        mode: relation.mode,
        satisfied: witnesses.is_some(),
        witnesses: witnesses.unwrap_or_default(),
    }
}

fn same_relation_witnesses(groups: &[(String, BTreeSet<String>)]) -> Option<Vec<RelationWitness>> {
    let first = groups.first()?;
    let value = first
        .1
        .iter()
        .find(|value| groups.iter().all(|(_, values)| values.contains(*value)))?
        .clone();
    Some(
        groups
            .iter()
            .map(|(group, _)| RelationWitness {
                group: group.clone(),
                value: value.clone(),
            })
            .collect(),
    )
}

fn distinct_relation_witnesses(
    groups: &[(String, BTreeSet<String>)],
) -> Option<Vec<RelationWitness>> {
    fn assign(
        groups: &[(String, BTreeSet<String>)],
        index: usize,
        used: &mut BTreeSet<String>,
        witnesses: &mut Vec<RelationWitness>,
    ) -> bool {
        if index == groups.len() {
            return true;
        }
        let (group, values) = &groups[index];
        for value in values {
            if used.insert(value.clone()) {
                witnesses.push(RelationWitness {
                    group: group.clone(),
                    value: value.clone(),
                });
                if assign(groups, index + 1, used, witnesses) {
                    return true;
                }
                witnesses.pop();
                used.remove(value);
            }
        }
        false
    }

    let mut used = BTreeSet::new();
    let mut witnesses = Vec::with_capacity(groups.len());
    assign(groups, 0, &mut used, &mut witnesses).then_some(witnesses)
}

fn sort_candidate_diagnostics(diagnostics: &mut [CandidateDiagnostic]) {
    diagnostics.sort_by(|left, right| {
        (
            left.key_name.as_str(),
            left.algorithm.as_str(),
            left.signature_id.as_str(),
            left.code,
        )
            .cmp(&(
                right.key_name.as_str(),
                right.algorithm.as_str(),
                right.signature_id.as_str(),
                right.code,
            ))
    });
}

fn candidate_diagnostic(candidate: &SignatureCandidate, code: ReasonCode) -> CandidateDiagnostic {
    CandidateDiagnostic {
        key_name: candidate.key_name.clone(),
        algorithm: candidate.algorithm.clone(),
        signature_id: candidate.signature_id.clone(),
        code,
    }
}

/// Canonicalize semantically unordered policy collections before hashing or
/// persisting policy-chain state.
pub fn canonicalize_policy(policy: &mut SignaturePolicy) {
    policy
        .family_registry
        .sort_by(|left, right| left.family.cmp(&right.family));
    policy
        .algorithm_registry
        .sort_by(|left, right| left.algorithm.cmp(&right.algorithm));
    policy
        .group_definitions
        .sort_by(|left, right| left.group.cmp(&right.group));
    for clause in &mut policy.accept_if_any {
        clause
            .required_groups
            .sort_by(|left, right| left.group.cmp(&right.group));
        clause.relations.sort_by(|left, right| {
            (left.relation_id.as_str(), left.attribute, left.mode).cmp(&(
                right.relation_id.as_str(),
                right.attribute,
                right.mode,
            ))
        });
        for relation in &mut clause.relations {
            relation.groups.sort();
        }
    }
    policy
        .accept_if_any
        .sort_by(|left, right| left.clause_id.cmp(&right.clause_id));
}

/// SHA-256 of the canonical JSON policy representation.
pub fn canonical_policy_sha256(policy: &SignaturePolicy) -> Result<String, serde_json::Error> {
    let mut canonical = policy.clone();
    canonicalize_policy(&mut canonical);
    let bytes = serde_json::to_vec(&canonical)?;
    let digest = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

/// Validate an append-only policy-chain transition.
pub fn validate_policy_transition(
    previous: &SignaturePolicy,
    next: &SignaturePolicy,
) -> Result<(), PolicyTransitionError> {
    if previous.policy_id != next.policy_id {
        return Err(PolicyTransitionError::PolicyDomainChanged {
            previous: previous.policy_id.clone(),
            next: next.policy_id.clone(),
        });
    }
    if next.epoch <= previous.epoch {
        return Err(PolicyTransitionError::EpochDidNotAdvance {
            previous: previous.epoch,
            next: next.epoch,
        });
    }
    let expected = canonical_policy_sha256(previous)
        .map_err(|error| PolicyTransitionError::Serialization(error.to_string()))?;
    let actual = next
        .previous_policy_hash
        .clone()
        .ok_or(PolicyTransitionError::MissingPreviousPolicyHash)?;
    if actual != expected {
        return Err(PolicyTransitionError::PreviousPolicyHashMismatch { expected, actual });
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Validate policy and trusted-key structure without evaluating signature evidence.
///
/// This is used by control-plane state handling before a candidate set exists.
pub fn validate_policy_structure(policy: &SignaturePolicy, trusted_keys: &[TrustedKey]) -> bool {
    policy_is_well_formed(policy, trusted_keys)
}

fn policy_is_well_formed(policy: &SignaturePolicy, trusted_keys: &[TrustedKey]) -> bool {
    if policy.policy_id.is_empty()
        || policy.version == 0
        || policy.epoch == 0
        || policy.accept_if_any.is_empty()
        || policy.family_registry.is_empty()
        || policy.algorithm_registry.is_empty()
        || policy.group_definitions.is_empty()
        || policy
            .previous_policy_hash
            .as_deref()
            .is_some_and(|hash| !is_lower_hex_sha256(hash))
        || policy
            .active_from
            .zip(policy.expires_at)
            .is_some_and(|(start, end)| start >= end)
        || policy.max_signature_observations == 0
        || policy.max_signature_observations > MAX_CONFIGURABLE_SIGNATURE_OBSERVATIONS
        || policy.max_signature_candidates == 0
        || policy.max_signature_candidates > MAX_CONFIGURABLE_SIGNATURE_CANDIDATES
        || policy.max_signature_candidates > policy.max_signature_observations
    {
        return false;
    }

    let mut family_ids = HashSet::new();
    for definition in &policy.family_registry {
        if definition.family.is_empty() || !family_ids.insert(definition.family.as_str()) {
            return false;
        }
    }

    let mut algorithm_ids = HashSet::new();
    for definition in &policy.algorithm_registry {
        if definition.algorithm.is_empty()
            || definition.family.is_empty()
            || definition.assurance_class.is_empty()
            || !family_ids.contains(definition.family.as_str())
            || !algorithm_ids.insert(definition.algorithm.as_str())
        {
            return false;
        }
    }

    let mut group_ids = HashSet::new();
    for definition in &policy.group_definitions {
        if definition.group.is_empty()
            || !group_ids.insert(definition.group.as_str())
            || !definition.predicate.is_well_formed()
            || !all_nonempty(&definition.predicate.allowed_algorithms)
            || !all_nonempty(&definition.predicate.allowed_families)
            || !all_nonempty(&definition.predicate.allowed_assurance_classes)
            || !all_nonempty(&definition.predicate.required_roles)
            || !all_nonempty(&definition.predicate.allowed_authorities)
            || !all_nonempty(&definition.predicate.allowed_custody_domains)
            || !definition
                .predicate
                .allowed_algorithms
                .iter()
                .all(|algorithm| algorithm_ids.contains(algorithm.as_str()))
            || !definition
                .predicate
                .allowed_families
                .iter()
                .all(|family| family_ids.contains(family.as_str()))
        {
            return false;
        }
    }

    let mut clause_ids = HashSet::new();
    for clause in &policy.accept_if_any {
        if clause.clause_id.is_empty()
            || !clause_ids.insert(clause.clause_id.as_str())
            || clause.required_groups.is_empty()
            || clause
                .active_from
                .zip(clause.active_until)
                .is_some_and(|(start, end)| start >= end)
        {
            return false;
        }
        let mut required_groups = HashSet::new();
        for requirement in &clause.required_groups {
            let has_threshold = requirement.min_distinct_identities > 0
                || requirement.min_distinct_families > 0
                || requirement.min_distinct_authorities > 0
                || requirement.min_distinct_custody_domains > 0;
            if requirement.group.is_empty()
                || !has_threshold
                || !group_ids.contains(requirement.group.as_str())
                || !required_groups.insert(requirement.group.as_str())
            {
                return false;
            }
        }

        let mut relation_ids = HashSet::new();
        for relation in &clause.relations {
            let relation_groups: HashSet<&str> =
                relation.groups.iter().map(String::as_str).collect();
            if relation.relation_id.is_empty()
                || !relation_ids.insert(relation.relation_id.as_str())
                || relation.groups.len() < 2
                || relation_groups.len() != relation.groups.len()
                || !relation_groups
                    .iter()
                    .all(|group| required_groups.contains(group))
            {
                return false;
            }
        }
    }

    let mut key_ids = HashSet::new();
    let mut wire_keys = HashSet::new();
    for key in trusted_keys {
        if key.key_id.is_empty()
            || key.key_name.is_empty()
            || key.signer_identity.is_empty()
            || key.algorithm.is_empty()
            || key.authority.is_empty()
            || key.custody_domain.is_empty()
            || !all_nonempty(&key.roles)
            || !algorithm_ids.contains(key.algorithm.as_str())
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

fn all_nonempty(values: &BTreeSet<String>) -> bool {
    values.iter().all(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn algorithm_registry() -> Vec<AlgorithmDefinition> {
        vec![
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
            AlgorithmDefinition {
                algorithm: "slh-dsa-128s".into(),
                family: "hash_based".into(),
                assurance_class: "post_quantum".into(),
            },
        ]
    }

    fn group(group: &str, assurance: &str) -> GroupDefinition {
        GroupDefinition {
            group: group.into(),
            predicate: GroupPredicate {
                allowed_assurance_classes: BTreeSet::from([assurance.into()]),
                ..GroupPredicate::default()
            },
        }
    }

    fn requirement(group: &str, identities: usize) -> GroupRequirement {
        GroupRequirement {
            group: group.into(),
            min_distinct_identities: identities,
            min_distinct_families: 0,
            min_distinct_authorities: 0,
            min_distinct_custody_domains: 0,
        }
    }

    fn policy(required_groups: &[(&str, usize)]) -> SignaturePolicy {
        SignaturePolicy {
            policy_id: "test-policy".into(),
            version: 1,
            epoch: 1,
            previous_policy_hash: None,
            active_from: None,
            expires_at: None,
            max_signature_observations: DEFAULT_MAX_SIGNATURE_OBSERVATIONS,
            max_signature_candidates: DEFAULT_MAX_SIGNATURE_CANDIDATES,
            family_registry: vec![
                FamilyDefinition {
                    family: "elliptic_curve".into(),
                    status: FamilyStatus::Enabled,
                },
                FamilyDefinition {
                    family: "lattice".into(),
                    status: FamilyStatus::Enabled,
                },
                FamilyDefinition {
                    family: "hash_based".into(),
                    status: FamilyStatus::Enabled,
                },
            ],
            algorithm_registry: algorithm_registry(),
            group_definitions: vec![
                group("classical", "classical"),
                group("post-quantum", "post_quantum"),
            ],
            accept_if_any: vec![PolicyClause {
                clause_id: "required".into(),
                required_groups: required_groups
                    .iter()
                    .map(|(group, count)| requirement(group, *count))
                    .collect(),
                relations: Vec::new(),
                active_from: None,
                active_until: None,
            }],
        }
    }

    fn key(id: &str, name: &str, identity: &str, algorithm: &str) -> TrustedKey {
        TrustedKey {
            key_id: id.into(),
            key_name: name.into(),
            signer_identity: identity.into(),
            algorithm: algorithm.into(),
            roles: BTreeSet::from(["cache-signing".into()]),
            authority: identity.into(),
            custody_domain: id.into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        }
    }

    fn candidate(name: &str, algorithm: &str, signature_id: &str) -> SignatureCandidate {
        SignatureCandidate {
            key_name: name.into(),
            algorithm: algorithm.into(),
            signature_id: signature_id.into(),
            verification: VerificationOutcome::Valid,
        }
    }

    #[test]
    fn hybrid_policy_requires_both_typed_groups() {
        let trusted = vec![
            key("ed", "cache", "cache-owner", "ed25519"),
            key("pq", "cache", "cache-owner", "ml-dsa-65"),
        ];
        let only_classical = vec![candidate("cache", "ed25519", "ed-sig")];
        let refused = evaluate_policy(
            &policy(&[("classical", 1), ("post-quantum", 1)]),
            &trusted,
            &only_classical,
            0,
        );
        assert_eq!(refused.decision, Decision::Refuse);
        assert!(
            refused
                .reason_codes
                .contains(&ReasonCode::MissingRequiredGroup)
        );

        let both = vec![
            candidate("cache", "ed25519", "ed-sig"),
            candidate("cache", "ml-dsa-65", "pq-sig"),
        ];
        let accepted = evaluate_policy(
            &policy(&[("classical", 1), ("post-quantum", 1)]),
            &trusted,
            &both,
            0,
        );
        assert_eq!(accepted.decision, Decision::Accept);
    }

    #[test]
    fn policy_registry_prevents_classical_algorithm_from_satisfying_pq_group() {
        let trusted = vec![key("ed", "cache", "cache-owner", "ed25519")];
        let decision = evaluate_policy(
            &policy(&[("post-quantum", 1)]),
            &trusted,
            &[candidate("cache", "ed25519", "ed-sig")],
            0,
        );
        assert_eq!(decision.decision, Decision::Refuse);
    }

    #[test]
    fn same_identity_relation_binds_hybrid_signatures() {
        let mut bound = policy(&[("classical", 1), ("post-quantum", 1)]);
        bound.accept_if_any[0].relations.push(GroupRelation {
            relation_id: "same-owner".into(),
            attribute: RelationAttribute::Identity,
            mode: RelationMode::Same,
            groups: vec!["classical".into(), "post-quantum".into()],
        });
        let trusted = vec![
            key("ed", "cache", "owner-a", "ed25519"),
            key("pq", "cache", "owner-b", "ml-dsa-65"),
        ];
        let decision = evaluate_policy(
            &bound,
            &trusted,
            &[
                candidate("cache", "ed25519", "ed-sig"),
                candidate("cache", "ml-dsa-65", "pq-sig"),
            ],
            0,
        );
        assert_eq!(decision.decision, Decision::Refuse);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::MissingRequiredRelation)
        );
    }

    #[test]
    fn distinct_identity_relation_supports_independent_authorities() {
        let mut independent = policy(&[("classical", 1), ("post-quantum", 1)]);
        independent.accept_if_any[0].relations.push(GroupRelation {
            relation_id: "independent-owners".into(),
            attribute: RelationAttribute::Identity,
            mode: RelationMode::Distinct,
            groups: vec!["classical".into(), "post-quantum".into()],
        });
        let trusted = vec![
            key("ed", "cache", "owner-a", "ed25519"),
            key("pq", "cache", "owner-b", "ml-dsa-65"),
        ];
        let decision = evaluate_policy(
            &independent,
            &trusted,
            &[
                candidate("cache", "ed25519", "ed-sig"),
                candidate("cache", "ml-dsa-65", "pq-sig"),
            ],
            0,
        );
        assert_eq!(decision.decision, Decision::Accept);
    }

    #[test]
    fn family_diversity_counts_families_not_algorithms_or_keys() {
        let mut diverse = policy(&[("post-quantum", 1)]);
        diverse.accept_if_any[0].required_groups[0].min_distinct_families = 2;
        let trusted = vec![
            key("lattice", "cache-lattice", "owner-a", "ml-dsa-65"),
            key("hash", "cache-hash", "owner-b", "slh-dsa-128s"),
        ];
        let decision = evaluate_policy(
            &diverse,
            &trusted,
            &[
                candidate("cache-lattice", "ml-dsa-65", "lattice-sig"),
                candidate("cache-hash", "slh-dsa-128s", "hash-sig"),
            ],
            0,
        );
        assert_eq!(decision.decision, Decision::Accept);
    }

    #[test]
    fn raw_observation_cap_applies_before_deduplication() {
        let mut capped = policy(&[("classical", 1)]);
        capped.max_signature_observations = 2;
        capped.max_signature_candidates = 2;
        let trusted = vec![key("ed", "cache", "cache-owner", "ed25519")];
        let duplicate = candidate("cache", "ed25519", "same-signature");
        let decision = evaluate_policy(
            &capped,
            &trusted,
            &[duplicate.clone(), duplicate.clone(), duplicate],
            0,
        );
        assert_eq!(decision.decision, Decision::Refuse);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::TooManyObservations)
        );
    }

    #[test]
    fn duplicate_signatures_do_not_inflate_identity_thresholds() {
        let trusted = vec![key("ed", "cache", "cache-owner", "ed25519")];
        let duplicate = candidate("cache", "ed25519", "same-signature");
        let decision = evaluate_policy(
            &policy(&[("classical", 2)]),
            &trusted,
            &[duplicate.clone(), duplicate],
            0,
        );
        assert_eq!(decision.decision, Decision::Refuse);
        assert_eq!(decision.unique_candidate_count, 1);
        assert!(
            decision
                .reason_codes
                .contains(&ReasonCode::DuplicateCandidate)
        );
    }

    #[test]
    fn forbidden_family_is_ineligible_and_hash_based_recovery_accepts() {
        let mut recovering = policy(&[("classical", 1), ("post-quantum", 1)]);
        recovering.family_registry[1].status = FamilyStatus::Forbidden;
        let trusted = vec![
            key("ed", "cache", "owner", "ed25519"),
            key("lattice", "cache", "owner", "ml-dsa-65"),
            key("hash", "cache", "owner", "slh-dsa-128s"),
        ];
        let decision = evaluate_policy(
            &recovering,
            &trusted,
            &[
                candidate("cache", "ed25519", "ed-sig"),
                candidate("cache", "ml-dsa-65", "lattice-sig"),
                candidate("cache", "slh-dsa-128s", "hash-sig"),
            ],
            0,
        );
        assert_eq!(decision.decision, Decision::Accept);
        assert!(decision.reason_codes.contains(&ReasonCode::ForbiddenFamily));
    }

    #[test]
    fn committed_epoch_refuses_policy_rollback() {
        let decision = evaluate_policy_with_context(
            &policy(&[("classical", 1)]),
            &[key("ed", "cache", "owner", "ed25519")],
            &[candidate("cache", "ed25519", "ed-sig")],
            EvaluationContext {
                evaluation_time: 0,
                minimum_policy_epoch: 2,
            },
        );
        assert_eq!(decision.decision, Decision::Refuse);
        assert!(decision.reason_codes.contains(&ReasonCode::PolicyRollback));
    }

    #[test]
    fn policy_chain_binds_monotonic_successors() {
        let previous = policy(&[("classical", 1)]);
        let mut next = previous.clone();
        next.epoch = 2;
        next.previous_policy_hash = Some(canonical_policy_sha256(&previous).unwrap());
        assert_eq!(validate_policy_transition(&previous, &next), Ok(()));

        next.previous_policy_hash = Some("00".repeat(32));
        assert!(matches!(
            validate_policy_transition(&previous, &next),
            Err(PolicyTransitionError::PreviousPolicyHashMismatch { .. })
        ));
    }

    #[test]
    fn expired_clause_is_not_a_permanent_legacy_fallback() {
        let mut migrating = policy(&[("classical", 1)]);
        migrating.accept_if_any[0].active_until = Some(10);
        let decision = evaluate_policy(
            &migrating,
            &[key("ed", "cache", "owner", "ed25519")],
            &[candidate("cache", "ed25519", "ed-sig")],
            10,
        );
        assert_eq!(decision.decision, Decision::Refuse);
        assert!(decision.reason_codes.contains(&ReasonCode::NoActiveClause));
    }

    #[test]
    fn malformed_policy_refuses_instead_of_accepting_vacuously() {
        let malformed = SignaturePolicy {
            policy_id: "empty".into(),
            version: 1,
            epoch: 1,
            previous_policy_hash: None,
            active_from: None,
            expires_at: None,
            max_signature_observations: DEFAULT_MAX_SIGNATURE_OBSERVATIONS,
            max_signature_candidates: DEFAULT_MAX_SIGNATURE_CANDIDATES,
            family_registry: vec![
                FamilyDefinition {
                    family: "elliptic_curve".into(),
                    status: FamilyStatus::Enabled,
                },
                FamilyDefinition {
                    family: "lattice".into(),
                    status: FamilyStatus::Enabled,
                },
                FamilyDefinition {
                    family: "hash_based".into(),
                    status: FamilyStatus::Enabled,
                },
            ],
            algorithm_registry: algorithm_registry(),
            group_definitions: vec![group("classical", "classical")],
            accept_if_any: Vec::new(),
        };
        let decision = evaluate_policy(&malformed, &[], &[], 0);
        assert_eq!(decision.decision, Decision::Refuse);
        assert!(decision.reason_codes.contains(&ReasonCode::InvalidPolicy));
    }
}
