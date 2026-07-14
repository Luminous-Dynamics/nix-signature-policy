#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use nix_signature_policy::policy::{
    AlgorithmDefinition, FamilyDefinition, FamilyStatus, GroupDefinition, GroupPredicate,
    GroupRequirement, PolicyClause, SignatureCandidate, SignaturePolicy, TrustedKey,
    VerificationOutcome, evaluate_policy,
};

fn trusted_keys() -> Vec<TrustedKey> {
    vec![
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
    ]
}

fn requirement(group: &str) -> GroupRequirement {
    GroupRequirement {
        group: group.into(),
        min_distinct_identities: 1,
        min_distinct_families: 0,
        min_distinct_authorities: 0,
        min_distinct_custody_domains: 0,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let max = data.first().copied().unwrap_or(32) as usize % 64 + 1;
    let policy = SignaturePolicy {
        policy_id: "fuzz-hybrid".into(),
        version: 1,
        epoch: 1,
        previous_policy_hash: None,
        active_from: None,
        expires_at: None,
        max_signature_observations: 128,
        max_signature_candidates: max.min(128),
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
            required_groups: vec![requirement("classical"), requirement("post-quantum")],
            relations: Vec::new(),
            active_from: None,
            active_until: None,
        }],
    };

    let mut candidates = Vec::new();
    for (index, byte) in data.iter().copied().skip(1).take(128).enumerate() {
        let verification = match (byte >> 1) % 3 {
            0 => VerificationOutcome::Valid,
            1 => VerificationOutcome::Invalid,
            _ => VerificationOutcome::Malformed,
        };
        let algorithm = if byte & 1 == 0 {
            "ed25519"
        } else {
            "ml-dsa-65"
        };
        candidates.push(SignatureCandidate {
            key_name: "cache".into(),
            algorithm: algorithm.into(),
            signature_id: format!("sig-{index}-{}", byte % 16),
            verification,
        });
    }

    let _ = evaluate_policy(&policy, &trusted_keys(), &candidates, 100);
});
