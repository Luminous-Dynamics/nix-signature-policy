use std::collections::BTreeSet;

use nix_signature_policy::narinfo::{
    MAX_NARINFO_BYTES, MAX_NARINFO_LINE_BYTES, MAX_NARINFO_LINES, MAX_NARINFO_REFERENCES,
    MAX_NARINFO_SIGNATURE_FIELDS, NarInfo,
};
use nix_signature_policy::policy::{
    AlgorithmDefinition, DEFAULT_MAX_SIGNATURE_OBSERVATIONS, Decision, FamilyDefinition,
    FamilyStatus, GroupDefinition, GroupPredicate, GroupRequirement, PolicyClause, ReasonCode,
    SignatureCandidate, SignaturePolicy, TrustedKey, VerificationOutcome, evaluate_policy,
};
use nix_signature_policy::policy_adapters::{
    AlgorithmTaggedSignature, ConformanceInput, NamedSignature, SemanticSignature, SigPqcSignature,
};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};

fn requirement(group: &str) -> GroupRequirement {
    GroupRequirement {
        group: group.into(),
        min_distinct_identities: 1,
        min_distinct_families: 0,
        min_distinct_authorities: 0,
        min_distinct_custody_domains: 0,
    }
}

fn hybrid_policy(max_signature_candidates: usize) -> SignaturePolicy {
    SignaturePolicy {
        policy_id: "property-hybrid".into(),
        version: 1,
        epoch: 1,
        previous_policy_hash: None,
        active_from: None,
        expires_at: None,
        max_signature_observations: DEFAULT_MAX_SIGNATURE_OBSERVATIONS,
        max_signature_candidates,
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
    }
}

fn trusted_keys() -> Vec<TrustedKey> {
    vec![
        TrustedKey {
            key_id: "cache-ed".into(),
            key_name: "cache".into(),
            signer_identity: "cache-owner".into(),
            algorithm: "ed25519".into(),
            roles: BTreeSet::from(["cache-signing".into()]),
            authority: "cache-owner".into(),
            custody_domain: "cache-ed".into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        },
        TrustedKey {
            key_id: "cache-pq".into(),
            key_name: "cache".into(),
            signer_identity: "cache-owner".into(),
            algorithm: "ml-dsa-65".into(),
            roles: BTreeSet::from(["cache-signing".into()]),
            authority: "cache-owner".into(),
            custody_domain: "cache-pq".into(),
            revoked: false,
            valid_from: None,
            valid_until: None,
        },
    ]
}

fn candidate(
    algorithm: &str,
    signature_id: impl Into<String>,
    verification: VerificationOutcome,
) -> SignatureCandidate {
    SignatureCandidate {
        key_name: "cache".into(),
        algorithm: algorithm.into(),
        signature_id: signature_id.into(),
        verification,
    }
}

fn generated_narinfo(references: &[String], separator: &str) -> String {
    format!(
        "StorePath: /nix/store/00000000000000000000000000000000-demo\nURL: nar/demo.nar\nCompression: none\nNarHash: sha256:0000000000000000000000000000000000000000000000000000\nNarSize: 1\nReferences: {}\n",
        references.join(separator)
    )
}

#[test]
fn generated_reference_order_whitespace_and_duplicates_are_canonical() {
    let mut rng = StdRng::seed_from_u64(0x58454e49412d5051);
    for case in 0..128 {
        let mut unique: Vec<String> = (0..rng.gen_range(0..24))
            .map(|index| format!("{case:08x}{index:024x}-ref-{index}"))
            .collect();
        unique.shuffle(&mut rng);

        let canonical = NarInfo::parse(&generated_narinfo(&unique, " "))
            .unwrap()
            .fingerprint()
            .unwrap();

        let mut noisy = unique.clone();
        noisy.extend(unique.iter().take(rng.gen_range(0..=unique.len())).cloned());
        noisy.shuffle(&mut rng);
        let separator = match case % 4 {
            0 => " ",
            1 => "  ",
            2 => "\t",
            _ => " \t ",
        };
        let observed = NarInfo::parse(&generated_narinfo(&noisy, separator))
            .unwrap()
            .fingerprint()
            .unwrap();
        assert_eq!(observed, canonical, "case {case}");
    }
}

#[test]
fn generated_narinfo_round_trip_is_idempotent() {
    for count in 0..64 {
        let references: Vec<String> = (0..count)
            .map(|index| format!("{index:032x}-dependency-{index}"))
            .collect();
        let first = NarInfo::parse(&generated_narinfo(&references, "  ")).unwrap();
        let canonical = first.to_text();
        let second = NarInfo::parse(&canonical).unwrap();
        assert_eq!(second.to_text(), canonical);
        assert_eq!(second.fingerprint().unwrap(), first.fingerprint().unwrap());
    }
}

#[test]
fn narinfo_parser_limits_fail_closed() {
    assert!(NarInfo::parse(&"x".repeat(MAX_NARINFO_BYTES + 1)).is_err());

    let too_many_lines = "Ignored: x\n".repeat(MAX_NARINFO_LINES + 1);
    assert!(NarInfo::parse(&too_many_lines).is_err());

    let long_line = format!(
        "StorePath: /nix/store/demo\nIgnored: {}\nNarHash: sha256:x\nNarSize: 1\nReferences:\n",
        "x".repeat(MAX_NARINFO_LINE_BYTES)
    );
    assert!(NarInfo::parse(&long_line).is_err());

    let references: Vec<String> = (0..=MAX_NARINFO_REFERENCES)
        .map(|_| "x".to_string())
        .collect();
    assert!(NarInfo::parse(&generated_narinfo(&references, " ")).is_err());

    let mut signatures = generated_narinfo(&[], " ");
    signatures.push_str(&"Sig: cache:AAAA\n".repeat(MAX_NARINFO_SIGNATURE_FIELDS + 1));
    assert!(NarInfo::parse(&signatures).is_err());
}

#[test]
fn signature_pair_replacement_is_idempotent_and_preserves_other_keys() {
    let mut info = NarInfo {
        sigs: vec![
            "other:AAAA".into(),
            "cache:old".into(),
            "cache:older".into(),
        ],
        sig_pqc: vec!["other:AQAA".into(), "cache:old-pq".into()],
        ..NarInfo::default()
    };

    for _ in 0..100 {
        info.replace_signature_pair("cache", "cache:new-classical".into(), "cache:new-pq".into())
            .unwrap();
    }

    assert_eq!(
        info.sigs,
        vec![
            String::from("other:AAAA"),
            String::from("cache:new-classical"),
        ]
    );
    assert_eq!(
        info.sig_pqc,
        vec![String::from("other:AQAA"), String::from("cache:new-pq")]
    );

    let before = info.clone();
    assert!(
        info.replace_signature_pair("cache", "other:not-cache".into(), "cache:newer-pq".into(),)
            .is_err()
    );
    assert_eq!(info.to_text(), before.to_text());
}

#[test]
fn policy_decision_is_permutation_invariant() {
    let policy = hybrid_policy(32);
    let trusted = trusted_keys();
    let mut candidates = vec![
        candidate("ed25519", "ed-valid", VerificationOutcome::Valid),
        candidate("ml-dsa-65", "pq-valid", VerificationOutcome::Valid),
        candidate("ed25519", "ed-invalid", VerificationOutcome::Invalid),
        candidate("unknown", "unknown", VerificationOutcome::Valid),
        candidate("ed25519", "ed-invalid", VerificationOutcome::Invalid),
    ];
    let expected = evaluate_policy(&policy, &trusted, &candidates, 100);

    let mut rng = StdRng::seed_from_u64(0x504f4c494359);
    for _ in 0..256 {
        candidates.shuffle(&mut rng);
        assert_eq!(
            evaluate_policy(&policy, &trusted, &candidates, 100),
            expected
        );
    }
}

#[test]
fn contradictory_verification_outcomes_fail_closed_in_every_order() {
    let policy = hybrid_policy(32);
    let trusted = trusted_keys();
    let forward = vec![
        candidate("ed25519", "same", VerificationOutcome::Valid),
        candidate("ed25519", "same", VerificationOutcome::Invalid),
        candidate("ml-dsa-65", "pq", VerificationOutcome::Valid),
    ];
    let mut reverse = forward.clone();
    reverse.reverse();

    let first = evaluate_policy(&policy, &trusted, &forward, 100);
    let second = evaluate_policy(&policy, &trusted, &reverse, 100);
    assert_eq!(first, second);
    assert_eq!(first.decision, Decision::Refuse);
    assert!(
        first
            .reason_codes
            .contains(&ReasonCode::ConflictingCandidate)
    );
}

#[test]
fn candidate_limit_refusal_is_order_invariant() {
    let policy = hybrid_policy(8);
    let trusted = trusted_keys();
    let mut candidates: Vec<_> = (0..9)
        .map(|index| {
            candidate(
                "ed25519",
                format!("sig-{index}"),
                VerificationOutcome::Valid,
            )
        })
        .collect();
    let expected = evaluate_policy(&policy, &trusted, &candidates, 100);
    assert_eq!(expected.decision, Decision::Refuse);
    assert!(
        expected
            .reason_codes
            .contains(&ReasonCode::TooManyCandidates)
    );

    let mut rng = StdRng::seed_from_u64(0x424f554e444544);
    for _ in 0..128 {
        candidates.shuffle(&mut rng);
        assert_eq!(
            evaluate_policy(&policy, &trusted, &candidates, 100),
            expected
        );
    }
}

#[test]
fn all_transport_adapters_match_for_generated_outcomes() {
    let trusted = trusted_keys();
    let policy = hybrid_policy(32);
    let outcomes = [
        VerificationOutcome::Valid,
        VerificationOutcome::Invalid,
        VerificationOutcome::Malformed,
    ];

    for ed in outcomes {
        for pq in outcomes {
            let semantic = ConformanceInput::Semantic {
                signatures: vec![
                    SemanticSignature {
                        key_id: "cache-ed".into(),
                        signature_id: "ed".into(),
                        verification: ed,
                    },
                    SemanticSignature {
                        key_id: "cache-pq".into(),
                        signature_id: "pq".into(),
                        verification: pq,
                    },
                ],
            };
            let sig_pqc = ConformanceInput::SigPqc {
                sig: vec![NamedSignature {
                    key_name: "cache".into(),
                    signature_id: "ed".into(),
                    verification: ed,
                }],
                sig_pqc: vec![SigPqcSignature {
                    key_name: "cache".into(),
                    algorithm_tag: "ml-dsa-65".into(),
                    signature_id: "pq".into(),
                    verification: pq,
                }],
            };
            let tagged = ConformanceInput::AlgorithmTagged {
                signatures: vec![
                    AlgorithmTaggedSignature {
                        key_name: "cache".into(),
                        algorithm: "ed25519".into(),
                        signature_id: "ed".into(),
                        verification: ed,
                    },
                    AlgorithmTaggedSignature {
                        key_name: "cache".into(),
                        algorithm: "ml-dsa-65".into(),
                        signature_id: "pq".into(),
                        verification: pq,
                    },
                ],
            };

            let semantic_candidates = semantic.normalize(&trusted);
            assert_eq!(sig_pqc.normalize(&trusted), semantic_candidates);
            assert_eq!(tagged.normalize(&trusted), semantic_candidates);
            let expected = evaluate_policy(&policy, &trusted, &semantic_candidates, 100);
            assert_eq!(
                evaluate_policy(&policy, &trusted, &sig_pqc.normalize(&trusted), 100),
                expected
            );
            assert_eq!(
                evaluate_policy(&policy, &trusted, &tagged.normalize(&trusted), 100),
                expected
            );
        }
    }
}
