use std::path::Path;

use nix_pqc_cache_proxy::conformance::{assert_equivalent_decisions, load_case, run_directory};
use nix_pqc_cache_proxy::policy::evaluate_policy;

#[test]
fn committed_policy_vectors_all_pass() {
    let report = run_directory(Path::new("policy-vectors")).expect("load policy vectors");
    assert!(
        report.is_success(),
        "{} policy vectors failed: {:#?}",
        report.failed,
        report
            .cases
            .iter()
            .filter(|case| !case.passed)
            .collect::<Vec<_>>()
    );
    assert!(report.total >= 20, "expected a substantive adversarial set");
    assert_eq!(report.adapter_counts.get("semantic").copied(), Some(28));
    assert_eq!(report.adapter_counts.get("sig-pqc").copied(), Some(2));
    assert_eq!(
        report.adapter_counts.get("algorithm-tagged").copied(),
        Some(2)
    );
}

#[test]
fn equivalent_hybrid_cases_match_across_all_adapters() {
    let paths = [
        "policy-vectors/adapter-parity/semantic-hybrid-valid.json",
        "policy-vectors/adapter-parity/sig-pqc-hybrid-valid.json",
        "policy-vectors/adapter-parity/algorithm-tagged-hybrid-valid.json",
    ];
    let cases = paths
        .iter()
        .map(|path| load_case(Path::new(path)).expect("load parity vector"))
        .collect::<Vec<_>>();
    let decisions = cases
        .iter()
        .map(|case| {
            let candidates = case.input.normalize(&case.trusted_keys);
            evaluate_policy(
                &case.policy,
                &case.trusted_keys,
                &candidates,
                case.evaluation_time,
            )
        })
        .collect::<Vec<_>>();

    assert_equivalent_decisions(&[
        ("semantic", &decisions[0]),
        ("sig-pqc", &decisions[1]),
        ("algorithm-tagged", &decisions[2]),
    ])
    .expect("adapters must not alter policy semantics");
}

#[test]
fn unknown_vector_fields_are_rejected() {
    let source = std::fs::read_to_string("policy-vectors/semantic/001-classical-policy-valid.json")
        .expect("read source vector");
    let mut value: serde_json::Value = serde_json::from_str(&source).expect("parse source JSON");
    value
        .as_object_mut()
        .expect("top-level object")
        .insert("unexpected_field".into(), serde_json::Value::Bool(true));

    let directory = tempfile::tempdir().expect("temporary vector directory");
    std::fs::write(
        directory.path().join("unexpected.json"),
        serde_json::to_vec_pretty(&value).expect("serialize mutated vector"),
    )
    .expect("write mutated vector");

    let error = run_directory(directory.path()).expect_err("unknown field must fail closed");
    assert!(
        error.to_string().contains("parsing conformance vector"),
        "unexpected error: {error:#}"
    );
}

#[test]
fn unknown_adapter_fields_are_rejected() {
    let source = std::fs::read_to_string("policy-vectors/adapter-parity/sig-pqc-hybrid-valid.json")
        .expect("read source vector");
    let mut value: serde_json::Value = serde_json::from_str(&source).expect("parse source JSON");
    value["input"]
        .as_object_mut()
        .expect("input object")
        .insert(
            "unexpected_adapter_field".into(),
            serde_json::Value::Bool(true),
        );

    let directory = tempfile::tempdir().expect("temporary vector directory");
    std::fs::write(
        directory.path().join("unexpected-adapter.json"),
        serde_json::to_vec_pretty(&value).expect("serialize mutated vector"),
    )
    .expect("write mutated vector");

    run_directory(directory.path()).expect_err("unknown adapter field must fail closed");
}
