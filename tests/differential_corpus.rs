use std::fs;

use nix_signature_policy::conformance::{ConformanceCase, evaluate_case};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DifferentialCorpus {
    differential_schema_version: u32,
    generator_version: u32,
    source_profile: String,
    case_count: usize,
    cases: Vec<ConformanceCase>,
}

#[test]
fn generated_independent_model_corpus_matches_rust() {
    let bytes = fs::read("differential/corpus-v1.json").expect("read differential corpus");
    let corpus: DifferentialCorpus =
        serde_json::from_slice(&bytes).expect("parse differential corpus");
    assert_eq!(corpus.differential_schema_version, 1);
    assert_eq!(corpus.generator_version, 1);
    assert_eq!(corpus.source_profile, "core-v1");
    assert_eq!(corpus.case_count, corpus.cases.len());
    assert!(corpus.case_count >= 100);

    let failures = corpus
        .cases
        .iter()
        .filter_map(|case| {
            let report = evaluate_case(case, format!("differential/{}", case.case_id))
                .expect("evaluate generated case");
            (!report.passed).then_some((report.case_id, report.failures))
        })
        .collect::<Vec<_>>();
    assert!(failures.is_empty(), "differential failures: {failures:#?}");
}
