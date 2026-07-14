use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use nix_signature_policy::integration::{
    AdmissionDecision, AdmissionReasonCode, AuthorizationRequest, authorize,
};
use nix_signature_policy::policy::Decision;
use nix_signature_policy::registry::RegistryDecisionValue;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntegrationVector {
    schema_version: u32,
    case_id: String,
    description: String,
    request: AuthorizationRequest,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    policy_decision: Decision,
    registry_decision: RegistryDecisionValue,
    admission_decision: AdmissionDecision,
    required_reason_codes: BTreeSet<AdmissionReasonCode>,
}

#[test]
fn integration_mode_matrix_is_stable() {
    let mut paths = fs::read_dir("integration/vectors")
        .expect("read integration vectors")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(paths.len(), 10);

    for path in paths {
        run_vector(&path);
    }
}

fn run_vector(path: &Path) {
    let bytes = fs::read(path).expect("read integration vector");
    let vector: IntegrationVector =
        serde_json::from_slice(&bytes).expect("parse integration vector");
    assert_eq!(vector.schema_version, 1);
    assert!(!vector.case_id.trim().is_empty());
    assert!(!vector.description.trim().is_empty());
    assert_eq!(
        path.file_stem().and_then(|value| value.to_str()),
        Some(vector.case_id.as_str())
    );

    let response = authorize(&vector.request);
    assert_eq!(
        response.policy_decision.decision, vector.expected.policy_decision,
        "{}",
        vector.case_id
    );
    assert_eq!(
        response.registry_decision.decision, vector.expected.registry_decision,
        "{}",
        vector.case_id
    );
    assert_eq!(
        response.decision, vector.expected.admission_decision,
        "{}",
        vector.case_id
    );
    assert!(
        vector
            .expected
            .required_reason_codes
            .is_subset(&response.reason_codes),
        "{} missing reasons: expected {:?}, actual {:?}",
        vector.case_id,
        vector.expected.required_reason_codes,
        response.reason_codes,
    );
}
