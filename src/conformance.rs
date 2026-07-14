//! Machine-readable adversarial signature-policy conformance harness.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::policy::{
    Decision, EvaluationContext, POLICY_VECTOR_SCHEMA_VERSION, PolicyDecision, ReasonCode,
    SignaturePolicy, TrustedKey, evaluate_policy_with_context,
};
use crate::policy_adapters::ConformanceInput;

const MAX_VECTOR_FILES: usize = 4096;
const MAX_VECTOR_BYTES: u64 = 1024 * 1024;

/// One representation-neutral policy vector.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConformanceCase {
    pub schema_version: u32,
    pub case_id: String,
    pub description: String,
    #[serde(default)]
    pub tags: BTreeSet<String>,
    #[serde(default)]
    pub evaluation_time: i64,
    /// Highest policy epoch already committed for this policy domain.
    #[serde(default)]
    pub minimum_policy_epoch: u64,
    pub policy: SignaturePolicy,
    pub trusted_keys: Vec<TrustedKey>,
    pub input: ConformanceInput,
    pub expected: ExpectedOutcome,
}

/// Assertions intentionally limited to stable semantic properties.
///
/// Vectors may require or forbid reason codes without coupling themselves to
/// diagnostic ordering or human-readable text.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExpectedOutcome {
    pub decision: Decision,
    #[serde(default)]
    pub satisfied_clause: Option<String>,
    #[serde(default)]
    pub required_reason_codes: BTreeSet<ReasonCode>,
    #[serde(default)]
    pub forbidden_reason_codes: BTreeSet<ReasonCode>,
    #[serde(default)]
    pub group_counts: BTreeMap<String, usize>,
}

/// Result for one vector.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CaseReport {
    pub case_id: String,
    pub path: String,
    pub adapter: String,
    pub passed: bool,
    pub failures: Vec<String>,
    pub decision: PolicyDecision,
}

/// Aggregate machine-readable report.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConformanceReport {
    pub report_schema_version: u32,
    pub vector_schema_version: u32,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub adapter_counts: BTreeMap<String, usize>,
    pub cases: Vec<CaseReport>,
}

impl ConformanceReport {
    pub fn is_success(&self) -> bool {
        self.failed == 0
    }
}

/// Load every `.json` vector beneath `root`, sorted by path, and evaluate it.
pub fn run_directory(root: &Path) -> Result<ConformanceReport> {
    let paths = collect_json_files(root)?;
    if paths.is_empty() {
        bail!("no JSON conformance vectors found beneath {root:?}");
    }

    let mut cases = Vec::with_capacity(paths.len());
    let mut seen_case_ids = BTreeSet::new();
    let mut adapter_counts = BTreeMap::new();

    for path in paths {
        let metadata = fs::metadata(&path)
            .with_context(|| format!("reading conformance metadata {path:?}"))?;
        if metadata.len() > MAX_VECTOR_BYTES {
            bail!(
                "conformance vector {path:?} is {} bytes, limit is {MAX_VECTOR_BYTES}",
                metadata.len()
            );
        }
        let text = fs::read_to_string(&path)
            .with_context(|| format!("reading conformance vector {path:?}"))?;
        let case: ConformanceCase = serde_json::from_str(&text)
            .with_context(|| format!("parsing conformance vector {path:?}"))?;
        validate_case_structure(&case, &path)?;
        if !seen_case_ids.insert(case.case_id.clone()) {
            bail!("duplicate conformance case_id {:?}", case.case_id);
        }

        let adapter = case.input.adapter_name().to_string();
        *adapter_counts.entry(adapter).or_insert(0) += 1;
        let relative_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        cases.push(evaluate_case(&case, relative_path)?);
    }

    let passed = cases.iter().filter(|case| case.passed).count();
    let total = cases.len();
    Ok(ConformanceReport {
        report_schema_version: 1,
        vector_schema_version: POLICY_VECTOR_SCHEMA_VERSION,
        total,
        passed,
        failed: total - passed,
        adapter_counts,
        cases,
    })
}

fn collect_json_files(root: &Path) -> Result<Vec<PathBuf>> {
    if !root.is_dir() {
        bail!("conformance vector root is not a directory: {root:?}");
    }

    let mut pending = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("reading conformance directory {directory:?}"))?
        {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension == "json")
                && path
                    .file_name()
                    .is_none_or(|name| !name.to_string_lossy().starts_with("schema-"))
            {
                paths.push(path);
                if paths.len() > MAX_VECTOR_FILES {
                    bail!("more than {MAX_VECTOR_FILES} conformance vectors found");
                }
            }
        }
    }
    paths.sort();
    Ok(paths)
}

fn validate_case_structure(case: &ConformanceCase, path: &Path) -> Result<()> {
    if case.schema_version != POLICY_VECTOR_SCHEMA_VERSION {
        bail!(
            "vector {path:?} uses schema_version {}, expected {}",
            case.schema_version,
            POLICY_VECTOR_SCHEMA_VERSION
        );
    }
    if case.case_id.trim().is_empty() {
        bail!("vector {path:?} has an empty case_id");
    }
    if case.description.trim().is_empty() {
        bail!("vector {path:?} has an empty description");
    }
    if !case
        .expected
        .required_reason_codes
        .is_disjoint(&case.expected.forbidden_reason_codes)
    {
        bail!("vector {path:?} requires and forbids the same reason code");
    }
    Ok(())
}

/// Evaluate one already-parsed conformance case.
pub fn evaluate_case(case: &ConformanceCase, path: String) -> Result<CaseReport> {
    validate_case_structure(case, Path::new(&path))?;
    let adapter = case.input.adapter_name().to_string();
    let candidates = case.input.normalize(&case.trusted_keys);
    let decision = evaluate_policy_with_context(
        &case.policy,
        &case.trusted_keys,
        &candidates,
        EvaluationContext {
            evaluation_time: case.evaluation_time,
            minimum_policy_epoch: case.minimum_policy_epoch,
        },
    );
    let failures = compare_expected(&case.expected, &decision);
    Ok(CaseReport {
        case_id: case.case_id.clone(),
        path,
        adapter,
        passed: failures.is_empty(),
        failures,
        decision,
    })
}

fn compare_expected(expected: &ExpectedOutcome, actual: &PolicyDecision) -> Vec<String> {
    let mut failures = Vec::new();
    if actual.decision != expected.decision {
        failures.push(format!(
            "decision was {:?}, expected {:?}",
            actual.decision, expected.decision
        ));
    }
    if let Some(expected_clause) = &expected.satisfied_clause {
        if actual.satisfied_clause.as_ref() != Some(expected_clause) {
            failures.push(format!(
                "satisfied_clause was {:?}, expected {:?}",
                actual.satisfied_clause, expected_clause
            ));
        }
    }
    for code in &expected.required_reason_codes {
        if !actual.reason_codes.contains(code) {
            failures.push(format!("required reason code {code:?} was absent"));
        }
    }
    for code in &expected.forbidden_reason_codes {
        if actual.reason_codes.contains(code) {
            failures.push(format!("forbidden reason code {code:?} was present"));
        }
    }

    let observed_group_counts = best_group_counts(actual);
    for (group, expected_count) in &expected.group_counts {
        let observed = observed_group_counts.get(group).copied().unwrap_or(0);
        if observed != *expected_count {
            failures.push(format!(
                "group {group:?} observed {observed} distinct identities, expected {expected_count}"
            ));
        }
    }
    failures
}

fn best_group_counts(decision: &PolicyDecision) -> BTreeMap<String, usize> {
    let selected = if let Some(clause_id) = &decision.satisfied_clause {
        decision
            .clause_evaluations
            .iter()
            .find(|clause| &clause.clause_id == clause_id)
    } else {
        // For a refusal, choose the clause with the fewest missing identities;
        // tie-break by fixture order. This makes requested group-count
        // assertions deterministic without declaring one failed clause to be
        // semantically privileged.
        decision
            .clause_evaluations
            .iter()
            .filter(|clause| clause.active)
            .min_by_key(|clause| {
                clause
                    .groups
                    .iter()
                    .map(|group| {
                        group
                            .required_identities
                            .saturating_sub(group.observed_identities)
                    })
                    .sum::<usize>()
            })
    };

    selected
        .map(|clause| {
            clause
                .groups
                .iter()
                .map(|group| (group.group.clone(), group.observed_identities))
                .collect()
        })
        .unwrap_or_default()
}

/// Load one named case for focused tests or diagnostic tooling.
pub fn load_case(path: &Path) -> Result<ConformanceCase> {
    let metadata =
        fs::metadata(path).with_context(|| format!("reading vector metadata {path:?}"))?;
    if metadata.len() > MAX_VECTOR_BYTES {
        bail!(
            "conformance vector {path:?} is {} bytes, limit is {MAX_VECTOR_BYTES}",
            metadata.len()
        );
    }
    let text = fs::read_to_string(path).with_context(|| format!("reading vector {path:?}"))?;
    let case: ConformanceCase =
        serde_json::from_str(&text).with_context(|| format!("parsing vector {path:?}"))?;
    validate_case_structure(&case, path)?;
    Ok(case)
}

/// Assert that multiple vectors have equivalent decisions and normalized
/// policy evidence. Used by adapter-parity integration tests.
pub fn assert_equivalent_decisions(decisions: &[(&str, &PolicyDecision)]) -> Result<()> {
    let Some((first_name, first)) = decisions.first().copied() else {
        return Err(anyhow!("no decisions supplied for equivalence comparison"));
    };
    for (name, decision) in decisions.iter().copied().skip(1) {
        if decision.decision != first.decision
            || decision.satisfied_clause != first.satisfied_clause
            || decision.unique_candidate_count != first.unique_candidate_count
            || decision.eligible_candidate_count != first.eligible_candidate_count
            || decision.reason_codes != first.reason_codes
            || decision.clause_evaluations != first.clause_evaluations
        {
            bail!("decision {name:?} is not policy-equivalent to {first_name:?}");
        }
    }
    Ok(())
}
