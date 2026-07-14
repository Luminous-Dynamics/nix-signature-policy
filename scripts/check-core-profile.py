#!/usr/bin/env python3
"""Verify that the frozen core-v1 descriptor matches Rust and conformance data."""
from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]

descriptor = json.loads((ROOT / "core/core-v1.json").read_text())
schema = json.loads((ROOT / "core/core-v1.schema.json").read_text())
Draft202012Validator.check_schema(schema)
Draft202012Validator(schema).validate(descriptor)

rust = (ROOT / "src/core.rs").read_text()
policy = (ROOT / "src/policy.rs").read_text()
integration = (ROOT / "src/integration.rs").read_text()
commitment = (ROOT / "src/commitment.rs").read_text()


def rust_int(text: str, name: str) -> int:
    match = re.search(rf"pub const {name}: (?:u32|usize) = ([0-9_]+);", text)
    if not match:
        raise SystemExit(f"missing Rust constant {name}")
    return int(match.group(1).replace("_", ""))


def rust_str(text: str, name: str) -> str:
    match = re.search(rf'pub const {name}: &str = "([^"]+)";', text)
    if not match:
        raise SystemExit(f"missing Rust constant {name}")
    return match.group(1)


expected = {
    "profile_id": rust_str(rust, "CORE_PROFILE_ID"),
    "profile_version": rust_int(rust, "CORE_PROFILE_VERSION"),
    "normative_spec_revision": rust_int(rust, "CORE_NORMATIVE_SPEC_REVISION"),
    "policy_vector_schema_version": rust_int(policy, "POLICY_VECTOR_SCHEMA_VERSION"),
    "integration_contract_version": rust_int(integration, "INTEGRATION_CONTRACT_VERSION"),
    "commitment_format_version": rust_int(commitment, "COMMITMENT_FORMAT_VERSION"),
    "max_configurable_signature_observations": rust_int(
        policy, "MAX_CONFIGURABLE_SIGNATURE_OBSERVATIONS"
    ),
    "max_configurable_signature_candidates": rust_int(
        policy, "MAX_CONFIGURABLE_SIGNATURE_CANDIDATES"
    ),
    "max_candidate_diagnostics": rust_int(policy, "MAX_CANDIDATE_DIAGNOSTICS"),
}
if descriptor != expected:
    raise SystemExit(f"core-v1 descriptor drift:\nJSON={descriptor}\nRust={expected}")

manifest = json.loads((ROOT / "conformance/policy-manifest-v1.json").read_text())
profile = manifest.get("profiles", {}).get(descriptor["profile_id"])
if not profile:
    raise SystemExit("conformance manifest has no non-empty core-v1 profile")
if manifest.get("normative_spec_revision") != descriptor["normative_spec_revision"]:
    raise SystemExit("manifest normative revision does not match core-v1")
if manifest.get("vector_schema_version") != descriptor["policy_vector_schema_version"]:
    raise SystemExit("manifest vector schema does not match core-v1")

print(f"{descriptor['profile_id']} descriptor and manifest consistency checks passed")
