#!/usr/bin/env python3
"""Reject drift between Rust semantic enums, JSON schemas, and normative prose."""
from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def enum_values(path: str, name: str) -> list[str]:
    text = (ROOT / path).read_text()
    match = re.search(rf"pub enum {name}\s*\{{(.*?)\n\}}", text, re.S)
    if not match:
        raise SystemExit(f"missing Rust enum {name} in {path}")
    body = re.sub(r"///.*", "", match.group(1))
    body = re.sub(r"#\[[^\]]+\]", "", body)
    variants = re.findall(r"^\s*([A-Z][A-Za-z0-9_]*)\s*,", body, re.M)
    if not variants:
        raise SystemExit(f"could not parse variants for {name}")
    return [snake(value) for value in variants]


def assert_equal(label: str, left: list[str], right: list[str]) -> None:
    if len(left) != len(set(left)) or len(right) != len(set(right)):
        raise SystemExit(f"{label} contains duplicate values")
    if set(left) != set(right):
        raise SystemExit(f"{label} drift: Rust={left}, schema={right}")


policy_schema = json.loads((ROOT / "policy-vectors/schema-v2.json").read_text())
receipt_schema = json.loads((ROOT / "receipts/schema-v2.json").read_text())
manifest_schema = json.loads((ROOT / "conformance/manifest-schema-v1.json").read_text())
Draft202012Validator.check_schema(policy_schema)
Draft202012Validator.check_schema(receipt_schema)
Draft202012Validator.check_schema(manifest_schema)
manifest = json.loads((ROOT / "conformance/policy-manifest-v1.json").read_text())
Draft202012Validator(manifest_schema).validate(manifest)

assert_equal(
    "policy reason codes",
    enum_values("src/policy.rs", "ReasonCode"),
    policy_schema["$defs"]["reasonCode"]["enum"],
)
assert_equal(
    "family lifecycle states",
    enum_values("src/policy.rs", "FamilyStatus"),
    policy_schema["$defs"]["familyStatus"]["enum"],
)
assert_equal(
    "relation attributes",
    enum_values("src/policy.rs", "RelationAttribute"),
    policy_schema["$defs"]["groupRelation"]["properties"]["attribute"]["enum"],
)
assert_equal(
    "relation modes",
    enum_values("src/policy.rs", "RelationMode"),
    policy_schema["$defs"]["groupRelation"]["properties"]["mode"]["enum"],
)

payload = receipt_schema["$defs"]["payload"]["properties"]
assert_equal(
    "enforcement modes",
    enum_values("src/integration.rs", "EnforcementMode"),
    payload["enforcement_mode"]["enum"],
)
assert_equal(
    "built-in decisions",
    enum_values("src/integration.rs", "BuiltInDecision"),
    payload["built_in_decision"]["enum"],
)
assert_equal(
    "admission decisions",
    enum_values("src/integration.rs", "AdmissionDecision"),
    payload["decision"]["enum"],
)
assert_equal(
    "receipt policy reason codes",
    enum_values("src/policy.rs", "ReasonCode"),
    payload["policy_reason_codes"]["items"]["enum"],
)
assert_equal(
    "receipt admission reason codes",
    enum_values("src/integration.rs", "AdmissionReasonCode"),
    payload["admission_reason_codes"]["items"]["enum"],
)
assert_equal(
    "receipt registry reason codes",
    enum_values("src/registry.rs", "RegistryReasonCode"),
    payload["registry_reason_codes"]["items"]["enum"],
)

constants = {
    "src/policy.rs": ("POLICY_VECTOR_SCHEMA_VERSION", policy_schema["properties"]["schema_version"]["const"]),
    "src/receipt.rs": ("TRUST_RECEIPT_SCHEMA_VERSION", receipt_schema["properties"]["receipt_schema_version"]["const"]),
    "src/state.rs": ("TRUST_STATE_SCHEMA_VERSION", json.loads((ROOT / "trust-state/schema-v1.json").read_text())["properties"]["state_schema_version"]["const"]),
}
for path, (name, expected) in constants.items():
    text = (ROOT / path).read_text()
    match = re.search(rf"pub const {name}: u32 = (\d+);", text)
    if not match or int(match.group(1)) != expected:
        raise SystemExit(f"{name} does not match its schema const {expected}")

normative = (ROOT / "docs/NORMATIVE_AUTHORIZATION_SPEC.md").read_text()
for token in [
    "`enabled`",
    "`observe_only`",
    "`deprecated`",
    "`forbidden`",
    "`legacy`",
    "`supplemental`",
    "`authoritative`",
    "`conjunctive`",
    "permutation independence",
    "duplicate non-inflation",
]:
    if token not in normative:
        raise SystemExit(f"normative specification is missing {token!r}")

print("semantic enum, schema, and normative-spec consistency checks passed")
