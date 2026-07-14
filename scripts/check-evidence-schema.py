#!/usr/bin/env python3
"""Check evidence-schema structure and implementation/documentation alignment."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "evidence/schema-v1.json"
SOURCE = ROOT / "src/evidence.rs"
DOC = ROOT / "docs/EVIDENCE_BUNDLES.md"
CARGO = ROOT / "Cargo.toml"
EXAMPLE = ROOT / "evidence/examples/semantic-hybrid-valid.evidence.json"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    schema = json.loads(SCHEMA.read_text())
    Draft202012Validator.check_schema(schema)
    example = json.loads(EXAMPLE.read_text())
    Draft202012Validator(schema).validate(example)
    compact_payload = json.dumps(
        example["payload"], separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    require(
        hashlib.sha256(compact_payload).hexdigest() == example["payload_sha256"],
        "committed evidence example has an invalid payload digest",
    )
    source_path = ROOT / example["payload"]["source"]["identifier"]
    source_bytes = source_path.read_bytes()
    require(
        len(source_bytes) == example["payload"]["source"]["size_bytes"]
        and hashlib.sha256(source_bytes).hexdigest()
        == example["payload"]["source"]["sha256"],
        "committed evidence example has a stale source binding",
    )

    source = SOURCE.read_text()
    doc = DOC.read_text()
    cargo = CARGO.read_text()

    match = re.search(r"EVIDENCE_SCHEMA_VERSION:\s*u32\s*=\s*(\d+)", source)
    require(match is not None, "could not find EVIDENCE_SCHEMA_VERSION")
    implementation_version = int(match.group(1))
    require(
        schema["properties"]["bundle_schema_version"]["const"] == implementation_version,
        "evidence envelope schema version differs from Rust implementation",
    )
    require(
        schema["$defs"]["payload"]["properties"]["schema_version"]["const"]
        == implementation_version,
        "evidence payload schema version differs from Rust implementation",
    )
    require(
        'name = "policy-evidence"' in cargo,
        "Cargo.toml is missing the policy-evidence binary",
    )
    require(
        "policy replay" in doc.lower() and "does not prove" in doc.lower(),
        "evidence documentation must preserve the policy-replay limitation",
    )
    require(
        "deny_unknown_fields" in source,
        "evidence structs must continue rejecting unknown fields",
    )
    print("evidence schema and positioning checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
