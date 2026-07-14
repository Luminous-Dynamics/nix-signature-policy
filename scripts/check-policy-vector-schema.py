#!/usr/bin/env python3
"""Validate committed policy vectors against the published JSON Schema."""

from __future__ import annotations

import json
import sys
import subprocess
from collections import Counter
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "policy-vectors"
SCHEMA_PATH = VECTOR_ROOT / "schema-v2.json"
EXPECTED_ADAPTERS = {"semantic", "sig-pqc", "algorithm-tagged"}
MINIMUM_VECTOR_COUNT = 26


def fail(message: str) -> None:
    print(f"policy-vector schema check: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    paths = sorted(
        path
        for path in VECTOR_ROOT.rglob("*.json")
        if path.name != SCHEMA_PATH.name
    )
    if len(paths) < MINIMUM_VECTOR_COUNT:
        fail(f"found {len(paths)} vectors, expected at least {MINIMUM_VECTOR_COUNT}")

    case_ids: set[str] = set()
    adapters: Counter[str] = Counter()
    for path in paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
        if errors:
            rendered = "; ".join(
                f"{'.'.join(map(str, error.path)) or '<root>'}: {error.message}"
                for error in errors
            )
            fail(f"{path.relative_to(ROOT)}: {rendered}")

        case_id = value["case_id"]
        if case_id in case_ids:
            fail(f"duplicate case_id {case_id!r}")
        case_ids.add(case_id)
        adapters[value["input"]["adapter"]] += 1

    missing_adapters = EXPECTED_ADAPTERS - set(adapters)
    if missing_adapters:
        fail(f"missing adapter coverage: {sorted(missing_adapters)}")

    subprocess.run(
        [sys.executable, str(ROOT / "scripts/build-policy-manifest.py"), "--check"],
        check=True,
    )

    print(
        "policy-vector schema check passed: "
        f"{len(paths)} vectors; adapters={dict(sorted(adapters.items()))}"
    )


if __name__ == "__main__":
    main()
