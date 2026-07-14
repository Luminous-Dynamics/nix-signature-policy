#!/usr/bin/env python3
"""Build or verify the deterministic policy-vector interoperability manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR_ROOT = ROOT / "policy-vectors"
OUTPUT = ROOT / "conformance/policy-manifest-v1.json"
VECTOR_SCHEMA_VERSION = 2
MANIFEST_SCHEMA_VERSION = 1
NORMATIVE_SPEC_REVISION = 1

CORE_PROFILE = [
    "classical-policy-valid",
    "hybrid-rejects-classical-only",
    "hybrid-rejects-pq-only",
    "hybrid-rejects-invalid-pq",
    "duplicate-does-not-inflate-threshold",
    "unknown-key-does-not-sabotage-valid-hybrid",
    "revoked-pq-key-refused",
    "too-many-candidates-refused-explicitly",
    "conflicting-duplicate-refuses-order-independently",
    "typed-group-rejects-classical-key-as-pq",
    "bound-hybrid-rejects-different-identities",
    "pq-group-requires-two-families",
    "raw-observation-cap-precedes-deduplication",
    "expired-legacy-migration-clause-refused",
    "policy-rollback-refused",
    "forbidden-lattice-family-refused",
    "recovery-to-hash-based-pq-accepts",
    "observe-only-pq-does-not-authorize",
]


def vector_paths() -> list[Path]:
    return sorted(
        path
        for path in VECTOR_ROOT.rglob("*.json")
        if not path.name.startswith("schema-")
    )


def build_manifest() -> dict:
    vectors = []
    case_ids: set[str] = set()
    for path in vector_paths():
        raw = path.read_bytes()
        value = json.loads(raw)
        case_id = value["case_id"]
        if case_id in case_ids:
            raise SystemExit(f"duplicate case_id {case_id!r}")
        case_ids.add(case_id)
        vectors.append(
            {
                "case_id": case_id,
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "adapter": value["input"]["adapter"],
                "tags": sorted(value.get("tags", [])),
            }
        )
    missing = sorted(set(CORE_PROFILE) - case_ids)
    if missing:
        raise SystemExit(f"core-v1 profile references missing cases: {missing}")
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "vector_schema_version": VECTOR_SCHEMA_VERSION,
        "normative_spec_revision": NORMATIVE_SPEC_REVISION,
        "profiles": {"core-v1": CORE_PROFILE},
        "vectors": vectors,
    }


def encoded(value: dict) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=False) + "\n").encode()


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    args = parser.parse_args()

    expected = encoded(build_manifest())
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(expected)
        print(f"wrote {OUTPUT.relative_to(ROOT)}")
        return
    if not OUTPUT.is_file():
        raise SystemExit(f"missing {OUTPUT.relative_to(ROOT)}; run with --write")
    actual = OUTPUT.read_bytes()
    if actual != expected:
        raise SystemExit("policy manifest is stale; run build-policy-manifest.py --write")
    print("policy conformance manifest is current")


if __name__ == "__main__":
    main()
