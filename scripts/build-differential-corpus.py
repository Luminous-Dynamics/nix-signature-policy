#!/usr/bin/env python3
"""Build deterministic model-derived differential conformance cases."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "model"))
import core_v1_model as model  # noqa: E402

GENERATOR_VERSION = 1
CORPUS_PATH = ROOT / "differential/corpus-v1.json"
MANIFEST_PATH = ROOT / "differential/manifest-v1.json"


def expected_for(case: dict) -> dict:
    result = model.evaluate(case)
    expected = {
        "decision": result["decision"],
        "required_reason_codes": sorted(result["reason_codes"]),
        "forbidden_reason_codes": [],
        "group_counts": model.best_group_counts(result),
    }
    if result["satisfied_clause"] is not None:
        expected["satisfied_clause"] = result["satisfied_clause"]
    return expected


def mutated(base: dict, name: str, signatures: list[dict]) -> dict:
    case = copy.deepcopy(base)
    case["case_id"] = f"differential-{base['case_id']}-{name}"
    case["description"] = f"Generated differential mutation {name} of {base['case_id']}."
    case["tags"] = sorted(set(case.get("tags", [])) | {"differential", "generated"})
    case["input"]["signatures"] = signatures
    case["expected"] = expected_for(case)
    return case


def variants(base: dict) -> list[dict]:
    signatures = copy.deepcopy(base["input"]["signatures"])
    out = [mutated(base, "original", signatures)]
    if len(signatures) > 1:
        out.append(mutated(base, "reversed", list(reversed(signatures))))
    if len(signatures) > 2:
        out.append(mutated(base, "rotated", signatures[1:] + signatures[:1]))
    if signatures:
        out.append(mutated(base, "duplicate-first", signatures + [copy.deepcopy(signatures[0])]))
        out.append(mutated(base, "duplicate-last", [copy.deepcopy(signatures[-1])] + signatures))
        conflicting = copy.deepcopy(signatures[0])
        conflicting["verification"] = "invalid" if conflicting["verification"] == "valid" else "valid"
        out.append(mutated(base, "conflicting-first", signatures + [conflicting]))
    out.append(
        mutated(
            base,
            "unknown-valid-tail",
            signatures
            + [{"key_id": "unknown-differential", "signature_id": "unknown-valid", "verification": "valid"}],
        )
    )
    out.append(
        mutated(
            base,
            "unknown-malformed-head",
            [{"key_id": "unknown-differential", "signature_id": "unknown-malformed", "verification": "malformed"}]
            + signatures,
        )
    )
    return out


def build() -> tuple[dict, dict]:
    manifest = json.loads((ROOT / "conformance/policy-manifest-v1.json").read_text())
    paths = {entry["case_id"]: entry["path"] for entry in manifest["vectors"]}
    cases = []
    for case_id in manifest["profiles"]["core-v1"]:
        base = json.loads((ROOT / paths[case_id]).read_text())
        if base["input"]["adapter"] != "semantic":
            continue
        cases.extend(variants(base))
    cases.sort(key=lambda case: case["case_id"])
    corpus = {
        "differential_schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "source_profile": "core-v1",
        "case_count": len(cases),
        "cases": cases,
    }
    encoded = (json.dumps(corpus, indent=2, sort_keys=True) + "\n").encode()
    differential_manifest = {
        "differential_schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "source_profile": "core-v1",
        "case_count": len(cases),
        "corpus_sha256": hashlib.sha256(encoded).hexdigest(),
    }
    return corpus, differential_manifest


def render(value: dict) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    corpus, manifest = build()
    expected = {CORPUS_PATH: render(corpus), MANIFEST_PATH: render(manifest)}
    if args.check:
        stale = [str(path.relative_to(ROOT)) for path, text in expected.items() if not path.exists() or path.read_text() != text]
        if stale:
            raise SystemExit("stale differential artifacts: " + ", ".join(stale))
        print(f"differential corpus is current ({corpus['case_count']} cases)")
        return
    for path, text in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    print(f"wrote {corpus['case_count']} differential cases")


if __name__ == "__main__":
    main()
