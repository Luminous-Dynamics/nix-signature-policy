#!/usr/bin/env python3
"""Run the independent Python model against every core-v1 semantic vector."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("core_v1_model", ROOT / "model/core_v1_model.py")
if spec is None or spec.loader is None:
    raise SystemExit("unable to load core-v1 model")
model = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = model
spec.loader.exec_module(model)

manifest = json.loads((ROOT / "conformance/policy-manifest-v1.json").read_text())
required = set(manifest["profiles"]["core-v1"])
entries = {item["case_id"]: item for item in manifest["vectors"]}
failures: list[str] = []

for case_id in sorted(required):
    entry = entries.get(case_id)
    if entry is None:
        failures.append(f"{case_id}: absent from vector manifest")
        continue
    if entry["adapter"] != "semantic":
        failures.append(f"{case_id}: core-v1 model supports semantic vectors, got {entry['adapter']}")
        continue
    case = json.loads((ROOT / entry["path"]).read_text())
    result = model.evaluate(case)
    expected = case["expected"]
    if result["decision"] != expected["decision"]:
        failures.append(f"{case_id}: decision {result['decision']} != {expected['decision']}")
    if expected.get("satisfied_clause") is not None and result["satisfied_clause"] != expected["satisfied_clause"]:
        failures.append(f"{case_id}: clause {result['satisfied_clause']!r} != {expected['satisfied_clause']!r}")
    for reason in expected.get("required_reason_codes", []):
        if reason not in result["reason_codes"]:
            failures.append(f"{case_id}: missing required reason {reason}")
    for reason in expected.get("forbidden_reason_codes", []):
        if reason in result["reason_codes"]:
            failures.append(f"{case_id}: emitted forbidden reason {reason}")
    counts = model.best_group_counts(result)
    for group, count in expected.get("group_counts", {}).items():
        if counts.get(group, 0) != count:
            failures.append(f"{case_id}: group {group} count {counts.get(group, 0)} != {count}")

if failures:
    raise SystemExit("independent core-v1 model failures:\n- " + "\n- ".join(failures))
print(f"independent core-v1 model passed {len(required)} vectors")
