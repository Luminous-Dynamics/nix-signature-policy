#!/usr/bin/env python3
"""Validate local trust-state schema and implementation positioning."""
from pathlib import Path
import json
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
schema = json.loads((ROOT / "trust-state/schema-v1.json").read_text())
Draft202012Validator.check_schema(schema)
src = (ROOT / "src/state.rs").read_text()
cli = (ROOT / "src/bin/trust-state.rs").read_text()
atomic = (ROOT / "src/atomic_file.rs").read_text()
cargo = (ROOT / "Cargo.toml").read_text()
doc = (ROOT / "docs/LOCAL_TRUST_STATE.md").read_text().lower()
for token in (
    "initialize_trust_state",
    "advance_trust_state",
    "apply_trust_state",
    "verify_trust_state",
    "NonContiguousAdvance",
    "PredecessorMismatch",
):
    if token not in src:
        raise SystemExit(f"trust-state implementation missing {token!r}")
# The CLI delegates its atomic-replacement discipline to the shared
# src/atomic_file.rs writer (extracted from a prior weaker local copy
# after an external review found it lacked durability/no-clobber
# guarantees) rather than implementing it inline -- check both files.
if "write_via_temp" not in cli or "CommitMode" not in cli:
    raise SystemExit("trust-state CLI lost its atomic-writer delegation")
if "hard_link" not in atomic or "fs::rename" not in atomic or "sync_all" not in atomic:
    raise SystemExit("shared atomic writer lost its no-clobber/durability boundary")
if "createnew" not in cli.lower():
    raise SystemExit("trust-state checkpoint writes (init/advance) lost their no-clobber commit mode")
if 'name = "trust-state"' not in cargo:
    raise SystemExit("trust-state binary is not registered")
if "not authentication" not in doc or "intermediate chain" not in doc:
    raise SystemExit("trust-state documentation lost assurance or chain boundary")
print("trust-state schema and positioning checks passed")
