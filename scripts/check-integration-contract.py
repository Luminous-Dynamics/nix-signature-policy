#!/usr/bin/env python3
"""Guard the authoritative Nix integration boundary against permissive drift."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = (ROOT / "src/integration.rs").read_text()
DOC = (ROOT / "docs/NIX_INTEGRATION_CONTRACT.md").read_text().lower()
LIB = (ROOT / "src/lib.rs").read_text()

required = [
    "pub enum EnforcementMode",
    "Legacy",
    "Supplemental",
    "Authoritative",
    "Conjunctive",
    "EnforcementMode::Authoritative =>",
    "policy_accepts",
    "authoritative_mode_cannot_be_bypassed_by_builtin_acceptance",
]
for token in required:
    if token not in SRC:
        raise SystemExit(f"integration contract is missing {token!r}")
if "pub mod integration;" not in LIB:
    raise SystemExit("integration module is not exported")
if "cannot enforce mandatory" not in DOC or "authoritative" not in DOC:
    raise SystemExit("integration documentation lost the downgrade warning")
print("integration contract guard passed")
