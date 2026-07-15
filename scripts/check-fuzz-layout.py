#!/usr/bin/env python3
"""Fail closed if the committed fuzz/property layout drifts."""

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("narinfo_parse", "policy_evaluator", "policy_adapters", "signature_codecs", "evidence_bundle", "authorization_protocol")

errors: list[str] = []
manifest = (ROOT / "fuzz/Cargo.toml").read_text(encoding="utf-8")
runner = (ROOT / "scripts/fuzz-smoke.sh").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

for target in TARGETS:
    expected_path = ROOT / f"fuzz/fuzz_targets/{target}.rs"
    corpus = ROOT / f"fuzz/corpus/{target}"
    if not expected_path.is_file():
        errors.append(f"missing fuzz target: {expected_path.relative_to(ROOT)}")
    if not corpus.is_dir() or not any(path.is_file() for path in corpus.iterdir()):
        errors.append(f"missing non-empty seed corpus: {corpus.relative_to(ROOT)}")
    if f'name = "{target}"' not in manifest:
        errors.append(f"fuzz/Cargo.toml does not declare target {target}")
    if target not in runner:
        errors.append(f"fuzz-smoke.sh does not run target {target}")

if not (ROOT / "tests/properties.rs").is_file():
    errors.append("missing deterministic property test suite")
if "nix run .#fuzz-smoke" not in workflow:
    errors.append("CI does not run the fuzz smoke app")
if not re.search(r'channel\s*=\s*"nightly-\d{4}-\d{2}-\d{2}"', (ROOT / "fuzz/rust-toolchain.toml").read_text()):
    errors.append("fuzz toolchain must be date-pinned")
if 'libfuzzer-sys = "=0.4.13"' not in manifest:
    errors.append("libfuzzer-sys must remain exact-version pinned")

if errors:
    for error in errors:
        print(f"fuzz-layout error: {error}", file=sys.stderr)
    raise SystemExit(1)
print(f"fuzz layout ok: {len(TARGETS)} targets with seed corpora")
