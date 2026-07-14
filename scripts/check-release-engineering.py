#!/usr/bin/env python3
"""Static guard for the maintainer-review and release-engineering surface."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED = {
    "SECURITY.md": ["Reporting a vulnerability", "Prototype security boundary"],
    "RELEASING.md": ["Deterministic source release", "Hybrid release attestation"],
    "docs/THREAT_MODEL.md": ["Assets", "Trust assumptions", "Residual risks"],
    "docs/MAINTAINER_REVIEW.md": ["Fifteen-minute review", "One-hour review"],
    "release/README.md": ["source-only", "release statement"],
    "scripts/build-source-release.py": ["git", "source_date_epoch", "artifact-attestation"],
    "scripts/verify-source-release.py": ["verify_archive", "trusted-key"],
    "scripts/demo-real-nix.sh": ["real_nix_e2e", "policy-conformance"],
    "src/artifact_attestation.rs": ["ATTESTATION_DOMAIN", "verify_artifact_attestation"],
    "src/bin/artifact-attestation.rs": ["Artifact attestation verification failed".lower()],
}


def main() -> int:
    for relative, needles in REQUIRED.items():
        path = ROOT / relative
        if not path.is_file():
            raise SystemExit(f"missing release-engineering file: {relative}")
        text = path.read_text().lower()
        missing = [needle for needle in needles if needle.lower() not in text]
        if missing:
            raise SystemExit(f"{relative}: missing release-engineering markers: {missing}")

    schema = json.loads((ROOT / "release/schema-v1.json").read_text())
    if schema.get("properties", {}).get("schema_version", {}).get("const") != 1:
        raise SystemExit("release/schema-v1.json does not pin schema_version 1")
    attestation_schema = json.loads(
        (ROOT / "release/attestation-schema-v1.json").read_text()
    )
    if (
        attestation_schema.get("properties", {})
        .get("bundle_schema_version", {})
        .get("const")
        != 1
    ):
        raise SystemExit(
            "release/attestation-schema-v1.json does not pin bundle_schema_version 1"
        )

    cargo = (ROOT / "Cargo.toml").read_text()
    if 'name = "artifact-attestation"' not in cargo:
        raise SystemExit("Cargo.toml does not install artifact-attestation")

    gitignore = (ROOT / ".gitignore").read_text().splitlines()
    if "/dist/" not in gitignore or "/demo-output/" not in gitignore:
        raise SystemExit("release/demo output directories are not ignored")

    print("release engineering guard passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
