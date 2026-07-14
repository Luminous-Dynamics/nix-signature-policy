#!/usr/bin/env python3
"""Fail CI when the project's prior-art positioning drifts.

This is intentionally a small static guard, not a live network checker.
External statuses are dated in the documents and must be reviewed manually.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    Path("README.md"),
    Path("docs/PRIOR_ART.md"),
    Path("docs/SIGNATURE_POLICY_MODEL.md"),
    Path("docs/adr/0001-policy-over-transport.md"),
    Path("rfc/README.md"),
    Path("rfc/0000-hybrid-binary-cache-signatures.md"),
    Path("src/policy.rs"),
    Path("src/policy_adapters.rs"),
    Path("src/conformance.rs"),
    Path("policy-vectors/README.md"),
    Path("policy-vectors/schema-v2.json"),
    Path("scripts/check-policy-vector-schema.py"),
)

REQUIRED_TEXT = {
    Path("README.md"): (
        "does not claim first PQ",
        "docs/PRIOR_ART.md",
        "docs/SIGNATURE_POLICY_MODEL.md",
        "harness model policy independently",
        "representation-neutral adversarial authorization",
        "nix run .#policy-conformance",
    ),
    Path("docs/PRIOR_ART.md"): (
        "DeterminateSystems/nix-src#449",
        "NixOS/nix#15926",
        "NixOS/nix#14451",
        "NixOS/rfcs#202",
        "does **not** claim to be the first implementation",
    ),
    Path("docs/SIGNATURE_POLICY_MODEL.md"): (
        "### 1. Encoding",
        "### 4. Authorization policy",
        "### 5. Migration",
        "### 6. Evidence",
        "representation-neutral",
    ),
    Path("rfc/README.md"): (
        "historical transport-format",
        "not the repository’s current upstream recommendation",
    ),
    Path("rfc/0000-hybrid-binary-cache-signatures.md"): (
        "historical transport draft",
        "does not claim first PQ signature",
        "representation-neutral",
    ),
    Path("policy-vectors/README.md"): (
        "semantic",
        "sig-pqc",
        "algorithm-tagged",
        "distinct identities, families",
    ),
}

# These exact positive claims are incompatible with the accepted positioning.
# Negated or historical discussion should use different, explicit wording.
FORBIDDEN_TEXT = {
    "README.md": (
        "This project is the first implementation of post-quantum signatures for Nix",
        "Sig-PQC: is required for Nix to support ML-DSA",
    ),
    "rfc/0000-hybrid-binary-cache-signatures.md": (
        "Nix has no practical migration path for adding signature algorithms",
        "The current upstream recommendation is Sig-PQC:",
    ),
}

MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


def fail(message: str) -> None:
    print(f"positioning check: {message}", file=sys.stderr)
    raise SystemExit(1)


def check_relative_links(path: Path, text: str) -> None:
    for target in MARKDOWN_LINK.findall(text):
        target = target.strip()
        if not target or target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        resolved = (ROOT / path.parent / target).resolve()
        try:
            resolved.relative_to(ROOT.resolve())
        except ValueError:
            fail(f"{path}: relative link escapes repository: {target}")
        if not resolved.exists():
            fail(f"{path}: broken relative link: {target}")


def main() -> None:
    for relative in REQUIRED_FILES:
        path = ROOT / relative
        if not path.is_file():
            fail(f"missing required document: {relative}")

        text = path.read_text(encoding="utf-8")
        for needle in REQUIRED_TEXT.get(relative, ()):
            if needle not in text:
                fail(f"{relative}: missing required positioning text: {needle!r}")
        for forbidden in FORBIDDEN_TEXT.get(relative.as_posix(), ()):
            if forbidden in text:
                fail(f"{relative}: forbidden obsolete claim: {forbidden!r}")
        check_relative_links(relative, text)

    print("prior-art positioning check passed")


if __name__ == "__main__":
    main()
