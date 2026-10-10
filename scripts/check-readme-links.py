#!/usr/bin/env python3
"""Fail when README.md contains a broken repository-relative Markdown link."""
from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"


def main() -> int:
    text = README.read_text(encoding="utf-8")
    # The root README uses tilde fences for examples; strip them before link parsing.
    text = re.sub(r"~~~[\s\S]*?~~~", "", text)
    links = re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text)
    errors: list[str] = []
    checked = 0

    for raw in links:
        target = raw.strip().split(maxsplit=1)[0].strip("<>")
        parts = urlsplit(target)
        if parts.scheme or parts.netloc or not parts.path or parts.path.startswith("/"):
            continue
        checked += 1
        local = ROOT / unquote(parts.path)
        if not local.exists():
            errors.append(f"broken README link: {target}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"README link check passed ({checked} repository-relative links checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
