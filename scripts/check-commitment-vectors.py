#!/usr/bin/env python3
"""Verify domain-separated commitment known-answer vectors."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / "core/commitment-v1-vectors.json").read_text())
version = data["commitment_format_version"]
payload = data["payload_utf8"].encode()
magic = b"nix-signature-policy\0"
for domain, expected in data["vectors"].items():
    framed = (
        magic
        + domain.encode()
        + b"\0"
        + version.to_bytes(4, "big")
        + len(payload).to_bytes(8, "big")
        + payload
    )
    actual = hashlib.sha256(framed).hexdigest()
    if actual != expected:
        raise SystemExit(f"commitment vector {domain} mismatch: {actual} != {expected}")
print(f"domain-separated commitment v{version} vectors passed")
