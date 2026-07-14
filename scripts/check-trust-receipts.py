#!/usr/bin/env python3
"""Validate compact trust receipt schema, digest, CLI, and assurance language."""
from pathlib import Path
import hashlib, json
from jsonschema import Draft202012Validator

ROOT=Path(__file__).resolve().parents[1]
schema=json.loads((ROOT/'receipts/schema-v2.json').read_text())
Draft202012Validator.check_schema(schema)
example=json.loads((ROOT/'receipts/examples/accepted-hash-based-pq.json').read_text())
Draft202012Validator(schema).validate(example)
compact=json.dumps(example['payload'],separators=(',',':'),ensure_ascii=False).encode()
framed=(
    b'nix-signature-policy\0'
    + b'receipt-payload'
    + b'\0'
    + (1).to_bytes(4,'big')
    + len(compact).to_bytes(8,'big')
    + compact
)
if hashlib.sha256(framed).hexdigest()!=example['payload_sha256']:
    raise SystemExit('trust receipt example has an invalid domain-separated payload digest')
src=(ROOT/'src/receipt.rs').read_text(); cargo=(ROOT/'Cargo.toml').read_text(); doc=(ROOT/'docs/TRUST_RECEIPTS.md').read_text().lower()
for token in ['build_trust_receipt','verify_trust_receipt','canonical_policy_sha256','canonical_registry_sha256','qualifying_families','deny_unknown_fields','CommitmentDomain::ReceiptPayload']:
    if token not in src: raise SystemExit(f'trust receipt implementation missing {token!r}')
if 'name = "trust-receipt"' not in cargo: raise SystemExit('trust-receipt binary is not registered')
if 'not a standalone proof' not in doc or 'policy-replay evidence' not in doc:
    raise SystemExit('trust receipt documentation lost its assurance boundary')
print('trust receipt schema, commitment, and positioning checks passed')
