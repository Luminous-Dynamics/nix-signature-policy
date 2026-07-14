#!/usr/bin/env python3
"""Guard the compact maintainer and security review package."""
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
policy=(ROOT/'src/policy.rs').read_text()
schema=(ROOT/'evidence/schema-v1.json').read_text()
minimal=(ROOT/'docs/UPSTREAM_MINIMAL_SLICE.md').read_text().lower()
review=(ROOT/'docs/SECURITY_REVIEW_CHECKLIST.md').read_text().lower()
bounds=(ROOT/'docs/BOUNDED_DECISION_EVIDENCE.md').read_text().lower()
match=re.search(r'pub const MAX_CANDIDATE_DIAGNOSTICS: usize = ([0-9_]+);',policy)
if not match or int(match.group(1).replace('_','')) != 256:
    raise SystemExit('candidate diagnostic cap is not frozen at 256')
if 'omitted_candidate_diagnostics' not in policy or 'omitted_candidate_diagnostics' not in schema:
    raise SystemExit('bounded evidence field is missing from implementation or schema')
if 'record_candidate_diagnostic' not in policy:
    raise SystemExit('bounded evidence helper is missing from implementation')
for token in ['authoritative','cannot be bypassed','existing behavior remains unchanged']:
    if token not in minimal:
        raise SystemExit(f'minimal upstream slice missing {token!r}')
for token in ['trust boundaries','determinism and bounds','lifecycle and recovery','assurance boundaries']:
    if token not in review:
        raise SystemExit(f'security review checklist missing {token!r}')
if '256' not in bounds or 'attacker' not in bounds:
    raise SystemExit('bounded decision evidence documentation is incomplete')
print('maintainer and security review package checks passed')
