#!/usr/bin/env python3
import json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
paths=sorted((root/'integration/vectors').glob('*.json'))
assert len(paths)==12
ids=set()
for path in paths:
 d=json.loads(path.read_text()); assert d['schema_version']==1
 assert d['case_id']==path.stem and d['case_id'] not in ids; ids.add(d['case_id'])
 r=d['request']; e=d['expected']
 contract=r['contract_version']==2
 registry=e['registry_decision']=='accept'
 builtin=r['built_in_decision']=='accept'
 policy=e['policy_decision']=='accept'
 mode=r['enforcement_mode']
 # `registry` (trust-registry validity) only gates the policy path, never
 # the built-in path -- a rolled-back or invalid registry must not be
 # able to veto Nix's own built-in trust result. `contract` is a genuine
 # cross-cutting gate in every mode.
 registry_gated_policy=registry and policy
 mode_accept={'legacy':builtin,'supplemental':builtin or registry_gated_policy,'authoritative':registry_gated_policy,'conjunctive':builtin and registry_gated_policy}[mode]
 expected='accept' if contract and mode_accept else 'refuse'
 assert expected==e['admission_decision'], d['case_id']
 required=set(e['required_reason_codes'])
 assert ('registry_accepted' in required)==registry
 assert ('policy_accepted' in required)==policy
 assert ('built_in_accepted' in required)==builtin
print(f"integration decision matrix passed ({len(paths)} vectors)")
