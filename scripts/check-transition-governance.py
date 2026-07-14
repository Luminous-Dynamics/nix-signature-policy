#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parents[1]
obj=json.loads((root/'governance/examples/two-family-recovery.json').read_text())
payload=json.dumps(obj['target'],separators=(',',':')).encode()
framed=b'nix-signature-policy\0transition\0'+(1).to_bytes(4,'big')+len(payload).to_bytes(8,'big')+payload
assert hashlib.sha256(framed).hexdigest()==obj['target_sha256']
rule=obj['rule']; endorsements=obj['endorsements']
eligible=[e for e in endorsements if e['verification']=='valid' and e['target_sha256']==obj['target_sha256'] and rule['required_role'] in e['roles'] and e['family'] not in rule['forbidden_families']]
assert len({e['signer_identity'] for e in eligible})>=rule['min_distinct_identities']
assert len({e['family'] for e in eligible})>=rule['min_distinct_families']
assert len({e['authority'] for e in eligible})>=rule['min_distinct_authorities']
source=(root/'src/governance.rs').read_text()
for token in ('MAX_TRANSITION_ENDORSEMENTS: usize = 1024','ForbiddenFamily','canonical_transition_sha256'):
 assert token in source, token
vectors=json.loads((root/'core/commitment-v1-vectors.json').read_text())
assert vectors['vectors']['transition']=='1c61c9a3b15cd7402a7fc84d3009ac58dcc9b568f4de87a150c4b05dd5677fa7'
print('transition governance checks passed')
