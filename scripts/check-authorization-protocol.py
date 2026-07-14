#!/usr/bin/env python3
import json
from pathlib import Path

root=Path(__file__).resolve().parents[1]
d=json.loads((root/'integration/protocol-v1.json').read_text())
assert d['protocol_id']=='nix-signature-authorization-json-v1'
assert d['protocol_version']==1
assert d['integration_contract_version']==2
assert d['max_request_bytes']==1048576
assert d['max_response_bytes']==2097152
assert d['max_response_bytes']>=d['max_request_bytes']
assert d['exit_codes']['0']=='authorization accepted'
assert d['exit_codes']['10']=='authorization refused'
request=json.loads((root/'integration/examples/authoritative-downgrade-refusal.request.json').read_text())
assert request['contract_version']==d['integration_contract_version']
assert request['enforcement_mode']=='authoritative'
assert request['built_in_decision']=='accept'
assert len(request['candidates'])==1
assert {g['group'] for g in request['policy']['group_definitions']}=={'classical','post-quantum'}
source=(root/'src/protocol.rs').read_text()
for token in (
 'AUTHORIZATION_PROTOCOL_ID: &str = "nix-signature-authorization-json-v1"',
 'MAX_AUTHORIZATION_REQUEST_BYTES: usize = 1_048_576',
 'MAX_AUTHORIZATION_RESPONSE_BYTES: usize = 2_097_152',
):
 assert token in source, token
cargo=(root/'Cargo.toml').read_text()
assert 'name = "nix-signature-authorize"' in cargo
print('bounded authorization protocol checks passed')
