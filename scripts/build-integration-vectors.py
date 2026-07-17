#!/usr/bin/env python3
"""Build deterministic integration-mode conformance vectors."""
from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BASE=json.loads((ROOT/'integration/examples/authoritative-downgrade-refusal.request.json').read_text())


def vector(case_id, description, request, policy, registry, admission, reasons):
    return {
      'schema_version':1,'case_id':case_id,'description':description,
      'request':request,
      'expected':{
        'policy_decision':policy,'registry_decision':registry,
        'admission_decision':admission,'required_reason_codes':sorted(reasons)}}


def with_pq(request):
    result=copy.deepcopy(request)
    result['candidates'].append({
      'key_name':'cache','algorithm':'ml-dsa-65',
      'signature_id':'pq-good','verification':'valid'})
    return result


def build():
    cases=[]
    r=copy.deepcopy(BASE)
    cases.append(vector('authoritative-refuses-builtin-downgrade','Built-in acceptance cannot bypass authoritative policy refusal.',r,'refuse','accept','refuse',{'built_in_accepted','policy_refused','registry_accepted','registry_required','authoritative_policy_required'}))
    r=copy.deepcopy(BASE); r['enforcement_mode']='supplemental'
    cases.append(vector('supplemental-preserves-compatibility','Supplemental mode accepts either path and is not mandatory composition.',r,'refuse','accept','accept',{'built_in_accepted','policy_refused','registry_accepted','registry_required','supplemental_path_accepted'}))
    r=copy.deepcopy(BASE); r['enforcement_mode']='legacy'
    cases.append(vector('legacy-preserves-builtin','Legacy mode preserves the built-in decision while still evaluating policy.',r,'refuse','accept','accept',{'built_in_accepted','policy_refused','registry_accepted','registry_required'}))
    r=with_pq(BASE); r['enforcement_mode']='conjunctive'
    cases.append(vector('conjunctive-accepts-both','Conjunctive mode accepts when both paths accept.',r,'accept','accept','accept',{'built_in_accepted','policy_accepted','registry_accepted','registry_required'}))
    r=with_pq(BASE); r['enforcement_mode']='conjunctive'; r['built_in_decision']='refuse'
    cases.append(vector('conjunctive-refuses-builtin-failure','Conjunctive mode refuses when built-in trust refuses.',r,'accept','accept','refuse',{'built_in_refused','policy_accepted','registry_accepted','registry_required','conjunctive_requirement_failed'}))
    r=with_pq(BASE); r['contract_version']=999
    cases.append(vector('unsupported-contract-fails-closed','An unsupported contract version fails closed.',r,'accept','accept','refuse',{'unsupported_contract_version','built_in_accepted','policy_accepted','registry_accepted','registry_required','authoritative_policy_required'}))
    r=with_pq(BASE); r['evaluation_context']['minimum_registry_epoch']=2
    cases.append(vector('registry-rollback-fails-closed','Registry rollback refuses independently of both authorization paths.',r,'accept','refuse','refuse',{'built_in_accepted','policy_accepted','registry_refused','registry_required','authoritative_policy_required'}))
    r=copy.deepcopy(BASE); r['enforcement_mode']='legacy'; r['evaluation_context']['minimum_registry_epoch']=2
    cases.append(vector('legacy-ignores-registry-rollback','A rolled-back registry does not veto legacy mode, which uses only the built-in decision.',r,'refuse','refuse','accept',{'built_in_accepted','policy_refused','registry_refused','registry_required'}))
    r=copy.deepcopy(BASE); r['enforcement_mode']='supplemental'; r['built_in_decision']='refuse'; r['evaluation_context']['minimum_registry_epoch']=2
    r=with_pq(r)
    cases.append(vector('supplemental-registry-rollback-blocks-policy-path','A rolled-back registry still blocks the policy path in supplemental mode when built-in trust refuses.',r,'accept','refuse','refuse',{'built_in_refused','policy_accepted','registry_refused','registry_required'}))
    r=with_pq(BASE); r['evaluation_context']['minimum_policy_epoch']=2
    cases.append(vector('policy-rollback-fails-authoritative','Policy rollback refuses under authoritative enforcement.',r,'refuse','accept','refuse',{'built_in_accepted','policy_refused','registry_accepted','registry_required','authoritative_policy_required'}))
    r=with_pq(BASE)
    next(item for item in r['policy']['family_registry'] if item['family']=='lattice')['status']='observe_only'
    cases.append(vector('observe-only-family-does-not-authorize','Observation-only PQ evidence cannot satisfy authoritative policy.',r,'refuse','accept','refuse',{'built_in_accepted','policy_refused','registry_accepted','registry_required','authoritative_policy_required'}))
    r=with_pq(BASE)
    next(item for item in r['policy']['family_registry'] if item['family']=='lattice')['status']='forbidden'
    cases.append(vector('forbidden-family-does-not-authorize','A forbidden family cannot satisfy authoritative policy.',r,'refuse','accept','refuse',{'built_in_accepted','policy_refused','registry_accepted','registry_required','authoritative_policy_required'}))
    return cases

for path in (ROOT/'integration/vectors').glob('*.json'):
    path.unlink()
for case in build():
    (ROOT/'integration/vectors'/f"{case['case_id']}.json").write_text(json.dumps(case,indent=2,sort_keys=True)+'\n')
print(f"wrote {len(build())} integration vectors")
