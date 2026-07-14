#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root/'model'))
import core_v1_model as model
corpus=json.loads((root/'differential/corpus-v1.json').read_text())
manifest=json.loads((root/'differential/manifest-v1.json').read_text())
assert corpus['case_count']==len(corpus['cases'])>=100
assert manifest['case_count']==corpus['case_count']
encoded=(json.dumps(corpus,indent=2,sort_keys=True)+'\n').encode()
assert hashlib.sha256(encoded).hexdigest()==manifest['corpus_sha256']
ids=set()
for case in corpus['cases']:
    assert case['case_id'] not in ids
    ids.add(case['case_id'])
    result=model.evaluate(case)
    expected=case['expected']
    assert result['decision']==expected['decision'], case['case_id']
    assert result['satisfied_clause']==expected.get('satisfied_clause'), case['case_id']
    assert set(result['reason_codes'])==set(expected['required_reason_codes']), case['case_id']
    assert model.best_group_counts(result)==expected['group_counts'], case['case_id']
print(f"differential corpus passed independent model ({len(ids)} cases)")
