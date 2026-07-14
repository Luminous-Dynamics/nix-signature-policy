#!/usr/bin/env python3
import json,re
from pathlib import Path
root=Path(__file__).resolve().parents[1]
d=json.loads((root/'limits/resource-v1.json').read_text())
source=(root/'src/limits.rs').read_text()
mapping={
 'max_policy_families':'MAX_POLICY_FAMILIES','max_policy_algorithms':'MAX_POLICY_ALGORITHMS',
 'max_policy_groups':'MAX_POLICY_GROUPS','max_policy_clauses':'MAX_POLICY_CLAUSES',
 'max_requirements_per_clause':'MAX_REQUIREMENTS_PER_CLAUSE',
 'max_relations_per_clause':'MAX_RELATIONS_PER_CLAUSE','max_groups_per_relation':'MAX_GROUPS_PER_RELATION',
 'max_trusted_keys':'MAX_TRUSTED_KEYS','max_roles_per_key':'MAX_ROLES_PER_KEY',
 'max_predicate_values':'MAX_PREDICATE_VALUES','max_identifier_bytes':'MAX_IDENTIFIER_BYTES'}
assert d['profile_id']=='resource-v1' and d['profile_version']==1
for field,const in mapping.items():
 m=re.search(rf'pub const {const}: usize = ([0-9_]+);',source)
 assert m, const
 assert int(m.group(1).replace('_',''))==d[field], (field,m.group(1),d[field])
policy=(root/'src/policy.rs').read_text()
assert 'policy_within_resource_limits(policy, trusted_keys)' in policy
print('resource profile checks passed')
