# Resource profile v1

`core-v1` bounds signature observations and diagnostics. `resource-v1` extends
that protection to policy and registry structure so a syntactically valid but
pathologically large policy cannot create surprising traversal or evidence
costs.

The profile caps:

- 64 cryptographic families;
- 256 algorithms;
- 128 typed groups and 128 clauses;
- 64 requirements and 64 relations per clause;
- 16 group references per relation;
- 4096 trusted keys;
- 64 roles per key;
- 256 aggregate predicate values per group;
- 256 UTF-8 bytes per identifier.

The exact values are deliberately generous for binary-cache authorization while
remaining small enough for review and cross-implementation parity. They are
published in `limits/resource-v1.json` and enforced before candidate evaluation.

`estimate_evaluation_work` also emits deterministic work units derived from the
request dimensions. These are not timing promises. They let operators compare
policies, set local admission budgets, and detect accidental complexity growth
without relying on one benchmark machine.
