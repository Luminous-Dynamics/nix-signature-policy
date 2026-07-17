#!/usr/bin/env python3
"""Adversarial performance check for the independent Python model's
distinct-relation matching (model.core_v1_model.has_system_of_distinct_representatives).

A prior version of this function decided the same question via
itertools.permutations -- exponential brute force, sharing its failure
mode with a separately-fixed exponential bug in the Rust evaluator
(src/policy.rs::distinct_relation_witnesses). This constructs the
sharpest Hall-deficient case the project's resource profile allows (15
groups, MAX_GROUPS_PER_RELATION is 16) drawing from a shared pool of
only 14 identities -- no system of distinct representatives can exist,
and the old permutations-based search would need to exhaust roughly 14!
(~87 billion) candidate assignments before concluding that. The current
Edmonds-Karp max-flow implementation is polynomial and should decide
this in well under a second even on a loaded machine.
"""
import importlib.util
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("core_v1_model", ROOT / "model/core_v1_model.py")
assert spec is not None and spec.loader is not None
model = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = model
spec.loader.exec_module(model)

shared_pool = [f"identity-{i}" for i in range(14)]
deficient = [list(shared_pool) for _ in range(15)]

start = time.monotonic()
result = model.has_system_of_distinct_representatives(deficient)
elapsed = time.monotonic() - start

assert result is False, "15 groups sharing only 14 identities cannot have distinct representatives"
assert elapsed < 5.0, f"Hall-deficient matching took {elapsed:.3f}s -- exponential regression"

# Non-adversarial counterpart: one more identity than group makes a full
# assignment possible, and the matcher must actually find it.
sufficient = [[f"identity-{j}" for j in range(15)] for _ in range(15)]
assert model.has_system_of_distinct_representatives(sufficient) is True

print(f"distinct-relation matching performance check passed ({elapsed:.3f}s on the deficient case)")
