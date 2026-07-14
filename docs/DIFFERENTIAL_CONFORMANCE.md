# Generated differential conformance

The committed hand-written vectors target known security boundaries. They are
supplemented by `differential/corpus-v1.json`, a deterministic corpus generated
by the independent Python `core-v1` model.

For every semantic case frozen into `core-v1`, the generator creates mutations
covering candidate ordering, exact duplicates, conflicting duplicates, unknown
keys, malformed observations, and input-bound interactions. The independent
model computes each expected decision, reason set, satisfied clause, and group
counts. A Rust integration test then evaluates the same cases through the
primary implementation.

This is not a proof that either implementation is correct. It reduces the risk
that the Rust evaluator and its handwritten tests share the same accidental
assumption, and it makes order sensitivity or diagnostic drift visible as a
reviewable corpus change.

Regenerate with:

```sh
python3 scripts/build-differential-corpus.py
```

CI uses `--check` and verifies the manifest SHA-256 before running the model.
