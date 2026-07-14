# Independent executable reference model

`model/core_v1_model.py` is a deliberately small Python implementation of the
semantic `core-v1` decision model. It does not import, shell out to, or reuse the
Rust evaluator.

Its purpose is not performance or production use. It is a second executable
interpretation that can detect shared-assumption errors in:

- candidate normalization and duplicate handling;
- typed group derivation;
- family lifecycle eligibility;
- threshold counting;
- same/distinct relations;
- activation and rollback ordering; and
- deterministic refusal reasons and group-count selection.

Run it with:

```sh
python3 scripts/check-reference-model.py
```

The check loads the exact vector membership from the hashed conformance
manifest. A vector cannot silently disappear from the model lane without also
changing the frozen profile.
