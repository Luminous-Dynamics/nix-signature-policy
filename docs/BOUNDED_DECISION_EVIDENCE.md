# Bounded decision evidence

Authorization inputs are attacker influenced, so diagnostics must not scale
without a hard ceiling even when evaluation itself is bounded.

`core-v1` retains at most 256 candidate-level diagnostics in one decision and
records the number of additional diagnostics in
`omitted_candidate_diagnostics`. Aggregate decision reason codes and clause
observations remain available even when candidate details are truncated.

The cap applies after raw-observation admission and before decision
serialization. It prevents repeated duplicate, malformed, or unknown
observations from producing an unbounded evidence or log payload.
