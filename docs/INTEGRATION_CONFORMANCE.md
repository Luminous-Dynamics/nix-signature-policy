# Integration decision conformance

`integration/vectors/` freezes the admission behavior at the boundary between
Nix's built-in trust path, the composed policy evaluator, and the versioned
trusted-key registry.

The matrix covers:

- legacy compatibility;
- supplemental migration behavior;
- authoritative downgrade refusal;
- conjunctive acceptance and refusal;
- unsupported contract versions;
- policy and registry rollback;
- observe-only and forbidden family behavior.

A Python checker independently recomputes the enforcement-mode truth table from
the expected component decisions. Rust integration tests evaluate the full
requests and require the same component decisions, final admission result, and
stable reason codes.

These vectors are intentionally separate from the policy corpus. This allows a
Nix implementation to reuse a different policy engine while still proving that
its final admission boundary is not bypassable.
