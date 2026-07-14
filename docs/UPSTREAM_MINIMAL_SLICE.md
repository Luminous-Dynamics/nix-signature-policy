# Minimal upstream integration slice

The first upstream change does not need to standardize the entire research
framework. The smallest durable decision is an explicit authorization boundary
for store-path signature evidence.

## Proposed first increment

1. Nix cryptographically verifies available signatures and normalizes bounded
   observations.
2. A configured authorization mechanism returns a structured accept/refuse
   result.
3. Enforcement mode is explicit: `legacy`, `supplemental`, `authoritative`, or
   `conjunctive`.
4. `authoritative` mode cannot be bypassed by an existing built-in any-valid
   acceptance.
5. Existing behavior remains unchanged unless a stricter mode is selected.
6. Unsupported contract versions and malformed responses fail closed in modes
   that depend on the external decision.
7. Requests, responses, diagnostics, and execution time are bounded.

The typed policy evaluator, rollback state, receipts, and conformance suite are
a reference implementation and evidence that the boundary supports useful
policies. They need not all become native Nix configuration in the first
increment.
