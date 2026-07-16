# Nix signature-authorization integration contract

Status: reference contract implemented and tested in this repository;
Nix-side integration (an actual invocation hook at Nix's admission
boundary) is not implemented -- see `docs/RAW_EVIDENCE_ADAPTER.md`'s
"What this does and does not remove as a dependency".

This contract isolates the smallest upstream-facing security boundary discovered
by the prototype: whether a composed authorization policy is merely advisory or
owns the final artifact-admission decision.

## Inputs

The caller supplies:

- the result of Nix's existing built-in trust path;
- normalized, already-verified signature candidates;
- trusted key and typed policy snapshots;
- evaluation time and committed minimum policy epoch;
- an explicit enforcement mode.

The contract begins after canonical fingerprint construction, wire parsing, and
cryptographic verification. It does not define a new signature transport.

## Enforcement modes

- `legacy`: preserve the built-in decision; policy runs for evidence only.
- `supplemental`: built-in trust or policy may accept. This is compatible with
  observation and migration, but cannot enforce mandatory composition.
- `authoritative`: policy owns the final decision. A built-in any-valid
  acceptance cannot bypass a policy refusal.
- `conjunctive`: both built-in trust and policy must accept.

The selected mode is returned in the deterministic response together with both
component decisions and stable reason codes.

## Upstream relevance

The exact Rust structures are a reference contract, not a demand that cppnix
adopt JSON or this crate. The durable requirement is semantic: a configurable
verifier needs an explicit authoritative mode. An unconditional OR with the
legacy trusted-key path is useful for compatibility but cannot express
mandatory classical-plus-PQ or threshold authorization.

A native C++ implementation, an external verifier, or tvix can share these
semantics and conformance cases while using different process and wire
boundaries.

## Independent registry commitment

The normalized request carries a versioned trusted-key registry rather than an
uncommitted key list. The integration boundary refuses an invalid registry or a
registry epoch below the client's committed minimum before applying any
enforcement mode. This prevents built-in acceptance from bypassing key-registry
rollback protection.
