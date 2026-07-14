# Bounded authorization JSON protocol

Status: experimental process boundary implementing the stable integration semantics.

`nix-signature-authorize` exposes the normalized authorization contract through
one bounded JSON request and one JSON response. It is intended for integration
experiments, cross-implementation testing, and external-verifier prototypes. It
is not a new narinfo signature format.

## Security boundary

The request starts after canonical store-path fingerprint construction,
signature parsing, and cryptographic verification. Candidate `verification`
values must therefore be produced by the caller's verifier rather than trusted
from an untrusted cache response.

The implementation:

- refuses inputs larger than 1 MiB before JSON parsing;
- uses closed Serde structures that reject unknown fields;
- emits at most 2 MiB;
- writes exactly one JSON document followed by a newline;
- distinguishes authorization refusal from protocol failure by exit status;
- never falls back to built-in acceptance after an authoritative refusal.

The machine-readable descriptor is `integration/protocol-v1.json`.

## Invocation

```sh
nix-signature-authorize \
  --request integration/examples/authoritative-downgrade-refusal.request.json \
  --pretty
```

Exit status `0` means accepted, `10` means a valid request was refused, and
`64` or greater means the protocol itself failed. Consumers must parse the JSON
response and must not treat process execution alone as authorization.

## Non-goals

This protocol does not standardize how cppnix, tvix, or another implementation
must expose the boundary. A native function call, sandboxed helper process, or
other IPC can implement the same semantics. The JSON protocol exists so those
implementations can be tested against a concrete, bounded reference boundary.
