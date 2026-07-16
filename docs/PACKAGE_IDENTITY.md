# Package and legacy binary identity

The repository, Cargo package, Rust library crate, release artifacts, and sync
tooling use the durable project identity `nix-signature-policy`.

The executable `nix-pqc-cache-proxy` is intentionally retained. It is the
historical transport and deployment experiment described in the README, and
renaming it would add churn without improving the generalized authorization
core.

`default-run` was removed 2026-07-16: with eight binaries in this crate
covering unrelated things (the historical proxy, the raw-evidence adapter,
policy conformance/evidence, attestation, trust state), no single one is
the canonical "just run it" entry point, and defaulting to the historical
proxy made it look like one. Bare `cargo run` now fails closed and lists
every binary; every invocation in this repository's own docs and scripts
names its binary explicitly with `--bin`.

Two internal hybrid-attestation domain strings also retain the old
`nix-pqc-cache-proxy/...` prefix. Those byte strings are cryptographic protocol
domains, not repository branding. Changing them in place would cause old and
new artifacts to be interpreted under different signing messages without an
explicit schema migration. A future replacement must introduce a new
attestation schema/domain version rather than silently renaming the existing
one.
