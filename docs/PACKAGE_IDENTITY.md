# Package and legacy binary identity

The repository, Cargo package, Rust library crate, release artifacts, and sync
tooling use the durable project identity `nix-signature-policy`.

The executable `nix-pqc-cache-proxy` is intentionally retained. It is the
historical transport and deployment experiment described in the README, and
renaming it would add churn without improving the generalized authorization
core. `cargo run` continues to select that binary through `default-run`.

Two internal hybrid-attestation domain strings also retain the old
`nix-pqc-cache-proxy/...` prefix. Those byte strings are cryptographic protocol
domains, not repository branding. Changing them in place would cause old and
new artifacts to be interpreted under different signing messages without an
explicit schema migration. A future replacement must introduce a new
attestation schema/domain version rather than silently renaming the existing
one.
