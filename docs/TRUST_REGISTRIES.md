# Versioned trusted-key registries

The authorization policy and the trusted-key set are separate trust domains.
A policy describes which trusted attributes are sufficient; a registry states
which concrete keys possess those attributes.

The trust-registry layer wraps trusted keys in a `TrustRegistry` containing:

- a stable `registry_id`;
- a monotonically increasing `epoch`;
- the canonical SHA-256 of the immediate predecessor;
- the trusted key records.

The registry hash is order-independent with respect to key records. Duplicate
key IDs and duplicate `(key_name, algorithm)` wire identities are invalid.

## Why the registry has its own chain

A policy rollback can restore a weaker threshold. A registry rollback can
restore a revoked or replaced key. Preventing only the first attack is
insufficient.

Clients therefore commit minimum epochs independently for policy and registry.
An authorization request below either committed epoch fails closed, including
when the built-in Nix path and the signature policy would otherwise accept.

## Scope of the commitment

The registry commits trusted metadata, not secret keys and not signature bytes.
It does not prove that the registry was distributed securely. Signed registry
distribution and multi-family control-plane authorization remain separate
future work.
