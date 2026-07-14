# Local trust-state checkpoints

Policy and registry epochs prevent rollback only after a client remembers the
highest state it has accepted. This layer adds a deliberately small local
checkpoint format and the `trust-state` CLI.

Each named deployment domain records:

- policy ID, epoch, and canonical hash;
- trusted-key registry ID, epoch, and canonical hash.

The complete payload is protected by its own SHA-256 so accidental edits are
detected. This is an integrity check, not authentication against an attacker who
can replace both the state file and its digest. Deployments should protect the
file using normal host integrity, permissions, backups, or a hardware-backed
monotonic store where appropriate.

## Advancement rules

A direct state update requires each changed component to:

1. advance exactly one epoch;
2. bind the previously committed canonical hash;
3. retain the same policy or registry domain ID.

At least one component must advance. An offline client that skipped multiple
epochs must receive and apply the intermediate chain objects rather than trusting
a single epoch jump.

## CLI

Initialize a deployment domain from a normalized authorization request:

```console
trust-state init --domain cache.example --request request.json --out state.json
```

Advance after receiving a linked successor:

```console
trust-state advance --domain cache.example --state state.json \
  --request successor.json --out state.next.json
```

Apply committed minimum epochs to a future request:

```console
trust-state apply --domain cache.example --state state.json \
  --request candidate.json --out guarded-request.json
```

`verify` checks the state format and digest. `show` emits canonical pretty JSON.
Writes use a same-directory temporary file followed by rename.

## Commitment migration

The trust-state payload and its policy/registry checkpoints use commitment-v1
framing. A state file created by an earlier undifferentiated-hash prototype must
not be silently upgraded. Reinitialize from independently trusted current
policy and registry objects, then preserve the older file only as historical
evidence.
