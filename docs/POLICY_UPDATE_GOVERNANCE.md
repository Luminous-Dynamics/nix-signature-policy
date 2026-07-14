# Policy and registry update governance

Monotonic epochs and predecessor commitments prevent rollback, but they do not
identify who is permitted to publish the next epoch. `src/governance.rs` adds a
small authorization layer for policy and trusted-key registry transitions.

A transition target commits to:

- the component being changed;
- its stable domain identifier;
- the previous and next epochs;
- the exact previous and next canonical commitments.

Verified endorsements bind the domain-separated `transition` commitment. A
bounded rule may require distinct signer identities, cryptographic families,
and administrative authorities while excluding a family believed to be broken.
This permits, for example, an elliptic-curve root and a hash-based root to remove
a compromised lattice family without requiring approval from that family.

The module begins after endorsement cryptographic verification. It does not
specify key storage, network distribution, or a universal governance policy.
Deployments define their own rule, but the rule is explicit, deterministic, and
bounded to at most 1024 endorsement observations.

The example `governance/examples/two-family-recovery.json` demonstrates a
recovery transition authorized by two unaffected families and two independent
authorities.
