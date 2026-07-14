# Security policy

## Prototype security boundary

`nix-signature-policy` is an experimental reference implementation. It is not an
audited production cache, a replacement for the Nix trust root, or a claim that
re-signing a classical upstream makes that upstream post-quantum secure.

The repository currently demonstrates:

- exact Nix narinfo fingerprint compatibility for the covered vectors;
- mandatory classical-and-post-quantum signature-policy composition;
- bounded, fail-closed proxy behavior;
- representation-neutral adversarial policy vectors;
- deterministic policy-decision and release evidence;
- real-Nix interoperability in dedicated CI lanes.

The complete assurance boundary and residual risks are documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability that could put
users, keys, caches, or infrastructure at risk. Use GitHub's private security
advisory workflow for this repository when available. If that is unavailable,
contact the repository owner privately through the contact method listed on the
Luminous Dynamics GitHub organization.

Include, where possible:

- affected commit or release;
- attacker capabilities and prerequisites;
- a minimal reproducer;
- expected and observed behavior;
- whether key material, authorization, availability, or evidence integrity is
  affected.

Do not include real secret keys, private cache URLs, or production credentials.

## Response expectations

This is an independently maintained research prototype, so no commercial SLA is
promised. Reports will be acknowledged and assessed as capacity permits. A
confirmed vulnerability will be documented with a narrowly stated impact,
regression coverage, and a corrected release or commit when feasible.

## Supported versions

Only the current `main` branch and the most recent tagged source release are
considered for security fixes. Historical patch sets and the bundled historical
RFC transport draft are retained for research provenance, not maintained as
supported release lines.
