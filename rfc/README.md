# RFC directory status

The current upstream-oriented draft is:

- [`0001-composable-signature-authorization.md`](0001-composable-signature-authorization.md)

It proposes a transport-independent, bounded authorization layer over ordinary
algorithm-tagged signatures. The proposal focuses on typed signer groups,
thresholds, family diversity, identity binding, explicit enforcement modes,
and rollback-resistant migration.

The earlier file:

- [`0000-hybrid-binary-cache-signatures.md`](0000-hybrid-binary-cache-signatures.md)

is retained as a **historical transport-format draft**. It records the
`Sig-PQC:` experiment that exposed the difference between algorithm agility and
mandatory authorization composition. It is
not the repository’s current upstream recommendation.

Read alongside:

- [`../docs/NORMATIVE_AUTHORIZATION_SPEC.md`](../docs/NORMATIVE_AUTHORIZATION_SPEC.md)
- [`../docs/PRIOR_ART.md`](../docs/PRIOR_ART.md)
- [`../docs/SIGNATURE_POLICY_MODEL.md`](../docs/SIGNATURE_POLICY_MODEL.md)
- [`../docs/adr/0001-policy-over-transport.md`](../docs/adr/0001-policy-over-transport.md)
