# Security review checklist

A reviewer should be able to answer each item from code, tests, or committed
vectors.

## Trust boundaries

- Can signature input assign its own identity, role, family, authority, or
  custody domain?
- Can built-in any-valid acceptance bypass authoritative policy?
- Are policy authority, registry authority, artifact-signing authority, and
  recovery authority separable?

## Determinism and bounds

- Are candidate order and transport layout semantically irrelevant?
- Can duplicate evidence increase authority?
- Are raw observations, unique candidates, diagnostics, vector files, and
  parser inputs bounded?
- Does every acceptance include a complete deterministic witness?

## Lifecycle and recovery

- Are observe-only and forbidden families ineligible without sabotaging other
  evidence?
- Can a client reject older policy and registry epochs using persisted state?
- Can recovery proceed after any one required family is disabled?
- Are canonical commitments domain separated and versioned?

## Integration

- Is unsupported contract behavior fail closed in authoritative and conjunctive
  modes?
- Does disabled/default configuration preserve existing Nix behavior?
- Are response reason codes stable while human text remains non-normative?

## Assurance boundaries

- Are receipts described as decision records rather than independent
  cryptographic proofs?
- Is the historical proxy clearly separated from the normative policy design?
- Are unaudited cryptographic components and production limitations explicit?
