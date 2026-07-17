# Closure/build-trace archaeology (Model T groundwork)

**Status: non-normative research snapshot, not a specification.** Same
discipline as `docs/NIX_INTEGRATION_ARCHAEOLOGY.md`: a direct reading of
real source, file:line cited, written before any Model T code exists.
This document exists specifically to check whether Nix's existing
`Realisation`/`DrvOutput` machinery gives Model T (the closure/build-trace
authorization skeleton) anything to build on, or whether it needs new
plumbing from scratch.

- **Source examined**: `DeterminateSystems/nix-src`, commit
  `6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6` (`nix-src#449`, merged
  2026-05-20) — the same fork already used for the point-wise raw-evidence
  adapter's interoperability testing.
- **Date examined**: 2026-07-16.
- **External reference read (not cloned, not a dependency)**:
  `github.com/mschwaig/laut`'s README, fetched directly.

## The scenario this needs to support

From `mschwaig`'s real comment on `#14451`
([permalink](https://github.com/NixOS/nix/issues/14451#issuecomment-3687397244)):
build the same executable via two independent paths through two versions
of `gcc` that differ only in build-output content hash; if both paths
converge on the same final output, that convergence should count as
evidence toward a reproducibility quorum, even though neither individual
`gcc` build was itself reproducible. His own reference implementation,
`laut`, "has quorums implemented, but not correctly yet," by his own
account.

## Finding 1: Nix already has *a* signature-accumulation mechanism — but keyed wrong for this scenario

`LocalStore::registerDrvOutput()` (`src/libstore/local-store.cc:649-672`)
merges signature sets when a new `Realisation` registration is
`isCompatibleWith` an existing one:

```cpp
// local-store.cc:649
void LocalStore::registerDrvOutput(const Realisation & info)
{
    ...
    if (auto oldR = queryRealisation_(*state, info.id)) {
        if (info.isCompatibleWith(*oldR)) {
            auto combinedSignatures = oldR->signatures;
            combinedSignatures.insert(info.signatures.begin(), info.signatures.end());
            ...
        }
```

`Realisation::isCompatibleWith()` (`src/libstore/realisation.cc:64-67`)
checks `outPath == other.outPath` — the *actual converged content*, not
the derivation that produced it. This looks at first read like exactly
the mechanism Model T needs.

**It isn't, for ordinary derivations.** The lookup that finds `oldR` in
the first place (`queryRealisation_(*state, info.id)`) is keyed by
`info.id`, a `DrvOutput` (`realisation.hh:24-38`):

```cpp
struct DrvOutput {
    /**
     * The hash modulo of the derivation.
     *
     * Computed from the derivation itself for most types of
     * derivations, but computed from the (fixed) content address of the
     * output for fixed-output derivations.
     */
    Hash drvHash;
    OutputName outputName;
```

For an ordinary (non-fixed-output) derivation, `drvHash` is derived from
the derivation graph itself — two syntactically different derivations
(two different `gcc` build recipes, `mschwaig`'s exact example) get two
different `drvHash`es, hence two different `DrvOutput.id`s, **even if
their outputs are byte-identical**. `registerDrvOutput`'s merge path can
only ever fire for *repeat registrations of the identical derivation* (a
build re-signed by multiple independent builders/signers) — its
`isCompatibleWith`/`outPath`-equality check never gets a chance to run
across two different derivations, because the DB lookup that precedes it
is keyed by the wrong thing for that case. Fixed-output derivations are
the one exception the doc comment calls out explicitly (`drvHash` there
*is* the content address), so this gap is specific to ordinary
derivations — which is exactly `mschwaig`'s `gcc` example.

**This is the concrete, minimal gap Model T's skeleton needs to close**:
a query path that, given an `outPath`, finds every `Realisation` across
*every* `DrvOutput.id` that produced it — not just repeat registrations
under one id — so that two independently-built, differently-derived,
convergent outputs can be recognized as such at all before any quorum
policy can be evaluated over them.

## Finding 2: the daemon RPC gap from the point-wise archaeology recurs here, unchanged

`daemon.cc`'s `RegisterDrvOutput` handler (`src/libstore/daemon.cc:982-994`,
line numbers drift slightly from the vanilla-Nix pass but the code is the
same shape) calls the single-argument `registerDrvOutput(Realisation)`
overload unconditionally, in both protocol-version branches — the
overload that does **not** check signatures at all
(`local-store.cc:649`), never the `CheckSigsFlag`-gated one
(`local-store.cc:639-647`). Confirmed present, unchanged, in this
Determinate fork too. Not something Model T should silently patch as a
side effect — it's the same open question the point-wise archaeology
already flagged for a maintainer, reproduced here for completeness, not
re-litigated.

## Finding 3: no threshold/quorum concept exists anywhere in the live admission path

`ValidPathInfo::checkSignatures()` (`path-info.cc:120-130`, same CA-path
`maxSigs` short-circuit as the vanilla-Nix pass found, same unconditional
behavior in this fork) and `UnkeyedRealisation::checkSignatures()`
(`realisation.cc:46-55`) both return a plain `size_t` count with **any
value > 0 sufficient** at every real call site
(`pathInfoIsUntrusted`/`realisationIsUntrusted`, `local-store.cc:1003,1008`).
`--sigs-needed` exists **only** in `src/nix/verify.cc` — the standalone
`nix store verify` CLI command — entirely disconnected from what actually
gates substitution/`addToStore`/`registerDrvOutput`. Grepped the whole
`src/libstore/` tree for `quorum`/`threshold`: no hits outside unrelated
S3-upload chunking settings. This confirms Model N's own premise (native
grouped-signature admission is genuinely new work, not an existing-but-
unwired feature) and means Model T's quorum evaluation has nothing to
inherit from the CLI verify path either — it would need its own logic
regardless of which point-wise model it's paired with.

## Finding 4: `laut` is deliberately out-of-band, not a live admission-path patch

Per `laut`'s own README: it is a **standalone secondary binary**, not a
Nix core patch. `laut sign-and-upload` runs from an ordinary
post-build hook (the same `runPostBuildHook` mechanism the point-wise
archaeology already examined) and uploads to a `traces/` namespace on an
HTTP cache. `laut verify` is run **manually by the user**, resolves the
dependency tree itself, gathers signatures from configured caches, and
feeds the result into its own trust-model evaluator. It uses its own new
signature format on top of JWS — not narinfo `Sig:` lines. It is not
currently wired into `checkSignatures()`/`addToStore`/substitution at
all.

**Implication for Model T**: `laut` is not a smaller version of what
Model T needs to prototype — it's a differently-scoped, already much
larger tool (own signature format, own dependency resolution, own
trust-model DSL) solving a related but broader problem out-of-band.
Model T should not attempt to imitate `laut`'s architecture. It should
stay inside Nix's own `Realisation`/`DrvOutput` data model and close only
the narrow gap in Finding 1, enough to run the one distinguishing test
the plan specifies — nothing about correct quorum evaluation, revocation,
or an alternate signature format.

## What Model T's skeleton should actually be, given these findings

Not a quorum engine (matches the plan's explicit scope, now with concrete
grounding for *why* that's the right cut line — even Nix's own data model
doesn't yet represent the input this needs, so a correct evaluator would
be premature). Concretely, the smallest thing that demonstrates the real
distinction:

1. A new query, alongside the existing `id`-keyed `queryRealisation_`,
   that finds every `Realisation` sharing one `outPath` regardless of
   `DrvOutput.id` — the missing half of Finding 1.
2. Two fixture derivations in a functional test, deliberately different
   (different builder script, same declared output), each registered
   with its own signer.
3. One assertion that the new query returns both, with both signatures
   attributable to genuinely different `DrvOutput.id`s — i.e., the test
   proves the "two independent build paths converged" case is now
   *distinguishable* from "one derivation, signed twice" (which
   `registerDrvOutput`'s existing merge already handles), not that any
   policy has been evaluated over the distinction yet.

## Open questions, not resolved here

- Whether closing Finding 1's gap belongs in `registerDrvOutput` itself,
  a new read-only query alongside it, or a separate index — not designed,
  a real choice for whoever builds the Phase 7 skeleton.
- Whether the `daemon.cc:982` unconditional no-signature-check (Finding
  2) is intentional (matches "realisations are trusted build output"
  reasoning already noted in the point-wise archaeology) — still a
  maintainer question, not this project's to assume either way.
- Whether `laut`'s eventual signature format is worth aligning with here
  — deliberately out of scope for a skeleton; `laut` itself says its own
  envelope format may still change.
