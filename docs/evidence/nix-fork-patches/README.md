# Nix-fork patches (vendored evidence for `docs/CANDIDATE_ARCHITECTURES.md`)

**Why these are here.** Every model in `docs/CANDIDATE_ARCHITECTURES.md`
was built and tested against real, local checkouts of a Nix fork
(`DeterminateSystems/nix-src`). `origin` for every checkout used is
`DeterminateSystems/nix-src` itself — upstream, not a fork this project
controls — and no Luminous-Dynamics/personal fork of `nix-src` exists.
That means the branches those models were built on are **not reachable
from any public git remote**. Rather than create and push a new public
fork (a separate action, requiring its own review) just to make cited
commits fetchable, the exact diffs are vendored here as `git am`-
applyable patches. This repo is already public and already the
citation target for this comparison, so it is the more self-contained
place for this evidence to live.

**Verified reproducible, not just generated.** Every chain below was
actually replayed with `git am` against a fresh detached checkout of the
public base commit and confirmed to produce a byte-identical result
(`git diff <original-commit> --stat` empty, or for the cross-repository
H chain, matching `git rev-parse <commit>^{tree}` output) — not merely
assumed to apply because `git format-patch` produced a file.

## Base commit

`DeterminateSystems/nix-src` commit
[`6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6`](https://github.com/DeterminateSystems/nix-src/commit/6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6)
(`nix-src#449`, merged 2026-05-20) — a real, public, merged commit.
Chosen because this fork already has native Ed25519 + ML-DSA-65
verification, which every model depends on.

## Reproducing a model

```sh
git clone https://github.com/DeterminateSystems/nix-src
cd nix-src
git checkout --detach 6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6

# every chain starts with the shared foundation:
git am /path/to/0000-shared-foundation-checkSignaturesDetailed.patch

# then apply the patches for the model you want, in order:
```

| Model | Patches to apply, in order, after `0000` | Reproduces |
|---|---|---|
| N | `0001-model-n-native-grouped-signatures.patch` | `8ad4bbe` |
| P | `0001-model-n-...` , `0002-model-p-verify-signatures-json.patch` | `8858bef` |
| T | `0001-model-n-...` , `0002-model-p-...` , `0003-model-t-closure-trace-groundwork.patch` | `f317153` |
| H | `0001-model-h-wiring-and-caller.patch` , `0002-model-h-functional-test.patch` (**not** N — H is an independent branch from the shared foundation, not layered on N) | `8a01e8c` |
| O-process | `0001-model-n-...` , `0002-model-o-process-external-verifier.patch` | `187029b` |
| O-provider | `0001-model-n-...` , `0002-model-o-provider-inprocess-verifier.patch` | `840d22e` |
| S | `0001-model-n-...` , `0002-model-s-persistent-service.patch` | `21cc893` |

Note the deliberate numbering collision: there are multiple different
"`0002`" patches (one per independent branch off the shared foundation:
H, O-process, O-provider, S) and N's patch is
reused verbatim (byte-identical diff, confirmed) as the second step for
P/T/O-process/O-provider. This mirrors the actual commit graph rather
than flattening it into one fictitious linear sequence — see
"Branch structure, precisely" in `docs/CANDIDATE_ARCHITECTURES.md` for
why N/P/T are commits on one cumulative branch while H, O-process, and
O-provider are independent branches that each start from the shared
foundation.

## What this does not claim

These patches are the exact content of the commits cited in
`docs/CANDIDATE_ARCHITECTURES.md`. They are **not** re-verified by CI in
this repository, and applying them requires a working Nix build
environment (Meson/Ninja, the dependencies `DeterminateSystems/nix-src`
itself needs) that this repository does not provide or test. The
original verification (unit tests, E2E scenarios, the demonstrated
O-provider crash) was performed once, interactively, against real
builds of each of these trees — recorded in
`docs/CANDIDATE_ARCHITECTURES.md` — and is not re-run automatically by
anything in `nix-signature-policy`'s own CI.
