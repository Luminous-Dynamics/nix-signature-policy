# Evidence for `docs/CANDIDATE_ARCHITECTURES.md`

Two kinds of durable, re-runnable evidence, vendored here rather than
left as local-only worktree state (see "A recurring configuration-
mechanism gap" and the "reproducibility" discussion in
`docs/CANDIDATE_ARCHITECTURES.md` for context on why this was needed).

- **`nix-fork-patches/`** — the exact diffs for every commit cited in
  the comparison, as `git am`-applyable patches against a real, public
  base commit. None of the branches these came from are reachable from
  any public git remote (`origin` for every checkout used was
  `DeterminateSystems/nix-src` itself, and no fork under this project's
  control exists) — these patches are the substitute for "clone this
  branch," verified to reproduce byte-identical trees. See that
  directory's own `README.md`.
- **`e2e-scripts/`** — the actual shell scripts used to produce the E2E
  scenario results in `docs/CANDIDATE_ARCHITECTURES.md`'s correctness
  table for Model H (`run-h-e2e.sh`, the corrected reproduction of H's
  documented scenarios using the working store-URI invocation) and
  Model O-provider (`run-oprovider-e2e.sh`, including the scenario that
  demonstrates the in-process crash), plus the example provider `.c`
  sources and build script they depend on. Verified to run clean from
  this exact vendored location (self-contained, no path back into the
  original session's scratch directories) against real builds produced
  from the patches above.

Not vendored, deliberately: private/secret key material (only the
public halves of the frozen benchmark keys are here, matching this
repo's existing convention in
`tests/fixtures/determinate-nix-449/`), and compiled `.so`/binary
artifacts (build them with `provider/build.sh`; `.gitignore` in
`e2e-scripts/` keeps them from being accidentally committed on a
future rerun).

## Reproducing the full evidence trail

```sh
# 1. Get a model's Nix source tree (see nix-fork-patches/README.md)
git clone https://github.com/DeterminateSystems/nix-src && cd nix-src
git checkout --detach 6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6
git am ../nix-fork-patches/0000-shared-foundation-checkSignaturesDetailed.patch
git am ../nix-fork-patches/0001-model-n-native-grouped-signatures.patch
git am ../nix-fork-patches/0002-model-o-provider-inprocess-verifier.patch

# 2. Build it (meson/ninja; see the Nix project's own build docs)
meson setup build && ninja -C build src/nix/nix-store

# 3. Build the example provider(s)
cd ../e2e-scripts/provider && ./build.sh && cd ..

# 4. Run the E2E scenarios against the binary from step 2
./run-oprovider-e2e.sh /path/to/nix-src/build/src/nix/nix-store
```
