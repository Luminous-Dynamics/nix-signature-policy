# External review resolution (2026-07)

Two external review passes examined the composable authorization framework
(`src/policy.rs`, `src/integration.rs`, `src/state.rs`, the release-engineering
pipeline) and the broader hardening opportunity beyond those four findings.
This records what each of the first review's "must fix before review-ready"
findings actually was, and what happened to it — verified against the code,
not taken on the reviewer's word alone, matching this project's standing
practice of confirming a claim before acting on it.

## The four "must fix" findings

| Finding | Verified? | Outcome |
|---|---|---|
| Exponential distinct-relation matching (`distinct_relation_witnesses`, unmemoized backtracking, ~14! branches on a 15-groups/14-identities Hall-deficient input) | Confirmed by reading the code before changing it | Fixed: Kuhn's-algorithm bipartite matching in Rust (`src/policy.rs`), Edmonds-Karp max-flow in the independent Python model (`model/core_v1_model.py`) — deliberately different algorithm families so the two "independent" implementations aren't sharing the same bug. Adversarial regression tests in both languages assert a wall-clock bound. Commit `5eced1e`. |
| Legacy/Supplemental modes vetoed by registry rollback (`authorize()`'s final `accepts` ANDed `registry_accepts` across every mode, contradicting Legacy's own doc comment) | Confirmed by reading the code; found the identical bug independently baked into `check-integration-vectors.py`'s self-consistency formula, never caught because no existing vector combined a registry rollback with Legacy/Supplemental mode | Fixed: `registry_accepts` now only gates the policy path; Legacy mode uses `built_in_accepts` alone, matching its documented "existing behavior remains unchanged" contract. Two new adversarial vectors added and verified against the real `authorize()` function, not just the Python self-consistency check. Commit `82316e0`. |
| Trust-state rollback-checkpoint writer weaker than `src/keys.rs`'s hardened writer (predictable temp filename, no `create_new`, no `sync_all`, no parent-dir sync, no explicit mode, no concurrency protection — two concurrent `advance` calls could race to the same `--out` with the last rename silently winning) | Confirmed by reading both writers side by side | Fixed: extracted `src/keys.rs`'s writer into a shared `src/atomic_file.rs` module (randomized temp name, `create_new` open, `sync_all`, explicit mode, parent-directory sync). `trust-state.rs`'s `init`/`advance` now commit via `CommitMode::CreateNew` (atomically fails if `--out` already exists), closing the concurrent-lost-update race outright rather than just hardening the write path around it. Live-verified against the built binary (`scripts/check-trust-state-checkpoint-no-clobber.sh`), not just unit tests of the primitive. Commit `e2e6402`. |
| Broken release archive (symlink/directory path collision, generated artifacts included, missing tracked dotfiles) | Investigated directly rather than assumed: built the release twice via `scripts/build-source-release.py` (byte-identical output), extracted into an empty directory (clean `tar -xzf`, no symlinks, no generated artifacts, `.github/workflows/ci.yml` and `.gitignore` both present), ran `scripts/verify-source-release.py` (passed), read `verify-source-release.py`'s own checks (already rejects non-regular tar members, path escapes, duplicate/unmanifested/missing files — every defect class the review named), and confirmed the "Deterministic source release" CI job already does build-twice-diff-verify on every run | **Not a repository defect.** The reviewed archive was assembled outside the sanctioned `build-source-release.py`/`verify-source-release.py` pipeline, which was already sound, already self-verifying against exactly these failure modes, already CI-gated, and already documented in `RELEASING.md`'s publication checklist. No code change made — inventing a fix for a bug that doesn't exist in the actual tooling would have been unnecessary scope. |

## A note on process

The packaging finding is worth calling out specifically: it's the one place
in this pass where the right outcome was confirming the reviewer's inference
was wrong, not applying the suggested fix. Treating "an external review
raised it" as sufficient grounds to change code would have added unneeded
complexity to already-correct release tooling. The same investigate-before-
acting discipline that found and fixed the other three bugs is what caught
this one wasn't real.

## Known, unrelated CI signature

`Nix flake check (macos-latest)` fails on every run in this branch's history
(before and after every fix above) with the same signature:

```
error: failed to build archive at .../liballoca-....rlib:
LLVM error: Unknown attribute kind (102)
(Producer: 'LLVM21.1.8' Reader: 'LLVM 19.1.7-rust-1.86.0-stable')
```

A pre-existing incompatibility between the `alloca` crate and the macOS
runner's LLVM/rustc toolchain versions, unrelated to any change in this
document. Deserves its own tracking issue rather than being silently
normalized as "the one job that's always red."

## Second review: staged hardening program

A follow-up review, given the four findings above and asked what to do next,
recommended a 13-stage hardening program (canonical commitment encoding,
evaluation-time trust-boundary hardening, trust-domain binding, protocol
versioning, dynamic-only runtime requests, atomic trust configuration, kernel
crate extraction, `core-v1` minimization, deterministic witnesses, expanded
conformance, a minimal native Nix integration branch, presentation cleanup,
formal modeling, dependency/release assurance tooling, and licensing
analysis). Being executed as a staged, evidence-driven program rather than
one monolithic refactor — each stage independently verified and committed,
starting with the two items that are concrete correctness/security gaps
(`CallerConfig` validation, `evaluation_time` trust-boundary semantics)
rather than architecture preference. Progress tracked stage by stage below
as it lands.

- **Stage 1a — `CallerConfig` validation**: done. Verified the gap was real
  (`CallerConfig::new()`/`invoke()` had zero path-shape validation despite
  the module's own doc comment stating "callers should configure an
  absolute path"). Added `CallerConfig::validate()`, enforced as a
  mandatory pre-flight in `invoke()`: `command`/`working_dir` must be
  absolute (closes a real substitution risk — a relative `command`
  containing a separator resolves against `working_dir` *after* `chdir()`,
  independent of the cleared `PATH`), bounded `args`/`extra_env` entry
  counts, duplicate environment-key rejection, and a new
  `CallerFailure::InvalidConfiguration` variant distinct from
  `SpawnFailed`. Deliberately did *not* make filesystem-permission checks
  (regular file, writable-by-group/world, symlinks, ownership) mandatory —
  those depend on deployment specifics (Nix-store ownership, containers,
  CI runners) a blanket check would false-positive on; left as a future,
  explicitly opt-in layer. 7 new adversarial tests in
  `tests/helper_process_hostility.rs`, all passing alongside the existing
  23 (one, `hung_helper_is_killed_and_its_eventual_output_is_never_trusted`,
  is pre-existing documented timing-under-load flakiness unrelated to this
  change — confirmed by re-running in isolation and confirming the full
  suite passes cleanly on a subsequent run).
- **Stage 1b — `evaluation_time` trust boundary**: done. The field carried
  no documentation of its authority model at all. Traced how it actually
  flows (`EvaluationContext`/`SerializableEvaluationContext`, wire-carried
  inside `AuthorizationRequest`, read-only for every downstream lifecycle
  comparison) and documented it explicitly: the caller (in production, the
  real Nix caller reading its own OS clock) is solely responsible for its
  accuracy; a helper process only ever reads it, has no channel to alter
  it; a compromised *caller*, not a compromised helper, is the actual
  risk. Documented the half-open `[start, end)` boundary convention
  already implicit in all three lifecycle-window comparisons (policy
  `active_from`/`expires_at`, clause `active_from`/`active_until`, key
  `valid_from`/`valid_until`), and explicitly flagged offline-replay
  semantics and clock skew as not modeled yet (a real gap, left for a
  dedicated follow-up rather than silently glossed over here). Added 6
  boundary tests at exactly `t-1`/`t` for all three window types plus an
  `i64::{MIN,MAX}` overflow/panic check — all passed on first run, meaning
  this was a documentation and test-coverage gap, not a behavioral bug.
- Stages 2–13: not started.
