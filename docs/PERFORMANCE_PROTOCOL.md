# Performance campaign protocol (frozen before data collection)

**Status: frozen protocol, not yet a results document.** Written and
committed before any trial in this campaign runs, per this project's
own "freeze before collecting" discipline (the same pattern the
architecture comparison used for its fixtures and benchmark policy).
Results live separately in `docs/PROCESS_VS_PROVIDER_RESULTS.md`,
written only after every raw trial here is complete. Raw per-trial data
lives in `measurement/performance/` (JSON/CSV, not summaries).

## The question this campaign answers

> What portion of admission cost comes from the process/provider
> boundary, and how does that cost scale under realistic substitution
> workloads?

Nothing broader. This campaign does not decide whether to build
authorization caching — see "Explicitly out of scope," below.

## Models included

| Model | Why included |
|---|---|
| Legacy/native baseline | No external boundary at all — the zero point every other number is relative to |
| H | Minimal spawned-process reference (opaque decision, smallest settings surface) |
| O-process | The spawned-helper, typed-observation model |
| O-provider | The in-process `dlopen`'d model — the other half of the process-vs-provider question |
| P | Secondary only, run after the main O-process/O-provider result exists — measures external-*policy* overhead, a different question (policy delegation, not verification delegation) from the main comparison |

**T is excluded entirely.** It does not implement the same point-wise
admission decision as the other five — there is no comparable number to
measure.

## Measurement layers

### Layer 1 — boundary-only microbenchmark

Excludes substitution, filesystem, and store setup entirely. Measures
only:

- request construction
- serialization
- fork/exec (H, O-process) or provider call (O-provider)
- response parsing
- policy evaluation

**Priority target: explain O-process's ~55ms unexplained gap** (from
the architecture comparison: corrected O-process added ~88ms over
baseline, its own standalone verifier cost was only ~40ms, H's
equivalent gap was ~9ms over its own ~7ms standalone cost — leaving
~55ms in O-process unaccounted for by "the provider's own cost" alone).
This layer is instrumented stage-by-stage for H and O-process
specifically to close that gap:

- pipe and process setup
- executable startup
- dynamic linking
- registry parsing
- JSON construction and parsing
- signature verification
- Nix-side policy
- cleanup and wait time

### Layer 2 — standalone verifier cost

The verifier binary (H's hook, O-process's helper, O-provider's
`.so` via a thin harness) run directly against frozen fixtures, no Nix
process involved. Isolates cryptographic work from IPC/Nix-integration
cost.

### Layer 3 — real single-path admission

The full `pathInfoIsUntrusted()` path via `nix-store -r`, cold
destination store, the identical signed fixture used throughout the
architecture comparison (`xz942v39v8zf0scg37g1p10m0npvizwd-benchmark-
artifact`). User-visible latency, not a microbenchmark.

### Layer 4 — closure throughput

Transfer and authorize closures of 1, 10, and 100 paths. Expand beyond
100 only if these results show a scaling question worth chasing
further — not scheduled up front.

## Matrix bounds (deliberately kept small)

- **Signature counts**: 1, 2, 8, 32, 128 (new frozen fixtures, signed
  with that many distinct keys each — see task tracking for fixture
  generation; not yet built as of this protocol's freeze).
- **Concurrency**: 1, 4, 16 concurrent admission operations. **Not**
  64-way at this stage — add only if 1/4/16 shows a meaningful
  divergence worth resolving at higher concurrency.
- **Cold/warm state**:
  - O-provider: first `dlopen` in a fresh process; subsequent calls in
    the same process; a fresh Nix process each time; provider already
    resident from a prior run.
  - O-process: cold executable/library page cache (`echo 3 >
    /proc/sys/vm/drop_caches` where permitted, or a freshly-evicted
    equivalent); warm page cache.
- **Repetitions**: enough per cell to report median, p95, and p99 --
  minimum 20 trials per cell, more where variance is high (this
  machine has shown 3x+ range on prior single-digit-trial-count
  measurements under load; 10 trials was insufficient there and will
  not be treated as sufficient here either).

## Failure-path timing (5 essential cases only)

Not the full hostile-case list from the architecture comparison —
timed, not just correctness-checked, for:

- invalid evidence (signature that fails verification)
- verifier crash (H's hook / O-process's helper)
- process timeout or hang
- provider crash (O-provider)
- unsupported algorithm reaching the provider

Security failures often follow a different performance path than
success — e.g. a fail-fast rejection may be *faster* than the happy
path, which would itself be worth reporting, not assumed away.

## Environment control

**Honest limitation, stated up front rather than glossed over**: this
is a shared development machine, not a dedicated benchmark rig. Up to
~12 concurrent Claude Code sessions may be active on it at any time
(observed load average has ranged from ~5 to ~46 during this project),
and this campaign cannot guarantee exclusive access. The mitigations
below (interleaving, continuous load recording, wide repetition) are
designed to make cross-model comparisons *within one campaign run*
valid despite this, not to claim a clean laboratory environment. Any
number reported without its accompanying load-average record should be
treated as unverifiable.

Recorded for every trial batch:

- exact Nix-fork commit per model (already pinned:
  `n-p-t-verified-2026-07-17` / H `8a01e8c` / `o-process-
  verified-2026-07-17` / `o-provider-verified-2026-07-17`)
- exact compiler version and build profile (`gcc 15.2.0`,
  `debugoptimized` meson buildtype, as already used throughout the
  architecture comparison)
- CPU model (`Intel Core i9-8950HK`, 6C/12T, max 4.8GHz, min 800MHz,
  `performance` governor, turbo **enabled** — `no_turbo=0`, a real
  confound source explicitly not eliminated, only recorded)
- total memory (31GB) and available memory at trial time
- load average immediately before and continuously sampled during
  each trial batch (not just a single before/after snapshot)
- process affinity, if used for a given batch (not assumed by default,
  given other sessions share this machine's cores)
- warm-up trials excluded from reported statistics (first N trials of
  any batch are discarded, N determined by observing when timings
  stabilize, recorded per batch)
- page-cache state, explicitly noted per trial (cold/warm)

**Interleaving**: within any single comparison (e.g. baseline vs. H vs.
O-process vs. O-provider at a fixed signature count and concurrency
level), trial order across models is interleaved or randomized, never
run as one model's full batch followed by the next model's full batch.
This is the direct fix for the architecture comparison's earlier
mistake, where O-provider was measured in an entirely separate,
much-higher-load session than the baseline table — gradual load drift
during one campaign run cannot then consistently favor one model over
another.

## Explicitly out of scope for this campaign

- Designing or implementing any caching layer (`R→O` or `O→P`). See
  `docs/CACHE_DECISION_QUESTIONS.md` for the preserved-but-unanswered
  question list this campaign's results will inform, not resolve.
- Model S (persistent service) implementation — this campaign's
  results *feed* the decision of whether Model S is worth building
  (see stop/go criteria below), but building it is a separate,
  later step if triggered.
- 1000-path closures, 64-way concurrency, the full hostile-case list —
  explicitly deferred, not silently dropped, pending what the smaller
  matrix actually shows.

## Stop/go criteria (applied after all raw results are frozen)

**Defer caching entirely** when: O-process overhead is small relative
to total substitution cost; closure throughput remains acceptable;
batching amortizes the fixed cost; cryptographic work dominates rather
than IPC; a persistent service would resolve the remaining cost more
safely than a caching layer would.

**Investigate Model S (persistent service) before any caching work**
when: fork/exec cost dominates; the same verifier is repeatedly
started from cold; process isolation remains desirable as a property;
a persistent local service could plausibly amortize startup cost
without needing to reuse any actual security *decision* (only
avoiding repeated process-startup cost, not repeated verification
judgment).

**Begin cache-correctness research** (a separate, later project, not
triggered by this campaign alone) only when: repeated identical
verification work is shown to be a material bottleneck even after
batching/persistence are accounted for; results show meaningful reuse
potential across real admission operations; the expected performance
benefit is large enough to justify designing and validating a new
security-sensitive state machine.

## Deliverables

- `docs/PERFORMANCE_PROTOCOL.md` — this document.
- `measurement/performance/` — raw per-trial JSON/CSV, one file per
  batch, plus the exact environment manifest for that batch.
- `docs/PROCESS_VS_PROVIDER_RESULTS.md` — analysis, written only after
  every raw result exists. Interpretation stays separate from raw data
  throughout, matching the architecture comparison's own discipline of
  not collapsing distinct evidence classes into one number.
- `docs/CACHE_DECISION_QUESTIONS.md` — the short memo preserving the
  cache-invalidation question list without designing or implementing
  any of it.
