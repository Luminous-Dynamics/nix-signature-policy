# Process vs. provider: performance results and stop/go recommendation

**Status: results for the layers actually run, explicit stop/go
recommendation at the end.** Written against
`docs/PERFORMANCE_PROTOCOL.md`'s frozen scope. Three of the protocol's
matrix dimensions were not run this round (signature-count sweep,
cold/warm state isolation, failure-path timing) — flagged explicitly in
"Not run this round," not silently dropped. What *was* run answers the
protocol's central question with enough evidence to make the stop/go
call the campaign exists to inform.

All data: `measurement/performance/raw/*.jsonl`, one file per batch,
each with its own load-average record. Environment:
`measurement/performance/raw/batch1-environment.json`.

## The central question, answered

> What portion of admission cost comes from the process/provider
> boundary, and how does that cost scale under realistic substitution
> workloads?

**At single-path granularity, the process/provider boundary itself
costs almost nothing — the earlier "unexplained 55ms gap" was never
really about the boundary mechanism.** A trivial script invoked through
O-process's spawned-helper machinery costs 46ms over baseline; H's
trivial hook costs 43ms over baseline — statistically the same, ruling
out the two independently-written C++ IPC modules as a source of
inefficiency. The real gap is what gets invoked: a real compiled
verifier binary doing real cryptographic work costs ~247ms over
baseline embedded in the full admission path, of which ~97ms is the
binary's own standalone cost and a further, now-isolated ~92ms is a
real (not noise — confirmed via a single fully-interleaved batch)
interaction between the caller's pipe/multithreaded IPC and a
slower-starting child. Mechanism for that last piece not fully
isolated at the syscall level; left as a narrow, specific open question
rather than force-closed.

**At realistic workload granularity — many paths per operation, or
many operations concurrently — the boundary choice matters a great
deal, and the direction is unambiguous.**

## Layer 4: closure throughput (the decisive result)

100 real signed fixtures, N=15 interleaved rounds, 1/10/100 paths per
`nix-store -r` invocation:

| Config | n=1 | n=10 | n=100 | ms/path at n=100 |
|---|---:|---:|---:|---:|
| baseline | 239ms | 405ms | 1,003ms | 10.0ms |
| O-process | 438ms | 1,636ms | **13,586ms** | 135.9ms |
| O-provider | 263ms | 387ms | 1,042ms | 10.4ms |

O-provider is statistically indistinguishable from native baseline at
every size tested. O-process's per-path marginal cost does not amortize
with scale — direct evidence it forks a fresh subprocess per path
rather than batching per invocation, so cost scales ~linearly with
closure size. At 100 paths, O-process is **13x slower** than either
alternative (13.6s vs ~1.0s).

## Layer 5: concurrency (1/4/16 concurrent jobs)

Single path per job (isolates the boundary mechanism from Nix's own
store-locking — each job targets its own destination store), N=5
rounds:

| Config | C=1 p50 | C=4 p50 | C=16 p50 | C=16 throughput | C=16 peak RSS |
|---|---:|---:|---:|---:|---:|
| baseline | 235ms | 408ms | 730ms | 13.11 jobs/s | 43.4MB |
| O-process | 276ms | 326ms | 851ms | 12.32 jobs/s | 37.9MB |
| O-provider | 211ms | 291ms | 666ms | **16.56 jobs/s** | 43.6MB |

At C=16, O-provider pulls *ahead* of both baseline and O-process on
throughput, with the lowest p95/p99 latency. Consistent with `fork()`
having a real, non-trivial kernel cost (page-table duplication,
scheduling) that appears to degrade progressively worse under
concurrent contention than `dlopen()`'s one-time per-process load.
Peak RSS shows no meaningful difference between models (38-44MB across
the board) — memory is not a distinguishing factor at this scale. This
is a distinct finding from Layer 4, not a restatement of it: here each
job already spawns one `nix-store` process regardless of model, so
O-process's per-decision fork cost is proportionally smaller than in
the multi-path-per-invocation closure case. The two layers are
complementary.

## Layers 1-3: single-path admission and its explanation

See the "central question" section above for the full breakdown. Raw
data: `layer3-batch1.jsonl` (single-path, 5 configs interleaved, load
22.0-25.5), `layer2-batch1.jsonl` (standalone verifier, normal vs
cleared environment — env-clearing confirmed **not** a meaningful
factor, correcting an earlier ad-hoc single test that had suggested
otherwise), `layer23-combined-batch1.jsonl` (the single fully-
interleaved batch that resolved whether the standalone/embedded gap
was real or inter-batch drift — it was real, ~92ms).

## Not run this round (explicit, not silently dropped)

- **Signature-count sweep (1/2/8/32/128)**: not run. The frozen
  benchmark fixture and the closure fixtures both use a single Ed25519
  signature per path. Given Layer 4's result already shows the
  dominant cost driver is *forks per admission decision*, not
  signature-verification cost itself, this sweep's main remaining
  value would be confirming that O-provider's per-signature marginal
  cost (pure crypto, no fork) stays flat while O-process's does not --
  directionally predictable from what's already measured, but not
  directly evidenced.
- **Cold/warm state isolation**: not run separately. Layer 4's and
  Layer 5's trials used `rm -rf` fresh destination stores every trial
  (cold SQLite DB init each time) but did not separately isolate
  executable/library page-cache cold-vs-warm as its own factor.
- **Failure-path timing** (invalid evidence, verifier crash, timeout,
  provider crash, unsupported algorithm): not timed. Correctness of
  all these paths was already verified in
  `docs/CANDIDATE_ARCHITECTURES.md`'s E2E scenarios (7/7 for
  O-provider including the demonstrated crash, 5/5 for H); only their
  *latency* remains unmeasured.

## Stop/go recommendation

Applying `docs/PERFORMANCE_PROTOCOL.md`'s frozen criteria to the
evidence above:

**"Investigate Model S (persistent service) before any caching work"
— directly triggered for O-process, not hypothetical.** Its trigger
conditions are now directly confirmed, not inferred: fork/exec cost
dominates (Layer 3/4), the same verifier is repeatedly started from
cold on every single admission decision (Layer 4's linear, non-
amortizing scaling is the direct signature of this), and process
isolation remains a real, desired property of O-process's design (the
TCB analysis in `docs/CANDIDATE_ARCHITECTURES.md` — a compromised
O-process helper's damage is bounded to a subprocess, unlike
O-provider). A persistent local service could plausibly amortize
O-process's dominant cost (repeated process startup) without needing
to reuse any actual security *decision* — it only needs to avoid
repeated `execve`, not cache a verification result. **This is the
single clearest, most evidence-backed next step this campaign
produced.**

**"Defer caching entirely" — supported for O-provider.** Its
performance is statistically indistinguishable from native baseline at
every closure size and pulls ahead of baseline under concurrency.
There is no performance problem for a caching layer to solve here.
Combined with `docs/CANDIDATE_ARCHITECTURES.md`'s TCB finding (a
compromised O-provider crashes Nix's own process — demonstrated, not
theoretical), adding a caching layer to O-provider would add new
security-sensitive surface to a model that does not have a performance
problem motivating it.

**"Begin cache-correctness research" — not triggered by this
campaign.** Neither model shows a bottleneck that only caching (as
opposed to batching, which O-process structurally lacks, or a
persistent service) could fix. The performance case for taking on a
new security-sensitive state machine (see
`docs/CACHE_DECISION_QUESTIONS.md`) is not made by this evidence.

**Overall**: the process/provider choice is not primarily a raw-speed
question at single-path granularity (both are fast; the real single-
path cost driver is the verifier's own cryptographic/parsing work, not
the transport). It is a *scaling and concurrency* question, and there
the evidence points one direction: **O-process needs either batching
(invoke the helper once per closure, not once per path — a design
change, not a caching layer) or a persistent-service successor (Model
S) before it's viable for realistic multi-path substitution workloads;
O-provider does not have this problem, at the cost of the TCB trade-off
`docs/CANDIDATE_ARCHITECTURES.md` already documented.** Neither
conclusion depends on building a cache.
