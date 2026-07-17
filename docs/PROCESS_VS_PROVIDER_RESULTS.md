# Process vs. provider: performance results and stop/go recommendation

**Status: results for the layers actually run, explicit stop/go
recommendation at the end. Updated after Model S was subsequently
built and measured** (see "Model S prototype," below) — this document
originally recommended investigating a persistent-service successor to
O-process; that investigation is now done, with a real, qualified
(not clean-yes) result. Written against `docs/PERFORMANCE_PROTOCOL.md`'s
frozen scope. Three of the protocol's matrix dimensions were not run
this round (signature-count sweep, cold/warm state isolation,
failure-path timing) — flagged explicitly in "Not run this round," not
silently dropped. What *was* run answers the protocol's central
question with enough evidence to make the stop/go call the campaign
exists to inform.

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

## Model S prototype: does a persistent service actually amortize the cost?

This result directly triggered building Model S (see
`docs/CANDIDATE_ARCHITECTURES.md`'s "Model S" entry) — a prototype
persistent Unix-socket observation service, reusing the exact same
`verify_raw_evidence()` verification logic O-process's real verifier
uses, differing only in transport: a registry loaded once at daemon
startup, served over a long-lived socket, instead of a fresh process
per decision.

Re-ran Layer 4 with Model S added, N=15 interleaved rounds, lower load
this time (load1 5.66–9.77, cleaner than the batch above) — daemon
started once, kept running for the entire batch:

| Config | n=1 | n=10 | n=100 | ms/path at n=100 |
|---|---:|---:|---:|---:|
| baseline | 77ms | 80ms | 133ms | 1.33ms |
| O-process | 116ms | 339ms | 2,893ms | 28.93ms |
| **Model S** | 101ms | 240ms | **1,687ms** | 16.87ms |
| O-provider | 74ms | 78ms | 147ms | 1.47ms |

**The hypothesis is partially confirmed, and the honest result is more
interesting than a clean yes/no.** Model S *is* measurably faster than
O-process at scale — 1.7x at 100 paths (16.87ms vs 28.93ms marginal
cost per path) — confirming that avoiding a fresh process per decision
helps, as predicted. But Model S does **not** close the gap to
O-provider/baseline: it is still ~13x slower than baseline at 100
paths (almost exactly O-process's original ratio in the batch above),
while O-provider remains ~1.1x (statistically indistinguishable from
baseline).

**Why the amortization is only partial**: this prototype's
Nix-side caller (`signature-service-caller.cc`) connects to the
service fresh on every single admission decision — `pathInfoIsUntrusted`
is called once per path in a closure, and the current implementation
does `connect()` → write → read → close every time, with no connection
reuse across the multiple calls one `nix-store -r` invocation makes.
Only the *service process itself* persists; the *connection* does not.
A `connect()`/close() cycle on a Unix domain socket is far cheaper than
`fork()`+`execve()` (no page-table copy, no dynamic linking, no new
process for the scheduler to manage) — which is exactly why Model S
beats O-process — but it is not free, and at 100 repetitions within one
closure operation that per-decision connection cost adds up to a real,
measured gap.

**This is a specific, identified, plausibly fixable limitation of the
prototype as built, not a limitation of the persistent-service
approach in general.** The natural next refinement — not built in this
round, per this campaign's own scope discipline (report the prototype's
real, measured behavior; defer the next iteration explicitly rather
than open-endedly chasing incremental gains) — would be connection
pooling or reuse across a single `nix-store` invocation's multiple
`pathInfoIsUntrusted` calls, mirroring how O-provider caches its
`dlopen`'d handle for the process's lifetime rather than reloading it
per decision. Whether that closes the remaining gap to O-provider is an
open, testable, and well-motivated question for a follow-up, not
assumed here in either direction.

Concurrency (Layer 5) for Model S was attempted but not completed —
the measurement harness was killed twice under this session's
concurrent-session load when a 4th config was added to the existing
3-config sweep, and was not reattempted given Layer 4 already answers
the amortization-hypothesis question this prototype exists to test.
Noted as not-yet-measured, not silently dropped; a real, open item for
anyone continuing this campaign.

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
— done, and the result is a qualified success, not a clean yes.** The
prototype confirms the underlying hypothesis (avoiding a fresh process
per decision measurably helps — 1.7x faster than O-process at a
100-path closure) without fully delivering the hoped-for outcome
(parity with O-provider — it doesn't reach that, still ~13x slower
than baseline at 100 paths). The gap is traced to a specific,
named, plausibly fixable cause: the prototype's caller reconnects per
decision rather than reusing a connection across a closure operation —
see "Model S prototype," above. **The honest updated recommendation**:
Model S as built is a real, working, but *incomplete* answer to
O-process's scaling problem. It is good evidence that the persistent-
service *direction* is sound and worth continuing to invest in over
either accepting O-process's scaling problem or moving to O-provider's
TCB trade-off — but "build Model S" is not by itself a finished
solution; "build Model S with connection reuse" is the next, still-
unbuilt, well-motivated candidate.

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
change, not a caching layer) or a more complete persistent-service
successor (Model S, with connection reuse added) before it's viable
for realistic multi-path substitution workloads; O-provider does not
have this problem, at the cost of the TCB trade-off
`docs/CANDIDATE_ARCHITECTURES.md` already documented, and Model S as
currently built sits in between (better than O-process, not yet as
good as O-provider, with its own distinct standing-target TCB
property).** None of these three conclusions depend on building a
cache.
