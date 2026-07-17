# Process vs. provider: performance results and stop/go recommendation

**Status: results for the layers actually run, explicit stop/go
recommendation at the end. Three times updated as Model S was built,
measured, refined, re-measured, and then the batching hypothesis it
raised was tested directly** (see "Model S prototype" and "Batching
diagnostic," below) — this document originally recommended
investigating a persistent-service successor to O-process; that
investigation is done, and its first favorable result (Model S 1.7x
faster than O-process) did **not** replicate once the identified next
refinement (connection reuse) was actually built and re-measured under
the same interleaved discipline as everything else in this campaign. A
follow-on hypothesis — that batching many decisions into one round
trip would amortize the remaining floor — was then tested directly and
also **refuted**. The final reading is that neither Model S nor
O-process resolves the closure-throughput problem, no transport-level
refinement of either one does either, and only O-provider does, in
this campaign's data. This two-step reversal is itself evidence for
the value of this document's own interleaving/replication discipline:
a single favorable measurement, even a clean-looking one, was not
trustworthy until re-tested, and a plausible follow-on hypothesis was
not trustworthy until it was actually tried. Written against
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

## Model S prototype: does a persistent service actually amortize the cost?

This result directly triggered building Model S (see
`docs/CANDIDATE_ARCHITECTURES.md`'s "Model S" entry) — a prototype
persistent Unix-socket observation service, reusing the exact same
`verify_raw_evidence()` verification logic O-process's real verifier
uses, differing only in transport: a registry loaded once at daemon
startup, served over a long-lived socket, instead of a fresh process
per decision.

**Batch A (before connection reuse)** — N=15 interleaved rounds, load1
5.66–9.77, daemon started once and kept running for the batch, but the
Nix-side caller connected to the socket fresh on every single admission
decision (no connection reuse yet):

| Config | n=1 | n=10 | n=100 | ms/path at n=100 |
|---|---:|---:|---:|---:|
| baseline | 77ms | 80ms | 133ms | 1.33ms |
| O-process | 116ms | 339ms | 2,893ms | 28.93ms |
| Model S (connect-per-decision) | 101ms | 240ms | 1,687ms | 16.87ms |
| O-provider | 74ms | 78ms | 147ms | 1.47ms |

At the time, this read as "Model S is 1.7x faster than O-process,
confirming that avoiding a fresh process per decision helps." A
connection-reuse fix was then implemented (see the paired
`nix-signature-policy` commits: NDJSON framing on the daemon so one
connection can serve many sequential requests, plus a
`Sync<map<socketPath, fd>>` cache on the Nix side mirroring O-provider's
`dlopen`-handle cache) and **directly confirmed to work as intended** —
the daemon's own connection-accept log shows exactly one connection
accepted per `nix-store` invocation regardless of how many paths it
processes (a 10-path closure produces exactly one "accepted connection"
line, not ten).

**Batch B (after connection reuse, verified working)** — N=8
interleaved rounds, load1 6.96–9.25, same daemon, same fixtures:

| Config | n=1 | n=10 | n=100 | ms/path at n=100 |
|---|---:|---:|---:|---:|
| baseline | 84ms | 85ms | 164ms | 1.64ms |
| O-process | 123ms | 369ms | 3,320ms | 33.20ms |
| **Model S (connection reused)** | 112ms | 385ms | **3,325ms** | 33.25ms |
| O-provider | 85ms | 86ms | 183ms | 1.83ms |

**Connection reuse, despite being mechanically verified correct,
produced no measurable improvement over O-process** — 33.25ms vs.
33.20ms marginal cost per path, statistically indistinguishable, both
distributions overlapping substantially at n=100 (O-process: 2,856–
3,864ms across 8 rounds; Model S: 2,595–3,739ms). This directly
contradicts Batch A's "1.7x faster" reading. Batch B is the more
trustworthy number: both configs were measured in the same interleaved
batch against their own contemporaneous baseline, whereas Batch A's
"1.7x" was only ever compared across two different measurement
sessions (see this document's own earlier caution, in the Layers 1-3
section, about exactly this kind of cross-batch comparison). **Batch
A's result should be treated as likely noise or an unidentified
load-related artifact, not a reproducible effect** — a real example of
why this campaign's own interleaving discipline exists, and why a
single favorable measurement should not be trusted until it either
replicates or is understood mechanistically.

**Diagnostic follow-up, to understand what actually dominates the
per-decision cost now that connection setup is ruled out**: a pure
Python client — no Nix, no closure machinery, just connect once and
send 100 sequential newline-delimited requests over the reused
connection — was used to isolate the raw protocol round-trip cost.
Sending the *same* two-signature (Ed25519 + ML-DSA-65) request the
original frozen benchmark fixture uses: median 42.4ms per round-trip.
Restricted to *only* the Ed25519 signature (matching what Model S's
real caller actually sends for the closure fixtures, which were signed
with Ed25519 only): median 14.0ms. **The raw protocol round-trip itself
— write one line, wait, read one line, over an already-open, reused
connection, doing real signature verification — has an ~14ms floor on
this machine**, even with zero connection-setup cost. That floor is
close enough to O-process's fork/exec/pipe/verify total cost that
removing fork/exec alone doesn't produce a visible win once the
connection is already warm — whatever dominates is something the two
models now share (candidates, not confirmed: cryptographic verification
cost, or synchronous cross-process scheduling/context-switch cost under
this machine's load — genuinely not isolated further here, flagged as
open rather than guessed at).

**Revised understanding**: the original hypothesis — "O-process is slow
because it forks a process per decision" — was too narrow. Fork/exec is
*a* cost, and Batch A's H-vs-O-process-trivial-script comparison
earlier in this document still correctly shows the transport mechanism
itself (spawned process vs. persistent connection) costs about the same
when the payload is trivial. But once the payload requires *real
verification work*, that work's own cost — not the transport — appears
to set the floor, and neither O-process nor a connection-reused Model S
escapes it. **Only O-provider, which eliminates the cross-process
round-trip entirely (a direct function call, no serialization, no
socket, no scheduler involvement), escapes this floor** — which is
exactly why O-provider alone lands within noise of native baseline at
every closure size measured in this campaign.

Concurrency (Layer 5) for Model S — both before and after the
connection-reuse fix — was attempted but not completed; the measurement
harness was killed repeatedly under this session's concurrent-session
load when a 4th config was added to the existing 3-config sweep. Given
Layer 4 now shows connection reuse produces no measurable win, a
concurrency measurement is lower-priority than it would have been under
Batch A's (likely spurious) result, but remains a real open item, not
silently dropped, for anyone continuing this campaign.

## Batching diagnostic: does round-trip amortization help?

The diagnostic above traced Model S's floor to something other than
connection setup, leaving open whether it's round-trip count (one
write-wait-read cycle per decision) or the verification work itself
(dominated by ML-DSA-65 cost) that actually sets the cost. This is
directly testable, cheaply, without touching Nix or any C++: extend the
daemon's protocol with a batch request (one line carries every
decision; one line returns every result, same order) and measure
whether N decisions sent as one batched round trip cost less than N
decisions sent as N individual round trips, on the same already-open
connection.

Added `IncomingRequest::{Batch,Single}` (untagged enum) to the daemon
and a standalone Python client
(`measurement/performance/model-s-batching-diagnostic.py`) that
alternates individual-call and batch-call rounds against the same
connection — matching this campaign's interleaving discipline so a
load spike can't be misread as a real effect. N=5 rounds, 100
decisions per round, both payload shapes from the earlier diagnostic:

| Payload | Individual, median ms/decision | Batch, median ms/decision | Individual range | Batch range |
|---|---:|---:|---:|---:|
| ed25519-only | 16.07 | 14.66 | 14.61–16.31 | 14.28–16.37 |
| both signatures (ed25519+ml-dsa-65) | 53.71 | 52.68 | 44.10–60.05 | 45.06–67.02 |

**Batching produces no measurable improvement over individual calls,
for either payload shape — the two distributions overlap almost
completely, and what small difference exists is within round-to-round
noise, not a consistent direction.** This decisively refutes the
batching hypothesis as stated: amortizing round-trip *count* is not the
lever. Combined with the earlier finding that connection-reuse (which
already removed connect-per-decision cost) also produced no
improvement, the remaining explanation is the more mundane one flagged
as a candidate earlier — the verification work itself (real Ed25519
and, especially, ML-DSA-65 signature checking) is what costs ~14-54ms
per decision on this machine, and no transport-level change (spawn a
process, open a connection, or batch several decisions into one
round trip) touches that cost, because every one of those framings
still calls the same verification routine once per decision.

Raw data: `measurement/performance/raw/model-s-batching-diagnostic-batch1.json`.

This also revises the "batching" recommendation this document's Stop/go
section previously pointed at as the most promising next step for
O-process — see the correction there.

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
— done, in full, including the specific refinement (connection reuse)
this document originally identified as the next step. The result is
not the success the first measurement suggested.** Connection reuse was
implemented, directly verified to work mechanically (one connection per
`nix-store` invocation, confirmed via the daemon's own connection-accept
log, not inferred from timing), and re-measured under the same
interleaved discipline as every other result in this campaign. **It
produced no measurable improvement over O-process** — 33.25ms vs.
33.20ms marginal cost per path at 100 paths, distributions
substantially overlapping. The earlier "1.7x faster" reading (Batch A,
before the fix existed to compare against) did not replicate and should
be treated as likely noise, not a real effect — see "Model S
prototype," above, including the diagnostic that traced the
~14ms-per-decision floor to something other than connection setup
(most likely the verification round-trip's own cost, not isolated
further). **The honest, final recommendation**: the persistent-service
*direction*, at least as prototyped here, is not a fix for O-process's
scaling problem. Removing fork/exec alone — whether via a persistent
process (Model S) or nothing else — does not reach O-provider's
performance, because fork/exec was never the sole or even dominant
cost; a synchronous cross-process round-trip doing real verification
work carries a cost of its own that a warm, reused connection does not
eliminate. Only eliminating the *round-trip itself* (O-provider's
in-process call) does.

**"Defer caching entirely" — still supported, now for both O-process
and Model S, not only O-provider.** O-provider's performance is
statistically indistinguishable from native baseline at every closure
size and pulls ahead of baseline under concurrency — no performance
problem for a cache to solve. O-process and Model S now both show the
same floor, for reasons this campaign traced to verification-round-trip
cost, not a caching-shaped problem (a cache would need to store a
*security decision*, exactly what `docs/CACHE_DECISION_QUESTIONS.md`
declines to design without a demonstrated performance case — and the
case demonstrated here points at a different fix, batching or
eliminating the round-trip, not caching its result).

**"Begin cache-correctness research" — not triggered by this
campaign, now more clearly than before.** Neither model shows a
bottleneck caching (as opposed to batching, or eliminating the
round-trip entirely) would fix. The performance case for taking on a
new security-sensitive state machine (see
`docs/CACHE_DECISION_QUESTIONS.md`) is not made by this evidence.

**Overall, corrected twice now**: the process/provider choice is not
primarily a raw-speed question at single-path granularity (both are
fast). At closure-throughput granularity, the real cost driver turned
out to be neither "forking a process" nor "opening a connection" nor
"one round trip per decision," but the cost of the verification work
itself — real Ed25519 and ML-DSA-65 signature checking, ~14-54ms per
decision on this machine depending on how many signatures a decision
carries — which every transport-level model measured here (fork+exec,
a reused warm connection, or a batched round trip) still pays exactly
once per decision, because none of them change how many times
`verify_raw_evidence()` actually runs. **O-provider is the only model
measured in this campaign that avoids paying this cost as a
synchronous cross-process (or cross-connection) round-trip** — not
because it does less verification work, but because that work happens
via a direct in-process function call with no serialization, socket,
or scheduler involvement, so it doesn't additionally pay a round-trip
floor on top of the verification cost. This is a narrower, more honest
claim than the campaign's original framing ("avoid fork/exec") — the
fix that mattered turned out to be "avoid a synchronous IPC boundary
around verification," not "avoid a process boundary" specifically,
and the batching diagnostic (above) directly ruled out "just amortize
the round-trip count" as a substitute fix. This comes at the TCB cost
`docs/CANDIDATE_ARCHITECTURES.md` already documents (a compromised
provider crashes Nix's own process, demonstrated not theoretical).
**There is no remaining evidence-backed transport-level fix for
O-process** at realistic multi-path closure sizes short of eliminating
the IPC boundary the way O-provider does — batching, this document's
prior candidate, was measured directly (above) and refuted. None of
these conclusions depend on building a cache.
