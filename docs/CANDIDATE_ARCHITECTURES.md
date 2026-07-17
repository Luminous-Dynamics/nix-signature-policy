# Candidate Nix signature-authorization-boundary architectures

**Status: factual results from a real, multi-model empirical comparison.
Ranking and recommendations are deliberately not included in this
document** (see "What this document does not do," below) — that
synthesis, if any, happens separately, after every section here has
been reviewed on its own terms.

This document exists because presenting a single working prototype as
*the* answer to Nix issue
[#14451](https://github.com/NixOS/nix/issues/14451) (an external
`trusted-signatures-command` authorization hook) overstates confidence.
#14451's own thread raises three distinct, real technical objections —
an in-process PKCS#11-shaped verifier, a closure/build-trace scope
broader than one artifact, and per-nar-info (not per-signature)
invocation granularity — and no single architecture answers all three
without trade-offs. Six point-wise admission-boundary models and one
closure/build-trace skeleton were built, independently verified, and
measured against the same fork, the same frozen fixtures, and (where
meaningful) the same benchmark policy.

## Verified thread grounding

Checked directly against the live GitHub API before driving any design
decision here, not taken from notes:

- **In-process PKCS#11-style provider** — `xokdvium` (CONTRIBUTOR),
  [comment 1](https://github.com/NixOS/nix/issues/14451#issuecomment-3690761593) /
  [comment 2](https://github.com/NixOS/nix/issues/14451#issuecomment-3690765664),
  2025-12-25: fork+exec per signature check is "quite crazy expensive";
  proposes a PKCS#11 module (a shared library with a small vtable,
  `C_Verify`) as a more standard, in-process, HSM-compatible hookable
  mechanism, citing `p11-kit` and RFC 7512 URIs, and explicitly scopes
  the suggestion to "building on top of the existing signature
  formats" — verification, not evidence normalization or policy.
  `mschwaig` (MEMBER) pointed at a real, unrelated prior-art project,
  [`numinit/nixpkcs`](https://github.com/numinit/nixpkcs)
  ([comment](https://github.com/NixOS/nix/issues/14451#issuecomment-3691059858)).
- **Closure/build-trace scope** — `mschwaig` (MEMBER),
  [2025-12-23](https://github.com/NixOS/nix/issues/14451#issuecomment-3687397244):
  point-wise final-derivation checks are "strictly less useful" than
  whole-build-time-closure verification; gives two concrete examples
  (changing your mind about trusting `nixpkgs` later; two independently
  reproducible-but-different `gcc` paths converging on one output);
  states his own reference implementation,
  [`mschwaig/laut`](https://github.com/mschwaig/laut), "has quorums
  implemented, but not correctly yet."
- **Invocation granularity** — `jkarni` (issue author, NONE),
  [2025-12-25](https://github.com/NixOS/nix/issues/14451#issuecomment-3691602442):
  "the program would not be invoked per signature but per nar-info" —
  any spawned-helper model must batch every signature entry for one
  path into a single invocation.

## The three axes

- **Scope** — point-wise (one narinfo/store path) or closure/build-trace
  (the whole build-time closure; the direction `mschwaig` is actively
  developing).
- **Verification boundary** — native (Nix verifies in-process, no
  plugin), in-process provider (a dynamically loaded module, PKCS#11-
  shaped per `xokdvium`), spawned helper (bounded subprocess), or
  persistent local service (long-running, amortizes startup —
  documented as a successor below, not built).
- **Policy ownership** — native narrow policy (Nix owns a small fixed
  vocabulary, composed with its own built-in trust result), external P
  with Nix composing (an external component returns typed evidence or a
  policy result that Nix combines with its own check), or external final
  decision (kept only as a design reference, not a built candidate — it
  obscures the composition this comparison is built to make legible).

Every point-wise model instantiates the invariant **R → O → P,
composed with B** (Nix's own built-in trust result): raw evidence, to
verified observations, to a policy result, composed with B under
whatever enforcement mode is configured. Models differ in *where* the
O→P boundary sits and who owns it — never in whether B is still
checked.

## Models built

All branched from a single fork of Nix, `DeterminateSystems/nix-src`
commit `6b78b5d8b4332f8f302abd19d1b9d9e7edbb8ce6` (`nix-src#449`, merged
2026-05-20; chosen because Determinate's fork already has native
Ed25519 + ML-DSA-65 verification, which every model below depends on).
All share one additional commit as common infrastructure, authored by a
concurrent session and reused read-only: `11a967a`, adding
`ValidPathInfo::checkSignaturesDetailed()` (a single verification pass
producing both the existing valid-count and a typed
`vector<VerifiedSignature>`) and `keyTypeProtocolName()` (frozen wire
algorithm-name strings). Every model that needed the native
grouped-signature primitive (`KeyGroup` / `allSignatureGroupsSatisfied`)
depends on Model N's commit for it, rather than re-deriving it.

**Branch structure, precisely** (correcting an earlier draft's looser
"isolation discipline" phrasing, which glossed over a real difference
in how N/P/T vs. H/O-process/O-provider actually relate to each other):
**N, P, and T are three successive commits on one research branch**
(`model-n-native-grouped-signatures`, at `8ad4bbe`, `8858bef`, and
`f317153` respectively) — not three independent branches. **H,
O-process, O-provider, and S are each an independent branch**, starting
fresh from the shared foundation (`11a967a`) and, for O-process,
O-provider, and S, cherry-picking N's commit onto that fresh start
rather than building on N's branch directly.

This is legitimate, not a shortcut that compromises any result, and was
checked rather than assumed: P's commit (`8858bef`) touches only
`src/nix/{meson.build,verify-signatures-json.{cc,md}}` — zero reference
to N's `signature-groups.hh` or `KeyGroup`; T's commit (`f317153`)
touches only `src/libstore{,-tests}/local-store*` — zero reference to
P's `verify-signatures-json.cc`. Each of P and T would compile and pass
its own tests identically if cherry-picked alone onto the shared
foundation, exactly like O-process's and O-provider's own cherry-picks
of N were. The cumulative branch is a matter of convenience (P and T
were written after N, in the same research session, and simply weren't
reset to a fresh branch each time) — verified, not assumed, to have had
zero effect on either commit's actual diff content or test results.

| Model | Axes | Branch @ commit | Verified evidence tag |
|---|---|---|---|
| **N** — native grouped-signature baseline | point-wise · native · native-narrow | `model-n-native-grouped-signatures` @ `8ad4bbe` | `n-p-t-verified-2026-07-17` |
| **P** — Nix produces O, external evaluator returns P | point-wise · native (verify) + spawned (policy) · external-P | `model-n-native-grouped-signatures` @ `8858bef` | `n-p-t-verified-2026-07-17` |
| **T** — closure/build-trace skeleton (groundwork, not a decision model) | closure · n/a · n/a | `model-n-native-grouped-signatures` @ `f317153` | `n-p-t-verified-2026-07-17` |
| **H** — spawned helper returns a final decision | point-wise · spawned · external-P (opaque) | `admission-boundary-experiment-v1` @ `8a01e8c` (independently verified, see below) | (author's own, independently reproduced) |
| **O-process** — spawned helper returns typed observations, Nix owns policy | point-wise · spawned · native-narrow | `o-process-external-verifier` @ `187029b` | `o-process-verified-2026-07-17` |
| **O-provider** — in-process `dlopen`'d C ABI returns typed observations, Nix owns policy | point-wise · in-process provider · native-narrow | `o-provider-inprocess-verifier` @ `840d22e` | `o-provider-verified-2026-07-17` |
| **S** — persistent Unix-socket observation service, Nix owns policy | point-wise · persistent service · native-narrow | `model-s-persistent-service` @ `21cc893` | `model-s-verified-2026-07-17` |

**Model S was originally documented-but-not-built** in this
comparison's first pass, deferred because "daemon lifecycle,
authentication, and cache-invalidation semantics would each need their
own real design and would have distorted this round's comparison
scope." It was subsequently built as a *deliberately scoped prototype*
after `docs/PROCESS_VS_PROVIDER_RESULTS.md`'s performance campaign
directly confirmed its trigger conditions (O-process's fork/exec cost
dominates and does not amortize across a closure) rather than leaving
them hypothetical.

**First measurement suggested a real win (1.7x faster than O-process at
100 paths); that result did not replicate.** The identified next
refinement (connection reuse across a closure, instead of connecting
fresh per admission decision) was built, directly verified to work
mechanically (the daemon's own connection-accept log confirms exactly
one connection per `nix-store` invocation regardless of path count),
and re-measured under the same interleaved discipline as every other
result in this comparison. The re-measurement landed **statistically
identical to O-process** (33.25ms vs. 33.20ms marginal cost per path),
not the improvement the first measurement predicted. A follow-up
diagnostic (a pure protocol client bypassing Nix entirely) traced the
~14ms-per-decision floor to something other than connection setup —
most plausibly the cost of the verification round-trip itself, shared
by both O-process and a connection-reused Model S, which only
O-provider's in-process call avoids. Full numbers, the batch-to-batch
reversal, and the diagnostic that explains it are in
`docs/PROCESS_VS_PROVIDER_RESULTS.md`'s "Model S prototype" section —
kept there rather than duplicated here, per this document's own
discipline of pointing at the performance campaign rather than
re-stating it. This reversal is itself a real finding about
measurement discipline: a single favorable result, even one with a
plausible mechanism attached, needed replication before being trusted,
and did not survive it.

Explicitly still out of scope for this prototype, matching the original
write-up's own boundary and the doc comment in
`nix-signature-verify-raw-daemon.rs` (in the `nix-signature-policy`
repo): real authentication beyond socket-file permissions, supervision/
lifecycle management, and any caching of verification results (a
performance question, kept fully separate from the caching question
`docs/CACHE_DECISION_QUESTIONS.md` preserves but does not answer).

### Reproducibility

`origin` for every checkout used to build every model above is
`DeterminateSystems/nix-src` itself (upstream) — none of the branches
cited in the table are pushed to any remote this project controls, and
no such fork exists. Rather than create and push a new public fork just
to make commits fetchable, the exact diff for every commit cited above
is vendored as a `git am`-applyable patch in
[`docs/evidence/nix-fork-patches/`](evidence/nix-fork-patches/README.md)
— each verified (not just generated) to reproduce a byte-identical tree
from the public base commit. The E2E scripts that produced this
document's correctness-table results for H and O-provider are similarly
vendored, self-contained and re-run-verified from their vendored
location, in
[`docs/evidence/e2e-scripts/`](evidence/e2e-scripts/). See
[`docs/evidence/README.md`](evidence/README.md) for the full
reproduction steps.

### Why H is included despite an author-side gap

H's own committed functional test (`tests/functional/signature-
authorization-hook.sh`) is broken as committed: it configures the hook
via `--option`, which is silently ignored for `LocalStoreConfig`-scoped
settings (see "A recurring configuration-mechanism gap," below), so the
test currently validates nothing. Rather than exclude H on that basis,
its C++ implementation was independently code-reviewed in full and 5 of
6 documented scenarios were reproduced end-to-end with the corrected
invocation (real keygen, real signing, real substituter, real hook
processes) — all behaved exactly as documented. This reproduction is
itself committed and re-runnable, not a one-off manual reconstruction:
`docs/evidence/e2e-scripts/run-h-e2e.sh`, verified to run clean
end-to-end from that exact vendored location against a real build. The
one unreproduced scenario (content-addressed paths) was confirmed by
code review only (an explicit `warn(...); return true;` before any hook
logic runs), matching the same shortcut this comparison's own O-provider
CA-path handling uses. H is included on the strength of that independent
reproduction, not the strength of its own (currently non-functional)
test.

## A recurring configuration-mechanism gap

Discovered independently three times while building this comparison,
each time before checking whether it had already been found elsewhere:

- `LocalStoreConfig`-scoped `Setting<T>` fields (`require-sigs`,
  `signature-authorization-hook`, `signature-observation-provider-*`,
  …) are **silently ignored** via `--option` or `NIX_CONFIG` — they
  produce `warning: unknown setting '...'` and never apply. They only
  work via store-URI query parameters
  (`local?root=...&key=value&...`), and values containing `:` or `,`
  need percent-encoding there.
- The reverse also holds: `trusted-public-keys` is a *global*
  `Settings` field, not `LocalStoreConfig`-scoped — putting it in the
  store URI instead produces the same "unknown setting" warning and
  silently configures zero trusted keys. It has to be a `--option`.

Nothing in `nix.conf`/`--help` output distinguishes which mechanism a
given setting needs, and getting it wrong doesn't error — it silently
does nothing. Every model in this comparison hit at least one side of
this. Worth reporting to Nix independent of which model (if any) is
ever adopted.

## Factual results

### Nix source change size (`git diff --stat`, literal)

Shared foundation shown separately so no per-model row is inflated by
cost every model pays identically.

| | Files | Insertions | Deletions | Commit |
|---|---:|---:|---:|---|
| Shared foundation (`11a967a` vs `6b78b5d`) | 7 | 219 | 9 | `11a967a` |
| **N** (vs shared foundation) | 6 | 186 | 0 | `8ad4bbe` |
| **P** (vs N) | 3 | 132 | 0 | `8858bef` |
| **T** (vs P) | 3 | 176 | 0 | `f317153` |
| **H** (vs shared foundation) | 7 | 617 | 1 | `8a01e8c` |
| **O-process** total (vs shared foundation) | 12 | 686 | 1 | `187029b` |
| ...of which N reuse (cherry-picked) | 6 | 186 | 0 | `e306919` |
| ...O-process's own marginal cost | 6 | 500 | 1 | `187029b` vs `e306919` |
| **O-provider** total (vs shared foundation) | 13 | 642 | 1 | `840d22e` |
| ...of which N reuse (cherry-picked) | 6 | 186 | 0 | `0bd28ca` |
| ...O-provider's own marginal cost | 7 | 456 | 1 | `840d22e` vs `0bd28ca` |
| **S** total (vs shared foundation) | 12 | 628 | 1 | `21cc893` |
| ...of which N reuse (cherry-picked) | 6 | 186 | 0 | `fd4708e` |
| ...S's own marginal cost | 6 | 442 | 1 | `21cc893` vs `fd4708e` |

N, P, and T are each small and strictly additive (zero deletions),
consistent with each being a narrow, single-purpose slice. H, O-process,
O-provider, and S are the four models that modify existing control flow
(`pathInfoIsUntrusted`) rather than only adding new files/functions. Of
those four, H's *total* (617) is the largest, but O-process's,
O-provider's, and S's *marginal* cost over N (500, 456, and 442
respectively — the fairer comparison, since all three deliberately
reuse N's policy primitive rather than re-deriving one) are all smaller
than H's total, despite each also modifying `pathInfoIsUntrusted` and
needing their own transport-specific module. S's marginal cost is the
smallest of the four, slightly under O-provider's — a socket-based
caller (connect, write, half-close, poll-bounded read, close) turned
out simpler to write than either the fork/exec/pipe/thread machinery
(H, O-process) or the `dlopen`/ABI-versioning machinery (O-provider).

O-provider's diff also includes a genuinely different artifact type the
others don't have: a plain-C ABI header
(`signature-provider-abi.h`, 92 lines) meant to be included by code Nix
does not build. The example provider that implements it
(`measurement/provider/example-provider.c`, real libsodium Ed25519
verification) is deliberately **not** part of the Nix diff at all — a
real provider is an out-of-tree artifact, and building it that way here
is more representative than wiring an example plugin into Nix's own
build.

### Correctness (real test runs, not just compiled)

| Model | Unit tests | Functional/E2E |
|---|---|---|
| N | 6/6 targeted + 618/618 full suite | N/A — no IPC, no separate functional test |
| P | N/A (reuses `checkSignaturesDetailed` coverage) | Real E2E: signed path → real O → real evaluator → `decision: accept`, cross-checked against `nix store verify` |
| T | 1/1 new + 618/618 full suite | N/A by design — the SQLite-backed `LocalStore` test *is* the real-infrastructure test; no derivation-build-level E2E, matching the skeleton's explicit non-goal (see `docs/CLOSURE_TRACE_ARCHAEOLOGY.md`) |
| H | 611/611 full suite (pre-N/P/T baseline count) | Committed test broken (see above); 5/6 scenarios independently reproduced E2E with the corrected invocation, all correct |
| O-process | 617/617 full suite | Real E2E, 4/4 scenarios: full evidence admits; incomplete evidence refuses; legacy mode never launches the provider (sentinel-confirmed); crashing provider fails closed |
| O-provider | 617/617 `libstore-tests` + 707/707 `libutil-tests` | Real E2E, 7/7 scenarios: legacy never `dlopen`s the provider; conjunctive admits on a satisfied group; conjunctive refuses on an unsatisfiable group; an ABI-version mismatch is a hard load-time error; a missing provider library fails closed; an algorithm the provider can't evaluate is a hard error, never silently "invalid"; **a crashing provider segfaults `nix-store`'s own process (exit 139/SIGSEGV) — demonstrated, not asserted** |
| S | 617/617 `libstore-tests` + 707/707 `libutil-tests` | Real E2E, 6/6 scenarios: legacy never connects; conjunctive admits on a satisfied group; **a second decision against the same already-running daemon process also admits correctly (persistence itself exercised, not just correctness)**; conjunctive refuses on an unsatisfiable group; a missing/not-running service fails closed; **a service that accepts a connection but never responds correctly times out (~1080-1100ms against a configured 1000ms deadline) and fails closed, rather than hanging Nix indefinitely** |

O-provider's `dlopen`/`dlsym` wiring has no dedicated unit tests
(mirroring O-process's own gap for its process-invocation code at this
stage) — its correctness evidence is entirely the 7 E2E scenarios,
which exercise every branch end-to-end but not in isolation. A
unit-testable seam (injecting a fake vtable rather than always going
through real `dlopen`) was not built, matching the stop/go review's
"stay small" scope.

O-provider's adversarial coverage matches H's and O-process's own
hostile-case lists on every applicable case (accept, refuse-on-
unsatisfied-policy, legacy-never-invoked, crashing-implementation-fails-
closed, missing-executable/-library-fails-closed). One category present
for H and O-process — subprocess timeout — **does not apply to
O-provider by construction**: there is no subprocess to time out. A
hang inside an in-process provider hangs Nix itself, with no
independent timeout to fall back on. This is a real difference in
failure modes (bounded-but-external vs. unbounded-but-contained-in-one-
process), not a gap in this comparison's test coverage.

**S reintroduces a real, independently-verified timeout**, unlike
O-provider — a service that accepts a connection but never sends a
response is bounded by `signature-observation-service-timeout-ms`, the
same shape as H's and O-process's subprocess timeouts, and was tested
the same way (a real hung listener, not a mocked one): the caller
correctly gives up and fails closed rather than blocking Nix
indefinitely. This is expected given S's transport is still a
process-external boundary (a socket connection to a separate process),
just a persistent one rather than a freshly spawned one — it inherits
H's/O-process's bounded-failure-mode property, not O-provider's
unbounded one.

### Runtime trusted computing base and compromise blast radius

| Model | What runs, where | A compromised/buggy verifier can... | A compromised/buggy policy evaluator can... |
|---|---|---|---|
| N | Nix's own process only; no delegation | n/a — verification is Nix's own code | n/a — policy is Nix's own compiled code |
| P | Verification: Nix's own process (same as N). Policy: a spawned subprocess, bounded, that only ever receives already-Nix-verified typed observations, never raw signature bytes | n/a — same as N | Return any policy decision over trustworthy observations — a bad *policy* call, never a forged signature claim, since it never sees raw crypto |
| H | A spawned subprocess, bounded (timeout, bounded output), that receives raw signature entries and returns one opaque `accept`/`refuse` decision — verification and policy are not separated | Claim any policy decision for any reason; in conjunctive mode this can only ever *narrow* admission (Nix's own check must also pass), never widen it. Cannot be distinguished from a bad policy call — H has no typed-observation boundary at all | Same box as "verifier" — H does not split these two failure modes |
| O-process | A spawned subprocess, bounded, that only verifies cryptography and returns typed per-signature observations; Nix's own compiled policy evaluates them | Falsely claim a specific (key, signature) pair verified or didn't — bounded to the observations it's asked about; cannot invent new policy semantics, since Nix's fixed vocabulary evaluates the result | n/a — Nix's own code is the policy evaluator, same class as N |
| O-provider | A `dlopen`'d shared library running *inside Nix's own process*, sharing its address space and fault domain; same observation/policy split as O-process | Same *logical* scope as O-process (bounded to per-signature claims) but a categorically worse *consequence*: no process boundary at all, so a bug can corrupt Nix's own memory or crash the process outright — **demonstrated** via the crash-provider E2E scenario (exit 139), not merely a theoretical concern | n/a — same as O-process |
| S | A separate, long-running service process, connected to fresh per admission decision over a Unix-domain socket; same observation/policy split as O-process and O-provider. Adds a TCB dimension none of the point-wise process-per-decision models have: the service process's *own trustworthiness persists across every decision it ever serves* — a subverted or degraded service (not merely a single bad decision) affects every subsequent admission until the process is restarted, unlike O-process where each decision gets a fresh process | Same *logical* scope as O-process (bounded to per-signature claims, process-isolated so a crash is contained the same way O-process's is) — but a persistent process is a *standing* target in a way a process that lives for one decision and exits is not; compromise, once achieved, has a longer window | n/a — same as O-process |

**P and O-process share a security property H does not have**: because
both split "did this verify" from "does policy accept it," a
compromised external component's damage is bounded to the half of the
question it was given (crypto-only for O-process's helper; policy-only
for P's evaluator). To be precise about what "bounded" means for H, so
this isn't overstated in either direction: a compromised H helper is
**not** unbounded in the sense of widening admission under conjunctive
mode — Nix's own native check `B` still has to independently pass, the
same ceiling every model in this comparison has. H's actual weakness is
narrower and more specific than "unbounded damage": because its helper
receives raw evidence and returns one opaque decision, **cryptographic
dishonesty and policy dishonesty cannot be distinguished, or
independently constrained, from each other** — a reviewer auditing H
has no way to ask "is this helper trustworthy about crypto" separately
from "is this helper trustworthy about policy," because H's design
never poses those as two questions in the first place.

**O-provider is the only model in this comparison where "compromised
verifier" and "process crash/memory corruption of Nix itself" are the
same failure mode.** This is its defining, deliberate trade-off — traded
against removing fork/exec/pipe overhead entirely — not an oversight.

**S is the only model where the verifier's trustworthiness is a
property of *time*, not just of a single decision.** Every other
process-based model (H, O-process) starts a fresh, freshly-trusted-or-
not process per decision; a compromise of one decision's helper says
nothing about the next decision's freshly-spawned helper. S's service
persists, so a single successful compromise (of the service process
itself, its host, or its supply chain) potentially taints every
decision made until it is restarted — a real, distinct risk shape this
comparison had not needed to name until S existed to have it.

### Evidence-format and policy-language agility

| Model | Can a new *evidence type* (e.g. a crypto scheme Nix doesn't natively verify) be added without patching Nix? | Can the *policy vocabulary* (e.g. thresholds, quorums, distinct-identity rules) be extended without patching Nix? |
|---|---|---|
| N | No — verification and policy are both Nix's own compiled code | No |
| P | No — verification stays in Nix's own code (same limitation as N) | Yes — arbitrary external policy logic over trustworthy typed observations |
| H | Yes — the helper can evaluate any evidence it wants; Nix never inspects it | Yes — same helper, same freedom, but conflated with evidence handling (see TCB table) |
| O-process | Yes — the provider can implement any crypto scheme and just report typed valid/invalid | No — Nix's fixed `KeyGroup` vocabulary, same limit as N |
| O-provider | Yes — same as O-process | No — same fixed vocabulary as N/O-process |
| S | Yes — same as O-process/O-provider (in this prototype, the *same* `verify_raw_evidence` code O-process's real verifier uses, so it already supports both Ed25519 and ML-DSA-65 without O-provider's Ed25519-only scoping) | No — same fixed vocabulary as N/O-process/O-provider |

No model in this comparison provides *both* kinds of agility without
also conflating verification and policy into one opaque decision (H's
shape). This is a real, structural trade-off in the design space, not
an oversight in any one model: separating verification from policy (P,
O-process, O-provider) buys the bounded-blast-radius property above at
the cost of picking, for each model, which one axis of agility that
model gets.

### Operational properties

| Model | Config surface | Runtime reconfiguration | Migration compatibility |
|---|---|---|---|
| N | 1 repeatable setting (`signature-key-group`) | `nix.conf`/store-URI change, no rebuild | Fully additive; empty group list is vacuously satisfied (no behavior change for a caller that configures none) |
| P | Evaluator path/mode/timeout (3) | Same | Additive |
| H | Hook path/mode/timeout (3) | Same | Additive; legacy mode preserves exact prior behavior |
| O-process | Provider path/mode/timeout + repeatable key-group (4) | Same | Additive |
| O-provider | Provider *library* path/mode + repeatable key-group (3) | Provider `.so` is `dlopen`'d once and cached for the **process's lifetime, never reloaded** — swapping the file on disk does not take effect without restarting the Nix process, unlike every subprocess-based model, which execs fresh on every invocation | Additive |
| S | Service socket path/mode/timeout + repeatable key-groups (4) | Same reconfiguration story as O-process/H — the *client* (Nix) picks up a config change on its next invocation, no restart needed on Nix's side. But the *service itself* has no hot-reload for its registry (verification keys are loaded once at daemon startup) — changing trusted keys means restarting the daemon, a real operational cost O-process/H don't have (their "process" is re-created from current config on every single decision, so their equivalent of "config" is always fresh) | Additive |

O-process needed one more setting than H (4 vs. 3) because Nix's own
native policy needs the group structure explicit — H's helper makes
that decision externally and only needs a path/mode/timeout. This is a
second, independent illustration of the same trade-off the agility
table shows: pushing policy vocabulary into Nix's own settings surface
(O-process, O-provider, N) vs. off it entirely (H).

### Process/batching overhead (measured, real repeated trials)

10 trials each, cold destination store per trial, same machine.
Wall-clock via `date +%s%N` around the whole `nix-store -r` invocation.

**Baseline table, load average 4.7–6.1 throughout:**

| Configuration | Median | Mean | Range |
|---|---:|---:|---:|
| Legacy mode, no external process at all | 70 ms | 71 ms | 64–81 ms |
| H, conjunctive, accept-hook (`echo` one-liner) | 79 ms | 83 ms | 78–108 ms |
| O-process, conjunctive, first provider (Python-merge wrapper) | 252 ms | 299 ms | 243–472 ms |
| O-process, conjunctive, corrected provider (`--registry`, no Python) | 158 ms | 158 ms | 148–177 ms |

H's hook adds ~9ms over the no-external-process baseline — small,
consistent with a well-optimized process-invocation path (no
unnecessary work between fork and exec). The first O-process
measurement (~180ms delta) was mostly a test-harness artifact — a
Python wrapper spawning a second process to merge a trust registry
before piping to the verifier — traced and fixed at the source
(`nix-signature-verify-raw --registry`, no wrapper process needed);
corrected cost dropped to 158ms median. **A real, still only partially
explained gap remains**: H adds ~9ms over baseline; the corrected
O-process provider adds ~88ms, even though its own standalone cost is
only ~40ms (vs. H's ~7ms). ~55ms is unaccounted for by "the provider's
own cost" alone — candidates not yet ruled out: independently-written
process-invocation code between the two models, payload-shape
differences (a JSON candidate array plus a file read, vs. a single
decision string), or measurement noise at this sample size.

**O-provider was measured under a materially different load regime
(load average 30–40, from ~30 more concurrent sessions on this machine
at measurement time) and is NOT directly comparable to the table
above.** Rather than present a noisy number next to a low-load table and
let the juxtaposition imply a comparison the data doesn't support, a
same-load-regime baseline was collected alongside it:

| Configuration (load 30–40, not comparable to the table above) | Median | Mean | Range |
|---|---:|---:|---:|
| Legacy mode, no external process, same load | 254 ms | 264 ms | 144–440 ms |
| O-provider, conjunctive, real provider call, same load | 250 ms | 267 ms | 173–494 ms |

At this noise level, O-provider's per-operation cost is statistically
indistinguishable from the no-external-process baseline measured under
identical conditions — directionally consistent with the hypothesis
that avoiding fork/exec/pipe removes the dominant cost O-process pays,
but this is a directional signal, not a precise number. A clean
low-load re-measurement of O-provider, matching the original table's
conditions, is an explicit open item, not silently dropped.

**Not measured**: decision latency at higher signature counts (the
original 1/2/8/32/128 sweep) for any model — all timing above is at
exactly 2 signatures, the frozen benchmark policy's own evidence set.
No claim is made about how any model scales with signature count.

**This section's single-path numbers turned out to be the wrong level
of granularity to answer the real performance question.** A dedicated
follow-up campaign — `docs/PERFORMANCE_PROTOCOL.md` (frozen scope) →
`docs/PROCESS_VS_PROVIDER_RESULTS.md` (results + stop/go
recommendation) — found that at single-path granularity every model is
fast and the boundary mechanism itself costs almost nothing (the ~55ms
gap above traces to the *specific verifier binary invoked*, not the
IPC transport, once measured properly). The real signal is at
closure-throughput and concurrency granularity: **O-process's
per-decision fork/exec cost does not amortize across a multi-path
closure — 13x slower than baseline at 100 paths** — while O-provider
does not have this problem. **Model S (persistent Unix-socket service,
built after that campaign confirmed O-process's fork/exec cost as the
dominant factor) was measured twice — once before and once after
implementing connection reuse — and the two results disagree**: the
first measurement showed 1.7x improvement over O-process; after
connection reuse was built and directly verified to work mechanically,
the re-measurement landed statistically identical to O-process, not
improved. A follow-up diagnostic traces this to a per-decision
verification-round-trip cost that connection reuse does not eliminate,
which only O-provider's in-process call avoids. Full numbers, the
batch-to-batch reversal, and the diagnostic live in
`docs/PROCESS_VS_PROVIDER_RESULTS.md`, not duplicated here.

### Closure/build-trace extensibility (does this survive a move toward whole-closure scope?)

- **N, P, O-process, O-provider** are point-wise by construction —
  each evaluates one artifact's signature set at admission time. None
  of the four inherently blocks a future closure-aware extension
  (nothing about their shape assumes single-artifact scope at the type
  level), but none of them *is* one either.
- **H** is the one point-wise model whose shape could plausibly extend
  to closure-level decisions without a Nix code change, precisely
  because its decision is an opaque black box — if invoked with the
  right batched inputs (e.g. every artifact in a closure at once), the
  hook could evaluate whatever policy it wants over them. This is the
  same "high agility, low legibility" trade-off the evidence-format
  table already shows, appearing again at the closure-scope axis.
- **T** is the only model that actually examined this question against
  real Nix internals (see `docs/CLOSURE_TRACE_ARCHAEOLOGY.md`).
  Finding: `LocalStore::registerDrvOutput()`'s existing signature-merge
  path is keyed by `DrvOutput.id`, which is derived from the derivation
  graph — so two differently-derived-but-content-identical builds
  (`mschwaig`'s two-`gcc`-paths example) never reach the existing
  `isCompatibleWith`/`outPath`-equality merge check at all, because the
  database lookup that precedes it is keyed by the wrong thing for that
  case. T's skeleton adds `queryRealisationsForOutputPath()` — a query
  that finds every `Realisation` sharing one output path regardless of
  `DrvOutput.id` — closing exactly that gap, with one test distinguishing
  "two independent build paths converged" from "one derivation, signed
  twice" (which the existing merge already handles correctly). **T is
  explicitly not a quorum engine** — `mschwaig`'s own `laut` doesn't have
  a correct one yet either, by his account — and `laut` itself was found
  to be a differently-scoped, already much larger out-of-band tool (own
  signature format, own dependency resolution, own trust DSL), not a
  smaller version of what a Nix-internal closure-aware skeleton needs.

## What this document does not do

It does not rank the models, does not recommend one for adoption, and
does not draft the `#14451` comment itself (Nix's own Automation/AI
policy requires a human to write that). Every section above is a
factual result: what was built, what it costs in diff size, what it
costs and buys in trusted-computing-base terms, what tests and E2E
scenarios passed, what was measured and under what conditions, and what
remains open. Synthesis — if any is warranted — is a separate, later
step, informed by this document but not contained in it.
