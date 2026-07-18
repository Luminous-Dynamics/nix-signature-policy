# Caller safety

`src/caller.rs` is a hardened Unix reference implementation of how to safely
invoke an external `nix-signature-authorize`-shaped helper process. It is
the concrete answer to a question [NixOS/nix#14451](https://github.com/NixOS/nix/issues/14451)
leaves open (see `docs/PRIOR_ART_AND_DESIGN_DELTA.md`): what does a *safe*
caller actually do when the configured helper hangs, crashes, floods
output, or otherwise misbehaves?

This is deliberately not part of the frozen `core-v1` interoperability
surface. Process invocation is platform- and integration-specific; `core-v1`
is about the authorization semantics themselves. This document — and
`src/caller.rs`, and `tests/helper_process_hostility.rs` — exist so a future
C++ implementation has a concrete, adversarially-tested specification to
mirror, not an underspecified prose contract.

## Contract

Given a `CallerConfig` (absolute helper path, arguments, explicit working
directory, timeout, and an opt-in environment allowlist) and request bytes,
`caller::invoke` returns one of two outcomes:

- `InvocationOutcome::Decision(AuthorizationResponse)` — a well-formed,
  trusted response was obtained. The actual accept/refuse decision lives in
  `AuthorizationResponse::decision`.
- `InvocationOutcome::Failure(CallerFailure)` — no trustworthy decision was
  obtained at all.

Both must be treated as non-admission under `authoritative` enforcement.
They are kept as distinct enum variants, not collapsed into one shared
"refuse," so operational diagnostics can tell "the helper decided to
refuse" apart from "the caller couldn't get an answer" — without that
distinction ever being allowed to affect the admission decision itself.

## Security properties, and why each one exists

| Property | Why |
|---|---|
| No shell; direct exec | Matches the existing `nix-signature-authorize` precedent and every cited prior-art tool (`pam_exec`, OpenSSH `AuthorizedKeysCommand`). |
| `env_clear()`, no `PATH`, opt-in allowlist only | An absolute helper path needs no `PATH` to resolve; clearing it removes an entire class of environment-controlled lookup surface. |
| `CallerConfig::validate()` rejects a non-absolute `command` or `working_dir` before `invoke` spawns anything (`CallerFailure::InvalidConfiguration`) | Not merely documented, actually enforced (an external review found this gap 2026-07): a *relative* `command` containing a path separator (e.g. `"sub/helper"`) resolves against the child's `working_dir` *after* `chdir()` runs there, entirely independent of `PATH` being cleared — an attacker able to place a file at `<working_dir>/<relative command>` could otherwise substitute the executed binary. `validate()` also caps `args`/`extra_env` entry counts and rejects duplicate environment keys; it deliberately does *not* check filesystem permissions/ownership/symlinks, which depend on deployment specifics (Nix-store ownership, container images, CI runners) a blanket check would false-positive on. |
| Explicit working directory, never inherited | A helper shouldn't be able to exploit the caller's own cwd via relative-path tricks. |
| stdout and stderr drained by dedicated reader threads, armed *before* any wait/poll loop | Polling `Child::try_wait()` and only reading pipes afterward can deadlock: a helper that fills a pipe buffer before exiting leaves the caller waiting (or timing out) despite the output cap existing. Both readers start immediately after spawn. |
| Separate byte caps for stdout ([`MAX_RESPONSE_BYTES`], 2 MiB, matching the protocol's own response bound) and stderr ([`MAX_DIAGNOSTIC_BYTES`], 64 KiB) | stdout carries the decision and must be bounded to that. stderr is diagnostic-only and must *never* influence the decision — bounding it separately (and smaller) is a pure memory guard, not a correctness gate. An endless-stderr helper is instead reaped by the overall timeout, exactly like any other hang. |
| New process group (`setpgid` via `process_group(0)`) | Lets cleanup reach every process the helper spawned, not just the direct child. Verified by `grandchild_does_not_survive_group_kill`. |
| Timeout/overflow → straight to `SIGKILL` on the group, then always `wait()` the direct child | This is a failure path, not a graceful shutdown — a helper that already overran its bounds doesn't get a `SIGTERM` grace period, and the child is always reaped so it never becomes a zombie. |
| Output from a failed invocation is never read | Once this module decides to fail an invocation (timeout or overflow), it never inspects what the reader threads collected. A helper cannot win a race by emitting an acceptance right as the deadline expires — not because the timing usually works out, but because the code path structurally never looks. |
| Exit code is a protocol-success gate only, never the decision | An authorization decision comes *only* from the parsed JSON response. `nix-signature-authorize`'s own CLI additionally uses exit 0/10 as a scripting convenience (`docs/AUTHORIZATION_JSON_PROTOCOL.md`) — this caller treats both as "a response should exist, go parse it," and takes the actual decision only from `AuthorizationResponse::decision`. Any other exit code is `UnexpectedExitStatus`, even if stdout happens to contain what looks like a valid response. |
| Exactly one JSON value, non-whitespace trailing bytes rejected | Duplicate top-level keys, a second concatenated document, and garbage after the response are all rejected. The duplicate-key behavior is verified empirically (`duplicate_keys_are_rejected` in `src/caller.rs`), not assumed from `serde_json`'s general reputation. |

## Platform scope

This is a Unix reference implementation (Nix itself has no Windows target).
Process-group handling is `#[cfg(unix)]`-gated; on a hypothetical non-Unix
build, cleanup falls back to killing only the direct child, and
grandchildren may be leaked. This asymmetry is deliberate and documented,
not accidental.

## Test coverage vs. the original failure-mode list

The hostile-helper brainstorm that motivated this work listed 18 failure
modes. Final disposition:

**Directly tested** (`tests/helper_process_hostility.rs`): executable
missing, permission denied, process crash, signal termination, timeout,
oversized stdout, endless stderr, invalid UTF-8, duplicate JSON keys,
trailing data, unsupported protocol/contract version, "accepts after
timeout" race, child processes surviving cancellation, environment
manipulation, working-directory assumptions, a bounded excessive-forking
simulation, repeated-timeout robustness, and independently-bounded
concurrent invocations.

**Covered by the fuzz target instead of hand-written cases**
(`fuzz/fuzz_targets/authorization_protocol.rs`): deeply nested JSON, huge
individual strings within the byte cap — these are resource-exhaustion
shapes fuzzing explores far more thoroughly than a fixed set of examples.

**Explicitly out of scope for this layer, not silently dropped**: "network
access where prohibited" requires OS-level sandboxing (seccomp, namespaces)
that belongs to a deployment/integration layer — the same boundary Nix's
own build sandbox already owns. This crate's test suite proves the
*application-level* invocation contract; it does not attempt to reimplement
process sandboxing.

**Explicitly not attempted**: a literal unbounded fork bomb. The bounded
stand-in (`bounded_excessive_forking_is_fully_reaped`, ~50 short-lived
children) proves process-group cleanup reaps a burst without risking the
CI runner.

## Performance

The concern raised directly in the #14451 thread — "shelling out on each
signature check sounds quite strange and crazy expensive" — was answered
there with an estimate (~1ms process spawn vs. ~500ms narinfo fetch over
the network), not a measurement. This section reports a real measurement
in its place, deliberately not as a universal performance guarantee: a
single machine, one point in time, one request shape. For an admission
path, the tail matters more than the mean — a p99 spike is what an
operator actually notices.

**Method**: `hyperfine --shell=none --warmup 20 --min-runs 200` invoking
the release-profile `nix-signature-authorize` binary directly (no shell
wrapper) against `integration/examples/authoritative-downgrade-refusal.
request.json`, one full process spawn-exec-exit per sample — every sample
is a genuine cold start, hyperfine does not reuse or warm a worker
process. Measured 2026-07-15 on the development machine this project is
built on, under real background load from several other unrelated
concurrent processes competing for the same CPUs — not an isolated
benchmark box, and if anything a pessimistic rather than optimistic
condition. 1755 samples:

| | latency |
|---|---:|
| min | 1.46 ms |
| p50 | 1.83 ms |
| p90 | 2.30 ms |
| p95 | 2.64 ms |
| p99 | 4.66 ms |
| max | 7.15 ms |
| mean | 1.96 ms |

Reproduce with:

```sh
cargo build --release --bin nix-signature-authorize
hyperfine --shell=none --warmup 20 --min-runs 200 --ignore-failure \
  "target/release/nix-signature-authorize --request integration/examples/authoritative-downgrade-refusal.request.json"
```

(`--ignore-failure` because a refusal exits 10, which is a correct,
expected outcome for this particular example request, not a benchmark
failure.)

Even the p99 here is consistent with the #14451 thread's own order-of-
magnitude estimate and roughly two orders of magnitude below narinfo fetch
latency over a real network — the invocation itself does not look like
the bottleneck the original objection worried about. This does not by
itself settle *closure-wide* invocation cost (many store paths per
substitution, potentially concurrent), which is a Phase B / native-
integration measurement this standalone binary's per-call numbers cannot
answer alone.
