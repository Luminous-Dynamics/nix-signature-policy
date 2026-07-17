# Performance campaign (in progress)

Per `docs/PERFORMANCE_PROTOCOL.md`. This directory holds raw trial data
and the scripts that produced it as the campaign progresses — **not yet
complete**; `docs/PROCESS_VS_PROVIDER_RESULTS.md` does not exist yet and
won't until every layer in the protocol has raw data behind it.

**Status so far**: Layer 3 (real single-path admission) batch 1 and
Layer 2 (standalone verifier) batch 1 complete, both interleaved,
N=25/config, load recorded per-trial. Everything else in the protocol
(signature-count sweep, closure throughput, concurrency, cold/warm,
failure-path timing, and a second, lower-load Layer 3 batch for
cross-batch confirmation) is not yet run.

**Scripts here are recorded as-run, not yet portability-hardened**:
`layer3-interleaved.sh` expects `NIX_STORE_BASELINE`/`_H`/`_OPROCESS`/
`_OPROVIDER` env vars pointing at built `nix-store` binaries and a
`fixtures/` directory one level up (present in the original working
tree at `measurement/fixtures/`, a superset of what's vendored at
`docs/evidence/e2e-scripts/fixtures/`). Rerunning from this vendored
location requires supplying that layout; not yet done here, matching
this checkpoint's "raw data first, polish later" priority.

See `raw/batch1-environment.json` for the full environment record
(CPU, load, build config, and two important corrections made *during*
this batch: a wrong default meson buildtype caught before any trial
ran, and an earlier ad-hoc environment-clearing hypothesis that did
NOT replicate under a proper interleaved N=25 test — reported as a
negative result).
