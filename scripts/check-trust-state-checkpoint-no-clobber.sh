#!/usr/bin/env bash
# Real, runnable proof (against the built `trust-state` binary, not just
# unit tests of the underlying primitive) that a review-found race is
# fixed: `init` and `advance` must refuse to silently replace an
# existing checkpoint at `--out`, so two concurrent invocations reading
# the same starting state can no longer race to the same output path
# with the last rename silently discarding the other's result. See
# src/atomic_file.rs and src/bin/trust-state.rs's write_checkpoint().
#
# Run against an already-built binary, e.g.:
#   ./check-trust-state-checkpoint-no-clobber.sh /path/to/target/debug/trust-state
# or via `nix run .#trust-state-checkpoint-no-clobber`.
set -euo pipefail

BIN="${1:?usage: check-trust-state-checkpoint-no-clobber.sh /path/to/trust-state}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REQUEST="$ROOT/integration/examples/authoritative-downgrade-refusal.request.json"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# 1. A fresh checkpoint is written successfully.
if "$BIN" init --domain checkpoint-no-clobber --request "$REQUEST" --out "$WORKDIR/state.json" >/dev/null 2>&1; then
    pass "init writes a fresh checkpoint"
else
    fail "init should succeed for a fresh --out path"
fi
ORIGINAL_DIGEST="$(sha256sum "$WORKDIR/state.json" | cut -d' ' -f1)"

# 2. A second init to the SAME --out must fail, and must not touch the
#    file that's already there -- this is the exact scenario a
#    concurrent-writer race would hit.
if "$BIN" init --domain checkpoint-no-clobber --request "$REQUEST" --out "$WORKDIR/state.json" >/dev/null 2>&1; then
    fail "a second init to an existing --out must be refused, not silently accepted"
else
    pass "a second init to an existing --out is refused"
fi
AFTER_DIGEST="$(sha256sum "$WORKDIR/state.json" | cut -d' ' -f1)"
if [ "$ORIGINAL_DIGEST" = "$AFTER_DIGEST" ]; then
    pass "the refused second init did not modify the existing checkpoint"
else
    fail "the existing checkpoint's content changed despite the write being refused"
fi

# 3. No leftover temporary file from either attempt.
LEFTOVERS="$(find "$WORKDIR" -maxdepth 1 -name '.*.tmp-*' | wc -l | tr -d ' ')"
if [ "$LEFTOVERS" = "0" ]; then
    pass "no leftover temporary files after a successful commit or a refused one"
else
    fail "found $LEFTOVERS leftover temporary file(s)"
fi

# 4. advance exhibits the same no-clobber discipline as init.
if "$BIN" advance --domain checkpoint-no-clobber --state "$WORKDIR/state.json" --request "$REQUEST" --out "$WORKDIR/state.json" >/dev/null 2>&1; then
    fail "advance writing to an existing --out (even its own --state path) must be refused"
else
    pass "advance refuses to clobber an existing --out"
fi

echo
echo "trust-state checkpoint no-clobber check: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
