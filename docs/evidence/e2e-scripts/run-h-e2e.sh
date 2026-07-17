#!/usr/bin/env bash
# Real, runnable reproduction of Model H's 6 documented scenarios, using
# the corrected store-URI settings-invocation mechanism (the committed
# tests/functional/signature-authorization-hook.sh uses --option, which
# is silently a no-op for LocalStoreConfig-scoped settings -- see
# H_INDEPENDENT_VERIFICATION.md and docs/CANDIDATE_ARCHITECTURES.md's
# "recurring configuration-mechanism gap" section).
#
# This exists so H's independent verification is itself reproducible by
# a third party, not just a manually-reconstructed table of commands and
# outputs.
#
# Run from a built admission-boundary-experiment-v1 (H) checkout, e.g.:
#   ./run-h-e2e.sh /path/to/nix-src/build/src/nix/nix-store
set -uo pipefail

NIX_STORE_BIN="${1:?usage: run-h-e2e.sh /path/to/nix-store}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures"
STOREPATH="$(grep STOREPATH= "$FIX/artifact.env" | cut -d= -f2)"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

TRUSTED_KEYS="acme-release-ed25519-1:$(cut -d: -f2 "$FIX/publisher-ed25519.public") acme-release-mldsa65-1:$(cut -d: -f2 "$FIX/publisher-mldsa65.public")"

dest_store_uri() {
    local dest="$1"; shift
    printf 'local?root=%s&require-sigs=true%s' "$dest" "$*"
}

copy_artifact() {
    local dest="$1"; shift
    rm -rf "$dest"; mkdir -p "$dest"
    local uri
    uri="$(dest_store_uri "$dest" "$@")"
    "$NIX_STORE_BIN" --store "$uri" -r "$STOREPATH" \
        --option substituters "file://$FIX/cache" \
        --option trusted-substituters "file://$FIX/cache" \
        --option trusted-public-keys "$TRUSTED_KEYS" \
        --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
        2>&1
}

admitted() { [ -e "$1/nix/store/$(basename "$STOREPATH")" ]; }

echo "== Scenario 1: accept-hook, conjunctive mode -> admit =="
dest="$HERE/dest-h-accept"
out=$(copy_artifact "$dest" "&signature-authorization-hook=$FIX/hook-accept.sh&signature-authorization-mode=conjunctive")
if admitted "$dest"; then pass "accept-hook admits"; else fail "accept-hook did not admit: $out"; fi

echo
echo "== Scenario 2: refuse-hook, conjunctive mode -> refuse =="
cat > "$HERE/hook-refuse.sh" <<'EOF'
#!/bin/sh
cat > /dev/null
echo '{"decision":"refuse"}'
EOF
chmod +x "$HERE/hook-refuse.sh"
dest="$HERE/dest-h-refuse"
out=$(copy_artifact "$dest" "&signature-authorization-hook=$HERE/hook-refuse.sh&signature-authorization-mode=conjunctive")
if admitted "$dest"; then fail "refuse-hook admitted a path it should have refused"; else pass "refuse-hook refuses ($out)"; fi

echo
echo "== Scenario 3: legacy mode, refuse-hook configured -> admit, hook never launched =="
dest="$HERE/dest-h-legacy"
out=$(copy_artifact "$dest" "&signature-authorization-hook=$HERE/hook-refuse.sh&signature-authorization-mode=legacy")
if admitted "$dest"; then pass "legacy mode admits despite a refuse-hook being configured (hook never consulted)"; else fail "legacy mode incorrectly refused: $out"; fi

echo
echo "== Scenario 4: crashing hook (exit 1, no output), conjunctive mode -> fail closed =="
cat > "$HERE/hook-crash.sh" <<'EOF'
#!/bin/sh
cat > /dev/null
exit 1
EOF
chmod +x "$HERE/hook-crash.sh"
dest="$HERE/dest-h-crash"
out=$(copy_artifact "$dest" "&signature-authorization-hook=$HERE/hook-crash.sh&signature-authorization-mode=conjunctive")
if admitted "$dest"; then fail "crashing hook was silently treated as accept"; else pass "crashing hook fails closed ($out)"; fi

echo
echo "== Scenario 5: missing hook path, conjunctive mode -> fail closed =="
dest="$HERE/dest-h-missing"
out=$(copy_artifact "$dest" "&signature-authorization-hook=$HERE/does-not-exist.sh&signature-authorization-mode=conjunctive")
if admitted "$dest"; then fail "missing hook path was silently treated as accept"; else pass "missing hook path fails closed ($out)"; fi

echo
echo "== Scenario 6: CA path, conjunctive mode -> refuse (code-review-confirmed short-circuit; no CA fixture built here, so this scenario is intentionally not exercised end-to-end -- matches the original independent verification's own documented gap) =="
echo "SKIPPED (code-review only, see H_INDEPENDENT_VERIFICATION.md)"

echo
echo "=================================================="
echo "H E2E reproduction: $PASS passed, $FAIL failed (of 5 runnable scenarios; scenario 6 is a documented code-review-only skip)"
echo "=================================================="
[ "$FAIL" -eq 0 ]
