#!/usr/bin/env bash
# Real E2E scenarios for Model S (persistent Unix-socket observation
# service). Mirrors the scenario shape used for O-process/O-provider.
#
# Run from a built model-s-persistent-service checkout:
#   ./run-models-e2e.sh /path/to/nix-src/build/src/nix/nix-store
set -uo pipefail

NIX_STORE_BIN="${1:?usage: run-models-e2e.sh /path/to/nix-store}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures"
DAEMON_BIN="${DAEMON_BIN:?set DAEMON_BIN to the built nix-signature-verify-raw-daemon path}"
STOREPATH="$(grep STOREPATH= "$FIX/artifact.env" | cut -d= -f2)"
# Unix domain socket paths are limited to ~108 bytes (sizeof sun_path) --
# this worktree's own path is already too long, so the socket must live
# somewhere short regardless of where this script itself lives.
SOCK="/tmp/model-s-e2e-$$.sock"

PASS=0
FAIL=0
pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

TRUSTED_KEYS="acme-release-ed25519-1:$(cut -d: -f2 "$FIX/publisher-ed25519.public") acme-release-mldsa65-1:$(cut -d: -f2 "$FIX/publisher-mldsa65.public")"

start_daemon() {
    rm -f "$SOCK"
    "$DAEMON_BIN" --socket "$SOCK" --registry "$FIX/registry.json" >"$HERE/models-daemon.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 50); do
        [ -S "$SOCK" ] && return 0
        sleep 0.05
    done
    return 1
}

stop_daemon() {
    kill "$DAEMON_PID" 2>/dev/null
    wait "$DAEMON_PID" 2>/dev/null
    rm -f "$SOCK"
}

dest_store_uri() {
    local dest="$1"; shift
    printf 'local?root=%s&require-sigs=true%s' "$dest" "$*"
}

copy_artifact() {
    local dest="$1"; shift
    rm -rf "$dest"; mkdir -p "$dest"
    local uri; uri="$(dest_store_uri "$dest" "$@")"
    "$NIX_STORE_BIN" --store "$uri" -r "$STOREPATH" \
        --option substituters "file://$FIX/cache" \
        --option trusted-substituters "file://$FIX/cache" \
        --option trusted-public-keys "$TRUSTED_KEYS" \
        --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
        2>&1
}

admitted() { [ -e "$1/nix/store/$(basename "$STOREPATH")" ]; }

echo "== Scenario 1: legacy mode never connects to the service =="
dest="$HERE/dest-models-legacy"
out=$(copy_artifact "$dest" "&signature-observation-service-socket=/nonexistent/does-not-exist.sock&signature-observation-service-mode=legacy")
if admitted "$dest"; then pass "legacy mode admits via native trust, with a bogus (never-connected) socket configured"; else fail "legacy mode did not admit: $out"; fi

echo
echo "== Scenario 2: conjunctive mode, real daemon running, group satisfied -> admit =="
start_daemon || { fail "daemon did not start"; exit 1; }
dest="$HERE/dest-models-accept"
groups="ed25519-group%3Aacme-release-ed25519-1"
out=$(copy_artifact "$dest" "&signature-observation-service-mode=conjunctive&signature-observation-service-socket=$SOCK&signature-observation-service-key-groups=$groups")
if admitted "$dest"; then pass "conjunctive mode admits when the service verifies the required group"; else fail "conjunctive mode did not admit: $out"; fi

echo
echo "== Scenario 2b: a second decision against the SAME already-running daemon process (persistence) =="
dest="$HERE/dest-models-accept2"
out=$(copy_artifact "$dest" "&signature-observation-service-mode=conjunctive&signature-observation-service-socket=$SOCK&signature-observation-service-key-groups=$groups")
if admitted "$dest"; then pass "second decision against the same daemon process admits correctly"; else fail "second decision failed: $out"; fi

echo
echo "== Scenario 3: conjunctive mode, unsatisfiable group -> refuse =="
dest="$HERE/dest-models-refuse"
groups2="impossible-group%3Aattacker-key-1"
out=$(copy_artifact "$dest" "&signature-observation-service-mode=conjunctive&signature-observation-service-socket=$SOCK&signature-observation-service-key-groups=$groups2")
if admitted "$dest"; then fail "conjunctive mode admitted a path that does not satisfy the configured group"; else pass "conjunctive mode correctly refuses ($out)"; fi
stop_daemon

echo
echo "== Scenario 4: missing/not-running service, conjunctive mode -> fail closed =="
rm -f "$SOCK"
dest="$HERE/dest-models-missing"
out=$(copy_artifact "$dest" "&signature-observation-service-mode=conjunctive&signature-observation-service-socket=$SOCK&signature-observation-service-key-groups=$groups")
if admitted "$dest"; then fail "missing service was silently treated as passing"; else pass "missing/not-running service correctly fails closed: $out"; fi

echo
echo "== Scenario 5: service accepts but never responds (hang) -> times out and fails closed =="
python3 -c "
import socket, os
sock_path = '$SOCK'
if os.path.exists(sock_path):
    os.remove(sock_path)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sock_path)
s.listen(5)
while True:
    conn, _ = s.accept()
    # accept but never read/respond -- simulates a hung service
" &
STUB_PID=$!
sleep 0.3
dest="$HERE/dest-models-hang"
start=$(date +%s%N)
out=$(copy_artifact "$dest" "&signature-observation-service-mode=conjunctive&signature-observation-service-socket=$SOCK&signature-observation-service-timeout-ms=1000&signature-observation-service-key-groups=$groups")
end=$(date +%s%N)
elapsed_ms=$(( (end-start)/1000000 ))
kill "$STUB_PID" 2>/dev/null
rm -f "$SOCK"
if admitted "$dest"; then
    fail "hung service was silently treated as passing"
elif [ "$elapsed_ms" -ge 900 ] && [ "$elapsed_ms" -lt 5000 ]; then
    pass "hung service correctly times out (~1000ms configured, took ${elapsed_ms}ms) and fails closed"
else
    fail "hung service failed closed but timing looks wrong (${elapsed_ms}ms, expected ~1000-2000ms): $out"
fi

echo
echo "=================================================="
echo "Model S E2E: $PASS passed, $FAIL failed"
echo "=================================================="
[ "$FAIL" -eq 0 ]
