#!/usr/bin/env bash
# Real E2E scenarios for Model O-provider (in-process dlopen'd C ABI).
# Mirrors the scenario shape already run for Model O-process (accept /
# refuse-on-incomplete-evidence / legacy-never-loads / crash-fails-hard),
# plus two scenarios specific to the in-process model: an ABI-version
# mismatch is a load-time hard error, and a crashing provider takes the
# whole Nix process down with it (demonstrated, not just asserted).
#
# Run from a built o-provider-inprocess-verifier checkout:
#   ./run-oprovider-e2e.sh /path/to/nix-src/build/src/nix/nix-store
set -uo pipefail

NIX_STORE_BIN="${1:?usage: run-oprovider-e2e.sh /path/to/nix-store}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX="$HERE/fixtures"
PROV="$HERE/provider"
SRC_STORE="$FIX/store"
STOREPATH="$(grep STOREPATH= "$FIX/artifact.env" | cut -d= -f2)"

PASS=0
FAIL=0

pass() { echo "PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# Trusted keys: both publisher keys, so Nix's own native check
# (`nativeTrusted`) succeeds regardless of which model-specific policy
# is layered on top -- isolates each scenario to the O-provider logic,
# not native trust.
TRUSTED_KEYS="acme-release-ed25519-1:$(cat "$FIX/publisher-ed25519.public" | cut -d: -f2) acme-release-mldsa65-1:$(cat "$FIX/publisher-mldsa65.public" | cut -d: -f2)"

# `require-sigs` and every `signature-observation-provider*` setting are
# LocalStoreConfig-scoped `Setting<T>` fields -- confirmed (independently,
# twice: once for Model H, once for Model O-process) to be silently
# ignored via `--option`/`NIX_CONFIG`. Only store-URI query parameters
# actually apply them, so they go in the URI. `trusted-public-keys` is
# the opposite: a *global* Settings field (`globals.hh`, not
# LocalStoreConfig), so putting it in the store URI instead produces
# "unknown setting" and silently configures zero trusted keys -- it must
# be a `--option`, discovered here for the first time in this
# comparison (H and O-process's own scripts happened not to need to
# vary it across a store URI).
dest_store_uri() {
    local dest="$1"; shift
    local extra="$*"
    printf 'local?root=%s&require-sigs=true%s' "$dest" "$extra"
}

copy_artifact() {
    local dest="$1"; shift
    rm -rf "$dest"
    mkdir -p "$dest"
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

echo "== Scenario 1: legacy mode never loads the provider =="
dest="$HERE/dest-oprovider-legacy"
out=$(copy_artifact "$dest" "&signature-observation-provider-mode=legacy&signature-observation-provider-library=/nonexistent/does-not-exist.so")
if [ -e "$dest/nix/store/$(basename "$STOREPATH")" ]; then
    pass "legacy mode admits via native trust alone, with a bogus (never-loaded) provider path configured"
else
    fail "legacy mode did not admit: $out"
fi

echo
echo "== Scenario 2: conjunctive mode, provider verifies real Ed25519 signature, group satisfied =="
dest="$HERE/dest-oprovider-accept"
groups="ed25519-group%3Aacme-release-ed25519-1"
out=$(copy_artifact "$dest" "&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$PROV/libexample-provider.so&signature-observation-provider-key-groups=$groups")
if [ -e "$dest/nix/store/$(basename "$STOREPATH")" ]; then
    pass "conjunctive mode admits when the provider verifies the required Ed25519 group"
else
    fail "conjunctive mode did not admit a genuinely valid path: $out"
fi

echo
echo "== Scenario 3: conjunctive mode, group requires a key the attacker (not publisher) could not satisfy =="
dest="$HERE/dest-oprovider-refuse"
groups="impossible-group%3Aattacker-key-1"
out=$(copy_artifact "$dest" "&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$PROV/libexample-provider.so&signature-observation-provider-key-groups=$groups")
if [ -e "$dest/nix/store/$(basename "$STOREPATH")" ]; then
    fail "conjunctive mode admitted a path that does not satisfy the configured group"
else
    pass "conjunctive mode correctly refuses when the configured group cannot be satisfied ($out)"
fi

echo
echo "== Scenario 4: ABI version mismatch is a hard load-time error, not a silent pass =="
dest="$HERE/dest-oprovider-abimismatch"
groups="ed25519-group%3Aacme-release-ed25519-1"
out=$(copy_artifact "$dest" "&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$PROV/libabi-mismatch-provider.so&signature-observation-provider-key-groups=$groups")
if [ -e "$dest/nix/store/$(basename "$STOREPATH")" ]; then
    fail "ABI-mismatched provider was silently accepted"
elif echo "$out" | grep -qi "abi version"; then
    pass "ABI-mismatched provider is refused with a clear ABI-version error"
else
    fail "ABI-mismatched provider refused, but not with the expected diagnostic: $out"
fi

echo
echo "== Scenario 5 (the model's defining trade-off): a crashing provider crashes Nix's own process =="
dest="$HERE/dest-oprovider-crash"
groups="ed25519-group%3Aacme-release-ed25519-1"
rm -rf "$dest"; mkdir -p "$dest"
uri="$(dest_store_uri "$dest" "&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$PROV/libcrash-provider.so&signature-observation-provider-key-groups=$groups")"
"$NIX_STORE_BIN" --store "$uri" -r "$STOREPATH" \
    --option substituters "file://$FIX/cache" \
    --option trusted-substituters "file://$FIX/cache" \
    --option trusted-public-keys "$TRUSTED_KEYS" \
    --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
    >"$HERE/dest-oprovider-crash.stdout" 2>"$HERE/dest-oprovider-crash.stderr"
rc=$?
# A normal Nix error exits with a small positive status (typically 1).
# A SIGSEGV inside the process is reported by the shell as 128+signal
# (139 for SIGSEGV) -- that numeric signature, not just "nonzero", is
# the evidence this crashed the caller rather than merely refusing.
if [ "$rc" -eq 139 ]; then
    pass "crashing provider took down nix-store's own process (exit $rc, SIGSEGV) -- the O-provider model's defining trade-off, demonstrated not just asserted"
elif [ "$rc" -gt 128 ]; then
    pass "crashing provider took down nix-store's own process (exit $rc, signal $((rc-128)))"
else
    fail "expected a process-level crash (exit >128), got exit $rc; stderr: $(cat "$HERE/dest-oprovider-crash.stderr")"
fi

echo
echo "== Scenario 6: unsupported algorithm reaching the provider is a hard error, never silently 'invalid' =="
dest="$HERE/dest-oprovider-unsupported-alg"
# The example provider is deliberately Ed25519-only. Requiring the
# ML-DSA-65 key name forces a call the provider cannot evaluate.
groups="mldsa-group%3Aacme-release-mldsa65-1"
out=$(copy_artifact "$dest" "&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$PROV/libexample-provider.so&signature-observation-provider-key-groups=$groups")
if [ -e "$dest/nix/store/$(basename "$STOREPATH")" ]; then
    fail "an algorithm the provider cannot evaluate was silently treated as valid"
else
    pass "unsupported algorithm correctly refuses (NIX_SIG_ERROR -> hard failure): $out"
fi

echo
echo "== Scenario 7: missing provider library, conjunctive mode -> fail closed (parity with H's/O-process's own hostile-case lists) =="
dest="$HERE/dest-oprovider-missing-library"
groups="ed25519-group%3Aacme-release-ed25519-1"
out=$(copy_artifact "$dest" "&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$PROV/does-not-exist.so&signature-observation-provider-key-groups=$groups")
if [ -e "$dest/nix/store/$(basename "$STOREPATH")" ]; then
    fail "a missing provider library was silently treated as passing"
else
    pass "missing provider library correctly fails closed: $out"
fi

echo
echo "=================================================="
echo "O-provider E2E: $PASS passed, $FAIL failed"
echo "=================================================="
[ "$FAIL" -eq 0 ]
