#!/usr/bin/env bash
# Combined Layer 2 + Layer 3 in ONE interleaved batch, specifically to
# test whether the "residual" seen comparing batch1's separately-run
# Layer 3 and Layer 2 scripts is a real second-order effect or just
# inter-batch load drift (Layer 3 and Layer 2 in batch1 ran sequentially,
# not interleaved with each other -- a real gap in the protocol's own
# interleaving discipline, caught and fixed here).
set -uo pipefail

FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fixtures" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STOREPATH="$(grep STOREPATH= "$FIX/artifact.env" | cut -d= -f2)"
ROUNDS="${ROUNDS:-25}"
NIX_STORE_OPROCESS="${NIX_STORE_OPROCESS:?}"

TRUSTED_KEYS="acme-release-ed25519-1:$(cut -d: -f2 "$FIX/publisher-ed25519.public") acme-release-mldsa65-1:$(cut -d: -f2 "$FIX/publisher-mldsa65.public")"

emit() {
    python3 -c "
import json, sys
print(json.dumps({'layer': sys.argv[1], 'config': sys.argv[2], 'round': int(sys.argv[3]), 'ms': int(sys.argv[4]), 'load1_before': float(sys.argv[5])}))
" "$1" "$2" "$3" "$4" "$5"
}

trial_embedded() {
    local name="$1" round="$2" providerarg="$3"
    local dest="$HERE/dest-combined-$name"
    rm -rf "$dest"; mkdir -p "$dest"
    local load1; load1=$(cut -d' ' -f1 /proc/loadavg)
    local uri="local?root=$dest&require-sigs=true&signature-observation-provider-mode=conjunctive&signature-observation-provider=$providerarg&signature-observation-provider-timeout-ms=2000&signature-key-group=g%3Aacme-release-ed25519-1"
    local start end
    start=$(date +%s%N)
    "$NIX_STORE_OPROCESS" --store "$uri" -r "$STOREPATH" \
        --option substituters "file://$FIX/cache" \
        --option trusted-substituters "file://$FIX/cache" \
        --option trusted-public-keys "$TRUSTED_KEYS" \
        --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
        >/dev/null 2>&1
    end=$(date +%s%N)
    emit "embedded" "$name" "$round" "$(( (end-start)/1000000 ))" "$load1"
}

trial_standalone() {
    local name="$1" round="$2" bin="$3"
    local load1; load1=$(cut -d' ' -f1 /proc/loadavg)
    local start end
    start=$(date +%s%N)
    "$bin" < "$FIX/verify-raw-request.json" >/dev/null 2>&1
    end=$(date +%s%N)
    emit "standalone" "$name" "$round" "$(( (end-start)/1000000 ))" "$load1"
}

for round in $(seq 1 "$ROUNDS"); do
    trial_embedded   "trivial" "$round" "$HERE/trivial-oprocess-provider.sh"
    trial_standalone "trivial" "$round" "$HERE/trivial-oprocess-provider.sh"
    trial_embedded   "real"    "$round" "$FIX/observation-provider-lean.sh"
    trial_standalone "real"    "$round" "$FIX/observation-provider-lean.sh"
done
