#!/usr/bin/env bash
# Layer 4 (closure throughput), interleaved across N in {1,10,100} and
# across configs, per docs/PERFORMANCE_PROTOCOL.md.
set -uo pipefail

CF="$(cd "$(dirname "${BASH_SOURCE[0]}")/closure-fixtures" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fixtures" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUNDS="${ROUNDS:-10}"

TRUSTED_KEYS="acme-release-ed25519-1:$(cut -d: -f2 "$FIX/publisher-ed25519.public") acme-release-mldsa65-1:$(cut -d: -f2 "$FIX/publisher-mldsa65.public")"

declare -A BINS=(
    [baseline]="${NIX_STORE_BASELINE:?}"
    [oprocess_real]="${NIX_STORE_OPROCESS:?}"
    [oprovider]="${NIX_STORE_OPROVIDER:?}"
    [models_s]="${NIX_STORE_MODELS:-${NIX_STORE_OPROVIDER:?}}"
)
declare -A EXTRA=(
    [baseline]=""
    [oprocess_real]="&signature-observation-provider-mode=conjunctive&signature-observation-provider=$FIX/observation-provider-lean.sh&signature-observation-provider-timeout-ms=2000&signature-key-group=g%3Aacme-release-ed25519-1"
    [oprovider]="&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$HERE/../provider/libexample-provider.so&signature-observation-provider-key-groups=g%3Aacme-release-ed25519-1"
    [models_s]="&signature-observation-service-mode=conjunctive&signature-observation-service-socket=${MODEL_S_SOCK:-/tmp/model-s-perf.sock}&signature-observation-service-timeout-ms=2000&signature-observation-service-key-groups=g%3Aacme-release-ed25519-1"
)

emit() {
    python3 -c "
import json, sys
print(json.dumps({'config': sys.argv[1], 'n_paths': int(sys.argv[2]), 'round': int(sys.argv[3]), 'ms': int(sys.argv[4]), 'load1_before': float(sys.argv[5])}))
" "$1" "$2" "$3" "$4" "$5"
}

trial() {
    local name="$1" n="$2" round="$3"
    local bin="${BINS[$name]}"
    local dest="$HERE/dest-closure-$name-$n"
    rm -rf "$dest"; mkdir -p "$dest"
    local paths; paths=$(head -n "$n" "$CF/paths-100.txt")
    local uri="local?root=$dest&require-sigs=true${EXTRA[$name]}"
    local load1; load1=$(cut -d' ' -f1 /proc/loadavg)
    local start end
    start=$(date +%s%N)
    # shellcheck disable=SC2086
    "$bin" --store "$uri" -r $paths \
        --option substituters "file://$CF/cache" \
        --option trusted-substituters "file://$CF/cache" \
        --option trusted-public-keys "$TRUSTED_KEYS" \
        --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
        >/dev/null 2>&1
    end=$(date +%s%N)
    emit "$name" "$n" "$round" "$(( (end-start)/1000000 ))" "$load1"
}

for round in $(seq 1 "$ROUNDS"); do
    for n in 1 10 100; do
        for name in baseline oprocess_real oprovider models_s; do
            trial "$name" "$n" "$round"
        done
    done
done
