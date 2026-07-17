#!/usr/bin/env bash
# Concurrency sweep (1/4/16), per docs/PERFORMANCE_PROTOCOL.md. For a
# given concurrency level C, launches C `nix-store -r` invocations in
# parallel, each against its OWN destination store (so Nix's own
# single-writer SQLite lock isn't the thing being measured -- the
# question is the boundary mechanism's behavior under concurrent load,
# not Nix's store-locking), each importing a distinct fixture path from
# the closure-fixtures pool (cycling if C exceeds available fixtures).
# Records per-job wall time, peak RSS (GNU time -v), and batch-level
# throughput (C / batch wall time).
set -uo pipefail

CF="$(cd "$(dirname "${BASH_SOURCE[0]}")/closure-fixtures" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fixtures" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUNDS="${ROUNDS:-5}"
TIMEBIN="$(command -v time)"

TRUSTED_KEYS="acme-release-ed25519-1:$(cut -d: -f2 "$FIX/publisher-ed25519.public") acme-release-mldsa65-1:$(cut -d: -f2 "$FIX/publisher-mldsa65.public")"

declare -A BINS=(
    [baseline]="${NIX_STORE_BASELINE:?}"
    [oprocess_real]="${NIX_STORE_OPROCESS:?}"
    [oprovider]="${NIX_STORE_OPROVIDER:?}"
)
declare -A EXTRA=(
    [baseline]=""
    [oprocess_real]="&signature-observation-provider-mode=conjunctive&signature-observation-provider=$FIX/observation-provider-lean.sh&signature-observation-provider-timeout-ms=2000&signature-key-group=g%3Aacme-release-ed25519-1"
    [oprovider]="&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$HERE/../provider/libexample-provider.so&signature-observation-provider-key-groups=g%3Aacme-release-ed25519-1"
)

mapfile -t ALL_PATHS < "$CF/paths-100.txt"

one_job() {
    local name="$1" c="$2" round="$3" worker="$4"
    local path_idx=$(( (worker) % ${#ALL_PATHS[@]} ))
    local path="${ALL_PATHS[$path_idx]}"
    local bin="${BINS[$name]}"
    local dest="$HERE/dest-conc-$name-$c-$round-$worker"
    rm -rf "$dest"; mkdir -p "$dest"
    local uri="local?root=$dest&require-sigs=true${EXTRA[$name]}"
    local timelog="$HERE/conc-timelog-$name-$c-$round-$worker.txt"
    local start end
    start=$(date +%s%N)
    "$TIMEBIN" -v -o "$timelog" \
        "$bin" --store "$uri" -r "$path" \
        --option substituters "file://$CF/cache" \
        --option trusted-substituters "file://$CF/cache" \
        --option trusted-public-keys "$TRUSTED_KEYS" \
        --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
        >/dev/null 2>&1
    end=$(date +%s%N)
    local ms=$(( (end-start)/1000000 ))
    local maxrss="-1"
    if [ -f "$timelog" ]; then
        maxrss=$(grep "Maximum resident set size" "$timelog" | grep -o '[0-9]*' || echo -1)
    fi
    rm -f "$timelog"
    echo "$ms $maxrss"
}

for name in baseline oprocess_real oprovider; do
    for c in 1 4 16; do
        for round in $(seq 1 "$ROUNDS"); do
            load1=$(cut -d' ' -f1 /proc/loadavg)
            batch_start=$(date +%s%N)
            declare -a results=()
            for w in $(seq 0 $((c-1))); do
                one_job "$name" "$c" "$round" "$w" > "$HERE/conc-result-$name-$c-$round-$w.txt" &
            done
            wait
            batch_end=$(date +%s%N)
            batch_ms=$(( (batch_end-batch_start)/1000000 ))
            for w in $(seq 0 $((c-1))); do
                f="$HERE/conc-result-$name-$c-$round-$w.txt"
                read -r job_ms job_maxrss < "$f"
                rm -f "$f"
                python3 -c "
import json, sys
print(json.dumps({'config': sys.argv[1], 'concurrency': int(sys.argv[2]), 'round': int(sys.argv[3]), 'worker': int(sys.argv[4]), 'job_ms': int(sys.argv[5]), 'batch_ms': int(sys.argv[6]), 'maxrss_kb': int(sys.argv[7]), 'load1_before': float(sys.argv[8])}))
" "$name" "$c" "$round" "$w" "$job_ms" "$batch_ms" "$job_maxrss" "$load1"
            done
        done
    done
done
