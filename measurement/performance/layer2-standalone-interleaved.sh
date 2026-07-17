#!/usr/bin/env bash
# Layer 2 (standalone verifier cost), interleaved, isolating the
# env-clearing effect (the real caller invokes via execve with a fully
# cleared environment; a shell-invoked "standalone" measurement normally
# does not) from the trivial-script baseline and the real binary's own
# cost. Four configs, interleaved every round.
set -uo pipefail

FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fixtures" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROUNDS="${ROUNDS:-25}"

trial() {
    local name="$1" round="$2"
    local load1 start end rc ms
    load1=$(cut -d' ' -f1 /proc/loadavg)
    start=$(date +%s%N)
    case "$name" in
        trivial_normalenv)
            "$HERE/trivial-oprocess-provider.sh" < "$FIX/verify-raw-request.json" > /dev/null 2>&1 ;;
        trivial_clearedenv)
            env -i "$HERE/trivial-oprocess-provider.sh" < "$FIX/verify-raw-request.json" > /dev/null 2>&1 ;;
        real_normalenv)
            "$FIX/nix-signature-verify-raw" --registry "$FIX/registry.json" < "$FIX/verify-raw-request.json" > /dev/null 2>&1 ;;
        real_clearedenv)
            env -i "$FIX/nix-signature-verify-raw" --registry "$FIX/registry.json" < "$FIX/verify-raw-request.json" > /dev/null 2>&1 ;;
    esac
    rc=$?
    end=$(date +%s%N)
    ms=$(( (end-start)/1000000 ))
    python3 -c "
import json, sys
print(json.dumps({'config': sys.argv[1], 'round': int(sys.argv[2]), 'ms': int(sys.argv[3]), 'load1_before': float(sys.argv[4]), 'rc': int(sys.argv[5])}))
" "$name" "$round" "$ms" "$load1" "$rc"
}

ORDER=(trivial_normalenv trivial_clearedenv real_normalenv real_clearedenv)
for round in $(seq 1 "$ROUNDS"); do
    for name in "${ORDER[@]}"; do
        trial "$name" "$round"
    done
done
