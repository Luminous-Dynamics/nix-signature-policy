#!/usr/bin/env bash
# Layer 3 (real single-path admission), interleaved across configurations,
# per docs/PERFORMANCE_PROTOCOL.md. Each "round" runs one trial of every
# configuration in the same fixed order before starting the next round, so
# gradual load/thermal drift cannot consistently favor one configuration --
# the direct fix for the architecture comparison's earlier flaw (O-provider
# measured in a separate, much-higher-load session).
#
# Emits one JSON object per line (JSONL) to stdout: config, round, ms,
# load1_before. Redirect to a file under measurement/performance/.
set -uo pipefail

FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fixtures" && pwd)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STOREPATH="$(grep STOREPATH= "$FIX/artifact.env" | cut -d= -f2)"
ROUNDS="${ROUNDS:-30}"

TRUSTED_KEYS="acme-release-ed25519-1:$(cut -d: -f2 "$FIX/publisher-ed25519.public") acme-release-mldsa65-1:$(cut -d: -f2 "$FIX/publisher-mldsa65.public")"

# config name -> "nix-store binary path|extra store-URI query string"
declare -A CONFIGS=(
    [baseline]="${NIX_STORE_BASELINE:?}|"
    [h_accept]="${NIX_STORE_H:?}|&signature-authorization-hook=$FIX/hook-accept.sh&signature-authorization-mode=conjunctive"
    [oprocess_trivial]="${NIX_STORE_OPROCESS:?}|&signature-observation-provider-mode=conjunctive&signature-observation-provider=$HERE/trivial-oprocess-provider.sh&signature-observation-provider-timeout-ms=2000&signature-key-group=g%3Aacme-release-ed25519-1"
    [oprocess_real]="${NIX_STORE_OPROCESS:?}|&signature-observation-provider-mode=conjunctive&signature-observation-provider=$FIX/observation-provider-lean.sh&signature-observation-provider-timeout-ms=2000&signature-key-group=g%3Aacme-release-ed25519-1"
    [oprovider]="${NIX_STORE_OPROVIDER:?}|&signature-observation-provider-mode=conjunctive&signature-observation-provider-library=$HERE/../provider/libexample-provider.so&signature-observation-provider-key-groups=g%3Aacme-release-ed25519-1"
)
ORDER=(baseline h_accept oprocess_trivial oprocess_real oprovider)

trial() {
    local name="$1"
    local bin="${CONFIGS[$name]%%|*}"
    local extra="${CONFIGS[$name]#*|}"
    local dest="$HERE/dest-$name"
    rm -rf "$dest"; mkdir -p "$dest"
    local uri="local?root=$dest&require-sigs=true$extra"
    local load1
    load1=$(cut -d' ' -f1 /proc/loadavg)
    local start end
    start=$(date +%s%N)
    "$bin" --store "$uri" -r "$STOREPATH" \
        --option substituters "file://$FIX/cache" \
        --option trusted-substituters "file://$FIX/cache" \
        --option trusted-public-keys "$TRUSTED_KEYS" \
        --extra-experimental-features configurable-signature-authorization \
        --extra-experimental-features cnsa \
        >/dev/null 2>/tmp/layer3-last-stderr
    local rc=$?
    end=$(date +%s%N)
    local ms=$(( (end-start)/1000000 ))
    local ok="true"
    [ -e "$dest/nix/store/$(basename "$STOREPATH")" ] || ok="false"
    python3 -c "
import json, sys
print(json.dumps({'config': sys.argv[1], 'round': int(sys.argv[2]), 'ms': int(sys.argv[3]), 'load1_before': float(sys.argv[4]), 'admitted': sys.argv[5] == 'true', 'rc': int(sys.argv[6])}))
" "$name" "$2" "$ms" "$load1" "$ok" "$rc"
}

for round in $(seq 1 "$ROUNDS"); do
    for name in "${ORDER[@]}"; do
        trial "$name" "$round"
    done
done
