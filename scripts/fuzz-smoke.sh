#!/usr/bin/env bash
set -euo pipefail

seconds="${FUZZ_SECONDS_PER_TARGET:-10}"
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check

for target in narinfo_parse policy_evaluator policy_adapters signature_codecs evidence_bundle; do
  echo "== fuzz smoke: ${target} (${seconds}s) =="
  mkdir -p "fuzz/artifacts/${target}"
  cargo fuzz run "${target}" -- \
    -max_total_time="${seconds}" \
    -timeout=10 \
    -rss_limit_mb=2048 \
    -artifact_prefix="fuzz/artifacts/${target}/"
done
