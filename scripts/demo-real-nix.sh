#!/usr/bin/env bash
set -euo pipefail

out_dir="demo-output"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir)
      out_dir="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${NIX_PQC_E2E_STORE_PATH:-}" ]]; then
  echo "NIX_PQC_E2E_STORE_PATH must identify a prebuilt store path" >&2
  exit 2
fi

mkdir -p "$out_dir"
python3 scripts/report-environment.py >"$out_dir/environment.json"
cargo run --locked --bin policy-conformance -- \
  --vectors policy-vectors --format json >"$out_dir/policy-conformance.json"
cargo run --locked --bin policy-evidence -- export-vector \
  policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --out "$out_dir/policy-evidence.json"
cargo run --locked --bin policy-evidence -- verify \
  "$out_dir/policy-evidence.json" \
  --source policy-vectors/adapter-parity/semantic-hybrid-valid.json \
  --require-source --format json >"$out_dir/policy-evidence-verification.json"

set -o pipefail
cargo test --locked --test real_nix_e2e -- --ignored --nocapture \
  2>&1 | tee "$out_dir/real-nix-e2e.log"

python3 - "$out_dir" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])
artifacts = []
for path in sorted(item for item in out.iterdir() if item.is_file()):
    data = path.read_bytes()
    artifacts.append({
        "path": path.name,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    })
report = {
    "schema_version": 1,
    "result": "passed",
    "real_nix_store_path": __import__("os").environ["NIX_PQC_E2E_STORE_PATH"],
    "artifacts": artifacts,
}
(out / "demo-report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
PY

echo "real-Nix demonstration passed; evidence written to $out_dir"
