#!/usr/bin/env bash
set -eo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source /tmp/nix-dev-env.sh

NIX_STORE_BIN=/srv/luminous-dynamics/.claude/worktrees/nix-authorization-boundary-experiments-1ebf353c/nix-src/build/src/nix/nix-store
NIX_BIN=/srv/luminous-dynamics/.claude/worktrees/nix-authorization-boundary-experiments-1ebf353c/nix-src/build/src/nix/nix
FIX=/srv/luminous-dynamics/.claude/worktrees/nix-authorization-boundary-experiments-1ebf353c/measurement/fixtures

echo "signing..."
"$NIX_BIN" store sign --key-file "$FIX/publisher-ed25519.secret" $(cat paths-100.txt) --extra-experimental-features "nix-command flakes"

echo "verifying first path has a signature..."
"$NIX_BIN" path-info --json "$(head -1 paths-100.txt)" --extra-experimental-features "nix-command flakes" | head -c 500
echo

echo "exporting to file cache..."
rm -rf cache
mkdir -p cache
"$NIX_BIN" copy --to "file://$(pwd)/cache" $(cat paths-100.txt) --extra-experimental-features "nix-command flakes"

echo "done"
ls cache/ | head -5
