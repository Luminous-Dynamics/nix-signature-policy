#!/usr/bin/env bash
# Sync nix-signature-policy to its standalone public GitHub repo.
#
# Standalone: github.com/Luminous-Dynamics/nix-signature-policy
#   (the prototype backing the draft NixOS RFC in rfc/. The crate is
#    designed to have zero private-monorepo path dependencies -- see
#    README.md's "fresh-clone reproducibility" claim -- so this sync is a
#    plain directory copy, no path-dependency fixups needed.)
#
# Usage:
#   bash nix-signature-policy/scripts/sync-to-standalone.sh [--dry-run] [--force]

set -euo pipefail

STANDALONE_REMOTE="git@github.com:Luminous-Dynamics/nix-signature-policy.git"

MONOREPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CRATE_DIR="${MONOREPO_ROOT}/nix-signature-policy"
STANDALONE_REPO="/tmp/nix-signature-policy-standalone-sync"

DRY_RUN=false
FORCE=false
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --force)   FORCE=true ;;
    esac
done

GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; CYAN="\033[36m"; RESET="\033[0m"
info()  { printf "${CYAN}[info]${RESET}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[warn]${RESET}  %s\n" "$*"; }
ok()    { printf "${GREEN}[ok]${RESET}    %s\n" "$*"; }
error() { printf "${RED}[error]${RESET} %s\n" "$*"; exit 1; }

[ -f "${CRATE_DIR}/Cargo.toml" ] || error "Cannot find ${CRATE_DIR}/Cargo.toml"

info "Monorepo root: ${MONOREPO_ROOT}"
$DRY_RUN && warn "DRY RUN — no commits or pushes"

# --- Clone or update standalone -----------------------------------------------

if [ -d "${STANDALONE_REPO}/.git" ]; then
    info "Updating existing standalone clone..."
    git -C "${STANDALONE_REPO}" fetch origin
    git -C "${STANDALONE_REPO}" reset --hard origin/main
else
    info "Cloning standalone repo..."
    git clone "${STANDALONE_REMOTE}" "${STANDALONE_REPO}"
fi

# --- Export committed HEAD (NOT the working tree) ------------------------------
# 16+ concurrent sessions leave uncommitted WIP in the shared tree; rsyncing
# the working tree would publish everyone's WIP wholesale (see
# MASTER_ROADMAP.md "Clean-checkpoint sync cadence"). git archive exports
# exactly what is committed.

STAGING="$(mktemp -d /tmp/nix-signature-policy-sync-staging.XXXXXX)"
trap 'rm -rf "${STAGING}"' EXIT

info "Exporting committed HEAD to staging..."
git -C "${MONOREPO_ROOT}" archive HEAD -- nix-signature-policy | tar -x -C "${STAGING}"

info "Syncing nix-signature-policy (HEAD) -> standalone root..."
rsync -a --delete \
    --exclude='.git' \
    "${STAGING}/nix-signature-policy/" "${STANDALONE_REPO}/"

# --- Post-sync check ------------------------------------------------------------
# Cargo.lock is tracked for this crate (it's a [[bin]] application, not a
# library — see the root .gitignore's !nix-signature-policy/Cargo.lock
# exception) specifically so this check (and the standalone repo's own CI)
# build against the exact dependency versions this prototype was tested
# against, not whatever the registry resolves to today.

if [ -f "${STANDALONE_REPO}/Cargo.lock" ]; then
    info "Verifying standalone build (cargo check --locked)..."
    (cd "${STANDALONE_REPO}" && cargo check --locked --all-targets) || \
        warn "cargo check --locked failed on the synced tree — investigate before pushing"
else
    warn "No Cargo.lock in synced tree — was it committed in the monorepo?"
fi

# --- Commit and push ------------------------------------------------------------

cd "${STANDALONE_REPO}"
git add -A
if git diff --cached --quiet; then
    ok "No changes to sync"
    exit 0
fi

CHANGED=$(git diff --cached --stat | tail -1)
info "Changes: ${CHANGED}"

if $DRY_RUN; then
    warn "DRY RUN — skipping commit and push"
    git diff --cached --stat
    exit 0
fi

MONO_SHA=$(git -C "${MONOREPO_ROOT}" rev-parse --short HEAD)
COMMIT_MSG="sync: update from monorepo @ ${MONO_SHA} ($(date -u +%Y-%m-%dT%H:%M:%SZ))"

if ! $FORCE; then
    echo ""
    echo "About to commit and push to the public prototype repo:"
    git diff --cached --stat
    echo ""
    read -rp "Proceed? [y/N] " confirm
    [ "$confirm" = "y" ] || [ "$confirm" = "Y" ] || { warn "Aborted"; exit 1; }
fi

git commit -m "${COMMIT_MSG}"
git push origin HEAD
ok "Synced nix-signature-policy to standalone — CI will run from main"
