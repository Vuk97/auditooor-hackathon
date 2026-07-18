#!/usr/bin/env bash
# pre-push-secret-scrub.sh — Git pre-push hook: secret scanner gate.
#
# PR #658 Lane 7 — Tier-B #11 deliverable.
#
# Calls tools/secret-scrub-changed-files.py over all added/modified files
# between @{upstream} and HEAD.  Fails closed (exit 1) if any HIGH-confidence
# secret pattern fires so the push is aborted before secrets reach origin.
#
# Install:
#   cp scripts/pre-push-secret-scrub.sh .git/hooks/pre-push
#   chmod +x .git/hooks/pre-push
#
# Or for worktree installs (idempotent):
#   bash scripts/pre-push-secret-scrub.sh --install
#
# Dry-run (no-fail, prints findings):
#   bash scripts/pre-push-secret-scrub.sh --dry-run
#
# The hook is ADVISORY on missing Python/git — it exits 0 rather than
# blocking pushes on misconfigured dev machines.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SCRUB_TOOL="${REPO_ROOT}/tools/secret-scrub-changed-files.py"

# -------------------------------------------------------------------------
# --install mode: copy self into .git/hooks/pre-push
# -------------------------------------------------------------------------
if [[ "${1:-}" == "--install" ]]; then
    HOOK_DIR="${REPO_ROOT}/.git/hooks"
    mkdir -p "$HOOK_DIR"
    HOOK_PATH="${HOOK_DIR}/pre-push"
    cp "${BASH_SOURCE[0]}" "$HOOK_PATH"
    chmod +x "$HOOK_PATH"
    echo "[pre-push-secret-scrub] installed at ${HOOK_PATH}"
    exit 0
fi

# -------------------------------------------------------------------------
# Guard: Python3 must be available
# -------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    echo "[pre-push-secret-scrub] WARNING: python3 not found — skipping secret scrub." >&2
    exit 0
fi

# -------------------------------------------------------------------------
# Guard: scrub tool must exist
# -------------------------------------------------------------------------
if [[ ! -f "$SCRUB_TOOL" ]]; then
    echo "[pre-push-secret-scrub] WARNING: ${SCRUB_TOOL} not found — skipping." >&2
    exit 0
fi

# -------------------------------------------------------------------------
# Dry-run mode (prints findings, never fails)
# -------------------------------------------------------------------------
if [[ "${1:-}" == "--dry-run" ]]; then
    echo "[pre-push-secret-scrub] DRY-RUN: scanning changed files..."
    python3 "$SCRUB_TOOL" --upstream "@{upstream}" || true
    exit 0
fi

# -------------------------------------------------------------------------
# Normal (pre-push) mode: exit-fail on HIGH findings
# -------------------------------------------------------------------------
echo "[pre-push-secret-scrub] scanning changed files for secrets..."

if python3 "$SCRUB_TOOL" --upstream "@{upstream}" --exit-fail; then
    # Exit 0 from scrub tool = clean
    exit 0
else
    RC=$?
    if [[ $RC -eq 2 ]]; then
        echo "" >&2
        echo "┌─────────────────────────────────────────────────────────────┐" >&2
        echo "│  PRE-PUSH BLOCKED — secret(s) detected in changed files.    │" >&2
        echo "│  Redact or whitelist, then retry push.                       │" >&2
        echo "│  Dry-run:  bash scripts/pre-push-secret-scrub.sh --dry-run  │" >&2
        echo "└─────────────────────────────────────────────────────────────┘" >&2
        exit 1
    fi
    # RC=1 means error (not git repo, etc.) — don't block push
    echo "[pre-push-secret-scrub] WARNING: scrub tool error (rc=${RC}) — skipping." >&2
    exit 0
fi
