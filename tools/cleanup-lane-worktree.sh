#!/usr/bin/env bash
# cleanup-lane-worktree.sh - companion cleanup tool for spawn-lane-worktree.sh
# (Phase -1 PER-LANE-WORKTREE, 2026-05-23).
#
# Behaviour:
#   - Resolve the lane's worktree under <worktree-root>/auditooor-lane-<id>-*.
#   - If the worktree has zero commits ahead of the base branch AND a clean
#     working tree -> `git worktree remove` + drop the lane branch + drop
#     the R36/R55 pathspec entry. Exit 0 with verdict=removed-clean.
#   - If the worktree has commits ahead -> emit `verdict=ahead` and leave
#     the worktree in place. The operator (or downstream lane-integrator
#     --push) handles the merge / push.
#   - If the worktree is dirty (uncommitted) -> emit `verdict=dirty` and
#     leave the worktree in place. Same operator responsibility.
#
# CLI:
#   cleanup-lane-worktree.sh --lane-id <X>
#                            [--base-branch main]
#                            [--worktree-root /tmp]
#                            [--worktree-path <explicit-path>]
#                            [--force]
#                            [--force-unmerged]
#                            [--unregister-pathspec]
#                            [--dry-run]
#                            [--json]
#
# --force-unmerged (LANE-INTEGRATOR-AUTOMERGE-PATCH, 2026-05-23):
# permit removal even when the worktree HEAD is NOT an ancestor of
# origin/main (commits would be lost). Distinct from --force which only
# overrides dirty + ahead checks. The unmerged-commits refusal protects
# against the stranded-branch failure mode audited in
# `reports/v3_iter_2026-05-23_iter18_phase_0/lane_BRANCH_RECONCILE_AUDIT/`.
#
# Output (stdout): the verdict token, or --json schema auditooor.cleanup_lane_worktree.v1.
#
# Exit codes:
#   0 - verdict=removed-clean OR verdict=already-absent OR verdict=ahead (informational)
#       OR verdict=dirty (informational)
#   1 - bad CLI arg
#   2 - git worktree remove failed
#   3 - underlying repo not a git tree
#
# Composes with: tools/spawn-lane-worktree.sh, tools/agent-pathspec-register.py.
# Tests: tools/tests/test_per_lane_worktree.sh

set -uo pipefail

SCRIPT_NAME="cleanup-lane-worktree.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
PATHSPEC_TOOL="${REPO_ROOT}/tools/agent-pathspec-register.py"

SCHEMA="auditooor.cleanup_lane_worktree.v1"

LANE_ID=""
BASE_BRANCH="main"
WORKTREE_ROOT="/tmp"
WORKTREE_PATH=""
FORCE=0
FORCE_UNMERGED=0
UNREGISTER_PATHSPEC=0
DRY_RUN=0
JSON_OUTPUT=0

print_help() {
    sed -n '2,30p' "$SCRIPT_DIR/$SCRIPT_NAME"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lane-id) LANE_ID="$2"; shift 2 ;;
        --base-branch) BASE_BRANCH="$2"; shift 2 ;;
        --worktree-root) WORKTREE_ROOT="$2"; shift 2 ;;
        --worktree-path) WORKTREE_PATH="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --force-unmerged) FORCE_UNMERGED=1; shift ;;
        --unregister-pathspec) UNREGISTER_PATHSPEC=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --json) JSON_OUTPUT=1; shift ;;
        --help|-h) print_help; exit 0 ;;
        *)
            echo "[$SCRIPT_NAME] ERROR: unknown arg: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$LANE_ID" ]] && [[ -z "$WORKTREE_PATH" ]]; then
    echo "[$SCRIPT_NAME] ERROR: --lane-id or --worktree-path is required" >&2
    exit 1
fi

cd "$REPO_ROOT" || { echo "[$SCRIPT_NAME] ERROR: cannot cd to $REPO_ROOT" >&2; exit 3; }

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "[$SCRIPT_NAME] ERROR: $REPO_ROOT is not a git tree" >&2
    exit 3
fi

BASE_SHA=""
if git rev-parse --verify -q "origin/$BASE_BRANCH" >/dev/null 2>&1; then
    BASE_SHA=$(git rev-parse "origin/$BASE_BRANCH")
elif git rev-parse --verify -q "$BASE_BRANCH" >/dev/null 2>&1; then
    BASE_SHA=$(git rev-parse "$BASE_BRANCH")
fi

# ---------------------------------------------------------------------------
# Resolve the worktree path
# ---------------------------------------------------------------------------

if [[ -z "$WORKTREE_PATH" ]]; then
    # Find the lane's worktree under <worktree-root>/auditooor-lane-<id>-*.
    # Prefer git worktree list to be authoritative (handles renames).
    cand=$(git worktree list --porcelain 2>/dev/null \
            | awk -v lane="$LANE_ID" '
                /^worktree / { path = substr($0, 10) }
                /^branch / && path ~ "auditooor-lane-" lane "-" { print path; exit }
              ')
    if [[ -z "$cand" ]]; then
        # Fall back to glob.
        for d in "${WORKTREE_ROOT}/auditooor-lane-${LANE_ID}-"*; do
            if [[ -d "$d" ]]; then
                cand="$d"
                break
            fi
        done
    fi
    WORKTREE_PATH="$cand"
fi

VERDICT="already-absent"
REMOVED=0
AHEAD_COUNT=0
DIRTY=0
UNMERGED=0
BRANCH_NAME=""

# Auto-merge-gap protection (LANE-INTEGRATOR-AUTOMERGE-PATCH, 2026-05-23):
# fetch origin/<base_branch> so the ancestor check below uses the latest
# remote main, not the local stale ref. Best-effort: a fetch failure does
# not block cleanup (we fall back to local BASE_SHA which the existing
# block already resolved). HAS_ORIGIN_BASE gates the unmerged-commits
# check: if origin/<base_branch> doesn't resolve, we have no remote to
# compare against, and the existing `ahead` verdict semantics apply.
HAS_ORIGIN_BASE=0
git -C "$REPO_ROOT" fetch origin "$BASE_BRANCH" >/dev/null 2>&1 || true
if git -C "$REPO_ROOT" rev-parse --verify -q "origin/$BASE_BRANCH" >/dev/null 2>&1; then
    BASE_SHA=$(git -C "$REPO_ROOT" rev-parse "origin/$BASE_BRANCH")
    HAS_ORIGIN_BASE=1
fi

if [[ -n "$WORKTREE_PATH" ]] && [[ -d "$WORKTREE_PATH" ]]; then
    BRANCH_NAME=$(git -C "$WORKTREE_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")
    DIRTY_OUT=$(git -C "$WORKTREE_PATH" status --porcelain 2>/dev/null || echo "ERROR")
    if [[ -n "$DIRTY_OUT" ]] && [[ "$DIRTY_OUT" != "ERROR" ]]; then
        DIRTY=1
    fi
    if [[ -n "$BASE_SHA" ]]; then
        WT_HEAD=$(git -C "$WORKTREE_PATH" rev-parse HEAD 2>/dev/null || echo "")
        if [[ -n "$WT_HEAD" ]]; then
            AHEAD_COUNT=$(git -C "$REPO_ROOT" rev-list --count "$BASE_SHA..$WT_HEAD" 2>/dev/null || echo 0)
            # Unmerged-commits guard: HEAD must be an ancestor of
            # origin/<base_branch>. When NOT, the worktree carries commits
            # that have not landed on main; removing the worktree (and
            # later the branch ref) would strand or lose them. Only fires
            # when origin/<base_branch> resolves; otherwise the existing
            # `ahead` semantics apply.
            if [[ $HAS_ORIGIN_BASE -eq 1 ]]; then
                if ! git -C "$REPO_ROOT" merge-base --is-ancestor "$WT_HEAD" "$BASE_SHA" >/dev/null 2>&1; then
                    UNMERGED=1
                fi
            fi
        fi
    fi

    if [[ $DIRTY -eq 1 ]] && [[ $FORCE -eq 0 ]]; then
        VERDICT="dirty"
    elif [[ $UNMERGED -eq 1 ]] && [[ $FORCE_UNMERGED -eq 0 ]] && [[ $FORCE -eq 0 ]]; then
        VERDICT="unmerged"
        echo "[$SCRIPT_NAME] REFUSE: lane has unmerged commits (HEAD is NOT an ancestor of origin/$BASE_BRANCH). Run lane-integrator --push first to FF-merge to main, OR pass --force-unmerged to remove the worktree and lose the commits." >&2
    elif [[ "$AHEAD_COUNT" -gt 0 ]] && [[ $FORCE -eq 0 ]] && [[ $FORCE_UNMERGED -eq 0 ]]; then
        VERDICT="ahead"
    else
        if [[ $DRY_RUN -eq 1 ]]; then
            VERDICT="would-remove-clean"
        else
            # Remove worktree (use --force if FORCE set).
            remove_args=("remove" "$WORKTREE_PATH")
            if [[ $FORCE -eq 1 ]]; then
                remove_args+=("--force")
            fi
            if git worktree "${remove_args[@]}" >/dev/null 2>&1; then
                # Drop the lane branch if it matches our convention.
                if [[ -n "$BRANCH_NAME" ]] && [[ "$BRANCH_NAME" == lane/${LANE_ID}-* ]]; then
                    git branch -D "$BRANCH_NAME" >/dev/null 2>&1 || true
                fi
                REMOVED=1
                VERDICT="removed-clean"
            else
                echo "[$SCRIPT_NAME] ERROR: git worktree remove failed for $WORKTREE_PATH" >&2
                exit 2
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Unregister R36/R55 pathspec (opt-in)
# ---------------------------------------------------------------------------

PATHSPEC_STATUS="not-requested"
if [[ $UNREGISTER_PATHSPEC -eq 1 ]] && [[ -n "$LANE_ID" ]]; then
    if [[ ! -f "$PATHSPEC_TOOL" ]]; then
        PATHSPEC_STATUS="tool-missing"
    elif [[ $DRY_RUN -eq 1 ]]; then
        PATHSPEC_STATUS="would-unregister"
    else
        if python3 "$PATHSPEC_TOOL" unregister --lane "$LANE_ID" >/dev/null 2>&1; then
            PATHSPEC_STATUS="unregistered"
        else
            PATHSPEC_STATUS="unregister-failed"
        fi
    fi
fi

TS_NOW=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))' 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

if [[ $JSON_OUTPUT -eq 1 ]]; then
    python3 -c "
import json
print(json.dumps({
    'schema': '$SCHEMA',
    'ts': '$TS_NOW',
    'lane_id': '$LANE_ID',
    'worktree_path': '$WORKTREE_PATH',
    'branch_name': '$BRANCH_NAME',
    'base_branch': '$BASE_BRANCH',
    'verdict': '$VERDICT',
    'removed': bool($REMOVED),
    'ahead_count': int('$AHEAD_COUNT' or 0),
    'dirty': bool($DIRTY),
    'unmerged': bool($UNMERGED),
    'force': bool($FORCE),
    'force_unmerged': bool($FORCE_UNMERGED),
    'pathspec_status': '$PATHSPEC_STATUS',
    'dry_run': bool($DRY_RUN),
}, sort_keys=True))
"
else
    echo "$VERDICT"
    echo "[$SCRIPT_NAME] lane=$LANE_ID worktree=$WORKTREE_PATH verdict=$VERDICT removed=$REMOVED ahead=$AHEAD_COUNT dirty=$DIRTY unmerged=$UNMERGED pathspec=$PATHSPEC_STATUS" >&2
fi

exit 0
