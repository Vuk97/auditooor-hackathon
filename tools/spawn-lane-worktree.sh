#!/usr/bin/env bash
# spawn-lane-worktree.sh - per-lane git worktree provisioning (Phase -1
# PER-LANE-WORKTREE, 2026-05-23).
#
# STRUCTURAL fix for R36 absorption: every commit-producing lane gets its
# OWN git worktree under /tmp. Sibling lanes physically cannot stomp each
# other because they work in different directories. Composes with the
# existing R36/R55 pathspec gate (`tools/agent-pathspec-register.py`) -
# the per-lane worktree still registers a pathspec so the gate can refuse
# absorption even WITHIN the lane's own worktree if the lane attempts a
# sweeping commit.
#
# Anchor: CLAUDE.md Rule 36 (c) "Per-agent worktree (preferred for any
# commit-producing agent)" + `docs/R36_PARALLEL_SESSION_RECOVERY_2026-05-23.md`
# Section 5.1. Wave-1 PR #726 cross-pollination + iter17 OOOOO integration
# stomp are the historical anchors.
#
# CLI:
#   spawn-lane-worktree.sh --lane-id <X>
#                          [--base-branch main]
#                          [--worktree-root /tmp]
#                          [--branch <name>]
#                          [--workspace <path>]
#                          [--register-pathspec]
#                          [--pathspec-files "tools/foo.py,docs/FOO.md"]
#                          [--ttl 7200]
#                          [--cleanup-on-empty-diff]
#                          [--bypass-lane-cooldown-check]
#                          [--bypass-lane-cooldown-reason <audited-reason>]
#                          [--dry-run]
#                          [--json]
#
# Output (stdout):
#   - Default: the worktree path (one line). Operators can `cd $(spawn-lane-worktree.sh ...)`.
#   - --json: a one-line JSON summary (schema auditooor.spawn_lane_worktree.v1).
#
# Exit codes:
#   0 - success (worktree provisioned or dry-run)
#   1 - bad CLI arg
#   2 - git worktree add failed
#   3 - pathspec registration failed (only when --register-pathspec)
#   4 - underlying repo not a git tree
#   5 - cleanup-on-empty-diff requested + already-empty worktree existed and
#       was removed (warn-grade success; operator likely re-running)
#   6 - lane cooldown check failed closed or blocked by active cooldown
#
# Composes with:
#   - tools/spawn-worker.sh --use-worktree (calls this tool internally)
#   - tools/lane-integrator.py (auto-detects when running in a worktree)
#   - tools/cleanup-lane-worktree.sh (companion cleanup tool)
#   - tools/git-hooks/pre-commit-pathspec-discipline.sh (R36)
#   - tools/git-hooks/pre-destructive-op-sibling-check.sh (R55)
#
# Tests: tools/tests/test_per_lane_worktree.sh

set -uo pipefail

SCRIPT_NAME="spawn-lane-worktree.sh"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
PATHSPEC_TOOL="${REPO_ROOT}/tools/agent-pathspec-register.py"
MCP_TOOL="${REPO_ROOT}/tools/vault-mcp-server.py"

SCHEMA="auditooor.spawn_lane_worktree.v1"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

LANE_ID=""
BASE_BRANCH="main"
WORKTREE_ROOT="/tmp"
BRANCH_NAME=""
COOLDOWN_WORKSPACE_PATH=""
REGISTER_PATHSPEC=0
PATHSPEC_FILES=""
TTL=7200
CLEANUP_ON_EMPTY_DIFF=0
DRY_RUN=0
JSON_OUTPUT=0
COOLDOWN_BYPASS=0
COOLDOWN_BYPASS_REASON=""
COOLDOWN_STATUS="not-run"
COOLDOWN_VERDICT=""
COOLDOWN_RC=0
COOLDOWN_CONTEXT_PACK_ID=""
COOLDOWN_CONTEXT_PACK_HASH=""

print_help() {
    sed -n '2,60p' "$SCRIPT_DIR/$SCRIPT_NAME"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lane-id) LANE_ID="$2"; shift 2 ;;
        --base-branch) BASE_BRANCH="$2"; shift 2 ;;
        --worktree-root) WORKTREE_ROOT="$2"; shift 2 ;;
        --branch) BRANCH_NAME="$2"; shift 2 ;;
        --workspace|--workspace-path) COOLDOWN_WORKSPACE_PATH="$2"; shift 2 ;;
        --register-pathspec) REGISTER_PATHSPEC=1; shift ;;
        --pathspec-files) PATHSPEC_FILES="$2"; shift 2 ;;
        --ttl) TTL="$2"; shift 2 ;;
        --cleanup-on-empty-diff) CLEANUP_ON_EMPTY_DIFF=1; shift ;;
        --bypass-lane-cooldown-check) COOLDOWN_BYPASS=1; shift ;;
        --bypass-lane-cooldown-reason) COOLDOWN_BYPASS_REASON="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --json) JSON_OUTPUT=1; shift ;;
        --help|-h) print_help; exit 0 ;;
        *)
            echo "[$SCRIPT_NAME] ERROR: unknown arg: $1" >&2
            echo "[$SCRIPT_NAME] run --help for usage." >&2
            exit 1
            ;;
    esac
done

if [[ -z "$LANE_ID" ]]; then
    echo "[$SCRIPT_NAME] ERROR: --lane-id is required" >&2
    exit 1
fi

# Slug-validate lane-id: only kebab/underscore/alphanumerics. Keeps the
# /tmp path safe and bounds blast radius.
if ! [[ "$LANE_ID" =~ ^[A-Za-z0-9_-]+$ ]]; then
    echo "[$SCRIPT_NAME] ERROR: lane-id must match [A-Za-z0-9_-]+ (got: $LANE_ID)" >&2
    exit 1
fi
if [[ ${#LANE_ID} -gt 64 ]]; then
    echo "[$SCRIPT_NAME] ERROR: lane-id too long (>64 chars): $LANE_ID" >&2
    exit 1
fi

if [[ $COOLDOWN_BYPASS -eq 1 && -z "$COOLDOWN_BYPASS_REASON" ]]; then
    echo "[$SCRIPT_NAME] ERROR: --bypass-lane-cooldown-check requires --bypass-lane-cooldown-reason" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Verify repo state
# ---------------------------------------------------------------------------

cd "$REPO_ROOT" || { echo "[$SCRIPT_NAME] ERROR: cannot cd into $REPO_ROOT" >&2; exit 4; }

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
    echo "[$SCRIPT_NAME] ERROR: $REPO_ROOT is not a git tree" >&2
    exit 4
fi

# Resolve the base branch to a commit. Prefer origin/<base> if present;
# fall back to local <base>. Empty result is fatal.
BASE_SHA=""
if git rev-parse --verify -q "origin/$BASE_BRANCH" >/dev/null 2>&1; then
    BASE_SHA=$(git rev-parse "origin/$BASE_BRANCH")
elif git rev-parse --verify -q "$BASE_BRANCH" >/dev/null 2>&1; then
    BASE_SHA=$(git rev-parse "$BASE_BRANCH")
else
    echo "[$SCRIPT_NAME] ERROR: base branch '$BASE_BRANCH' not resolvable (local nor origin/)" >&2
    exit 4
fi
SHORT_SHA="${BASE_SHA:0:10}"

# ---------------------------------------------------------------------------
# Compute worktree path + branch name
# ---------------------------------------------------------------------------

WORKTREE_PATH="${WORKTREE_ROOT}/auditooor-lane-${LANE_ID}-${SHORT_SHA}"

if [[ -z "$BRANCH_NAME" ]]; then
    BRANCH_NAME="lane/${LANE_ID}-${SHORT_SHA}"
fi
if [[ -z "$COOLDOWN_WORKSPACE_PATH" ]]; then
    COOLDOWN_WORKSPACE_PATH="${AUDITOOOR_WORKSPACE_PATH:-$REPO_ROOT}"
fi

# ---------------------------------------------------------------------------
# Enforce lane cooldown before mutating worktree state
# ---------------------------------------------------------------------------

run_lane_cooldown_check() {
    if [[ $COOLDOWN_BYPASS -eq 1 ]]; then
        COOLDOWN_STATUS="bypassed"
        COOLDOWN_VERDICT="bypassed"
        echo "[$SCRIPT_NAME] WARN: AUDITED BYPASS of vault_lane_cooldown_check for lane=$LANE_ID" >&2
        echo "[$SCRIPT_NAME] WARN: bypass_reason=$COOLDOWN_BYPASS_REASON" >&2
        return 0
    fi

    if [[ ! -f "$MCP_TOOL" ]]; then
        COOLDOWN_STATUS="unsupported-mcp-cli-missing"
        COOLDOWN_VERDICT="unsupported"
        echo "[$SCRIPT_NAME] WARN: vault_lane_cooldown_check unsupported: MCP CLI missing at $MCP_TOOL" >&2
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        COOLDOWN_STATUS="unsupported-python3-missing"
        COOLDOWN_VERDICT="unsupported"
        echo "[$SCRIPT_NAME] WARN: vault_lane_cooldown_check unsupported: python3 not found" >&2
        return 0
    fi

    local args_json
    if ! args_json=$(COOLDOWN_WORKSPACE_PATH="$COOLDOWN_WORKSPACE_PATH" REPO_ROOT="$REPO_ROOT" WORKTREE_PATH="$WORKTREE_PATH" LANE_ID="$LANE_ID" python3 - <<'PY'
import json
import os

print(json.dumps({
    "workspace_path": os.environ["COOLDOWN_WORKSPACE_PATH"],
    "worktree_path": os.environ["WORKTREE_PATH"],
    "lane_id": os.environ["LANE_ID"],
}, sort_keys=True))
PY
); then
        COOLDOWN_STATUS="args-json-failed"
        COOLDOWN_VERDICT="error"
        echo "[$SCRIPT_NAME] ERROR: failed to construct vault_lane_cooldown_check args; failing closed" >&2
        exit 6
    fi

    local out_file err_file parse_file
    out_file=$(mktemp -t spawn-lane-cooldown-out-XXXXXX)
    err_file=$(mktemp -t spawn-lane-cooldown-err-XXXXXX)
    parse_file=$(mktemp -t spawn-lane-cooldown-parse-XXXXXX)

    echo "[$SCRIPT_NAME] checking vault_lane_cooldown_check lane=$LANE_ID workspace=$COOLDOWN_WORKSPACE_PATH worktree=$WORKTREE_PATH" >&2
    python3 "$MCP_TOOL" \
        --repo-root "$REPO_ROOT" \
        --call vault_lane_cooldown_check \
        --args "$args_json" \
        >"$out_file" 2>"$err_file"
    COOLDOWN_RC=$?

    if [[ $COOLDOWN_RC -ne 0 ]]; then
        COOLDOWN_STATUS="mcp-cli-failed"
        COOLDOWN_VERDICT="error"
        echo "[$SCRIPT_NAME] ERROR: vault_lane_cooldown_check failed (rc=$COOLDOWN_RC); failing closed" >&2
        echo "[$SCRIPT_NAME] ERROR: stderr tail:" >&2
        tail -c 2000 "$err_file" >&2 || true
        rm -f "$out_file" "$err_file" "$parse_file"
        exit 6
    fi

    if ! python3 - "$out_file" >"$parse_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
    payload = json.load(fh)

lanes = payload.get("lanes", [])
if not isinstance(lanes, list):
    lanes = []

fields = [
    str(payload.get("verdict", "")),
    str(payload.get("context_pack_id", "")),
    str(payload.get("context_pack_hash", "")),
    str(payload.get("state_file_status", "")),
    str(payload.get("state_file_path", "")),
    str(len(lanes)),
]
for field in fields:
    print(field.replace("\n", " "))
PY
    then
        COOLDOWN_STATUS="mcp-json-unparseable"
        COOLDOWN_VERDICT="error"
        echo "[$SCRIPT_NAME] ERROR: vault_lane_cooldown_check returned unparseable JSON; failing closed" >&2
        echo "[$SCRIPT_NAME] ERROR: stdout head:" >&2
        head -c 2000 "$out_file" >&2 || true
        echo "" >&2
        echo "[$SCRIPT_NAME] ERROR: stderr tail:" >&2
        tail -c 2000 "$err_file" >&2 || true
        rm -f "$out_file" "$err_file" "$parse_file"
        exit 6
    fi

    local state_file_status state_file_path lane_count
    local parsed_fields=()
    while IFS= read -r parsed_line; do
        parsed_fields+=("$parsed_line")
    done <"$parse_file"
    COOLDOWN_VERDICT="${parsed_fields[0]:-}"
    COOLDOWN_CONTEXT_PACK_ID="${parsed_fields[1]:-}"
    COOLDOWN_CONTEXT_PACK_HASH="${parsed_fields[2]:-}"
    state_file_status="${parsed_fields[3]:-}"
    state_file_path="${parsed_fields[4]:-}"
    lane_count="${parsed_fields[5]:-}"
    COOLDOWN_STATUS="checked"

    echo "[$SCRIPT_NAME] cooldown_check verdict=$COOLDOWN_VERDICT lanes=$lane_count state_file_status=$state_file_status state_file=$state_file_path context_pack_id=$COOLDOWN_CONTEXT_PACK_ID" >&2

    if [[ "$COOLDOWN_VERDICT" == "active-cooldown" ]]; then
        COOLDOWN_STATUS="blocked-active-cooldown"
        echo "[$SCRIPT_NAME] ERROR: lane is still in cooldown; refusing to create worktree (lane=$LANE_ID)" >&2
        echo "[$SCRIPT_NAME] ERROR: cooldown payload head:" >&2
        head -c 2000 "$out_file" >&2 || true
        echo "" >&2
        rm -f "$out_file" "$err_file" "$parse_file"
        exit 6
    fi

    case "$COOLDOWN_VERDICT" in
        pass-no-cooldown-ledger|pass-no-active-cooldowns|pass-lane-not-cooled)
            ;;
        *)
            COOLDOWN_STATUS="unexpected-verdict"
            echo "[$SCRIPT_NAME] ERROR: unexpected vault_lane_cooldown_check verdict='$COOLDOWN_VERDICT'; failing closed" >&2
            echo "[$SCRIPT_NAME] ERROR: cooldown payload head:" >&2
            head -c 2000 "$out_file" >&2 || true
            echo "" >&2
            rm -f "$out_file" "$err_file" "$parse_file"
            exit 6
            ;;
    esac

    rm -f "$out_file" "$err_file" "$parse_file"
}

run_lane_cooldown_check

# Handle pre-existing worktree.
PRE_EXISTING=0
EMPTY_DIFF_CLEANED=0
if [[ -d "$WORKTREE_PATH" ]]; then
    PRE_EXISTING=1
    if [[ $CLEANUP_ON_EMPTY_DIFF -eq 1 ]]; then
        # Check whether the existing worktree has any commits ahead of base
        # OR any uncommitted edits. Only remove if completely clean.
        clean_ok=0
        if [[ -d "$WORKTREE_PATH/.git" ]] || [[ -f "$WORKTREE_PATH/.git" ]]; then
            # Get the worktree branch
            wt_head=$(git -C "$WORKTREE_PATH" rev-parse HEAD 2>/dev/null || echo "")
            wt_status=$(git -C "$WORKTREE_PATH" status --porcelain 2>/dev/null || echo "DIRTY")
            if [[ -z "$wt_status" ]] && [[ "$wt_head" == "$BASE_SHA" ]]; then
                clean_ok=1
            fi
        fi
        if [[ $clean_ok -eq 1 ]]; then
            if [[ $DRY_RUN -eq 1 ]]; then
                echo "[$SCRIPT_NAME] [DRY-RUN] would remove clean empty worktree: $WORKTREE_PATH" >&2
            else
                git worktree remove "$WORKTREE_PATH" --force >/dev/null 2>&1 || true
                # Also drop the branch ref if it was an auto-created lane branch.
                if git rev-parse --verify -q "$BRANCH_NAME" >/dev/null 2>&1; then
                    git branch -D "$BRANCH_NAME" >/dev/null 2>&1 || true
                fi
            fi
            EMPTY_DIFF_CLEANED=1
            PRE_EXISTING=0
        else
            echo "[$SCRIPT_NAME] WARN: worktree exists with state ahead of base or dirty WT; keeping it: $WORKTREE_PATH" >&2
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Provision the worktree (unless still pre-existing)
# ---------------------------------------------------------------------------

GIT_ADD_RC=0
PROVISIONED=0

if [[ $PRE_EXISTING -eq 1 ]]; then
    # Pre-existing and not cleaned: noop-success. Return the path so the
    # caller can resume work in it.
    PROVISIONED=0
elif [[ $DRY_RUN -eq 1 ]]; then
    echo "[$SCRIPT_NAME] [DRY-RUN] would: git worktree add -b $BRANCH_NAME $WORKTREE_PATH $BASE_SHA" >&2
    PROVISIONED=1
else
    # Check if branch already exists; if so, add without -b.
    # IMPORTANT: redirect ALL output (stdout AND stderr) to /dev/null - git
    # worktree add prints "Preparing worktree..." to stderr, which would
    # corrupt our stdout path emission downstream.
    if git rev-parse --verify -q "$BRANCH_NAME" >/dev/null 2>&1; then
        git worktree add "$WORKTREE_PATH" "$BRANCH_NAME" >/dev/null 2>&1
        GIT_ADD_RC=$?
    else
        git worktree add -b "$BRANCH_NAME" "$WORKTREE_PATH" "$BASE_SHA" >/dev/null 2>&1
        GIT_ADD_RC=$?
    fi
    if [[ $GIT_ADD_RC -ne 0 ]]; then
        echo "[$SCRIPT_NAME] ERROR: git worktree add failed (rc=$GIT_ADD_RC): $WORKTREE_PATH" >&2
        exit 2
    fi
    PROVISIONED=1
fi

# ---------------------------------------------------------------------------
# Register R36/R55 pathspec (opt-in)
# ---------------------------------------------------------------------------

PATHSPEC_STATUS="not-requested"
PATHSPEC_RC=0
if [[ $REGISTER_PATHSPEC -eq 1 ]]; then
    if [[ ! -f "$PATHSPEC_TOOL" ]]; then
        PATHSPEC_STATUS="tool-missing"
        echo "[$SCRIPT_NAME] WARN: pathspec tool missing at $PATHSPEC_TOOL" >&2
    else
        FILES_ARG="$PATHSPEC_FILES"
        if [[ -z "$FILES_ARG" ]]; then
            # Sentinel directory pathspec. The lane's commit must declare
            # explicit files via lane-integrator.py; this entry just claims
            # the lane id so other lanes' R36 hooks see it.
            FILES_ARG="reports/v3_iter_*/lane_${LANE_ID}_*/"
        fi
        if [[ $DRY_RUN -eq 1 ]]; then
            PATHSPEC_STATUS="would-register"
        elif python3 "$PATHSPEC_TOOL" register \
                --lane "$LANE_ID" \
                --files "$FILES_ARG" \
                --ttl "$TTL" \
                --lane-title "spawn-lane-worktree:$BRANCH_NAME" \
                --notes "worktree=$WORKTREE_PATH" \
                >/dev/null 2>&1; then
            PATHSPEC_STATUS="registered"
        else
            PATHSPEC_RC=$?
            PATHSPEC_STATUS="register-failed"
            echo "[$SCRIPT_NAME] ERROR: pathspec registration failed (rc=$PATHSPEC_RC)" >&2
            # Don't tear down the worktree - operator may still want it.
            exit 3
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Emit result
# ---------------------------------------------------------------------------

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
    'base_sha': '$BASE_SHA',
    'short_sha': '$SHORT_SHA',
    'provisioned': bool($PROVISIONED),
    'pre_existing': bool($PRE_EXISTING),
    'empty_diff_cleaned': bool($EMPTY_DIFF_CLEANED),
    'pathspec_status': '$PATHSPEC_STATUS',
    'pathspec_rc': $PATHSPEC_RC,
    'cooldown_status': '$COOLDOWN_STATUS',
    'cooldown_verdict': '$COOLDOWN_VERDICT',
    'cooldown_rc': $COOLDOWN_RC,
    'cooldown_context_pack_id': '$COOLDOWN_CONTEXT_PACK_ID',
    'cooldown_context_pack_hash': '$COOLDOWN_CONTEXT_PACK_HASH',
    'cooldown_workspace_path': '$COOLDOWN_WORKSPACE_PATH',
    'dry_run': bool($DRY_RUN),
}, sort_keys=True))
"
else
    # Default: print just the path so callers can capture it via shell substitution.
    echo "$WORKTREE_PATH"
    {
        echo "[$SCRIPT_NAME] lane=$LANE_ID branch=$BRANCH_NAME base=$BASE_BRANCH@$SHORT_SHA"
        echo "[$SCRIPT_NAME] worktree=$WORKTREE_PATH provisioned=$PROVISIONED pre_existing=$PRE_EXISTING cleaned=$EMPTY_DIFF_CLEANED"
        echo "[$SCRIPT_NAME] pathspec=$PATHSPEC_STATUS"
        echo "[$SCRIPT_NAME] cooldown=$COOLDOWN_STATUS verdict=$COOLDOWN_VERDICT context_pack_id=$COOLDOWN_CONTEXT_PACK_ID"
    } >&2
fi

if [[ $EMPTY_DIFF_CLEANED -eq 1 ]] && [[ $PROVISIONED -eq 0 ]]; then
    # Special return: caller asked for empty-diff cleanup; we removed but
    # did not re-provision. Re-invoke this script to reprovision.
    # We treat this as exit 5 so callers can detect it; the worktree path
    # was already emitted. To keep workflows simple, we DO re-provision
    # below.
    if [[ $DRY_RUN -eq 0 ]]; then
        git worktree add -b "$BRANCH_NAME" "$WORKTREE_PATH" "$BASE_SHA" >/dev/null 2>&1 || true
    fi
fi

exit 0
