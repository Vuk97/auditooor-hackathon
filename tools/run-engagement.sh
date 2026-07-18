#!/usr/bin/env bash
# run-engagement.sh — legacy interactive bootstrap helper.
#
# Canonical day-to-day orchestration now lives in:
#   make engage WORKSPACE=<path>
#   python3 tools/engage.py --workspace <path> --stage all
#
# Usage:
#   ./tools/run-engagement.sh <project-name>
#
# Prompts the operator for 3 inputs (bounty URL, repo URL@tag, prior audits dir),
# then runs the older bootstrap/scanning flow below.
#
#   1.  setup-workspace.sh <project> ~/audits
#   2.  fetch-scope.sh <ws> <bounty-url>        (if bounty URL provided)
#   3.  write targets.tsv from the repo URL@tag
#   4.  fetch-targets.sh <ws>
#   5.  extract-oos.sh <ws>
#   6.  copy prior-audit PDFs + extract-pdfs.sh (if prior_audits_dir provided)
#   7.  orient-from-audits.sh <ws>
#   8.  skill-state.sh <ws> init
#   9.  env-check.sh <ws>
#   10. flow-gate.sh <ws>
#   11. apply-patterns.sh <ws>
#   12. scan.sh <ws>   →   time-engagement.sh <ws> scan_complete
#
# Every step's stdout+stderr is teed to <ws>/engagement_run.log.
# On any hard failure, exits with an actionable error — the workspace is NOT
# torn down (operator can inspect partial state).
#
# Total UX: 1 command + 3 prompts.

set -u

PROJECT="${1:-}"
if [ -z "$PROJECT" ]; then
    echo "Usage: $0 <project-name>" >&2
    echo "Example: $0 centrifuge-v3" >&2
    exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE_ROOT="${AUDITS_DIR:-$HOME/audits}"
WS="$WORKSPACE_ROOT/$PROJECT"

# ---- 3 prompts ----
# Read from /dev/tty when available (so piping echo -e works for tests).
prompt_tty() {
    local msg="$1" var
    if [ -t 0 ]; then
        printf '%s' "$msg"
        IFS= read -r var || true
    else
        IFS= read -r var || true
    fi
    printf '%s' "$var"
}

echo "========================================"
echo "auditooor engagement kickoff: $PROJECT"
echo "========================================"
BOUNTY_URL=$(prompt_tty "Bounty URL (or blank): ")
REPO_TAG=$(prompt_tty "Target repo URL + tag (format: URL@tag): ")
PRIOR_DIR=$(prompt_tty "Prior audits dir (or blank to skip): ")

if [ -z "$REPO_TAG" ]; then
    echo "[ERROR] Target repo URL@tag is required (prompt 2)." >&2
    exit 1
fi

# Parse URL@tag. If no @ present, treat entire string as URL + tag=main.
if [[ "$REPO_TAG" == *"@"* ]]; then
    REPO_URL="${REPO_TAG%@*}"
    REPO_REF="${REPO_TAG##*@}"
else
    REPO_URL="$REPO_TAG"
    REPO_REF="main"
fi
# Derive local_name from URL basename (strip .git).
LOCAL_NAME=$(basename "$REPO_URL" .git)

mkdir -p "$WORKSPACE_ROOT"
LOG=""  # set after workspace scaffolded

# ---- logger + step runner ----
log() {
    local msg="$*"
    printf '[run-engagement] %s\n' "$msg"
    if [ -n "$LOG" ]; then printf '[run-engagement] %s\n' "$msg" >> "$LOG"; fi
}

run_step() {
    # run_step <label> <required|optional> -- <cmd...>
    local label="$1" req="$2"; shift 2
    [ "$1" = "--" ] && shift
    log "── $label ──"
    log "    \$ $*"
    local rc=0
    if [ -n "$LOG" ]; then
        # shellcheck disable=SC2068
        $@ >>"$LOG" 2>&1
        rc=$?
    else
        # shellcheck disable=SC2068
        $@
        rc=$?
    fi
    if [ "$rc" -ne 0 ]; then
        if [ "$req" = "required" ]; then
            log "[ERROR] step failed ($label) rc=$rc — see $LOG"
            echo ""
            echo "[run-engagement] HARD STOP at step: $label (rc=$rc)"
            echo "[run-engagement] log: $LOG"
            exit "$rc"
        else
            log "[WARN] optional step failed ($label) rc=$rc — continuing"
        fi
    fi
}

# ---- Step 1: setup-workspace.sh ----
if [ -e "$WS" ]; then
    echo "[ERROR] workspace already exists: $WS" >&2
    echo "        rm -rf that dir (or pick a fresh project name) before rerunning." >&2
    exit 1
fi

log "Step 1/12: setup-workspace.sh → $WS"
if ! bash "$AUDITOOOR_DIR/tools/setup-workspace.sh" "$PROJECT" "$WORKSPACE_ROOT"; then
    echo "[run-engagement] setup-workspace.sh failed" >&2
    exit 1
fi

LOG="$WS/engagement_run.log"
: > "$LOG"
log "log started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "project=$PROJECT  ws=$WS"
log "bounty_url=${BOUNTY_URL:-<none>}"
log "repo=$REPO_URL  ref=$REPO_REF  local_name=$LOCAL_NAME"
log "prior_audits_dir=${PRIOR_DIR:-<none>}"

# ---- Step 2: fetch-scope.sh (if bounty URL provided) ----
if [ -n "$BOUNTY_URL" ]; then
    run_step "Step 2/12: fetch-scope.sh" required -- bash "$AUDITOOOR_DIR/tools/fetch-scope.sh" "$WS" "$BOUNTY_URL"
else
    log "Step 2/12: fetch-scope.sh SKIPPED (no bounty URL)"
    # setup-workspace.sh now seeds a placeholder SCOPE.md. Recreate a minimal
    # fallback only for older workspaces that predate that scaffold.
    if [ ! -f "$WS/SCOPE.md" ]; then
        {
            echo "# SCOPE — $PROJECT"
            echo ""
            echo "No bounty URL supplied during run-engagement kickoff."
            echo "Paste the program's in-scope + out-of-scope + severity caps"
            echo "sections here manually before running flow-gate.sh again."
            echo ""
            for i in $(seq 1 30); do echo "(placeholder row $i)"; done
        } > "$WS/SCOPE.md"
        log "    wrote placeholder SCOPE.md (operator must fill before submission)"
    else
        log "    keeping scaffolded placeholder SCOPE.md (operator must replace before submission)"
    fi
fi

# ---- Step 3: write targets.tsv ----
log "Step 3/12: targets.tsv ← $REPO_URL\t$REPO_REF\t$LOCAL_NAME"
# Strip the template comment block setup-workspace.sh writes, then append the real row.
{
    echo "# Generated by run-engagement.sh"
    printf '%s\t%s\t%s\n' "$REPO_URL" "$REPO_REF" "$LOCAL_NAME"
} > "$WS/targets.tsv"

# ---- Step 4: fetch-targets.sh ----
run_step "Step 4/12: fetch-targets.sh" required -- bash "$AUDITOOOR_DIR/tools/fetch-targets.sh" "$WS"

# ---- Step 5: extract-oos.sh ----
run_step "Step 5/12: extract-oos.sh" optional -- bash "$AUDITOOOR_DIR/tools/extract-oos.sh" "$WS"

# ---- Step 6: copy prior-audit PDFs + extract-pdfs.sh ----
if [ -n "$PRIOR_DIR" ]; then
    if [ -d "$PRIOR_DIR" ]; then
        mkdir -p "$WS/prior_audits"
        log "Step 6/12: copying PDFs from $PRIOR_DIR → $WS/prior_audits/"
        copied=0
        for f in "$PRIOR_DIR"/*.pdf; do
            [ -f "$f" ] || continue
            cp "$f" "$WS/prior_audits/" && copied=$((copied+1))
        done
        log "    copied $copied PDF(s)"
        if [ "$copied" -gt 0 ]; then
            run_step "Step 6b/12: extract-pdfs.sh" optional -- bash "$AUDITOOOR_DIR/tools/extract-pdfs.sh" "$WS/prior_audits" "$WS/prior_audits"
        fi
    else
        log "Step 6/12: prior-audits dir not found: $PRIOR_DIR — SKIPPED"
    fi
else
    log "Step 6/12: prior-audits SKIPPED (no dir given)"
fi

# ---- Step 7: orient-from-audits.sh ----
run_step "Step 7/12: orient-from-audits.sh" optional -- bash "$AUDITOOOR_DIR/tools/orient-from-audits.sh" "$WS"

# ---- Step 8: skill-state.sh init ----
run_step "Step 8/12: skill-state.sh init" optional -- bash "$AUDITOOOR_DIR/tools/skill-state.sh" "$WS" init

# ---- Step 9: env-check.sh ----
# env-check exits 5 for non-foundry targets (soft warn). Treat any non-zero as a warn
# here because run-engagement shouldn't refuse to scan just because the repo is
# non-foundry or solc wasn't installed; scan.sh will log its own errors.
run_step "Step 9/12: env-check.sh" optional -- bash "$AUDITOOOR_DIR/tools/env-check.sh" "$WS"

# ---- Step 10: flow-gate.sh ----
# Non-strict: HARD stops exit 1, soft warns exit 0.
run_step "Step 10/12: flow-gate.sh" optional -- bash "$AUDITOOOR_DIR/tools/flow-gate.sh" "$WS"

# ---- Step 11: apply-patterns.sh ----
run_step "Step 11/12: apply-patterns.sh" optional -- bash "$AUDITOOOR_DIR/tools/apply-patterns.sh" "$WS"

# ---- Step 12: scan.sh + time-engagement.sh scan_complete ----
run_step "Step 12/12: scan.sh" required -- bash "$AUDITOOOR_DIR/tools/scan.sh" "$WS"

# Record scan_complete timing event (R47 C4 instrumentation).
if [ -x "$AUDITOOOR_DIR/tools/time-engagement.sh" ]; then
    log "    time-engagement.sh $WS scan_complete"
    bash "$AUDITOOOR_DIR/tools/time-engagement.sh" "$WS" scan_complete >> "$LOG" 2>&1 || log "[WARN] time-engagement append failed"
fi

# ---- Next-step menu ----
cat <<MENU

========================================
Engagement kickoff complete: $PROJECT
========================================
Workspace: $WS
Log:       $LOG

Next-step menu (pick one — or run them in order):

  [1] auto-triage  →  ./tools/auto-triage.sh "$WS"
        Triages SCAN_REPORT hits into confirmed / candidate / dismissed.

  [2] attack-tree  →  ./tools/attack-tree.sh "$WS"
        Builds an attack-tree.md for adversarial reading.

  [3] scope-review →  ./tools/scope-review.sh "$WS"
        Cross-refs candidate findings against SEVERITY_CAPS.md + OOS_CHECKLIST.md
        BEFORE drafting — avoids wasting writeup cycles on excluded classes.

  When you draft the first finding, record it with:
     ./tools/time-engagement.sh "$WS" draft_ready

  When you file a submission, record it with:
     ./tools/time-engagement.sh "$WS" submission_filed
========================================
MENU

exit 0
