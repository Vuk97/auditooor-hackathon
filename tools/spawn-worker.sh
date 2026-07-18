#!/usr/bin/env bash
# spawn-worker.sh - Agent-tool spawn wrapper per WF-7 #2 (iter18 Phase -1 C)
#
# Purpose: close the META-1 wiring gap on the Anthropic Agent-tool spawn
# surface that complement WF-7 #1 (dispatch-preflight auto-invoke).
# `tools/dispatch-preflight.py` already covers the LLM-provider path
# (Kimi / Minimax via `tools/llm-dispatch.py`). This wrapper covers ALL
# OTHER orchestrator paths (Claude Agent tool, raw shell, codex, etc).
#
# Responsibilities (per WF-7 §6 Change 2):
# 1. Take CLI args: lane_id, lane_type, severity, workspace, prompt-file.
# 2. Register the lane's R36/R55 pathspec BEFORE spawn (via
#    `tools/agent-pathspec-register.py register`).
# 3. Pre-fetch the META-1 brief skeleton via the
#    `vault_dispatch_brief_skeleton` MCP callable, wrapped by
#    `tools/dispatch-agent-with-prebriefing.py`.
# 4. Inject the skeleton as a Section 15a/15b/15c/15d prefix on the
#    operator-supplied prompt (the wrapper handles BEGIN/END markers
#    and graceful degradation on MCP failure).
# 5. Verify the STEP 1c BEGIN/END markers are present in the enriched
#    prompt (per HACKERMAN_WORKER_PROMPT_TEMPLATE STEP 1c).
# 6. Emit the enriched prompt to a temp file under /tmp.
# 7. Print the enriched-prompt path so the operator / orchestrator can
#    hand it to whatever spawn surface they own (Agent tool, codex CLI,
#    raw stdin, etc).
# 8. Log dispatch to `.auditooor/spawn_worker_log.jsonl` with timestamp,
#    lane_id, prompt_sha256, prebriefing_status, pathspec_status.
#
# Override / bypass flags (mirror dispatch-preflight.py discipline):
#  --no-register      Skip pathspec registration (warn-only). Use when
#                     the operator has already registered the lane via
#                     another mechanism.
#  --no-prebriefing   Skip META-1 prefetch (emit raw prompt). Logs the
#                     bypass with reason from $SPAWN_WORKER_BYPASS_REASON.
#  --strict-markers   Hard-fail if BEGIN/END markers are missing (default
#                     is warn-only so MCP-degraded paths still spawn).
#  --use-worktree     STRUCTURAL R36 fix: provision a per-lane git worktree
#                     under /tmp via tools/spawn-lane-worktree.sh. Sibling
#                     lanes physically cannot stomp each other because
#                     they work in different directories. The enriched-
#                     prompt log line carries the worktree_path so the
#                     spawning orchestrator knows where to cd the agent.
#                     Auto-default ON for hunt/drill/comp lane types and
#                     OFF for tool-build lanes. Explicit overrides win.
#                     (Phase -1 PER-LANE-WORKTREE, 2026-05-23.)
#  --no-use-worktree   Explicitly disable per-lane worktree provisioning
#                     even when the lane-type default would enable it.
#  --worktree-base-branch <name>  Base branch for the per-lane worktree
#                     (default: main). Only meaningful with --use-worktree.
#  --dry-run          Compose + log but do NOT emit prompt path; prints
#                     `[DRY-RUN]` summary instead.
#  --json             Emit summary as JSON instead of human-readable text.
#  --inject-prior-lanes
#                     CAPABILITY-GAP-2: auto-invoke tools/lib/prior_lane_scan.py
#                     and append a "STEP 1.5 - Prior-Lane Scan" section to the
#                     enriched prompt. Default ON for hunt|drill|comp lane
#                     types; off for tool-build / infrastructure lanes.
#                     Use --no-inject-prior-lanes to force-off.
#  --no-inject-prior-lanes
#                     Force-disable prior-lane scan injection regardless of
#                     lane type.
#  --hypothesis-keywords <str>
#                     CAPABILITY-GAP-2: keywords for the prior-lane scan
#                     (comma- or whitespace-separated). If omitted, the
#                     wrapper auto-extracts hypothesis keywords from the
#                     prompt file (best-effort: looks for lines beginning
#                     with "Hypothesis:" / "Hypothesis keywords:" /
#                     "Goal:"). Empty keyword set = skip scan with warn.
#  --no-auto-markers  Disable auto-injection of hacker-mcp-rebuttal /
#                     r64-rebuttal / r57-rebuttal HTML-comment markers at
#                     the TOP of the enriched brief. Markers are only auto-
#                     injected for tool-build|corpus|docs|cleanup|infra
#                     lane types (never for hunt|drill|dispute|mediation|
#                     triager-response|rebuttal|filing). Use this flag for
#                     explicit testing or when the prompt already carries
#                     the markers.
#  --help             Print this help.
#
# Environment knobs:
#  SPAWN_WORKER_BYPASS_REASON  Required when --no-prebriefing is set.
#  SPAWN_WORKER_LOG_PATH       Override audit log path (default:
#                              <repo>/.auditooor/spawn_worker_log.jsonl).
#  SPAWN_WORKER_TMP_DIR        Override prompt-tempfile dir (default: /tmp).
#  AUDITOOOR_MCP_SESSION_TOKEN The MCP session token (set by Layer-1
#                              recall). Forwarded to the prebriefing
#                              subprocess if present.
#  AUDITOOOR_SPAWN_WORKER_OK   Set by this wrapper for child dispatch hooks
#                              so direct Agent dispatch can prove it came
#                              through spawn-worker.sh.
#  SPAWN_WORKER_GAP29_DISABLE  Set to 1 to disable the Gap #29 hunt-phase
#                              ordering precondition check (audit-complete
#                              marker freshness for hunt/drill/comp/
#                              opposed-trace-harness/escalation/dispute
#                              lanes at MEDIUM+ severity). Emergency
#                              bypass; logged in spawn_worker_log.jsonl
#                              as gap29_status=disabled-by-env.
#  SPAWN_WORKER_G13_STRICT     Set to 1 to promote the G13.2 full-tier-
#                              coverage gate (Step 3.7) from WARN-only to
#                              hard-fail (exit 7) when the enriched brief
#                              for a hunt-class lane omits a fileable
#                              SEVERITY.md tier or lacks a 'hunt every tier'
#                              directive. Default is WARN-only.
#
# Exit codes:
#  0  success - enriched prompt path printed to stdout
#  1  bad CLI arg / missing required arg
#  2  pathspec registration failed and --no-register not set
#  3  prebriefing failed AND --strict-markers set (otherwise warn-only)
#  4  cannot write enriched prompt to tmp dir
#  5  log write failed (non-fatal warning unless strict)
#  6  Gap #29 hunt-phase ordering refused spawn (stale or missing audit-
#     complete marker for hunt/drill/comp/escalation/dispute lane at
#     MEDIUM+); bypass with prompt-file gap29-rebuttal marker or
#     SPAWN_WORKER_GAP29_DISABLE=1
#  7  G13.2 full-tier-coverage refused spawn (enriched brief omits a
#     fileable SEVERITY.md tier or lacks a 'hunt every tier' directive for
#     a hunt-class lane) AND SPAWN_WORKER_G13_STRICT=1. Default is WARN-only
#     (no refusal). Bypass with a `<!-- g13-rebuttal: <reason> -->` marker
#     in the brief.
#
# Tests: tools/tests/test_spawn_worker.py

set -uo pipefail

# ---------------------------------------------------------------------------
# Globals (resolve repo root)
# ---------------------------------------------------------------------------

SPAWN_WORKER_SCRIPT="${BASH_SOURCE[0]}"
SPAWN_WORKER_DIR="$(cd "$(dirname "$SPAWN_WORKER_SCRIPT")" >/dev/null 2>&1 && pwd)"
# REPO_ROOT must be the auditooor-mcp repo where the tools + the canonical
# .auditooor/spawn_worker_log.jsonl live - derived from THIS SCRIPT's location, NOT
# the CWD git root. spawn-worker is invoked cross-worktree (orchestrator cwd != audit
# workspace, by design - L16). A CWD-relative `git rev-parse --show-toplevel` resolves
# to the AUDIT WORKSPACE, which (a) has no tools/ so every enrichment step silently
# reports "tool-missing", and (b) has a DIFFERENT .auditooor/spawn_worker_log.jsonl
# than the enforcement hook reads (it reads <auditooor-mcp>/.auditooor/...). The net
# effect: every cross-worktree dispatch logged to the wrong file and was then wrongly
# BLOCKED by the spawn-worker enforcement hook. Resolve from the script's own dir
# (the repo's tools/ dir) so CWD is irrelevant; fall back to git/pwd only if the
# layout is unexpected.
if [ "$(basename "$SPAWN_WORKER_DIR")" = "tools" ]; then
  REPO_ROOT="$(cd "${SPAWN_WORKER_DIR}/.." >/dev/null 2>&1 && pwd)"
else
  REPO_ROOT="$(git -C "$SPAWN_WORKER_DIR" rev-parse --show-toplevel 2>/dev/null || echo "$SPAWN_WORKER_DIR")"
fi

PREBRIEFING_TOOL="${REPO_ROOT}/tools/dispatch-agent-with-prebriefing.py"
PATHSPEC_TOOL="${REPO_ROOT}/tools/agent-pathspec-register.py"
WORKTREE_TOOL="${REPO_ROOT}/tools/spawn-lane-worktree.sh"
PRIOR_LANE_SCAN_TOOL="${REPO_ROOT}/tools/lib/prior_lane_scan.py"
GAP29_PHASE_ORDER_TOOL="${REPO_ROOT}/tools/hunt-phase-ordering-check.py"
# G13.2: full-tier-coverage gate on the POST-enrichment brief.
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].
G13_TIER_COVERAGE_TOOL="${REPO_ROOT}/tools/hunt-brief-full-tier-coverage-check.py"
DEFAULT_LOG_PATH="${REPO_ROOT}/.auditooor/spawn_worker_log.jsonl"

SCHEMA="auditooor.spawn_worker.v1"

# ---------------------------------------------------------------------------
# Args
# ---------------------------------------------------------------------------

LANE_ID=""
LANE_TYPE=""
SEVERITY=""
WORKSPACE=""
PROMPT_FILE=""
PATHSPEC_FILES=""
NO_REGISTER=0
NO_PREBRIEFING=0
STRICT_MARKERS=0
# USE_WORKTREE tri-state: -1 = auto, 0 = explicit off, 1 = explicit on.
USE_WORKTREE=-1
WORKTREE_BASE_BRANCH="main"
DRY_RUN=0
JSON_OUTPUT=0
# CAPABILITY-GAP-2 (2026-05-25): prior-lane scan injection.
# INJECT_PRIOR_LANES tri-state: -1 = auto (default-on for hunt/drill/comp),
# 0 = force-off, 1 = force-on.
INJECT_PRIOR_LANES=-1
HYPOTHESIS_KEYWORDS=""
NO_AUTO_MARKERS=0
# BRIEF-KIND GATING (2026-07-12): auto|tooling|hunt. A tooling/concrete-fix
# brief passes through RAW (no vulnerability-HUNT template wrap) and takes the
# FAST path (no bypass-reason requirement, no slow G13 full-tier-coverage gate).
BRIEF_KIND="auto"

print_help() {
    sed -n '2,60p' "$SPAWN_WORKER_SCRIPT"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --lane-id) LANE_ID="$2"; shift 2 ;;
        --lane-type) LANE_TYPE="$2"; shift 2 ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        --workspace) WORKSPACE="$2"; shift 2 ;;
        --prompt-file) PROMPT_FILE="$2"; shift 2 ;;
        --pathspec-files) PATHSPEC_FILES="$2"; shift 2 ;;
        --no-register) NO_REGISTER=1; shift ;;
        --no-prebriefing) NO_PREBRIEFING=1; shift ;;
        --strict-markers) STRICT_MARKERS=1; shift ;;
        --use-worktree) USE_WORKTREE=1; shift ;;
        --no-use-worktree) USE_WORKTREE=0; shift ;;
        --worktree-base-branch) WORKTREE_BASE_BRANCH="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --json) JSON_OUTPUT=1; shift ;;
        --inject-prior-lanes) INJECT_PRIOR_LANES=1; shift ;;
        --no-inject-prior-lanes) INJECT_PRIOR_LANES=0; shift ;;
        --hypothesis-keywords) HYPOTHESIS_KEYWORDS="$2"; shift 2 ;;
        --no-auto-markers) NO_AUTO_MARKERS=1; shift ;;
        --brief-kind) BRIEF_KIND="$2"; shift 2 ;;
        --help|-h) print_help; exit 0 ;;
        *)
            echo "[spawn-worker] ERROR: unknown arg: $1" >&2
            echo "[spawn-worker] run --help for usage." >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

require_arg() {
    local name="$1"; local val="$2"
    if [[ -z "$val" ]]; then
        echo "[spawn-worker] ERROR: missing required arg --$name" >&2
        exit 1
    fi
}

require_arg lane-id "$LANE_ID"
require_arg lane-type "$LANE_TYPE"
require_arg severity "$SEVERITY"
require_arg workspace "$WORKSPACE"
require_arg prompt-file "$PROMPT_FILE"

if [[ ! -f "$PROMPT_FILE" ]]; then
    echo "[spawn-worker] ERROR: prompt-file does not exist: $PROMPT_FILE" >&2
    exit 1
fi

# UNEXPANDED-COMMAND-SUBSTITUTION LINT (2026-07-07, Strata Midas cascade): an agent
# authoring a sub-dispatch tried to inline a file's content with $(cat ...) inside
# an Agent prompt string, but Agent prompts are NOT shell-evaluated, so the sub-
# agent received the LITERAL text "$(cat /tmp/....md)" instead of the brief and got
# stuck asking for the real content. A prompt-file that itself contains a literal
# `$(cat ` / `$(< ` / backtick-cat is that exact foot-gun. Advisory WARN (fail-open:
# some briefs legitimately quote a shell example) unless AUDITOOOR_SPAWN_SUBST_STRICT.
if grep -qE '\$\(cat |\$\(< |`cat ' "$PROMPT_FILE" 2>/dev/null; then
    _SUBST_HIT=$(grep -nE '\$\(cat |\$\(< |`cat ' "$PROMPT_FILE" 2>/dev/null | head -3)
    if [[ "${AUDITOOOR_SPAWN_SUBST_STRICT:-0}" == "1" ]]; then
        echo "[spawn-worker] ERROR: prompt-file contains an UNEXPANDED command-substitution (\$(cat ...)). Agent prompts are NOT shell-evaluated - the worker will receive the LITERAL text, not the file content. Read the file and paste its content, or pass the file PATH and tell the worker to Read it." >&2
        echo "$_SUBST_HIT" | sed 's/^/    /' >&2
        exit 1
    fi
    echo "[spawn-worker] WARN: prompt-file contains a literal \$(cat ...)/backtick-cat command-substitution; Agent prompts are NOT shell-evaluated so the worker gets the LITERAL text, not the file content. Read+paste the content or pass the file PATH for the worker to Read." >&2
    echo "$_SUBST_HIT" | sed 's/^/    /' >&2
fi

# ---------------------------------------------------------------------------
# SCOPE-OOS DISPATCH GUARD (2026-07-05). Refuse to dispatch a prompt/batch that
# targets OUT-OF-SCOPE units per the target workspace's SCOPE.md OOS carve-outs
# (driven by tools/lib/scope_oos_globs.py). Advisory-first, matching the META-1
# bypass pattern: an override marker (<ws>/.auditooor/scope_oos_dispatch_override)
# or SPAWN_WORKER_BYPASS_REASON warns-and-continues. FAIL-OPEN when the guard tool
# is missing or when SCOPE.md has no OOS section (guard prints pass-no-oos-in-batch,
# rc=0). Only BLOCKS when the guard confidently finds an OOS unit.
_SCOPE_OOS_GUARD="${REPO_ROOT}/tools/scope-oos-dispatch-guard.py"
if [[ -f "$_SCOPE_OOS_GUARD" ]] && [[ -d "$WORKSPACE" ]]; then
    if "${PY:-python3}" "$_SCOPE_OOS_GUARD" \
            --workspace "$WORKSPACE" --batch "$PROMPT_FILE" >/dev/null 2>/tmp/spawn_oos_guard.$$; then
        :  # rc=0: no OOS units (or allowed) - proceed
    else
        cat /tmp/spawn_oos_guard.$$ >&2 || true
        if [[ -f "$WORKSPACE/.auditooor/scope_oos_dispatch_override" ]] \
                || [[ -n "${SPAWN_WORKER_BYPASS_REASON:-}" ]]; then
            _why="${SPAWN_WORKER_BYPASS_REASON:-override marker present}"
            echo "[spawn-worker] WARN: SCOPE-OOS-DISPATCH-GUARD flagged OOS unit(s); continuing (bypass: $_why)" >&2
        else
            echo "[spawn-worker] ERROR: SCOPE-OOS-DISPATCH-GUARD blocked dispatch - prompt-file targets OUT-OF-SCOPE units per $WORKSPACE/SCOPE.md." >&2
            echo "[spawn-worker] remediation: remove the OOS units from the batch, OR set SPAWN_WORKER_BYPASS_REASON=<reason>, OR touch $WORKSPACE/.auditooor/scope_oos_dispatch_override" >&2
            rm -f /tmp/spawn_oos_guard.$$ 2>/dev/null || true
            exit 1
        fi
    fi
    rm -f /tmp/spawn_oos_guard.$$ 2>/dev/null || true
fi

# Validate severity
case "$SEVERITY" in
    LOW|MEDIUM|HIGH|CRITICAL) ;;
    *)
        echo "[spawn-worker] ERROR: severity must be LOW|MEDIUM|HIGH|CRITICAL (got: $SEVERITY)" >&2
        exit 1
        ;;
esac

# Validate lane-type
# r36-rebuttal: lane GAP-FIX-1-gap42 declared in agent_pathspec.json via tools/agent-pathspec-register.py
case "$LANE_TYPE" in
    dispute|mediation|filing|hunt|opposed-trace-harness|escalation|capability|wire-audit|tool-build|infra) ;;
    *)
        echo "[spawn-worker] WARN: non-canonical lane-type '$LANE_TYPE' (canonical: dispute|mediation|filing|hunt|opposed-trace-harness|escalation|capability|wire-audit|tool-build|infra); proceeding" >&2
        ;;
esac

# BRIEF-KIND RESOLUTION (2026-07-12). Validate + resolve auto -> tooling|hunt.
# A tooling lane-type (tool-build/infra/capability/wire-audit/corpus/docs/cleanup)
# under --brief-kind auto resolves to tooling; otherwise hunt. An explicit
# --brief-kind wins. RESOLVED_TOOLING=1 => FAST raw pass-through: no hunt template,
# no SPAWN_WORKER_BYPASS_REASON requirement, no slow G13 gate.
case "$BRIEF_KIND" in
    auto|tooling|hunt) ;;
    *)
        echo "[spawn-worker] ERROR: --brief-kind must be auto|tooling|hunt (got: $BRIEF_KIND)" >&2
        exit 1
        ;;
esac
RESOLVED_TOOLING=0
if [[ "$BRIEF_KIND" == "tooling" ]]; then
    RESOLVED_TOOLING=1
elif [[ "$BRIEF_KIND" == "auto" ]]; then
    case "$LANE_TYPE" in
        tool-build|infra|capability|wire-audit|corpus|docs|cleanup) RESOLVED_TOOLING=1 ;;
    esac
fi

# A tooling/concrete-fix brief passes through RAW (like --no-prebriefing) but on
# the FAST path: it does NOT require SPAWN_WORKER_BYPASS_REASON (fix c). The raw
# copy still routes through the prebriefing tool with --brief-kind tooling so the
# synthetic-system-tag scrubber runs (fix a) without any hunt-template wrap.
if [[ $NO_PREBRIEFING -eq 1 ]] && [[ $RESOLVED_TOOLING -eq 0 ]] && [[ -z "${SPAWN_WORKER_BYPASS_REASON:-}" ]]; then
    echo "[spawn-worker] ERROR: --no-prebriefing requires SPAWN_WORKER_BYPASS_REASON env var (or use --brief-kind tooling for a fast raw concrete-fix dispatch)" >&2
    exit 1
fi

LOG_PATH="${SPAWN_WORKER_LOG_PATH:-$DEFAULT_LOG_PATH}"
TMP_DIR="${SPAWN_WORKER_TMP_DIR:-/tmp}"
mkdir -p "$TMP_DIR" 2>/dev/null || true

# Resolve per-lane worktree default unless the operator explicitly overrode it.
if [[ $USE_WORKTREE -eq -1 ]]; then
    case "$LANE_TYPE" in
        drill|comp) USE_WORKTREE=1 ;;
        *) USE_WORKTREE=0 ;;
    esac
fi

# SHARED-BUILD COLLISION WARNING (codified 2026-06-23). hunt/drill/comp lanes
# auto-default to worktree ISOLATION precisely because parallel harness/PoC
# authoring shares ONE build (forge/cargo/go compile the whole project): a single
# broken sibling file fails EVERY sibling's baseline, and agents chase phantom
# failures that are not their own. If a harness-authoring lane EXPLICITLY disabled
# isolation (USE_WORKTREE==0 despite the comp/hunt/drill auto-default of 1), warn
# LOUDLY so the operator either restores isolation or serializes integrate-then-
# verify. Warn-only (a single solo lane is safe); see step4b-genuine-coverage-generic-playbook.
case "$LANE_TYPE" in
    drill|comp)
        if [[ $USE_WORKTREE -eq 0 ]]; then
            echo "[spawn-worker] WARNING: lane '$LANE_ID' (type=$LANE_TYPE) authoring in the SHARED workspace tree (--no-use-worktree). If other $LANE_TYPE lanes run concurrently, ONE broken harness/PoC fails the shared build for ALL of them (collision -> phantom baseline failures). Prefer worktree isolation, or serialize integrate-then-verify, or verify each artifact under a clean build (forge-build-readiness)." >&2
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# Step 0a: Stale per-lane worktree GC (disk-leak guard)
# ---------------------------------------------------------------------------
# r36-rebuttal: lane L37-SPAWN-WORKER-WORKTREE-PRUNE registered in .auditooor/agent_pathspec.json
# Each hunt lane provisions a FULL ~2.4G checkout under /tmp/auditooor-lane-*;
# left unpruned they accumulate and fill the disk (observed: 32 dirs -> 100% on a
# 460G volume -> silent sidecar-write failures). Before provisioning a new one,
# remove lane worktrees older than the TTL (default 6h; 0 disables). Bounded to
# /tmp/auditooor-lane-* and only stale ones, so active sibling lanes are safe.
prune_stale_lane_worktrees() {
    local ttl_h="${AUDITOOOR_LANE_WORKTREE_TTL_HOURS:-6}"
    [[ "$ttl_h" =~ ^[0-9]+$ ]] || ttl_h=6
    [[ "$ttl_h" -eq 0 ]] && return 0
    local base="${SPAWN_WORKER_TMP_DIR:-/tmp}"
    command -v git >/dev/null 2>&1 || return 0
    [[ -d "$REPO_ROOT/.git" || -f "$REPO_ROOT/.git" ]] || return 0
    local ttl_min=$(( ttl_h * 60 ))
    local d
    # find lane worktrees older than ttl (mtime), remove via git then hard rm.
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        git -C "$REPO_ROOT" worktree remove --force "$d" >/dev/null 2>&1 || true
        rm -rf "$d" >/dev/null 2>&1 || true
    done < <(find -L "$base" -maxdepth 1 -type d -name 'auditooor-lane-*' -mmin "+${ttl_min}" 2>/dev/null)
    git -C "$REPO_ROOT" worktree prune >/dev/null 2>&1 || true
}
prune_stale_lane_worktrees

# ---------------------------------------------------------------------------
# Step 0: Per-lane worktree provisioning (optional structural R36 fix)
# ---------------------------------------------------------------------------

WORKTREE_PATH=""
WORKTREE_STATUS="not-requested"
WORKTREE_RC=0

if [[ $USE_WORKTREE -eq 1 ]]; then
    if [[ ! -x "$WORKTREE_TOOL" ]]; then
        WORKTREE_STATUS="tool-missing"
        echo "[spawn-worker] WARN: worktree tool missing at $WORKTREE_TOOL; falling back to shared worktree" >&2
    else
        WORKTREE_PATH=$("$WORKTREE_TOOL" \
            --lane-id "$LANE_ID" \
            --base-branch "$WORKTREE_BASE_BRANCH" \
            2>>"${SPAWN_WORKER_TMP_DIR:-/tmp}/spawn-worker-worktree-${LANE_ID}.log")
        WORKTREE_RC=$?
        if [[ $WORKTREE_RC -eq 0 ]] && [[ -n "$WORKTREE_PATH" ]] && [[ -d "$WORKTREE_PATH" ]]; then
            WORKTREE_STATUS="provisioned"
        else
            WORKTREE_STATUS="provision-failed"
            echo "[spawn-worker] ERROR: per-lane worktree provisioning failed (rc=$WORKTREE_RC)" >&2
            if [[ $STRICT_MARKERS -eq 1 ]]; then
                exit 2
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 1: Pathspec registration (R36 + R55 prereq)
# ---------------------------------------------------------------------------

PATHSPEC_STATUS="skipped"
PATHSPEC_RC=0

if [[ $NO_REGISTER -eq 0 ]]; then
    if [[ ! -f "$PATHSPEC_TOOL" ]]; then
        echo "[spawn-worker] WARN: pathspec tool missing at $PATHSPEC_TOOL; skipping registration" >&2
        PATHSPEC_STATUS="tool-missing"
    else
        # If --pathspec-files not provided, fall back to a concrete workspace-
        # local anchor file. R36/R55 require exact file matches; globs are
        # rejected by the helper. Create the anchor lazily so registration
        # always has a literal path to store.
        FILES_ARG="$PATHSPEC_FILES"
        if [[ -z "$FILES_ARG" ]]; then
            SAFE_LANE_ID=$(printf '%s' "$LANE_ID" | tr -cs 'A-Za-z0-9._-' '_')
            if [[ -z "$SAFE_LANE_ID" ]]; then
                SAFE_LANE_ID="lane"
            fi
            PATHSPEC_ANCHOR_DIR="${WORKSPACE}/.auditooor/spawn-worker-pathspec/lane_${SAFE_LANE_ID}"
            PATHSPEC_ANCHOR_FILE="${PATHSPEC_ANCHOR_DIR}/anchor.txt"
            mkdir -p "$PATHSPEC_ANCHOR_DIR" 2>/dev/null || true
            : > "$PATHSPEC_ANCHOR_FILE" 2>/dev/null || true
            FILES_ARG="$PATHSPEC_ANCHOR_FILE"
        fi
        # Register; capture rc but don't fail unless registration explicitly fails.
        if python3 "$PATHSPEC_TOOL" register --lane "$LANE_ID" --files "$FILES_ARG" --ttl 7200 --lane-title "spawn-worker:$LANE_TYPE:$SEVERITY" >&2; then
            PATHSPEC_STATUS="registered"
        else
            PATHSPEC_RC=$?
            PATHSPEC_STATUS="register-failed"
            echo "[spawn-worker] ERROR: pathspec registration failed (rc=$PATHSPEC_RC)" >&2
            if [[ $STRICT_MARKERS -eq 1 ]]; then
                exit 2
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 1.5: Gap #29 hunt-phase ordering precondition (GAP-INTEG-1)
# ---------------------------------------------------------------------------
# For hunt / opposed-trace-harness / escalation / dispute / drill / comp
# lanes at MEDIUM+ severity, refuse spawn when `make audit` has not been
# run for the workspace (no .auditooor/last_audit_complete_marker) OR the
# marker is stale relative to docs/LIVE_TARGET_REPORT.md. Drills firing
# on stale audit state pursue stale hypotheses.
#
# Bypass:
#   - prompt-file contains `<!-- gap29-rebuttal: <reason> -->` or the
#     visible bounded line `gap29-rebuttal: <reason>` (<=200 chars).
#   - env SPAWN_WORKER_GAP29_DISABLE=1 (emergency bypass, audit-logged).

GAP29_STATUS="skipped"
GAP29_VERDICT=""
GAP29_RC=0

_GAP29_GATED_LANE_TYPE=0
case "$LANE_TYPE" in
    hunt|opposed-trace-harness|escalation|dispute|drill|comp|composition) _GAP29_GATED_LANE_TYPE=1 ;;
esac

_GAP29_GATED_SEVERITY=0
case "$SEVERITY" in
    MEDIUM|HIGH|CRITICAL) _GAP29_GATED_SEVERITY=1 ;;
esac

if [[ "${SPAWN_WORKER_GAP29_DISABLE:-}" == "1" ]]; then
    GAP29_STATUS="disabled-by-env"
elif [[ "$_GAP29_GATED_LANE_TYPE" -eq 0 ]]; then
    GAP29_STATUS="skipped-lane-type-not-gated"
elif [[ "$_GAP29_GATED_SEVERITY" -eq 0 ]]; then
    GAP29_STATUS="skipped-severity-below-medium"
elif [[ ! -f "$GAP29_PHASE_ORDER_TOOL" ]]; then
    GAP29_STATUS="tool-missing"
    echo "[spawn-worker] WARN: Gap #29 phase-ordering tool missing at $GAP29_PHASE_ORDER_TOOL" >&2
else
    _GAP29_JSON=$(python3 "$GAP29_PHASE_ORDER_TOOL" \
        --workspace "$WORKSPACE" \
        --lane-id "$LANE_ID" \
        --lane-type "$LANE_TYPE" \
        --prompt-file "$PROMPT_FILE" \
        --json 2>/dev/null)
    GAP29_RC=$?
    GAP29_VERDICT=$(printf '%s' "$_GAP29_JSON" | python3 -c "import json,sys
try:
    d=json.loads(sys.stdin.read())
    print(d.get('verdict',''))
except Exception:
    pass" 2>/dev/null)
    if [[ "$GAP29_RC" -eq 0 ]]; then
        GAP29_STATUS="pass:${GAP29_VERDICT}"
    else
        GAP29_STATUS="fail:${GAP29_VERDICT}"
        echo "[spawn-worker] ERROR: Gap #29 phase-ordering refused spawn (verdict=$GAP29_VERDICT)" >&2
        echo "[spawn-worker] ERROR: remediation: run \`make audit WS=$WORKSPACE\` OR add \`<!-- gap29-rebuttal: <reason up to 200 chars> -->\` to prompt-file" >&2
        # Append a diagnostic record then exit 6 (new code for Gap #29 refusal).
        if [[ -n "$_GAP29_JSON" ]]; then
            echo "$_GAP29_JSON" >&2
        fi
        # Audit-log the refusal before exiting.
        TS_REFUSE=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
        REFUSE_ROW=$(python3 -c "
import json
row = {
    'ts': '$TS_REFUSE',
    'tool': 'spawn-worker.sh',
    'schema': '$SCHEMA',
    'lane_id': '$LANE_ID',
    'lane_type': '$LANE_TYPE',
    'severity': '$SEVERITY',
    'workspace': '$WORKSPACE',
    'prompt_file': '$PROMPT_FILE',
    'gap29_status': '$GAP29_STATUS',
    'gap29_verdict': '$GAP29_VERDICT',
    'gap29_rc': $GAP29_RC,
    'refused': True,
}
print(json.dumps(row, sort_keys=True))
" 2>/dev/null)
        if [[ -n "$REFUSE_ROW" ]]; then
            mkdir -p "$(dirname "$LOG_PATH")" 2>/dev/null || true
            echo "$REFUSE_ROW" >> "$LOG_PATH" 2>/dev/null || true
        fi
        exit 6
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: META-1 prebriefing prefetch
# ---------------------------------------------------------------------------

ENRICHED_FILE="${TMP_DIR}/spawn_worker_${LANE_ID}_$$_enriched.md"
PREBRIEFING_STATUS="skipped"
PREBRIEFING_RC=0
BEGIN_MARKER_COUNT=0
END_MARKER_COUNT=0

if [[ $NO_PREBRIEFING -eq 1 ]]; then
    PREBRIEFING_STATUS="bypassed:${SPAWN_WORKER_BYPASS_REASON:-no-reason}"
    cp "$PROMPT_FILE" "$ENRICHED_FILE"
elif [[ ! -f "$PREBRIEFING_TOOL" ]]; then
    PREBRIEFING_STATUS="tool-missing"
    cp "$PROMPT_FILE" "$ENRICHED_FILE"
    echo "[spawn-worker] WARN: prebriefing tool missing at $PREBRIEFING_TOOL; emitting raw prompt" >&2
else
    if AUDITOOOR_SPAWN_WORKER_OK=1 \
            AUDITOOOR_SPAWN_WORKER_LANE_ID="$LANE_ID" \
            AUDITOOOR_SPAWN_WORKER_LOG_PATH="$LOG_PATH" \
            AUDITOOOR_SPAWN_WORKER_SCRIPT="$SPAWN_WORKER_SCRIPT" \
            python3 "$PREBRIEFING_TOOL" \
            --prompt-file "$PROMPT_FILE" \
            --lane-type "$LANE_TYPE" \
            --severity "$SEVERITY" \
            --workspace "$WORKSPACE" \
            --brief-kind "$BRIEF_KIND" \
            > "$ENRICHED_FILE" 2>/dev/null; then
        if [[ $RESOLVED_TOOLING -eq 1 ]]; then
            PREBRIEFING_STATUS="tooling-raw"
        else
            PREBRIEFING_STATUS="real"
        fi
    else
        PREBRIEFING_RC=$?
        PREBRIEFING_STATUS="fallback-degraded"
        # The wrapper emits a warn-stub block even on MCP failure; the file
        # should still contain content. But if it's empty, fall back to raw.
        if [[ ! -s "$ENRICHED_FILE" ]]; then
            cp "$PROMPT_FILE" "$ENRICHED_FILE"
            PREBRIEFING_STATUS="failed-raw-fallback"
        fi
        echo "[spawn-worker] WARN: prebriefing degraded (rc=$PREBRIEFING_RC, status=$PREBRIEFING_STATUS)" >&2
    fi
fi

if [[ ! -f "$ENRICHED_FILE" ]]; then
    echo "[spawn-worker] ERROR: failed to write enriched prompt to $ENRICHED_FILE" >&2
    exit 4
fi

# ---------------------------------------------------------------------------
# Step 2.6: EXECUTE-DIRECTLY / cwd-disambiguation banner (anti-redelegation)
# ---------------------------------------------------------------------------
# PROBLEM (operator-observed 2026-07-06, SEI OCC-scheduler lane): a dispatched
# worker, seeing a cross-worktree process cwd (orchestrator cwd != audit ws, BY
# DESIGN) unrelated to the audit workspace, BAILED on the assignment and spun up
# its own unmanaged nested agent / git worktree instead of executing the brief -
# burning the whole dispatch (3 tool-uses, zero result). Every enriched brief now
# opens with a standing banner telling the worker it IS the worker, must execute
# directly (no re-delegation / no self-spawned worktree), and that its ONLY
# working directory is $WORKSPACE regardless of process cwd. Injected BEFORE the
# Step 3.6 marker prepend so auto-markers stay at the very top for non-hunt lanes
# (the marker step prepends above this banner). Text carries no tool-path / rule
# citation shapes, so it never trips the universal-rule-enforce claim detector.
EXEC_BANNER_STATUS="skipped"
if [[ "${SPAWN_WORKER_NO_EXEC_BANNER:-0}" != "1" ]]; then
    _EXEC_BANNER_TMP="${TMP_DIR}/spawn_worker_${LANE_ID}_$$_execbanner.md"
    {
        printf '%s\n' '<!-- spawn-worker execute-directly banner (anti-redelegation) -->'
        printf '%s\n' 'YOU ARE THE WORKER FOR THIS LANE. Execute this brief DIRECTLY with your own tools - do NOT spawn another agent, create a git worktree, or re-delegate; do the work yourself and return real results.'
        printf '%s\n' "VERIFY-THEN-WORK: your workspace for this lane is ${WORKSPACE}. It is a real on-disk workspace - confirm it yourself (ls it: it has a source tree and a live .auditooor/ audit-state dir). Your process working directory may point at a different repository; that is expected for a cross-worktree dispatch - cd to ${WORKSPACE} and work there."
        printf '%s\n' 'If a tool the brief names is not loaded yet, load it and continue rather than stopping.'
        printf '%s\n' "MOCK-FAITHFULNESS: if your PoC/harness needs to mock an external protocol dependency, FIRST grep the workspace for a shipped reference (find <ws> -path '*/test/*' -iname 'Mock*.sol'). If one exists for that dependency, IMPORT and reuse it - it is the protocol team's authoritative behavior model. Do NOT roll your own mock from the interface NatSpec read literally; a rolled-own mock that diverges from the shipped reference produces false positives (a whole campaign can pass on an unfaithful harness). Only re-implement if the reference is genuinely unusable, and say why."
        printf '%s\n\n' '<!-- end execute-directly banner -->'
    } > "$_EXEC_BANNER_TMP"
    if cat "$ENRICHED_FILE" >> "$_EXEC_BANNER_TMP" && mv "$_EXEC_BANNER_TMP" "$ENRICHED_FILE" 2>/dev/null; then
        EXEC_BANNER_STATUS="injected"
    else
        EXEC_BANNER_STATUS="inject-failed"
        rm -f "$_EXEC_BANNER_TMP" 2>/dev/null || true
        echo "[spawn-worker] WARN: execute-directly banner injection failed" >&2
    fi
else
    EXEC_BANNER_STATUS="disabled-by-env"
fi

# ---------------------------------------------------------------------------
# Step 3: BEGIN/END marker verification (STEP 1c gate)
# ---------------------------------------------------------------------------

BEGIN_MARKER_COUNT=$(grep -c "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->" "$ENRICHED_FILE" 2>/dev/null | head -1)
BEGIN_MARKER_COUNT="${BEGIN_MARKER_COUNT:-0}"
END_MARKER_COUNT=$(grep -c "<!-- END dispatch-agent-with-prebriefing META-1 block -->" "$ENRICHED_FILE" 2>/dev/null | head -1)
END_MARKER_COUNT="${END_MARKER_COUNT:-0}"

MARKERS_OK=0
if [[ "$BEGIN_MARKER_COUNT" -ge 1 ]] && [[ "$END_MARKER_COUNT" -ge 1 ]]; then
    MARKERS_OK=1
fi

if [[ $MARKERS_OK -eq 0 ]] && [[ $NO_PREBRIEFING -eq 0 ]]; then
    echo "[spawn-worker] WARN: STEP 1c markers missing (BEGIN=$BEGIN_MARKER_COUNT END=$END_MARKER_COUNT)" >&2
    if [[ $STRICT_MARKERS -eq 1 ]]; then
        echo "[spawn-worker] ERROR: --strict-markers set and markers missing; aborting" >&2
        exit 3
    fi
fi

# ---------------------------------------------------------------------------
# Step 3.5: Prior-lane scan injection (CAPABILITY-GAP-2)
# ---------------------------------------------------------------------------
# Auto-injects a "STEP 1.5 - Prior-Lane Scan" section into the enriched
# prompt so workers see prior NEGATIVE / DROP / CLOSED chains BEFORE
# re-deriving them. Evidence anchor: COMP-5 burned ~1h re-deriving
# hb_loop9_chained_cross_component.md Chain 3.

PRIOR_LANE_SCAN_STATUS="skipped"
PRIOR_LANE_SCAN_RC=0
PRIOR_LANE_SCAN_MATCHES=0

# Resolve INJECT_PRIOR_LANES tri-state: -1 = auto-on for hunt/drill/comp,
# off for everything else.
_INJECT_RESOLVED=0
if [[ "$INJECT_PRIOR_LANES" -eq 1 ]]; then
    _INJECT_RESOLVED=1
elif [[ "$INJECT_PRIOR_LANES" -eq -1 ]]; then
    case "$LANE_TYPE" in
        hunt|opposed-trace-harness|escalation|dispute|mediation) _INJECT_RESOLVED=1 ;;
        *) _INJECT_RESOLVED=0 ;;
    esac
    # Also auto-on for lane-ids containing hunt/drill/comp/COMP/DRILL/HUNT.
    case "$LANE_ID" in
        *[Hh]unt*|*[Dd]rill*|*[Cc]omp*|*COMP*|*HUNT*|*DRILL*) _INJECT_RESOLVED=1 ;;
    esac
fi

if [[ "$_INJECT_RESOLVED" -eq 1 ]]; then
    # Resolve hypothesis keywords: explicit flag wins; otherwise best-effort
    # extract from the prompt file body.
    _HYPO_KW="$HYPOTHESIS_KEYWORDS"
    if [[ -z "$_HYPO_KW" ]]; then
        # Best-effort extract: grep first matching "Hypothesis:" /
        # "Hypothesis keywords:" / "Goal:" line, strip the prefix, trim to
        # at most ~30 tokens. Falls through to empty if nothing matches.
        _HYPO_KW=$(grep -i -m1 -E '^[[:space:]]*(hypothesis( keywords)?|goal|target|claim)[[:space:]]*:' "$PROMPT_FILE" 2>/dev/null \
            | sed -E 's/^[[:space:]]*(hypothesis( keywords)?|goal|target|claim)[[:space:]]*:[[:space:]]*//I' \
            | cut -c1-300 \
            | tr -s '[:space:]' ' ' \
            | sed 's/^ //;s/ $//')
    fi

    if [[ -z "$_HYPO_KW" ]]; then
        PRIOR_LANE_SCAN_STATUS="skipped-no-keywords"
        echo "[spawn-worker] WARN: prior-lane scan enabled but no hypothesis keywords (use --hypothesis-keywords or add 'Hypothesis:' line to prompt)" >&2
    elif [[ ! -f "$PRIOR_LANE_SCAN_TOOL" ]]; then
        PRIOR_LANE_SCAN_STATUS="tool-missing"
        echo "[spawn-worker] WARN: prior-lane scan tool missing at $PRIOR_LANE_SCAN_TOOL" >&2
    else
        _PLS_TMP="${TMP_DIR}/spawn_worker_${LANE_ID}_$$_prior_lanes.md"
        # K3-deadend-injection: pass the lane's files + the workspace pin so the
        # scanner can surface KNOWN-DEAD-END rows whose file_line matches the
        # lane scope at this pin (ranked above keyword overlap). Completeness-
        # safe: empty file list / unresolved pin just skips the file_line match
        # mode - the keyword scan still runs exactly as before.
        _TARGET_FILE_LINES="$(printf '%s' "$PATHSPEC_FILES" | tr ',' ' ' | tr -s '[:space:]' ' ' | sed 's/^ //;s/ $//')"
        _TARGET_PIN="$(git -C "$WORKSPACE" rev-parse HEAD 2>/dev/null || true)"
        if python3 "$PRIOR_LANE_SCAN_TOOL" \
                --workspace "$WORKSPACE" \
                --lane-id "$LANE_ID" \
                --hypothesis-keywords "$_HYPO_KW" \
                --target-file-lines "$_TARGET_FILE_LINES" \
                --target-pin "$_TARGET_PIN" \
                --render-brief \
                > "$_PLS_TMP" 2>/dev/null; then
            PRIOR_LANE_SCAN_STATUS="injected"
            # Append the brief section to the enriched file with a blank
            # separator. The brief carries its own BEGIN/END markers.
            {
                printf "\n\n"
                cat "$_PLS_TMP"
            } >> "$ENRICHED_FILE"
            # Count matches by looking for numbered list items in the brief.
            PRIOR_LANE_SCAN_MATCHES=$(grep -cE '^[0-9]+\.\s+\*\*' "$_PLS_TMP" 2>/dev/null | head -1)
            PRIOR_LANE_SCAN_MATCHES="${PRIOR_LANE_SCAN_MATCHES:-0}"
        else
            PRIOR_LANE_SCAN_RC=$?
            PRIOR_LANE_SCAN_STATUS="scan-failed"
            echo "[spawn-worker] WARN: prior-lane scan failed (rc=$PRIOR_LANE_SCAN_RC)" >&2
        fi
        rm -f "$_PLS_TMP" 2>/dev/null || true
    fi
else
    PRIOR_LANE_SCAN_STATUS="disabled-for-lane-type"
fi

# ---------------------------------------------------------------------------
# Step 3.55: EARLY prior-AUDIT dedup preflight (Strata 2026-07-07).
# ---------------------------------------------------------------------------
# prior_lane_scan (above) only checks THIS SESSION'S lanes. The prior-AUDIT
# dedup gate (early-prior-audit-dedup-gate.py) was orphaned from dispatch, so a
# candidate landing in an already-COVERED prior-audit class (e.g. Strata
# DiscreteAccounting.calculateNAVSplitProjected inside covered class #4
# "senior/junior nav reconciliation") sailed past here and was only caught at
# pre-submit R47/R53 - after a full hunt + 2 PoCs were already spent. Run it
# EARLY, before the Agent is emitted, for hunt-class + filing lanes. Advisory by
# default (WARN + log so the operator/agent sees it and argues extension-distinct
# up front); hard-block (exit 7) only under AUDITOOOR_DEDUP_PREFLIGHT_STRICT=1.
DEDUP_PREFLIGHT_STATUS="not-run"
DEDUP_PREFLIGHT_VERDICT=""
_EARLY_DEDUP_TOOL="${REPO_ROOT}/tools/early-prior-audit-dedup-gate.py"
case "$LANE_TYPE" in
    hunt|drill|comp|filing)
        if [[ -f "$_EARLY_DEDUP_TOOL" && -n "$WORKSPACE" ]]; then
            _DP_TITLE=$(grep -m1 -E '^#{1,3} ' "$PROMPT_FILE" 2>/dev/null | sed -E 's/^#{1,3} //' | cut -c1-200)
            [[ -z "$_DP_TITLE" ]] && _DP_TITLE="${_HYPO_KW:-$LANE_ID}"
            _DP_JSON=$(python3 "$_EARLY_DEDUP_TOOL" --title "$_DP_TITLE" --json "$WORKSPACE" 2>/dev/null || true)
            DEDUP_PREFLIGHT_VERDICT=$(printf '%s' "$_DP_JSON" | python3 -c 'import sys,json;
try: print(json.load(sys.stdin).get("verdict",""))
except Exception: print("")' 2>/dev/null)
            case "$DEDUP_PREFLIGHT_VERDICT" in
                KILLED|NEEDS-EXTENSION-DISTINCT)
                    DEDUP_PREFLIGHT_STATUS="flagged:$DEDUP_PREFLIGHT_VERDICT"
                    echo "[spawn-worker] DEDUP-PREFLIGHT: $DEDUP_PREFLIGHT_VERDICT - candidate '$_DP_TITLE' overlaps a prior-audit-covered class. Argue R47/R53 extension-distinctness BEFORE investing hunt/PoC effort (or KILL it)." >&2
                    case "$(printf '%s' "${AUDITOOOR_DEDUP_PREFLIGHT_STRICT:-}" | tr 'A-Z' 'a-z')" in
                        1|true|yes|on)
                            echo "[spawn-worker] BLOCKED (exit 7): AUDITOOOR_DEDUP_PREFLIGHT_STRICT=1 and dedup verdict=$DEDUP_PREFLIGHT_VERDICT. Add an extension-distinct argument to the brief, or clear the dupe, then re-dispatch." >&2
                            exit 7 ;;
                    esac ;;
                pass) DEDUP_PREFLIGHT_STATUS="pass" ;;
                warn|"") DEDUP_PREFLIGHT_STATUS="${DEDUP_PREFLIGHT_VERDICT:-inconclusive}" ;;
                *) DEDUP_PREFLIGHT_STATUS="$DEDUP_PREFLIGHT_VERDICT" ;;
            esac
        else
            DEDUP_PREFLIGHT_STATUS="tool-or-ws-missing"
        fi ;;
    *) DEDUP_PREFLIGHT_STATUS="disabled-for-lane-type" ;;
esac

# ---------------------------------------------------------------------------
# Step 3.6: Auto-inject hacker-mcp-rebuttal / r64-rebuttal / r57-rebuttal
#           markers at the TOP of the enriched brief for non-hunt lane types.
# ---------------------------------------------------------------------------
# Rationale: the universal-rule-enforce hook rejects Agent dispatches when
# the brief contains "factual-claim shapes" (tool paths, MCP callable names,
# Check #N references, R-rule citations) without corresponding rebuttal
# markers. For tooling/infrastructure lanes these markers are boilerplate;
# hand-injecting them every time caused 4+ friction hits on 2026-05-26.
# This step bakes them in automatically for lane types that are by-definition
# NOT finding drafts, so the boilerplate never has to be added manually.
#
# Auto-inject for: tool-build, corpus, docs, cleanup, infra
# Skip injection for: hunt, drill, dispute, mediation, triager-response,
#                     rebuttal, filing (these DO need genuine markers in the
#                     prompt body, not auto-injected boilerplate).
# Override: --no-auto-markers disables injection for any lane type.

AUTO_MARKERS_STATUS="skipped"

_DO_INJECT_MARKERS=0
if [[ "$NO_AUTO_MARKERS" -eq 0 ]]; then
    case "$LANE_TYPE" in
        tool-build|corpus|docs|cleanup|infra) _DO_INJECT_MARKERS=1 ;;
        hunt|drill|dispute|mediation|triager-response|rebuttal|filing) _DO_INJECT_MARKERS=0 ;;
        *) _DO_INJECT_MARKERS=0 ;;
    esac
fi

if [[ "$_DO_INJECT_MARKERS" -eq 1 ]]; then
    _MARKERS_HEADER="$(printf '%s\n%s\n%s\n\n' \
        '<!-- hacker-mcp-rebuttal: '"$LANE_TYPE"' lane (auto-injected by spawn-worker.sh) -->' \
        '<!-- r64-rebuttal: claims verified by spawn-worker.sh enrichment + R36 pathspec registration -->' \
        '<!-- r57-rebuttal: tool-build lane, not a finding draft -->')"
    _MARKER_TMP="${TMP_DIR}/spawn_worker_${LANE_ID}_$$_markers_prepend.md"
    printf '%s' "$_MARKERS_HEADER" > "$_MARKER_TMP"
    cat "$ENRICHED_FILE" >> "$_MARKER_TMP"
    if mv "$_MARKER_TMP" "$ENRICHED_FILE" 2>/dev/null; then
        AUTO_MARKERS_STATUS="injected:$LANE_TYPE"
    else
        AUTO_MARKERS_STATUS="inject-failed"
        echo "[spawn-worker] WARN: auto-marker injection failed (mv to enriched file)" >&2
        rm -f "$_MARKER_TMP" 2>/dev/null || true
    fi
elif [[ "$NO_AUTO_MARKERS" -eq 1 ]]; then
    AUTO_MARKERS_STATUS="disabled-by-flag"
else
    AUTO_MARKERS_STATUS="skipped-hunt-class-lane"
fi

# ---------------------------------------------------------------------------
# Step 3.65: Durable copy of the enriched brief (prebriefing-durability fix)
# ---------------------------------------------------------------------------
# PROBLEM (operator-caught, strata MIN_SHARES): the enriched brief above lives
# ONLY at the EPHEMERAL $ENRICHED_FILE (/tmp). Between this spawn-worker call and
# the Agent actually running (often a LATER turn), /tmp can be reaped -> the worker
# cannot find its Section-15 prebriefing / kill-rubric / prior dispositions and
# runs DEGRADED, silently. A real finding worker flew blind this way.
#
# ADDITIVE FIX: in ADDITION to $ENRICHED_FILE (unchanged), also write a DURABLE
# copy under the workspace at <ws>/.auditooor/dispatch_briefs/<lane>_enriched.md.
# The /tmp path + OK-line stdout contract are byte-unchanged; we ONLY add a new
# `[spawn-worker] durable_brief=<path>` stderr line so the orchestrator/agent can
# recover the brief after /tmp is gone. If the ws path is unavailable, behave
# exactly as before (no durable copy, no error).

DURABLE_BRIEF_PATH=""
DURABLE_BRIEF_STATUS="not-attempted"
if [[ -n "$WORKSPACE" ]] && [[ -d "$WORKSPACE" ]] && [[ -f "$ENRICHED_FILE" ]]; then
    _SAFE_LANE_DB=$(printf '%s' "$LANE_ID" | tr -cs 'A-Za-z0-9._-' '_')
    [[ -n "$_SAFE_LANE_DB" ]] || _SAFE_LANE_DB="lane"
    _DB_DIR="${WORKSPACE}/.auditooor/dispatch_briefs"
    if mkdir -p "$_DB_DIR" 2>/dev/null; then
        _DB_PATH="${_DB_DIR}/${_SAFE_LANE_DB}_enriched.md"
        if cp "$ENRICHED_FILE" "$_DB_PATH" 2>/dev/null; then
            DURABLE_BRIEF_PATH="$_DB_PATH"
            DURABLE_BRIEF_STATUS="written"
        else
            DURABLE_BRIEF_STATUS="copy-failed"
        fi
    else
        DURABLE_BRIEF_STATUS="mkdir-failed"
    fi
else
    DURABLE_BRIEF_STATUS="ws-unavailable"
fi

# ---------------------------------------------------------------------------
# Step 3.7: G13.2 full-tier-coverage gate (validates POST-enrichment brief)
# ---------------------------------------------------------------------------
# For hunt-class lanes (hunt / drill / comp / fuzz / opposed-trace-harness /
# escalation), validate that the ENRICHED brief actually injected the full
# SEVERITY.md tier surface + a "hunt every tier" directive (G13.1). Default
# WARN-only; promote to hard-fail (exit 7) only under SPAWN_WORKER_G13_STRICT=1.
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].

G13_TIER_STATUS="skipped"
G13_TIER_VERDICT=""
G13_TIER_RC=0

_G13_GATED_LANE_TYPE=0
case "$LANE_TYPE" in
    hunt|drill|comp|fuzz|opposed-trace-harness|escalation) _G13_GATED_LANE_TYPE=1 ;;
esac
# A tooling/concrete-fix brief is never hunt-template-wrapped, so the full-tier-
# coverage gate is inapplicable and would only add its ~2min timeout (fix c).
if [[ $RESOLVED_TOOLING -eq 1 ]]; then
    _G13_GATED_LANE_TYPE=0
fi

if [[ "$_G13_GATED_LANE_TYPE" -eq 0 ]]; then
    G13_TIER_STATUS="skipped-lane-type-not-gated"
elif [[ ! -f "$G13_TIER_COVERAGE_TOOL" ]]; then
    G13_TIER_STATUS="tool-missing"
    echo "[spawn-worker] WARN: G13 full-tier-coverage tool missing at $G13_TIER_COVERAGE_TOOL" >&2
else
    _G13_JSON=$(python3 "$G13_TIER_COVERAGE_TOOL" \
        --workspace "$WORKSPACE" \
        --lane-id "$LANE_ID" \
        --lane-type "$LANE_TYPE" \
        --prompt-file "$ENRICHED_FILE" \
        --json 2>/dev/null)
    G13_TIER_RC=$?
    G13_TIER_VERDICT=$(printf '%s' "$_G13_JSON" | python3 -c "import json,sys
try:
    d=json.loads(sys.stdin.read())
    print(d.get('verdict',''))
except Exception:
    pass" 2>/dev/null)
    if [[ "$G13_TIER_RC" -eq 0 ]]; then
        G13_TIER_STATUS="pass:${G13_TIER_VERDICT}"
    else
        G13_TIER_STATUS="fail:${G13_TIER_VERDICT}"
        echo "[spawn-worker] WARN: G13 full-tier-coverage gate flagged the enriched brief (verdict=$G13_TIER_VERDICT)" >&2
        echo "[spawn-worker] WARN: remediation: ensure Section 15i-FULL injected (re-run prebriefing) OR add \`<!-- g13-rebuttal: <reason up to 200 chars> -->\` to the brief" >&2
        if [[ -n "$_G13_JSON" ]]; then
            echo "$_G13_JSON" >&2
        fi
        if [[ "${SPAWN_WORKER_G13_STRICT:-}" == "1" ]]; then
            G13_TIER_STATUS="strict-fail:${G13_TIER_VERDICT}"
            echo "[spawn-worker] ERROR: SPAWN_WORKER_G13_STRICT=1 - refusing spawn on G13 full-tier-coverage fail" >&2
            TS_G13_REFUSE=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
            G13_REFUSE_ROW=$(python3 -c "
import json
row = {
    'ts': '$TS_G13_REFUSE',
    'tool': 'spawn-worker.sh',
    'schema': '$SCHEMA',
    'lane_id': '$LANE_ID',
    'lane_type': '$LANE_TYPE',
    'severity': '$SEVERITY',
    'workspace': '$WORKSPACE',
    'enriched_file': '$ENRICHED_FILE',
    'g13_tier_status': '$G13_TIER_STATUS',
    'g13_tier_verdict': '$G13_TIER_VERDICT',
    'g13_tier_rc': $G13_TIER_RC,
    'refused': True,
}
print(json.dumps(row, sort_keys=True))
" 2>/dev/null)
            if [[ -n "$G13_REFUSE_ROW" ]]; then
                mkdir -p "$(dirname "$LOG_PATH")" 2>/dev/null || true
                echo "$G13_REFUSE_ROW" >> "$LOG_PATH" 2>/dev/null || true
            fi
            exit 7
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 4: Log dispatch
# ---------------------------------------------------------------------------

PROMPT_SHA256=""
if command -v shasum >/dev/null 2>&1; then
    PROMPT_SHA256=$(shasum -a 256 "$ENRICHED_FILE" 2>/dev/null | awk '{print $1}')
elif command -v sha256sum >/dev/null 2>&1; then
    PROMPT_SHA256=$(sha256sum "$ENRICHED_FILE" 2>/dev/null | awk '{print $1}')
fi

TS_NOW=$(python3 -c 'from datetime import datetime,timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))' 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")

LOG_DIR="$(dirname "$LOG_PATH")"
mkdir -p "$LOG_DIR" 2>/dev/null || true

LOG_ROW=$(python3 -c "
import json, sys
row = {
    'ts': '$TS_NOW',
    'tool': 'spawn-worker.sh',
    'schema': '$SCHEMA',
    'lane_id': '$LANE_ID',
    'lane_type': '$LANE_TYPE',
    'severity': '$SEVERITY',
    'workspace': '$WORKSPACE',
    'prompt_file': '$PROMPT_FILE',
    'enriched_file': '$ENRICHED_FILE',
    'durable_brief_path': '$DURABLE_BRIEF_PATH',
    'durable_brief_status': '$DURABLE_BRIEF_STATUS',
    'prompt_sha256': '$PROMPT_SHA256',
    'pathspec_status': '$PATHSPEC_STATUS',
    'pathspec_rc': $PATHSPEC_RC,
    'prebriefing_status': '$PREBRIEFING_STATUS',
    'prebriefing_rc': $PREBRIEFING_RC,
    'markers_ok': $MARKERS_OK,
    'begin_marker_count': $BEGIN_MARKER_COUNT,
    'end_marker_count': $END_MARKER_COUNT,
    'strict_markers': $STRICT_MARKERS,
    'use_worktree': $USE_WORKTREE,
    'worktree_path': '$WORKTREE_PATH',
    'worktree_status': '$WORKTREE_STATUS',
    'worktree_rc': $WORKTREE_RC,
    'prior_lane_scan_status': '$PRIOR_LANE_SCAN_STATUS',
    'prior_lane_scan_rc': $PRIOR_LANE_SCAN_RC,
    'prior_lane_scan_matches': $PRIOR_LANE_SCAN_MATCHES,
    'inject_prior_lanes_flag': $INJECT_PRIOR_LANES,
    'gap29_status': '$GAP29_STATUS',
    'gap29_verdict': '$GAP29_VERDICT',
    'gap29_rc': $GAP29_RC,
    'g13_tier_status': '$G13_TIER_STATUS',
    'g13_tier_verdict': '$G13_TIER_VERDICT',
    'g13_tier_rc': $G13_TIER_RC,
    'auto_markers_status': '$AUTO_MARKERS_STATUS',
    'no_auto_markers_flag': $NO_AUTO_MARKERS,
    'dispatch_guard_env': 'AUDITOOOR_SPAWN_WORKER_OK',
    'dispatch_guard_provenance': 'spawn-worker.sh',
    'dry_run': $DRY_RUN,
}
print(json.dumps(row, sort_keys=True))
" 2>/dev/null)

if [[ -n "$LOG_ROW" ]]; then
    if ! echo "$LOG_ROW" >> "$LOG_PATH" 2>/dev/null; then
        echo "[spawn-worker] WARN: log append failed at $LOG_PATH" >&2
    fi
fi

# ---------------------------------------------------------------------------
# Step 5: Emit enriched prompt path or summary
# ---------------------------------------------------------------------------

if [[ $JSON_OUTPUT -eq 1 ]]; then
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "$LOG_ROW" | python3 -c "import json,sys; d=json.loads(sys.stdin.read()); d['mode']='dry-run'; print(json.dumps(d, sort_keys=True))"
    else
        echo "$LOG_ROW"
    fi
else
    if [[ $DRY_RUN -eq 1 ]]; then
        echo "[spawn-worker] [DRY-RUN] lane=$LANE_ID type=$LANE_TYPE severity=$SEVERITY"
        echo "[spawn-worker] [DRY-RUN] pathspec=$PATHSPEC_STATUS prebriefing=$PREBRIEFING_STATUS markers_ok=$MARKERS_OK worktree=$WORKTREE_STATUS prior_lane_scan=$PRIOR_LANE_SCAN_STATUS matches=$PRIOR_LANE_SCAN_MATCHES auto_markers=$AUTO_MARKERS_STATUS"
        echo "[spawn-worker] [DRY-RUN] enriched would be at: $ENRICHED_FILE"
        if [[ -n "$DURABLE_BRIEF_PATH" ]]; then
            echo "[spawn-worker] durable_brief=$DURABLE_BRIEF_PATH"
        fi
        if [[ -n "$WORKTREE_PATH" ]]; then
            echo "[spawn-worker] [DRY-RUN] worktree path: $WORKTREE_PATH"
        fi
    else
        # Print just the path on stdout so callers can capture it
        echo "$ENRICHED_FILE"
        if [[ -n "$WORKTREE_PATH" ]]; then
            echo "[spawn-worker] OK lane=$LANE_ID type=$LANE_TYPE severity=$SEVERITY pathspec=$PATHSPEC_STATUS prebriefing=$PREBRIEFING_STATUS markers_ok=$MARKERS_OK worktree=$WORKTREE_PATH prior_lane_scan=$PRIOR_LANE_SCAN_STATUS matches=$PRIOR_LANE_SCAN_MATCHES auto_markers=$AUTO_MARKERS_STATUS dedup_preflight=$DEDUP_PREFLIGHT_STATUS log=$LOG_PATH" >&2
        else
            echo "[spawn-worker] OK lane=$LANE_ID type=$LANE_TYPE severity=$SEVERITY pathspec=$PATHSPEC_STATUS prebriefing=$PREBRIEFING_STATUS markers_ok=$MARKERS_OK prior_lane_scan=$PRIOR_LANE_SCAN_STATUS matches=$PRIOR_LANE_SCAN_MATCHES auto_markers=$AUTO_MARKERS_STATUS dedup_preflight=$DEDUP_PREFLIGHT_STATUS log=$LOG_PATH" >&2
        fi
        # ADDITIVE (prebriefing-durability): tell the orchestrator/agent where the
        # durable copy lives so it can recover the brief after /tmp is reaped.
        # Separate stderr line; the /tmp stdout path + OK line above are unchanged.
        if [[ -n "$DURABLE_BRIEF_PATH" ]]; then
            echo "[spawn-worker] durable_brief=$DURABLE_BRIEF_PATH" >&2
        fi
    fi
fi

exit 0
