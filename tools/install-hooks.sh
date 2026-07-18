#!/usr/bin/env bash
# install-hooks.sh — Idempotent per-worktree git-hook installer for MCP +
# R36/R55 discipline.
#
# Installs three hooks, the session-start shim, AND the R36/R55 wiring:
#   pre-commit  — chains MCP recall freshness check + R36 pathspec discipline
#   commit-msg  — requires context_pack_id: line in commit body
#   pre-push    — requires fresh MCP recall + write-scoped MCP session token
#   shim        — ~/.auditooor/bin/auditooor-session-start.sh
#   core.hooksPath — points git at tools/git-hooks/ so the R36 hook fires
#   R55 wrappers — git-reset-safe.sh / git-checkout-safe.sh / git-clean-safe.sh /
#                  git-stash-safe.sh (require shell-alias setup; printed by
#                  the `install` subcommand for operator zshrc copy-paste).
#
# Usage:
#   bash tools/install-hooks.sh install       install hooks + R36/R55 wiring + shim
#   bash tools/install-hooks.sh uninstall     remove installed hooks
#   bash tools/install-hooks.sh check         report installed/missing/stale
#   bash tools/install-hooks.sh dogfood       run installation verifier (R36
#                                              refuses sibling-pathspec stage;
#                                              MCP sentinel freshness check)
#   bash tools/install-hooks.sh print-aliases print R55 wrapper aliases for
#                                              the operator to add to ~/.zshrc
#   bash tools/install-hooks.sh --help        show this help
#
# Environment variables:
#   AUDITOOOR_RECALL_MAX_AGE_S   max age in seconds for freshness check (default: 1800)
#   AUDITOOOR_MCP_SESSION_TOKEN  write-scoped token required by pre-push
#   AUDITOOOR_MCP_TOKEN_TOOL     override token verifier path (default: tools/auditooor_mcp_token.py)
#   AUDITOOOR_MCP_REQUIRED       set to 0 to bypass hooks (audit-logged)
#   AUDITOOOR_HOOKS_PATH_TARGET  override core.hooksPath value (default: tools/git-hooks)
#   AUDITOOOR_SKIP_HOOKS_PATH    set to 1 to skip setting core.hooksPath (advanced)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_START_INSTALLER="$SCRIPT_DIR/install-session-start-shim.sh"

# Resolve workspace: prefer GIT_DIR env override (for tests), then cwd, then script dir.
# This allows tests to inject a tempdir git repo without needing to cd first.
if [[ -n "${AUDITOOOR_WS_ROOT:-}" ]]; then
    WS_ROOT="$AUDITOOOR_WS_ROOT"
else
    WS_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || echo "")"
fi

if [[ -z "$WS_ROOT" ]]; then
    echo "[install-hooks] ERROR: not inside a git repository" >&2
    exit 1
fi

# Resolve the actual hooks directory (handles worktree gitdir indirection)
HOOKS_DIR="$(git -C "$WS_ROOT" rev-parse --git-path hooks 2>/dev/null || echo "$WS_ROOT/.git/hooks")"
# Make absolute
if [[ ! "$HOOKS_DIR" = /* ]]; then
    HOOKS_DIR="$WS_ROOT/$HOOKS_DIR"
fi

mkdir -p "$HOOKS_DIR"

BYPASS_LOG="$WS_ROOT/.auditooor/bypass_log.jsonl"

# ---------------------------------------------------------------------------
# Pre-commit hook content - chains MCP recall freshness check + R36 pathspec
# discipline. Either check failing aborts the commit (fail-closed). MCP
# bypass (AUDITOOOR_MCP_REQUIRED=0) skips ONLY the MCP check; R36 still
# fires because R36's bypass is the in-commit-message `r36-rebuttal:` marker.
# ---------------------------------------------------------------------------
pre_commit_hook() {
cat <<'HOOK'
#!/usr/bin/env bash
# auditooor pre-commit hook - MCP recall freshness check + R36 pathspec
# discipline (chained). Managed by tools/install-hooks.sh - do not edit
# directly. Both checks are fail-closed; see the rule sections in
# ~/.claude/CLAUDE.md (R36 + L25 MCP-first) for doctrine.

set -euo pipefail

AUDITOOOR_RECALL_MAX_AGE_S="${AUDITOOOR_RECALL_MAX_AGE_S:-1800}"
AUDITOOOR_MCP_REQUIRED="${AUDITOOOR_MCP_REQUIRED:-1}"

# Prefer explicit workspace root (test isolation / cross-worktree) over git discovery
if [[ -n "${AUDITOOOR_WS_ROOT:-}" ]]; then
    WS_ROOT="$AUDITOOOR_WS_ROOT"
else
    WS_ROOT="$(git rev-parse --show-toplevel)"
fi
SENTINEL="$WS_ROOT/.auditooor/last_mcp_recall.json"
BYPASS_LOG="$WS_ROOT/.auditooor/bypass_log.jsonl"

# ------------------------------------------------------------------
# MCP bypass path - skip the MCP-recall freshness check but STILL run R36
# pathspec discipline below. The MCP bypass and the R36 bypass are
# independent: AUDITOOOR_MCP_REQUIRED=0 silences MCP only; R36 has its
# own in-commit-message `<!-- r36-rebuttal: <reason> -->` bypass.
# ------------------------------------------------------------------
SKIP_MCP_CHECK=0
if [[ "$AUDITOOOR_MCP_REQUIRED" == "0" ]]; then
    mkdir -p "$WS_ROOT/.auditooor"
    COMMIT_HASH="$(git -C "$WS_ROOT" rev-parse HEAD 2>/dev/null || true)"
    COMMIT_HASH="${COMMIT_HASH:-pre-first-commit}"
    AUDITOOOR_BYPASS_LOG="$BYPASS_LOG" \
    AUDITOOOR_COMMIT_HASH="$COMMIT_HASH" \
    python3 - <<'PYEOF'
import json, time, os, pathlib
log = pathlib.Path(os.environ["AUDITOOOR_BYPASS_LOG"])
log.parent.mkdir(parents=True, exist_ok=True)
with open(log, "a") as f:
    json.dump({
        "event": "bypass",
        "hook": "pre-commit",
        "ts": time.time(),
        "iso": __import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "user": os.environ.get("USER", "unknown"),
        "commit_hash": os.environ.get("AUDITOOOR_COMMIT_HASH", "unknown"),
    }, f)
    f.write("\n")
PYEOF
    echo "[pre-commit] MCP freshness bypass logged (AUDITOOOR_MCP_REQUIRED=0)" >&2
    SKIP_MCP_CHECK=1
fi

# ------------------------------------------------------------------
# Check sentinel existence (only when MCP not bypassed)
# ------------------------------------------------------------------
if [[ "$SKIP_MCP_CHECK" == "0" ]] && [[ ! -f "$SENTINEL" ]]; then
    echo "[pre-commit] REJECTED: .auditooor/last_mcp_recall.json not found." >&2
    echo "[pre-commit] Run: bash tools/auditooor-session-start.sh" >&2
    echo "[pre-commit] Bypass: AUDITOOOR_MCP_REQUIRED=0 git commit ..." >&2
    exit 1
fi

# ------------------------------------------------------------------
# Check sentinel freshness (only when MCP not bypassed)
# ------------------------------------------------------------------
if [[ "$SKIP_MCP_CHECK" == "0" ]]; then
    NOW="$(python3 -c 'import time; print(int(time.time()))')"
    RECALL_TS="$(python3 -c "
import json
with open('$SENTINEL') as f:
    d = json.load(f)
print(int(d.get('recall_ts', 0)))
" 2>/dev/null || echo 0)"

    AGE=$(( NOW - RECALL_TS ))

    if [[ $AGE -gt $AUDITOOOR_RECALL_MAX_AGE_S ]]; then
        echo "[pre-commit] REJECTED: MCP recall sentinel is ${AGE}s old (max ${AUDITOOOR_RECALL_MAX_AGE_S}s)." >&2
        echo "[pre-commit] Run: bash tools/auditooor-session-start.sh" >&2
        echo "[pre-commit] Bypass: AUDITOOOR_MCP_REQUIRED=0 git commit ..." >&2
        exit 1
    fi

    echo "[pre-commit] MCP recall sentinel OK (age: ${AGE}s)" >&2
fi

# ------------------------------------------------------------------
# Validate staged hackerman corpus records when the validator is present.
# Legacy verdict tags are skipped by the validator unless they declare the
# hackerman v1 schema, so this is safe for mixed corpus directories.
# ------------------------------------------------------------------
if [[ -f "$WS_ROOT/tools/hackerman-record-validate.py" ]]; then
    HACKERMAN_STAGED=()
    while IFS= read -r rel; do
        [[ -n "$rel" ]] && HACKERMAN_STAGED+=("$rel")
    done < <(
        git -C "$WS_ROOT" diff --cached --name-only -- \
            'audit/corpus_tags/tags/*.yaml' \
            'audit/corpus_tags/tags/*.yml' \
            2>/dev/null || true
    )
    if [[ ${#HACKERMAN_STAGED[@]} -gt 0 ]]; then
        VALIDATE_ARGS=()
        VALIDATE_BATCH_SIZE=200
        VALIDATED_COUNT=0
        for rel in "${HACKERMAN_STAGED[@]}"; do
            [[ -f "$WS_ROOT/$rel" ]] || continue
            VALIDATE_ARGS+=(--validate "$WS_ROOT/$rel")
            VALIDATED_COUNT=$((VALIDATED_COUNT+1))
            if [[ $VALIDATED_COUNT -ge $VALIDATE_BATCH_SIZE ]]; then
                python3 "$WS_ROOT/tools/hackerman-record-validate.py" "${VALIDATE_ARGS[@]}" --quiet
                VALIDATE_ARGS=()
                VALIDATED_COUNT=0
            fi
        done
        if [[ ${#VALIDATE_ARGS[@]} -gt 0 ]]; then
            python3 "$WS_ROOT/tools/hackerman-record-validate.py" "${VALIDATE_ARGS[@]}" --quiet
        fi
        echo "[pre-commit] hackerman_record staged YAML OK (${#HACKERMAN_STAGED[@]} file(s))" >&2
    fi
fi

# ------------------------------------------------------------------
# CODEX-6: prevent new top-level agent output dumps. New artifacts must
# use agent_outputs/<owner>/<lane>/<YYYYMMDDTHHMMSSZ>_<phase>.json.
# Existing legacy tracked files are tolerated, but new top-level files
# are rejected so the namespace does not keep growing sideways.
# ------------------------------------------------------------------
AGENT_OUTPUT_TOPLEVEL=()
while IFS=$'\t' read -r status path1 path2; do
    [[ -n "${status:-}" ]] || continue
    case "$status" in
        A*|C*|R*) ;;
        *) continue ;;
    esac
    rel="${path2:-$path1}"
    if [[ "$rel" =~ ^agent_outputs/[^/]+$ ]]; then
        AGENT_OUTPUT_TOPLEVEL+=("$rel")
    fi
done < <(git -C "$WS_ROOT" diff --cached --name-status -- agent_outputs 2>/dev/null || true)

if [[ ${#AGENT_OUTPUT_TOPLEVEL[@]} -gt 0 ]]; then
    echo "[pre-commit] REJECTED: new top-level agent_outputs files are not allowed." >&2
    echo "[pre-commit] Use: agent_outputs/<owner>/<lane>/<YYYYMMDDTHHMMSSZ>_<phase>.json" >&2
    printf '  %s\n' "${AGENT_OUTPUT_TOPLEVEL[@]}" >&2
    exit 1
fi

# ------------------------------------------------------------------
# Optional: pr-hygiene-check on commit message file
# ------------------------------------------------------------------
if [[ -n "${1:-}" ]] && [[ -f "$WS_ROOT/tools/pr-hygiene-check.py" ]] && [[ -f "${1}" ]]; then
    python3 "$WS_ROOT/tools/pr-hygiene-check.py" "${1}" --strict 2>/dev/null || true
fi

# ------------------------------------------------------------------
# R36 pathspec discipline chain (FIX-C hardened). Fail-closed: if the
# pathspec hook refuses, the whole commit aborts. R36 has its own bypass
# (in-commit-message `<!-- r36-rebuttal: <reason> -->`) so we do not
# silence it via AUDITOOOR_MCP_REQUIRED=0.
# ------------------------------------------------------------------
R36_HOOK="$WS_ROOT/tools/git-hooks/pre-commit-pathspec-discipline.sh"
if [[ -x "$R36_HOOK" ]] || [[ -f "$R36_HOOK" ]]; then
    bash "$R36_HOOK" "$@"
    R36_RC=$?
    if [[ $R36_RC -ne 0 ]]; then
        echo "[pre-commit] R36 pathspec discipline REFUSED commit (rc=$R36_RC)" >&2
        exit "$R36_RC"
    fi
fi

# GLOBAL-RULE ADMISSION discipline (reverse-evolution defense): a newly-added
# global rule (R##/L## in docs/CODIFIED_RULES_INDEX.md, or a new
# _l37_gate_strict signal in tools/audit-completeness-check.py) must be admitted
# across >=3 workspaces or carry `<!-- admitted: <subject> -->`; else REFUSE.
# Bypass (audit-logged): AUDITOOOR_GLOBAL_RULE_BYPASS=1.
GRA_GATE="$WS_ROOT/tools/global-rule-admission-gate.py"
if [[ -f "$GRA_GATE" && "${AUDITOOOR_GLOBAL_RULE_BYPASS:-0}" != "1" ]]; then
    GRA_FILES=$(git diff --cached --name-only 2>/dev/null | grep -E 'docs/CODIFIED_RULES_INDEX\.md|tools/audit-completeness-check\.py' || true)
    if [[ -n "$GRA_FILES" ]]; then
        GRA_ADDED="$(mktemp)"
        git diff --cached -U0 -- $GRA_FILES 2>/dev/null | grep '^+' > "$GRA_ADDED" || true
        if [[ -s "$GRA_ADDED" ]]; then
            if ! python3 "$GRA_GATE" --added-lines-file "$GRA_ADDED" >&2; then
                echo "[pre-commit] REJECTED: a NEW global rule is not admitted across >=3 workspaces." >&2
                echo "[pre-commit] Fix locally, add '<!-- admitted: <subject> -->', or AUDITOOOR_GLOBAL_RULE_BYPASS=1." >&2
                rm -f "$GRA_ADDED"; exit 1
            fi
        fi
        rm -f "$GRA_ADDED"
    fi
fi

    # P17 rule-contract self-test (ADVISORY-first, default OFF). Staging an
    # edit to a check tool (tools/*.py) or a contract yaml replays the bound
    # must-catch/must-pass fixtures. Advisory: violations WARN, never abort.
    # Opt-in enforce: AUDITOOOR_RULE_CONTRACT_STRICT=1. Cannot brick when unset.
RCC_TOOL="$WS_ROOT/tools/rule-contract-check.py"
if [[ -f "$RCC_TOOL" ]]; then
    RCC_CHANGED=()
    while IFS= read -r rel; do
        [[ -n "$rel" ]] && RCC_CHANGED+=("$WS_ROOT/$rel")
    done < <(
        git -C "$WS_ROOT" diff --cached --name-only -- \
            'tools/*.py' 'tools/rules/contracts/*.yaml' 'tools/rules/contracts/*.yml' \
            2>/dev/null || true
    )
    if [[ ${#RCC_CHANGED[@]} -gt 0 ]]; then
        if python3 "$RCC_TOOL" --changed "${RCC_CHANGED[@]}" >&2; then
            :
        else
            RCC_RC=$?
            if [[ "${AUDITOOOR_RULE_CONTRACT_STRICT:-}" != "" && "$RCC_RC" -ne 2 ]]; then
                echo "[pre-commit] REJECTED: rule-contract violation (AUDITOOOR_RULE_CONTRACT_STRICT set)." >&2
                echo "[pre-commit] Fix the check/fixture, or unset the flag to downgrade to advisory." >&2
                exit "$RCC_RC"
            fi
            echo "[pre-commit] rule-contract advisory note (rc=$RCC_RC); not blocking." >&2
        fi
    fi
fi

exit 0
HOOK
}

# ---------------------------------------------------------------------------
# Commit-msg hook content
# ---------------------------------------------------------------------------
commit_msg_hook() {
cat <<'HOOK'
#!/usr/bin/env bash
# auditooor commit-msg hook - context_pack_id line requirement.
# Managed by tools/install-hooks.sh - do not edit directly.
#
# REFUSE (exit 1) when context_pack_id is absent from commit body.
#
# Bypass options (in order of specificity):
#   1. AUDITOOOR_MCP_REQUIRED=0         - blanket bypass (all MCP hooks); audit-logged
#   2. AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1 - pack-id only bypass; audit-logged
#   3. <!-- commit-msg-rebuttal: <reason> --> in commit body (<=200 chars non-empty)

set -euo pipefail

AUDITOOOR_MCP_REQUIRED="${AUDITOOOR_MCP_REQUIRED:-1}"
AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID="${AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID:-0}"

COMMIT_MSG_FILE="${1}"
if [[ -n "${AUDITOOOR_WS_ROOT:-}" ]]; then
    WS_ROOT="$AUDITOOOR_WS_ROOT"
else
    WS_ROOT="$(git rev-parse --show-toplevel)"
fi
BYPASS_LOG="$WS_ROOT/.auditooor/bypass_log.jsonl"

# Helper: write an audit-log entry
_log_bypass() {
    local reason="$1"
    mkdir -p "$WS_ROOT/.auditooor"
    AUDITOOOR_BYPASS_LOG="$BYPASS_LOG" AUDITOOOR_BYPASS_REASON="$reason" \
    python3 - <<'PYEOF'
import json, time, os, pathlib
log = pathlib.Path(os.environ["AUDITOOOR_BYPASS_LOG"])
log.parent.mkdir(parents=True, exist_ok=True)
with open(log, "a") as f:
    json.dump({
        "event": "bypass",
        "hook": "commit-msg",
        "ts": time.time(),
        "iso": __import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        "user": os.environ.get("USER", "unknown"),
        "commit_hash": "pending",
        "reason": os.environ.get("AUDITOOOR_BYPASS_REASON", ""),
    }, f)
    f.write("\n")
PYEOF
}

# ------------------------------------------------------------------
# Bypass path 1: blanket MCP bypass (AUDITOOOR_MCP_REQUIRED=0)
# ------------------------------------------------------------------
if [[ "$AUDITOOOR_MCP_REQUIRED" == "0" ]]; then
    _log_bypass "AUDITOOOR_MCP_REQUIRED=0"
    echo "[commit-msg] context_pack_id bypass logged (AUDITOOOR_MCP_REQUIRED=0)" >&2
    exit 0
fi

# ------------------------------------------------------------------
# Bypass path 2: pack-id-specific bypass envvar
# ------------------------------------------------------------------
if [[ "$AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID" == "1" ]]; then
    _log_bypass "AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1"
    echo "[commit-msg] context_pack_id bypass logged (AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1)" >&2
    exit 0
fi

# ------------------------------------------------------------------
# Bypass path 3: inline rebuttal marker in commit body
# <!-- commit-msg-rebuttal: <reason> -->  (non-empty, <=200 chars)
# Uses Python for reliable cross-platform regex extraction.
# ------------------------------------------------------------------
if grep -qiE '<!--\s*commit-msg-rebuttal:' "$COMMIT_MSG_FILE"; then
    REBUTTAL_RESULT="$(python3 - "$COMMIT_MSG_FILE" <<'PYEOF'
import re, sys
content = open(sys.argv[1]).read()
m = re.search(r'<!--\s*commit-msg-rebuttal:\s*(.*?)\s*-->', content, re.IGNORECASE | re.DOTALL)
if m:
    reason = m.group(1).strip()
    if not reason:
        print("EMPTY")
    elif len(reason) > 200:
        print("OVERSIZED:" + str(len(reason)))
    else:
        print("OK:" + reason)
else:
    print("NOMATCH")
PYEOF
)"

    case "$REBUTTAL_RESULT" in
        EMPTY)
            echo "[commit-msg] REJECTED: commit-msg-rebuttal marker found but reason is empty." >&2
            echo "[commit-msg] Usage: <!-- commit-msg-rebuttal: <reason up to 200 chars> -->" >&2
            exit 1
            ;;
        OVERSIZED:*)
            REASON_LEN="${REBUTTAL_RESULT#OVERSIZED:}"
            echo "[commit-msg] REJECTED: commit-msg-rebuttal reason is ${REASON_LEN} chars (max 200)." >&2
            echo "[commit-msg] Shorten the reason inside <!-- commit-msg-rebuttal: ... -->" >&2
            exit 1
            ;;
        NOMATCH)
            echo "[commit-msg] REJECTED: malformed commit-msg-rebuttal marker. Ensure it is closed with -->." >&2
            exit 1
            ;;
        OK:*)
            REBUTTAL_REASON="${REBUTTAL_RESULT#OK:}"
            _log_bypass "rebuttal: $REBUTTAL_REASON"
            echo "[commit-msg] context_pack_id bypassed via rebuttal: $REBUTTAL_REASON" >&2
            exit 0
            ;;
    esac
fi

# ------------------------------------------------------------------
# Main gate: require context_pack_id line in commit body
# ------------------------------------------------------------------
if ! grep -qiE 'context_pack_id:\s*[a-z0-9.:_-]+' "$COMMIT_MSG_FILE"; then
    echo "[commit-msg] REFUSED: commit body must contain a 'context_pack_id:' line." >&2
    echo "" >&2
    echo "  Add to your commit message:" >&2
    echo "    context_pack_id: auditooor.vault_resume_context.v1:resume:<hash16>" >&2
    echo "" >&2
    echo "  Bypass options:" >&2
    echo "    AUDITOOOR_COMMIT_MSG_BYPASS_PACK_ID=1 git commit ...   (pack-id bypass, audit-logged)" >&2
    echo "    AUDITOOOR_MCP_REQUIRED=0 git commit ...                (blanket bypass, audit-logged)" >&2
    echo "    Add to commit body: <!-- commit-msg-rebuttal: <reason up to 200 chars> -->" >&2
    exit 1
fi

echo "[commit-msg] context_pack_id line found - OK" >&2
exit 0
HOOK
}

# ---------------------------------------------------------------------------
# Pre-push hook content
# ---------------------------------------------------------------------------
pre_push_hook() {
cat <<'HOOK'
#!/usr/bin/env bash
# auditooor pre-push hook — MCP token + recall freshness check.
# Managed by tools/install-hooks.sh — do not edit directly.

set -euo pipefail

AUDITOOOR_RECALL_MAX_AGE_S="${AUDITOOOR_RECALL_MAX_AGE_S:-1800}"
AUDITOOOR_MCP_REQUIRED="${AUDITOOOR_MCP_REQUIRED:-1}"

REMOTE_NAME="${1:-unknown}"
REMOTE_URL="${2:-unknown}"

_resolve_path() {
    python3 - "$1" <<'PYEOF'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve())
PYEOF
}

ACTUAL_WS_ROOT="$(git rev-parse --show-toplevel)"
ACTUAL_WS_ROOT="$(_resolve_path "$ACTUAL_WS_ROOT")"

if [[ -n "${AUDITOOOR_WS_ROOT:-}" ]]; then
    OVERRIDE_WS_ROOT="$(_resolve_path "$AUDITOOOR_WS_ROOT")"
    if [[ "$OVERRIDE_WS_ROOT" != "$ACTUAL_WS_ROOT" ]]; then
        echo "[pre-push] REJECTED: AUDITOOOR_WS_ROOT resolves to $OVERRIDE_WS_ROOT, but git is pushing $ACTUAL_WS_ROOT." >&2
        exit 1
    fi
fi

WS_ROOT="$ACTUAL_WS_ROOT"
SENTINEL="$WS_ROOT/.auditooor/last_mcp_recall.json"
BYPASS_LOG="$WS_ROOT/.auditooor/bypass_log.jsonl"
TOKEN_TOOL="${AUDITOOOR_MCP_TOKEN_TOOL:-$WS_ROOT/tools/auditooor_mcp_token.py}"
TOKEN="${AUDITOOOR_MCP_SESSION_TOKEN:-}"

_log_bypass() {
    local reason="$1"
    mkdir -p "$WS_ROOT/.auditooor"
    AUDITOOOR_BYPASS_LOG="$BYPASS_LOG" \
    AUDITOOOR_BYPASS_REASON="$reason" \
    AUDITOOOR_REMOTE_NAME="$REMOTE_NAME" \
    AUDITOOOR_REMOTE_URL="$REMOTE_URL" \
    python3 - <<'PYEOF'
import json, time, os, pathlib
log = pathlib.Path(os.environ["AUDITOOOR_BYPASS_LOG"])
log.parent.mkdir(parents=True, exist_ok=True)
with open(log, "a") as f:
    json.dump({
        "event": "bypass",
        "hook": "pre-push",
        "reason": os.environ.get("AUDITOOOR_BYPASS_REASON", "unknown"),
        "ts": time.time(),
        "iso": __import__('datetime').datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
        "user": os.environ.get("USER", "unknown"),
        "remote_name": os.environ.get("AUDITOOOR_REMOTE_NAME", "unknown"),
        "remote_url": os.environ.get("AUDITOOOR_REMOTE_URL", "unknown"),
    }, f)
    f.write("\n")
PYEOF
}

# ------------------------------------------------------------------
# Bypass path
# ------------------------------------------------------------------
if [[ "$AUDITOOOR_MCP_REQUIRED" == "0" ]]; then
    _log_bypass "AUDITOOOR_MCP_REQUIRED=0"
    echo "[pre-push] MCP push gate bypass logged (AUDITOOOR_MCP_REQUIRED=0)" >&2
    exit 0
fi

# ------------------------------------------------------------------
# Check sentinel existence and freshness
# ------------------------------------------------------------------
if [[ ! -f "$SENTINEL" ]]; then
    echo "[pre-push] REJECTED: .auditooor/last_mcp_recall.json not found." >&2
    echo "[pre-push] Run: bash tools/auditooor-session-start.sh" >&2
    echo "[pre-push] Bypass: AUDITOOOR_MCP_REQUIRED=0 git push ..." >&2
    exit 1
fi

NOW="$(python3 -c 'import time; print(int(time.time()))')"
RECALL_TS="$(AUDITOOOR_RECALL_SENTINEL="$SENTINEL" python3 - <<'PYEOF' 2>/dev/null || echo 0
import json
import os
import pathlib

sentinel = pathlib.Path(os.environ["AUDITOOOR_RECALL_SENTINEL"])
with sentinel.open() as f:
    d = json.load(f)
print(int(d.get("recall_ts", 0)))
PYEOF
)"

AGE=$(( NOW - RECALL_TS ))

if [[ $AGE -gt $AUDITOOOR_RECALL_MAX_AGE_S ]]; then
    echo "[pre-push] REJECTED: MCP recall sentinel is ${AGE}s old (max ${AUDITOOOR_RECALL_MAX_AGE_S}s)." >&2
    echo "[pre-push] Run: bash tools/auditooor-session-start.sh" >&2
    echo "[pre-push] Bypass: AUDITOOOR_MCP_REQUIRED=0 git push ..." >&2
    exit 1
fi

echo "[pre-push] MCP recall sentinel OK (age: ${AGE}s)" >&2

# ------------------------------------------------------------------
# Verify write-scoped MCP session token
# ------------------------------------------------------------------
if [[ -z "$TOKEN" ]]; then
    echo "[pre-push] REJECTED: git push requires AUDITOOOR_MCP_SESSION_TOKEN with write scope." >&2
    echo "[pre-push] Issue: python3 tools/auditooor_mcp_token.py issue --workspace \"\$PWD\" --scope write" >&2
    echo "[pre-push] Bypass: AUDITOOOR_MCP_REQUIRED=0 git push ..." >&2
    exit 1
fi

if [[ ! -x "$TOKEN_TOOL" && ! -f "$TOKEN_TOOL" ]]; then
    echo "[pre-push] REJECTED: token verifier not found at $TOKEN_TOOL." >&2
    echo "[pre-push] Bypass: AUDITOOOR_MCP_REQUIRED=0 git push ..." >&2
    exit 1
fi

if ! python3 "$TOKEN_TOOL" verify "$TOKEN" --require-scope write --require-workspace "$WS_ROOT" >/dev/null 2>&1; then
    echo "[pre-push] REJECTED: invalid MCP session token for workspace $WS_ROOT (scope=write)." >&2
    echo "[pre-push] Issue: python3 tools/auditooor_mcp_token.py issue --workspace \"\$PWD\" --scope write" >&2
    echo "[pre-push] Bypass: AUDITOOOR_MCP_REQUIRED=0 git push ..." >&2
    exit 1
fi

echo "[pre-push] MCP session token OK (scope=write)" >&2
exit 0
HOOK
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_installed_by_us() {
    local hook="$1"
    [[ -f "$hook" ]] && grep -q "auditooor" "$hook" 2>/dev/null
}

_install_hook() {
    local name="$1"
    local target="$HOOKS_DIR/$name"

    if [[ -f "$target" ]] && ! _installed_by_us "$target"; then
        echo "[install-hooks] Backing up existing $name to $target.auditooor-backup"
        cp "$target" "$target.auditooor-backup"
    fi

    if [[ "$name" == "pre-commit" ]]; then
        pre_commit_hook > "$target"
    elif [[ "$name" == "commit-msg" ]]; then
        commit_msg_hook > "$target"
    elif [[ "$name" == "pre-push" ]]; then
        pre_push_hook > "$target"
    fi
    chmod +x "$target"
    echo "[install-hooks] Installed $name hook at $target"
}

_install_session_start_shim() {
    if [[ -x "$SESSION_START_INSTALLER" ]]; then
        bash "$SESSION_START_INSTALLER" install
    else
        echo "[install-hooks] WARNING: session-start shim installer missing at $SESSION_START_INSTALLER" >&2
    fi
}

_uninstall_hook() {
    local name="$1"
    local target="$HOOKS_DIR/$name"

    if [[ ! -f "$target" ]]; then
        echo "[install-hooks] $name hook not present — nothing to remove"
        return
    fi

    if ! _installed_by_us "$target"; then
        echo "[install-hooks] WARNING: $name hook was not installed by us — skipping removal" >&2
        return
    fi

    rm -f "$target"
    echo "[install-hooks] Removed $name hook"

    # Restore backup if present
    if [[ -f "$target.auditooor-backup" ]]; then
        mv "$target.auditooor-backup" "$target"
        echo "[install-hooks] Restored backup $target.auditooor-backup"
    fi
}

_check_hook() {
    local name="$1"
    local target="$HOOKS_DIR/$name"

    if [[ ! -f "$target" ]]; then
        echo "[install-hooks] $name: NOT INSTALLED"
        return
    fi

    if _installed_by_us "$target"; then
        echo "[install-hooks] $name: INSTALLED (auditooor-managed)"
    else
        echo "[install-hooks] $name: PRESENT (foreign — not managed by auditooor)"
    fi
}

_check_session_start_shim() {
    if [[ -x "$SESSION_START_INSTALLER" ]]; then
        bash "$SESSION_START_INSTALLER" check || true
    else
        echo "[install-hooks] session-start shim: INSTALLER MISSING ($SESSION_START_INSTALLER)" >&2
    fi
}

# ---------------------------------------------------------------------------
# R36/R55 wiring helpers
# ---------------------------------------------------------------------------
HOOKS_PATH_TARGET="${AUDITOOOR_HOOKS_PATH_TARGET:-tools/git-hooks}"
SKIP_HOOKS_PATH="${AUDITOOOR_SKIP_HOOKS_PATH:-0}"

R55_WRAPPER_SCRIPTS=(
    "git-reset-safe.sh"
    "git-checkout-safe.sh"
    "git-clean-safe.sh"
    "git-stash-safe.sh"
)

R36_HOOK_SCRIPT="$WS_ROOT/tools/git-hooks/pre-commit-pathspec-discipline.sh"
R55_GATE_SCRIPT="$WS_ROOT/tools/git-hooks/pre-destructive-op-sibling-check.sh"

# Set core.hooksPath so git uses tools/git-hooks/ as the canonical hooks dir.
# This is the central mechanism that makes the R36 hook actually fire when an
# operator runs `git commit` from any worktree of this repo. Idempotent: if
# core.hooksPath is already the target value, this is a no-op (informational).
# Safety: only set if the target dir exists in the workspace AND contains the
# canonical pre-commit-pathspec-discipline.sh - otherwise we'd point git at an
# empty/nonexistent dir and silently disable all hooks. Test/temp repos that
# do not bundle the tools/git-hooks/ tree will see a warn-skip.
_set_hooks_path() {
    if [[ "$SKIP_HOOKS_PATH" == "1" ]]; then
        echo "[install-hooks] AUDITOOOR_SKIP_HOOKS_PATH=1 - leaving core.hooksPath alone"
        return 0
    fi
    local target_abs="$WS_ROOT/$HOOKS_PATH_TARGET"
    if [[ ! -d "$target_abs" ]] || [[ ! -f "$target_abs/pre-commit-pathspec-discipline.sh" ]]; then
        echo "[install-hooks] core.hooksPath skip: '$target_abs' missing or lacks pre-commit-pathspec-discipline.sh"
        echo "[install-hooks]   (workspace does not bundle tools/git-hooks/; not an auditooor repo - safe to skip)"
        return 0
    fi
    local current
    current="$(git -C "$WS_ROOT" config --get core.hooksPath 2>/dev/null || true)"
    if [[ "$current" == "$HOOKS_PATH_TARGET" ]]; then
        echo "[install-hooks] core.hooksPath already set to '$HOOKS_PATH_TARGET' (no change)"
        return 0
    fi
    git -C "$WS_ROOT" config core.hooksPath "$HOOKS_PATH_TARGET"
    echo "[install-hooks] core.hooksPath set: '$current' -> '$HOOKS_PATH_TARGET'"
}

# Verify the R36 hook script exists + is executable. Silent-skip when not
# present (test/temp repos that do not bundle the tools/git-hooks/ tree).
_check_r36_hook() {
    if [[ ! -f "$R36_HOOK_SCRIPT" ]]; then
        echo "[install-hooks] R36 hook: NOT BUNDLED ($R36_HOOK_SCRIPT) - skipping"
        return 0
    fi
    if [[ ! -x "$R36_HOOK_SCRIPT" ]]; then
        echo "[install-hooks] R36 hook: not executable - fixing..."
        chmod +x "$R36_HOOK_SCRIPT"
    fi
    echo "[install-hooks] R36 hook: INSTALLED + executable ($R36_HOOK_SCRIPT)"
    return 0
}

# Verify the R55 gate script + wrapper scripts exist + are executable. Silent-
# skip when not bundled.
_check_r55_wrappers() {
    if [[ ! -f "$R55_GATE_SCRIPT" ]]; then
        echo "[install-hooks] R55 gate script: NOT BUNDLED ($R55_GATE_SCRIPT) - skipping"
        return 0
    fi
    [[ ! -x "$R55_GATE_SCRIPT" ]] && chmod +x "$R55_GATE_SCRIPT"
    echo "[install-hooks] R55 gate script: INSTALLED + executable ($R55_GATE_SCRIPT)"
    local rc=0
    for w in "${R55_WRAPPER_SCRIPTS[@]}"; do
        local p="$WS_ROOT/tools/git-hooks/$w"
        if [[ ! -f "$p" ]]; then
            echo "[install-hooks] R55 wrapper $w: NOT BUNDLED ($p) - skipping"
            continue
        fi
        [[ ! -x "$p" ]] && chmod +x "$p"
        echo "[install-hooks] R55 wrapper $w: INSTALLED + executable ($p)"
    done
    return $rc
}

# Print operator-copy-paste R55 wrapper aliases for shell rc setup.
_print_r55_aliases() {
    cat <<ALIASES

# ============================================================================
# R55 wrapper aliases (add to ~/.zshrc or ~/.bashrc)
#
# R55 doctrine: destructive git ops (\`git reset --hard\`, \`git checkout --\`,
# \`git clean -fd\`, \`git stash drop\`) MUST run the sibling-pathspec gate
# before chaining to the real git command. Mainline git (as of 2.39) lacks
# pre-reset / pre-checkout / pre-clean hooks, so wrappers are the only viable
# enforcement. Override per-call: R55_REBUTTAL='reason' git-reset --hard HEAD.
# ============================================================================

# (a) Hyphenated alias form (least invasive; you opt in by typing git-reset):
alias git-reset='bash \$(git rev-parse --show-toplevel)/tools/git-hooks/git-reset-safe.sh'
alias git-checkout='bash \$(git rev-parse --show-toplevel)/tools/git-hooks/git-checkout-safe.sh'
alias git-clean='bash \$(git rev-parse --show-toplevel)/tools/git-hooks/git-clean-safe.sh'
alias git-stash='bash \$(git rev-parse --show-toplevel)/tools/git-hooks/git-stash-safe.sh'

# (b) Full enforcement (shell function override of \`git\` - advanced):
# git() {
#   case "\$1" in
#     reset)
#       shift; bash "\$(command git rev-parse --show-toplevel)/tools/git-hooks/git-reset-safe.sh" "\$@"
#       return \$?
#       ;;
#     checkout)
#       shift; bash "\$(command git rev-parse --show-toplevel)/tools/git-hooks/git-checkout-safe.sh" "\$@"
#       return \$?
#       ;;
#     clean)
#       shift; bash "\$(command git rev-parse --show-toplevel)/tools/git-hooks/git-clean-safe.sh" "\$@"
#       return \$?
#       ;;
#     stash)
#       shift; bash "\$(command git rev-parse --show-toplevel)/tools/git-hooks/git-stash-safe.sh" "\$@"
#       return \$?
#       ;;
#     *)
#       command git "\$@"
#       ;;
#   esac
# }
ALIASES
}

# Dogfood: verify install end-to-end.
#  (1) core.hooksPath is set to tools/git-hooks (or operator override)
#  (2) tools/git-hooks/pre-commit exists + is executable
#  (3) R36 hook script + R55 wrappers all present + executable
#  (4) the in-repo pre-commit successfully delegates to the R36 hook
#       (smoke-test: invoke the in-repo pre-commit, expect rc=0 when no
#       sibling-pathspec violation present)
_dogfood() {
    local failures=0

    echo "[dogfood] (1/4) core.hooksPath..."
    local current
    current="$(git -C "$WS_ROOT" config --get core.hooksPath 2>/dev/null || true)"
    if [[ "$current" == "$HOOKS_PATH_TARGET" ]]; then
        echo "  OK: core.hooksPath = '$current'"
    else
        echo "  FAIL: core.hooksPath = '$current' (expected '$HOOKS_PATH_TARGET')" >&2
        failures=$((failures+1))
    fi

    echo "[dogfood] (2/4) tools/git-hooks/pre-commit present + executable..."
    local pc="$WS_ROOT/tools/git-hooks/pre-commit"
    if [[ -x "$pc" ]]; then
        echo "  OK: $pc is executable"
    else
        echo "  FAIL: $pc missing or not executable" >&2
        failures=$((failures+1))
    fi

    echo "[dogfood] (3/4) R36 hook + R55 gate + R55 wrappers..."
    _check_r36_hook || failures=$((failures+1))
    _check_r55_wrappers || failures=$((failures+1))

    echo "[dogfood] (4/4) in-repo pre-commit smoke test (no sibling violation)..."
    # Invoke pre-commit directly. With nothing staged it should pass (R36 hook
    # exits 0 on empty stage). Bypass the MCP recall check so we test only the
    # chain integrity. Capture stderr; rc=0 expected.
    if [[ -x "$pc" ]]; then
        local smoke_out smoke_rc
        smoke_out="$(AUDITOOOR_MCP_REQUIRED=0 bash "$pc" 2>&1)" && smoke_rc=$? || smoke_rc=$?
        if [[ "$smoke_rc" == "0" ]]; then
            echo "  OK: pre-commit smoke (rc=0). Output:"
            echo "$smoke_out" | sed 's/^/    /'
        else
            echo "  FAIL: pre-commit smoke rc=$smoke_rc. Output:" >&2
            echo "$smoke_out" | sed 's/^/    /' >&2
            failures=$((failures+1))
        fi
    else
        echo "  SKIP: pre-commit not present at $pc"
    fi

    echo ""
    if [[ "$failures" -eq 0 ]]; then
        echo "[dogfood] PASS: all 4 checks green"
        return 0
    else
        echo "[dogfood] FAIL: $failures check(s) failed" >&2
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Subcommand dispatch
# ---------------------------------------------------------------------------
CMD="${1:---help}"

case "$CMD" in
    install)
        _install_hook "pre-commit"
        _install_hook "commit-msg"
        _install_hook "pre-push"
        _install_session_start_shim
        _set_hooks_path
        _check_r36_hook
        _check_r55_wrappers
        echo "[install-hooks] Done. Hooks directory: $HOOKS_DIR"
        echo "[install-hooks] core.hooksPath: $(git -C "$WS_ROOT" config --get core.hooksPath 2>/dev/null || echo '(unset)')"
        echo ""
        echo "[install-hooks] R55 wrappers require shell-alias setup. Run:"
        echo "    bash tools/install-hooks.sh print-aliases >> ~/.zshrc"
        echo "  (or copy the aliases manually). Then reload your shell."
        ;;
    uninstall)
        _uninstall_hook "pre-commit"
        _uninstall_hook "commit-msg"
        _uninstall_hook "pre-push"
        echo "[install-hooks] Done. NOTE: core.hooksPath was NOT reset; remove"
        echo "[install-hooks] manually with 'git config --unset core.hooksPath' if desired."
        ;;
    check)
        echo "[install-hooks] Hooks directory: $HOOKS_DIR"
        _check_hook "pre-commit"
        _check_hook "commit-msg"
        _check_hook "pre-push"
        _check_session_start_shim
        echo "[install-hooks] core.hooksPath: $(git -C "$WS_ROOT" config --get core.hooksPath 2>/dev/null || echo '(unset)')"
        _check_r36_hook || true
        _check_r55_wrappers || true
        ;;
    dogfood)
        _dogfood
        ;;
    print-aliases)
        _print_r55_aliases
        ;;
    --help|-h|help)
        grep '^#' "$0" | sed 's/^# //' | sed 's/^#//'
        ;;
    *)
        echo "[install-hooks] Unknown subcommand: $CMD" >&2
        echo "Usage: bash tools/install-hooks.sh [install|uninstall|check|dogfood|print-aliases|--help]" >&2
        exit 1
        ;;
esac
