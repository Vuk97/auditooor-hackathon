#!/usr/bin/env bash
# auditooor-git-wrapper.sh — MCP-gated git wrapper.
# Lane 7 of MCP harness review (PR #658) commit 8 (worker a46b7c83ce8d8846e design).
# Wave-6 E-2: freshness gate added (AUDITOOOR_RECALL_MAX_AGE_S, default 1800 s).
#
# Gates: git commit, git push (incl. --force, --amend, --rebase commit-mode)
# Pass-through: git log, git status, git diff, git show, git fetch (read-only)
#
# Token resolution:
#   1. --mcp-token=<token> arg
#   2. $AUDITOOOR_MCP_SESSION_TOKEN env var
#
# Freshness gate (Wave-6 E-2):
#   Checks .auditooor/last_mcp_recall.json exists and recall_ts is within
#   AUDITOOOR_RECALL_MAX_AGE_S seconds (default 1800).
#   Bypass (transition): AUDITOOOR_NO_FRESHNESS_CHECK=1 skips freshness only.
#
# Bypass (full): AUDITOOOR_MCP_REQUIRED=0 logs to .auditooor/bypass_log.jsonl + continues.

set -uo pipefail

REAL_GIT="${AUDITOOOR_REAL_GIT:-/usr/bin/git}"
[ -x "$REAL_GIT" ] || REAL_GIT="$(command -v -p git 2>/dev/null || echo /usr/bin/git)"
WRAPPER_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOKEN_TOOL="${SCRIPT_DIR}/auditooor_mcp_token.py"
REQUIRE_SCOPE="write"
BYPASS_LOG_REL=".auditooor/bypass_log.jsonl"

# Workspace: prefer git-toplevel, else $PWD
WORKSPACE="${AUDITOOOR_WORKSPACE:-$($REAL_GIT rev-parse --show-toplevel 2>/dev/null || echo "$PWD")}"

# Determine if subcommand is gated.
GATED_SUBCMDS_RE='^(commit|push|am|merge|rebase|cherry-pick|revert)$'

is_gated() {
  local sub="$1"
  [[ "$sub" =~ $GATED_SUBCMDS_RE ]] && return 0
  return 1
}

# Find first non-flag argument (the subcommand)
SUB=""
for arg in "$@"; do
  case "$arg" in
    -*) ;;
    *) SUB="$arg"; break ;;
  esac
done

if ! is_gated "$SUB"; then
  exec "$REAL_GIT" "$@"
fi

# Extract --mcp-token=<...> if present, then strip from args
TOKEN="${AUDITOOOR_MCP_SESSION_TOKEN:-}"
FILTERED=()
for arg in "$@"; do
  case "$arg" in
    --mcp-token=*) TOKEN="${arg#--mcp-token=}" ;;
    *) FILTERED+=("$arg") ;;
  esac
done

# ---------------------------------------------------------------------------
# Wave-6 E-2: MCP recall freshness gate
# Bypass for transition period: AUDITOOOR_NO_FRESHNESS_CHECK=1
# Full bypass (audit-logged): AUDITOOOR_MCP_REQUIRED=0
# ---------------------------------------------------------------------------
if [ -z "${AUDITOOOR_NO_FRESHNESS_CHECK:-}" ]; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  RECALL="$WS/.auditooor/last_mcp_recall.json"
  if [ ! -f "$RECALL" ]; then
    echo "[$WRAPPER_NAME] REJECTED: no .auditooor/last_mcp_recall.json. Run: bash $SCRIPT_DIR/auditooor-session-start.sh" >&2
    if [ "${AUDITOOOR_MCP_REQUIRED:-1}" = "0" ]; then
      echo "[$WRAPPER_NAME] AUDITOOOR_MCP_REQUIRED=0 bypass (logged)" >&2
      mkdir -p "$WS/.auditooor"
      printf '{"ts":"%s","event":"bypass","tool":"%s","reason":"no_recall_file"}\n' \
        "$(date -u +%FT%TZ)" "$WRAPPER_NAME" >> "$WS/.auditooor/bypass_log.jsonl"
    else
      exit 1
    fi
  else
    _RECALL_TS="$(python3 -c "import json; d=json.load(open('$RECALL')); print(int(d.get('recall_ts',0)))" 2>/dev/null || echo 0)"
    _NOW="$(date +%s)"
    _AGE_S=$(( _NOW - _RECALL_TS ))
    _MAX_AGE="${AUDITOOOR_RECALL_MAX_AGE_S:-1800}"
    if [ "$_AGE_S" -gt "$_MAX_AGE" ]; then
      echo "[$WRAPPER_NAME] REJECTED: MCP recall stale (${_AGE_S}s > ${_MAX_AGE}s). Re-run: bash $SCRIPT_DIR/auditooor-session-start.sh" >&2
      if [ "${AUDITOOOR_MCP_REQUIRED:-1}" = "0" ]; then
        echo "[$WRAPPER_NAME] AUDITOOOR_MCP_REQUIRED=0 bypass (logged)" >&2
        mkdir -p "$WS/.auditooor"
        printf '{"ts":"%s","event":"bypass","tool":"%s","reason":"recall_stale","age_s":%d}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$_AGE_S" >> "$WS/.auditooor/bypass_log.jsonl"
      else
        exit 1
      fi
    fi
  fi
fi

# Verify token
GATE_PASS=0
if [ -n "$TOKEN" ] && [ -x "$TOKEN_TOOL" ]; then
  if python3 "$TOKEN_TOOL" verify "$TOKEN" --require-scope "$REQUIRE_SCOPE" --require-workspace "$WORKSPACE" >/dev/null 2>&1; then
    GATE_PASS=1
  fi
fi

if [ "$GATE_PASS" -eq 0 ]; then
  BYPASS="${AUDITOOOR_MCP_REQUIRED:-1}"
  if [ "$BYPASS" = "0" ]; then
    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    LOG_DIR="$WORKSPACE/.auditooor"
    mkdir -p "$LOG_DIR"
    printf '{"ts":"%s","wrapper":"%s","subcmd":"%s","pid":%d,"ppid":%d,"reason":"AUDITOOOR_MCP_REQUIRED=0"}\n' \
      "$TS" "$WRAPPER_NAME" "$SUB" "$$" "$PPID" >> "$LOG_DIR/bypass_log.jsonl"
    echo "[mcp-gate:$WRAPPER_NAME] BYPASS active (logged to $BYPASS_LOG_REL)" >&2
  else
    cat >&2 <<EOF
[mcp-gate:$WRAPPER_NAME] BLOCKED: 'git $SUB' requires a valid MCP session token (scope=$REQUIRE_SCOPE)
   Set AUDITOOOR_MCP_SESSION_TOKEN env var, or pass --mcp-token=<token>
   Issue token:
     python3 ${SCRIPT_DIR}/auditooor_mcp_token.py issue --workspace \$PWD
   Or override (audit-logged):
     AUDITOOOR_MCP_REQUIRED=0 git $SUB ...
EOF
    exit 1
  fi
fi

exec "$REAL_GIT" "${FILTERED[@]}"
