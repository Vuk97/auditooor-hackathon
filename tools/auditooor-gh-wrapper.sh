#!/usr/bin/env bash
# auditooor-gh-wrapper.sh — MCP-gated gh CLI wrapper.
# Lane 7 of MCP harness review (PR #658) commit 8.
# Wave-6 E-2: freshness gate added (AUDITOOOR_RECALL_MAX_AGE_S, default 1800 s).
#
# Gates: gh pr create, gh pr comment, gh pr edit, gh pr close, gh pr merge,
#        gh issue create, gh issue comment, gh issue close, gh release create
# Pass-through: gh pr view/list, gh issue view/list, gh repo view, etc. (read-only)
#
# Freshness gate (Wave-6 E-2):
#   Checks .auditooor/last_mcp_recall.json exists and recall_ts is within
#   AUDITOOOR_RECALL_MAX_AGE_S seconds (default 1800).
#   Bypass (transition): AUDITOOOR_NO_FRESHNESS_CHECK=1 skips freshness only.
#
# Bypass (full): AUDITOOOR_MCP_REQUIRED=0 logs to .auditooor/bypass_log.jsonl + continues.

set -uo pipefail

REAL_GH="${AUDITOOOR_REAL_GH:-$(command -v -p gh 2>/dev/null || echo /opt/homebrew/bin/gh)}"
[ -x "$REAL_GH" ] || REAL_GH="/usr/local/bin/gh"

# ANTI-HANG (generic): bound EVERY real-gh invocation with a timeout so a blocked
# macOS keychain / expired token with no TTY to refresh on (which made `gh auth
# token` hang forever and stall `make audit`) can NEVER hang the audit pipeline.
# On timeout, gh returns non-zero and the calling tool falls back (commit-mining
# -> local git history; pin/redirect checks -> unauthenticated public API).
# Configurable via AUDITOOOR_GH_TIMEOUT_S (default 30). 0/empty disables.
#
# COMMAND-AWARE (Axelar known-issues intake 2026-07-12): the tight 30s cap exists
# ONLY for the auth/token path that actually hangs on a keychain prompt. Applying
# 30s to a read-only BULK data command (issue/pr list, api, search) that
# legitimately paginates minutes of results on a large repo (e.g. 558 axelar-core
# issues WITH bodies) SILENTLY TRUNCATED it to empty at exactly 30s -> callers
# read non-zero + no output and fell back to UNAUTHENTICATED curl, degrading the
# whole enumeration. So bulk read-only data commands get AUDITOOOR_GH_READ_TIMEOUT_S
# (default 300s): still bounded (pipeline never hangs FOREVER, the real anti-hang
# requirement) but long enough to complete. auth/token keep the tight cap.
_GH_TIMEOUT_BIN="$(command -v timeout 2>/dev/null || command -v gtimeout 2>/dev/null || true)"
_GH_TIMEOUT_S="${AUDITOOOR_GH_TIMEOUT_S:-30}"
_GH_READ_TIMEOUT_S="${AUDITOOOR_GH_READ_TIMEOUT_S:-300}"
_gh_effective_timeout() {  # echo the timeout (s) for this gh invocation's args
  local _first="" _second=""
  for _a in "$@"; do
    case "$_a" in -*) ;; *)
      if [ -z "$_first" ]; then _first="$_a"
      elif [ -z "$_second" ]; then _second="$_a"; break; fi ;;
    esac
  done
  case "$_first $_second" in
    "api "*|"search "*|*" list"|*" view"|*" ls") echo "$_GH_READ_TIMEOUT_S" ;;
    api|search)                                   echo "$_GH_READ_TIMEOUT_S" ;;
    *)                                            echo "$_GH_TIMEOUT_S" ;;
  esac
}
_gh_exec() {  # exec real gh, time-bounded when a timeout binary is available
  local _t; _t="$(_gh_effective_timeout "$@")"
  if [ -n "$_GH_TIMEOUT_BIN" ] && [ -n "$_t" ] && [ "$_t" != "0" ]; then
    exec "$_GH_TIMEOUT_BIN" "$_t" "$REAL_GH" "$@"
  fi
  exec "$REAL_GH" "$@"
}
WRAPPER_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOKEN_TOOL="${SCRIPT_DIR}/auditooor_mcp_token.py"
REQUIRE_SCOPE="write"
WORKSPACE="${AUDITOOOR_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")}"

# Detect gated 2-arg subcommands like "pr create", "issue comment"
GATED_PAIRS_RE='^(pr (create|comment|edit|close|merge|reopen|review))|(issue (create|comment|edit|close|reopen))|(release (create|edit|delete))$'

# Build first 2 non-flag args
ARG_BUF=()
for arg in "$@"; do
  case "$arg" in -*) ;; *) ARG_BUF+=("$arg") ;; esac
  [ ${#ARG_BUF[@]} -eq 2 ] && break
done
PAIR="${ARG_BUF[0]:-} ${ARG_BUF[1]:-}"

if [[ ! "$PAIR" =~ $GATED_PAIRS_RE ]]; then
  _gh_exec "$@"
fi

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
      "$TS" "$WRAPPER_NAME" "$PAIR" "$$" "$PPID" >> "$LOG_DIR/bypass_log.jsonl"
    echo "[mcp-gate:$WRAPPER_NAME] BYPASS active (logged)" >&2
  else
    cat >&2 <<EOF
[mcp-gate:$WRAPPER_NAME] BLOCKED: 'gh $PAIR' requires a valid MCP session token
   Issue token: python3 ${SCRIPT_DIR}/auditooor_mcp_token.py issue --workspace \$PWD
   Override: AUDITOOOR_MCP_REQUIRED=0 gh $PAIR ...
EOF
    exit 1
  fi
fi

_gh_exec "${FILTERED[@]}"
