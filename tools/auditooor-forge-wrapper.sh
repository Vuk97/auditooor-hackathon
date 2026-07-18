#!/usr/bin/env bash
# auditooor-forge-wrapper.sh — MCP-gated Foundry forge wrapper.
# Lane 7 of MCP harness review (PR #658).
# Wave-6 E-2: freshness gate added (AUDITOOOR_RECALL_MAX_AGE_S, default 1800 s).
#
# Gates: script, create, send, verify-contract (write/deploy class)
# Pass-through: build, test, fmt, coverage, tree, inspect (read-only)
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

WRAPPER_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

resolve_real_binary() {
  local override="$1"
  local tool_name="$2"
  shift 2

  if [ -n "$override" ]; then
    printf '%s\n' "$override"
    return 0
  fi

  local candidate
  for candidate in "$@"; do
    if [ -n "$candidate" ] && [ -x "$candidate" ] && ! [ "$candidate" -ef "$0" ] 2>/dev/null; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  local old_ifs="$IFS"
  local dir
  IFS=:
  for dir in ${PATH:-}; do
    IFS="$old_ifs"
    [ -n "$dir" ] || dir=.
    candidate="$dir/$tool_name"
    if [ -x "$candidate" ] && ! [ "$candidate" -ef "$0" ] 2>/dev/null; then
      printf '%s\n' "$candidate"
      return 0
    fi
    IFS=:
  done
  IFS="$old_ifs"
  return 1
}

REAL_FORGE="$(resolve_real_binary \
  "${AUDITOOOR_REAL_FORGE:-}" \
  forge \
  "${HOME:-}/.foundry/bin/forge" \
  /opt/homebrew/bin/forge \
  /usr/local/bin/forge \
  /usr/bin/forge)"
if [ -z "$REAL_FORGE" ] || [ ! -x "$REAL_FORGE" ]; then
  echo "[auditooor-forge-wrapper.sh] ERROR: real forge binary not found. Set AUDITOOOR_REAL_FORGE=/path/to/forge." >&2
  exit 127
fi
TOKEN_TOOL="${SCRIPT_DIR}/auditooor_mcp_token.py"
REQUIRE_SCOPE="write"
BYPASS_LOG_REL=".auditooor/bypass_log.jsonl"

# Workspace: prefer git-toplevel, else $PWD
WORKSPACE="${AUDITOOOR_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")}"

# Gated subcommands: write/deploy class
GATED_SUBCMDS_RE='^(script|create|send|verify-contract)$'

is_gated() {
  local sub="$1"
  [[ "$sub" =~ $GATED_SUBCMDS_RE ]] && return 0
  return 1
}

# Find first non-flag argument (the subcommand)
SUB=""
for arg in "$@"; do
  case "$arg" in
    --help|--version) exec "$REAL_FORGE" "$@" ;;
    -*) ;;
    *) SUB="$arg"; break ;;
  esac
done

if ! is_gated "$SUB"; then
  exec "$REAL_FORGE" "$@"
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
[mcp-gate:$WRAPPER_NAME] BLOCKED: 'forge $SUB' requires a valid MCP session token (scope=$REQUIRE_SCOPE)
   Set AUDITOOOR_MCP_SESSION_TOKEN env var, or pass --mcp-token=<token>
   Issue token:
     python3 ${SCRIPT_DIR}/auditooor_mcp_token.py issue --workspace \$PWD
   Or override (audit-logged):
     AUDITOOOR_MCP_REQUIRED=0 forge $SUB ...
EOF
    exit 1
  fi
fi

exec "$REAL_FORGE" "${FILTERED[@]}"
