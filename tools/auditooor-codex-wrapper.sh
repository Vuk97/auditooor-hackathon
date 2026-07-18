#!/usr/bin/env bash
# auditooor-codex-wrapper.sh — MCP-gated Codex CLI wrapper.
# Lane 7 of MCP harness review (PR #658).
# Wave-6 E-2: freshness gate added (AUDITOOOR_RECALL_MAX_AGE_S, default 1800 s).
# Gap #72 (2026-05-26): pre-submit-check chaining for submit/apply that touch
#   submissions/<status>/<slug>/<slug>.md drafts.
# Gap #76 (2026-05-26): pre-write gate (L34 v2 path classifier) for apply
#   against draft files + pre-subagent-spawn gate (R64 prompt-claim verifier)
#   on exec/e/review/resume/fork/cloud subcommands. Closes Codex-side parity
#   with the Claude Code Agent-dispatch enforcement surface.
#
# Gates: exec, e, run, submit, apply, review, resume, fork, cloud, make audit-class targets
# Pass-through: --help, --version, list, status (read-only)
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
#
# Finalization gate:
#   Before write/dispatch-class Codex commands, checks the active dispatch
#   manifest for terminal rows that lack canonical task-finalization closure.
#   Bypass: AUDITOOOR_NO_FINALIZATION_CHECK=1 skips this gate.
#
# Pre-submit-check gate (Gap #72, 2026-05-26):
#   For `submit` / `apply` subcommands, scans args for any draft path matching
#   submissions/(staging|paste_ready|filed|packaged|held|superseded|_killed|_oos_rejected)/<slug>/<slug>.md.
#   For each detected draft, invokes `tools/pre-submit-check.sh <draft>`. Any
#   non-zero exit refuses the codex submit/apply unless rebuttal:
#     - AUDITOOOR_NO_PRESUBMIT_CHECK=1 (audit-logged bypass)
#     - <!-- codex-presubmit-rebuttal: <reason> --> in the draft body
#   Closes the ~80% cross-CLI parity gap (Codex CLI now enforces 81+ R-rule
#   pre-submit checks the same as Claude Code).
#
# Pre-write gate (Gap #76, 2026-05-26):
#   For `apply` subcommands targeting paths classified as `draft-file` by
#   tools/l34-path-classifier.py (per-finding-folder draft + siblings), refuse
#   the apply unless one of the rebuttals fires:
#     - CODEX_NO_PREWRITE_CHECK=1 (audit-logged bypass)
#     - L34-DRAFT-AUTHORIZED=<slug> env var per-draft authorization
#     - <!-- l34-rebuttal: <reason> --> in the existing draft body (apply re-edit)
#   Auto-executable buckets (tracker-file / workspace-ledger / lesson-anchor /
#   out-of-scope) pass through without per-draft auth.
#
# Pre-subagent-spawn gate (Gap #76, 2026-05-26):
#   For `exec` / `e` / `review` / `resume` / `fork` / `cloud` subcommands, the
#   Codex CLI is being asked to spawn a sub-agent with a prompt. Codex's
#   sub-agent dispatch is the equivalent of Claude Code's Agent/Task tool call.
#   The wrapper extracts the prompt (positional arg or --prompt-file=<path> or
#   stdin) and runs `tools/r64-prompt-claim-verifier.py --strict` on it. Any
#   unverified factual claim refuses the spawn unless rebuttal:
#     - CODEX_NO_SUBAGENT_CHECK=1 (audit-logged bypass)
#     - <!-- r64-rebuttal: <reason> --> in the prompt body
#     - AUDITOOOR_R64_REBUTTAL=<reason> env var (session-scope)
#   The verifier reads tools/canonical-inventory.py snapshot (24h TTL) so it
#   does not call out to MCP each spawn. After R64 passes, the wrapper also
#   injects the dispatch-agent-with-prebriefing META-1 Section 15 block unless
#   CODEX_NO_META1_INJECT=1 is set.
#
# Corpus refresh parity (P9, 2026-05-28):
#   After a successful `apply`, pass each path-like argument through
#   tools/hooks/auditooor-corpus-change-refresh.sh using a synthetic PostToolUse
#   payload. The hook itself decides whether the path is a corpus path and stays
#   fail-open. Bypass: AUDITOOOR_CODEX_NO_CORPUS_REFRESH=1.

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

REAL_CODEX="$(resolve_real_binary \
  "${AUDITOOOR_REAL_CODEX:-}" \
  codex \
  "${HOME:-}/.local/bin/codex" \
  /opt/homebrew/bin/codex \
  /usr/local/bin/codex \
  /usr/bin/codex)"
if [ -z "$REAL_CODEX" ] || [ ! -x "$REAL_CODEX" ]; then
  echo "[auditooor-codex-wrapper.sh] ERROR: real codex binary not found. Set AUDITOOOR_REAL_CODEX=/path/to/codex." >&2
  exit 127
fi
TOKEN_TOOL="${SCRIPT_DIR}/auditooor_mcp_token.py"
FINALIZATION_TOOL="${SCRIPT_DIR}/task-finalization-ledger.py"
DISPATCH_PREFLIGHT_TOOL="${SCRIPT_DIR}/dispatch-agent-with-prebriefing.py"
CORPUS_REFRESH_HOOK="${AUDITOOOR_CODEX_CORPUS_REFRESH_HOOK:-${SCRIPT_DIR}/hooks/auditooor-corpus-change-refresh.sh}"
REQUIRE_SCOPE="write"
BYPASS_LOG_REL=".auditooor/bypass_log.jsonl"

# Workspace: prefer git-toplevel, else $PWD
WORKSPACE="${AUDITOOOR_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")}"

# Gated subcommands: write/dispatch class.
# Gap #76 (2026-05-26): adds sub-agent-spawn surfaces (e=exec alias, review,
# resume, fork, cloud) so R64 prompt-claim verification fires before Codex
# spawns a sub-agent with a possibly hallucinated prompt.
GATED_SUBCMDS_RE='^(exec|e|run|submit|apply|review|resume|fork|cloud|make)$'

# Sub-agent-spawn subset: subcommands that take a PROMPT and dispatch a worker.
# These run R64 prompt-claim verification.
SUBAGENT_SPAWN_SUBCMDS_RE='^(exec|e|review|resume|fork|cloud)$'

# Write-targeting subset: subcommands that write to draft/finding-folder paths.
# These run L34 path classification + per-draft auth check (Gap #76 pre-write).
WRITE_TARGETING_SUBCMDS_RE='^(apply)$'

is_gated() {
  local sub="$1"
  [[ "$sub" =~ $GATED_SUBCMDS_RE ]] && return 0
  return 1
}

is_subagent_spawn() {
  local sub="$1"
  [[ "$sub" =~ $SUBAGENT_SPAWN_SUBCMDS_RE ]] && return 0
  return 1
}

is_write_targeting() {
  local sub="$1"
  [[ "$sub" =~ $WRITE_TARGETING_SUBCMDS_RE ]] && return 0
  return 1
}

is_gated_make_target() {
  local seen_make=0
  local arg
  for arg in "$@"; do
    if [ "$seen_make" -eq 0 ]; then
      [ "$arg" = "make" ] && seen_make=1
      continue
    fi
    case "$arg" in
      -*|*=*) continue ;;
    esac
    case "$arg" in
      audit|audit-deep|hunt|hunt-full|v3-source-first-audit)
        return 0
        ;;
      *)
        return 1
        ;;
    esac
  done
  return 1
}

inject_meta1_into_codex_prompt() {
  # Best-effort Codex subagent parity: prepend the same META-1 Section 15
  # block Claude workers receive. Failure is warn-only because R64 already
  # handled fail-closed prompt-claim verification above.
  [ -z "${CODEX_NO_META1_INJECT:-}" ] || {
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"bypass-env","reason":"CODEX_NO_META1_INJECT=1"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
    echo "[$WRAPPER_NAME] META-1 injection BYPASS: CODEX_NO_META1_INJECT=1 (logged)" >&2
    return 0
  }
  [ -f "$DISPATCH_PREFLIGHT_TOOL" ] || {
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"warn-meta1-tool-missing","tool_path":"%s"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$DISPATCH_PREFLIGHT_TOOL" >> "$R64_LOG"
    return 0
  }
  [ -n "${PROMPT_TMP:-}" ] && [ -f "$PROMPT_TMP" ] || return 0
  if grep -q 'BEGIN dispatch-agent-with-prebriefing META-1 block' "$PROMPT_TMP" 2>/dev/null; then
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"pass-meta1-already-present"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
    return 0
  fi

  local enriched_tmp enriched_err
  enriched_tmp="$(mktemp -t codex-meta1-prompt.XXXXXX)"
  enriched_err="${enriched_tmp}.stderr"
  local meta1_rc
  python3 "$DISPATCH_PREFLIGHT_TOOL" \
      --prompt-file "$PROMPT_TMP" \
      --workspace "$WS" \
      --json-meta > "$enriched_tmp" 2>"$enriched_err"
  meta1_rc=$?
  if [ "$meta1_rc" -ne 0 ]; then
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"warn-meta1-inject-failed","rc":%d}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$meta1_rc" >> "$R64_LOG"
    rm -f "$enriched_tmp" "$enriched_err"
    return 0
  fi

  local enriched_text
  enriched_text="$(cat "$enriched_tmp" 2>/dev/null || true)"
  if [ -z "$enriched_text" ]; then
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"warn-meta1-empty"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
    rm -f "$enriched_tmp" "$enriched_err"
    return 0
  fi

  local -a new_filtered
  new_filtered=()
  local sub_seen=0
  local replaced=0
  local arg
  for arg in "${FILTERED[@]}"; do
    case "$arg" in
      --prompt-file=*)
        if [ "$replaced" -eq 0 ]; then
          new_filtered+=("--prompt-file=$enriched_tmp")
          replaced=1
        else
          new_filtered+=("$arg")
        fi
        ;;
      --prompt=*)
        if [ "$replaced" -eq 0 ]; then
          new_filtered+=("--prompt=$enriched_text")
          replaced=1
          rm -f "$enriched_tmp"
        else
          new_filtered+=("$arg")
        fi
        ;;
      *)
        if [ "$sub_seen" -eq 0 ] && [ "$arg" = "$SUB" ]; then
          sub_seen=1
          new_filtered+=("$arg")
        elif [ "$sub_seen" -eq 1 ] && [ "$replaced" -eq 0 ] && [ -z "${PROMPT_PATH:-}" ] && [ -n "${PROMPT_INLINE:-}" ] && [ "$arg" = "$PROMPT_INLINE" ]; then
          new_filtered+=("$enriched_text")
          replaced=1
          rm -f "$enriched_tmp"
        else
          new_filtered+=("$arg")
        fi
        ;;
    esac
  done

  if [ "$replaced" -eq 1 ]; then
    FILTERED=("${new_filtered[@]}")
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"pass-meta1-injected","prompt_file":"%s"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$enriched_tmp" >> "$R64_LOG"
    echo "[$WRAPPER_NAME] META-1 prompt block injected for Codex subagent spawn" >&2
  else
    rm -f "$enriched_tmp"
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"warn-meta1-no-replace"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
  fi
  rm -f "$enriched_err"
  return 0
}

trigger_corpus_refresh_after_apply() {
  [ "$SUB" = "apply" ] || return 0
  [ "$1" -eq 0 ] || return 0
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  [ -z "${AUDITOOOR_CODEX_NO_CORPUS_REFRESH:-}" ] || {
    mkdir -p "$WS/.auditooor"
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"bypass-env","reason":"AUDITOOOR_CODEX_NO_CORPUS_REFRESH=1"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$WS/.auditooor/codex_corpus_refresh_gate.jsonl"
    return 0
  }
  [ -x "$CORPUS_REFRESH_HOOK" ] || [ -f "$CORPUS_REFRESH_HOOK" ] || return 0
  mkdir -p "$WS/.auditooor"
  local refresh_log="$WS/.auditooor/codex_corpus_refresh_gate.jsonl"
  local arg target fired=0
  for arg in "${FILTERED[@]}"; do
    case "$arg" in
      -*|"$SUB") continue ;;
    esac
    case "$arg" in
      *audit/corpus_tags/*|*obsidian-vault/anti-patterns/*|*obsidian-vault/mining/*|*reference/patterns.dsl*/*)
        target="$arg"
        ;;
      *)
        continue
        ;;
    esac
    if [[ "$target" != /* ]]; then
      target="$WS/$target"
    fi
    python3 - "$target" <<'PY' | bash "$CORPUS_REFRESH_HOOK" >/dev/null 2>&1 || true
import json, sys
print(json.dumps({
    "tool_name": "Bash",
    "tool_input": {
        "command": "codex apply " + sys.argv[1],
    },
}))
PY
    fired=$((fired + 1))
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","path":"%s","verdict":"refresh-hook-invoked"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$target" >> "$refresh_log"
  done
  if [ "$fired" -eq 0 ]; then
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"pass-no-corpus-path-detected"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$refresh_log"
  fi
  return 0
}

# Find first non-flag argument (the subcommand)
SUB=""
for arg in "$@"; do
  case "$arg" in
    --help|--version) exec "$REAL_CODEX" "$@" ;;
    -*) ;;
    *) SUB="$arg"; break ;;
  esac
done

if ! is_gated "$SUB"; then
  exec "$REAL_CODEX" "$@"
fi

if [ "$SUB" = "make" ] && ! is_gated_make_target "$@"; then
  exec "$REAL_CODEX" "$@"
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

# ---------------------------------------------------------------------------
# Loop-finalization gate: do not start fresh write-class work while prior
# terminal dispatch rows lack durable artifacts/memory closure.
# ---------------------------------------------------------------------------
if [ -z "${AUDITOOOR_NO_FINALIZATION_CHECK:-}" ] && [ -f "$FINALIZATION_TOOL" ]; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  FINALIZATION_STATUS="$WS/.auditooor/codex_finalization_gate.json"
  mkdir -p "$WS/.auditooor"
  if ! python3 "$FINALIZATION_TOOL" enforce-active-manifest \
      --workspace "$WS" \
      --out "$FINALIZATION_STATUS" >/dev/null 2>&1; then
    echo "[$WRAPPER_NAME] REJECTED: active dispatch manifest has unfinalized terminal rows." >&2
    echo "[$WRAPPER_NAME] See: $FINALIZATION_STATUS" >&2
    if [ "${AUDITOOOR_FINALIZATION_REQUIRED:-1}" = "0" ]; then
      echo "[$WRAPPER_NAME] AUDITOOOR_FINALIZATION_REQUIRED=0 bypass (logged)" >&2
      printf '{"ts":"%s","event":"bypass","tool":"%s","reason":"finalization_gap","status_file":"%s"}\n' \
        "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$FINALIZATION_STATUS" >> "$WS/.auditooor/bypass_log.jsonl"
    else
      exit 1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# Gap #72 (2026-05-26): pre-submit-check chaining for submit/apply that touch
# submissions/<status>/<slug>/<slug>.md drafts. Closes ~80% of cross-CLI parity
# gap with Claude Code (which already runs pre-submit-check via Edit/Write hook).
# Bypass: AUDITOOOR_NO_PRESUBMIT_CHECK=1 (audit-logged).
# Per-draft rebuttal: <!-- codex-presubmit-rebuttal: <reason up to 200 chars> -->
# ---------------------------------------------------------------------------
if [ -z "${AUDITOOOR_NO_PRESUBMIT_CHECK:-}" ] && [[ "$SUB" =~ ^(submit|apply)$ ]]; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  PRESUBMIT_TOOL="$(git -C "$WS" rev-parse --show-toplevel 2>/dev/null)/tools/pre-submit-check.sh"
  if [ ! -x "$PRESUBMIT_TOOL" ]; then
    # Try repo-relative resolution from auditooor-mcp checkout
    PRESUBMIT_TOOL="/Users/wolf/auditooor-mcp/tools/pre-submit-check.sh"
  fi
  DRAFT_RE='submissions/(staging|paste_ready|filed|packaged|held|superseded|_killed|_oos_rejected)/[^/]+/[^/]+\.md'
  DRAFTS_DETECTED=()
  for arg in "$@"; do
    if [[ "$arg" =~ $DRAFT_RE ]]; then
      DRAFT_PATH="$arg"
      # Resolve relative paths to absolute via workspace
      if [[ "$DRAFT_PATH" != /* ]]; then
        DRAFT_PATH="$WS/$DRAFT_PATH"
      fi
      if [ -f "$DRAFT_PATH" ]; then
        DRAFTS_DETECTED+=("$DRAFT_PATH")
      fi
    fi
  done
  if [ "${#DRAFTS_DETECTED[@]}" -gt 0 ] && [ -x "$PRESUBMIT_TOOL" ]; then
    mkdir -p "$WS/.auditooor"
    PRESUBMIT_LOG="$WS/.auditooor/codex_presubmit_gate.jsonl"
    for DRAFT in "${DRAFTS_DETECTED[@]}"; do
      # Per-draft rebuttal short-circuit
      if grep -qE 'codex-presubmit-rebuttal:\s*\S' "$DRAFT" 2>/dev/null; then
        echo "[$WRAPPER_NAME] pre-submit-check OK: $DRAFT (codex-presubmit-rebuttal marker)" >&2
        printf '{"ts":"%s","tool":"%s","subcmd":"%s","draft":"%s","verdict":"ok-rebuttal"}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$DRAFT" >> "$PRESUBMIT_LOG"
        continue
      fi
      # Run pre-submit-check
      if ! bash "$PRESUBMIT_TOOL" "$DRAFT" >/dev/null 2>&1; then
        _RC=$?
        echo "[$WRAPPER_NAME] REJECTED (Gap #72): pre-submit-check failed on $DRAFT (rc=$_RC)" >&2
        echo "[$WRAPPER_NAME] Re-run manually: bash $PRESUBMIT_TOOL $DRAFT" >&2
        echo "[$WRAPPER_NAME] Override: add '<!-- codex-presubmit-rebuttal: <reason> -->' to draft body OR export AUDITOOOR_NO_PRESUBMIT_CHECK=1" >&2
        printf '{"ts":"%s","tool":"%s","subcmd":"%s","draft":"%s","verdict":"fail-presubmit-check","rc":%d}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$DRAFT" "$_RC" >> "$PRESUBMIT_LOG"
        if [ "${AUDITOOOR_MCP_REQUIRED:-1}" = "0" ]; then
          echo "[$WRAPPER_NAME] AUDITOOOR_MCP_REQUIRED=0 bypass (logged)" >&2
        else
          exit 1
        fi
      else
        echo "[$WRAPPER_NAME] pre-submit-check OK: $DRAFT" >&2
        printf '{"ts":"%s","tool":"%s","subcmd":"%s","draft":"%s","verdict":"pass-presubmit-check"}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$DRAFT" >> "$PRESUBMIT_LOG"
      fi
    done
  elif [ "${#DRAFTS_DETECTED[@]}" -gt 0 ] && [ ! -x "$PRESUBMIT_TOOL" ]; then
    echo "[$WRAPPER_NAME] WARN (Gap #72): drafts detected but pre-submit-check.sh not found at $PRESUBMIT_TOOL" >&2
    mkdir -p "$WS/.auditooor"
    printf '{"ts":"%s","tool":"%s","subcmd":"%s","drafts":%d,"verdict":"warn-presubmit-tool-missing"}\n' \
      "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "${#DRAFTS_DETECTED[@]}" >> "$WS/.auditooor/codex_presubmit_gate.jsonl"
  fi
elif [[ "$SUB" =~ ^(submit|apply)$ ]] && [ -n "${AUDITOOOR_NO_PRESUBMIT_CHECK:-}" ]; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  mkdir -p "$WS/.auditooor"
  printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"bypass-env","reason":"AUDITOOOR_NO_PRESUBMIT_CHECK=1"}\n' \
    "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$WS/.auditooor/codex_presubmit_gate.jsonl"
  echo "[$WRAPPER_NAME] Gap #72 BYPASS: AUDITOOOR_NO_PRESUBMIT_CHECK=1 (logged)" >&2
fi

# ---------------------------------------------------------------------------
# Gap #76 pre-write gate (2026-05-26): L34 path classifier for write-targeting
# subcommands (apply). Refuses apply targeting paths classified as draft-file
# UNLESS the operator authorizes via L34_DRAFT_AUTHORIZED env, an in-draft
# l34-rebuttal marker, or the CODEX_NO_PREWRITE_CHECK bypass.
# Per the prompt's discipline: tracker-file / workspace-ledger / lesson-anchor /
# out-of-scope buckets PASS without per-draft auth.
# ---------------------------------------------------------------------------
if [ -z "${CODEX_NO_PREWRITE_CHECK:-}" ] && is_write_targeting "$SUB"; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  L34_TOOL="$(git -C "$WS" rev-parse --show-toplevel 2>/dev/null)/tools/l34-path-classifier.py"
  if [ ! -f "$L34_TOOL" ]; then
    L34_TOOL="/Users/wolf/auditooor-mcp/tools/l34-path-classifier.py"
  fi
  if [ -f "$L34_TOOL" ]; then
    mkdir -p "$WS/.auditooor"
    L34_LOG="$WS/.auditooor/codex_prewrite_gate.jsonl"
    L34_AUTH="${L34_DRAFT_AUTHORIZED:-}"
    SUBMISSION_RE='submissions/'
    for arg in "$@"; do
      # Skip flags and subcommand
      case "$arg" in
        -*|"$SUB") continue ;;
      esac
      # Only classify submission-tree paths (everything else is out-of-scope
      # by L34's definition and would noisily PASS).
      if ! [[ "$arg" =~ $SUBMISSION_RE ]]; then
        continue
      fi
      # Resolve absolute via workspace if relative
      CLASSIFY_PATH="$arg"
      if [[ "$CLASSIFY_PATH" != /* ]]; then
        CLASSIFY_PATH="$WS/$CLASSIFY_PATH"
      fi
      CLASSIFY_JSON="$(python3 "$L34_TOOL" "$CLASSIFY_PATH" --json 2>/dev/null || echo '{}')"
      BUCKET="$(printf '%s' "$CLASSIFY_JSON" | python3 -c 'import json,sys
try:
  d=json.loads(sys.stdin.read() or "{}")
  recs=d.get("results") or d.get("records") or []
  if recs:
    print(recs[0].get("bucket",""))
except Exception:
  pass' 2>/dev/null)"
      if [ "$BUCKET" = "draft-file" ]; then
        # Determine target slug for per-draft auth comparison
        DRAFT_SLUG="$(basename "$CLASSIFY_PATH" .md)"
        # Rebuttal check: in-draft l34-rebuttal marker (only applies if file exists)
        if [ -f "$CLASSIFY_PATH" ] && grep -qE 'l34-rebuttal:\s*\S' "$CLASSIFY_PATH" 2>/dev/null; then
          echo "[$WRAPPER_NAME] pre-write OK: $CLASSIFY_PATH (l34-rebuttal marker)" >&2
          printf '{"ts":"%s","tool":"%s","subcmd":"%s","path":"%s","bucket":"%s","verdict":"ok-rebuttal-l34"}\n' \
            "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$CLASSIFY_PATH" "$BUCKET" >> "$L34_LOG"
          continue
        fi
        # Per-draft auth env: L34_DRAFT_AUTHORIZED=<slug1>,<slug2>,...
        if [ -n "$L34_AUTH" ]; then
          if printf '%s\n' "${L34_AUTH//,/ }" | tr ' ' '\n' | grep -qxF "$DRAFT_SLUG"; then
            echo "[$WRAPPER_NAME] pre-write OK: $CLASSIFY_PATH (L34_DRAFT_AUTHORIZED)" >&2
            printf '{"ts":"%s","tool":"%s","subcmd":"%s","path":"%s","bucket":"%s","verdict":"ok-l34-authorized","slug":"%s"}\n' \
              "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$CLASSIFY_PATH" "$BUCKET" "$DRAFT_SLUG" >> "$L34_LOG"
            continue
          fi
        fi
        echo "[$WRAPPER_NAME] REJECTED (Gap #76 / L34): $CLASSIFY_PATH is a draft-file requiring per-draft op-auth" >&2
        echo "[$WRAPPER_NAME] Override: export L34_DRAFT_AUTHORIZED=$DRAFT_SLUG OR add '<!-- l34-rebuttal: <reason> -->' to draft OR export CODEX_NO_PREWRITE_CHECK=1" >&2
        printf '{"ts":"%s","tool":"%s","subcmd":"%s","path":"%s","bucket":"%s","verdict":"fail-l34-draft-without-auth","slug":"%s"}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$CLASSIFY_PATH" "$BUCKET" "$DRAFT_SLUG" >> "$L34_LOG"
        if [ "${AUDITOOOR_MCP_REQUIRED:-1}" = "0" ]; then
          echo "[$WRAPPER_NAME] AUDITOOOR_MCP_REQUIRED=0 bypass (logged)" >&2
        else
          exit 1
        fi
      else
        # Auto-executable buckets (tracker-file / workspace-ledger /
        # lesson-anchor / out-of-scope) pass without per-draft auth.
        printf '{"ts":"%s","tool":"%s","subcmd":"%s","path":"%s","bucket":"%s","verdict":"pass-auto-executable"}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$CLASSIFY_PATH" "$BUCKET" >> "$L34_LOG"
      fi
    done
  fi
elif [ -n "${CODEX_NO_PREWRITE_CHECK:-}" ] && is_write_targeting "$SUB"; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  mkdir -p "$WS/.auditooor"
  printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"bypass-env","reason":"CODEX_NO_PREWRITE_CHECK=1"}\n' \
    "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$WS/.auditooor/codex_prewrite_gate.jsonl"
  echo "[$WRAPPER_NAME] Gap #76 BYPASS (pre-write): CODEX_NO_PREWRITE_CHECK=1 (logged)" >&2
fi

# ---------------------------------------------------------------------------
# Gap #76 pre-subagent-spawn gate (2026-05-26): R64 prompt-claim verification
# for sub-agent-spawn subcommands (exec/e/review/resume/fork/cloud). Codex
# spawning a sub-agent with a prompt is the equivalent of Claude Code's
# Agent/Task dispatch surface. R64 verifies every factual claim in the prompt
# against the canonical-inventory snapshot. Unverified claims fail closed
# unless rebuttal: CODEX_NO_SUBAGENT_CHECK=1, AUDITOOOR_R64_REBUTTAL=<reason>,
# or `<!-- r64-rebuttal: <reason> -->` in the prompt body.
# Prompt extraction strategy (best-effort):
#   1. --prompt-file=<path>: read file
#   2. --prompt=<inline>: take inline string
#   3. trailing positional arg after subcommand: take as inline prompt
#   4. else: skip (no prompt detected, e.g. `codex exec resume --last`)
# ---------------------------------------------------------------------------
if [ -z "${CODEX_NO_SUBAGENT_CHECK:-}" ] && is_subagent_spawn "$SUB"; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  R64_TOOL="$(git -C "$WS" rev-parse --show-toplevel 2>/dev/null)/tools/r64-prompt-claim-verifier.py"
  if [ ! -f "$R64_TOOL" ]; then
    R64_TOOL="/Users/wolf/auditooor-mcp/tools/r64-prompt-claim-verifier.py"
  fi
  if [ -f "$R64_TOOL" ]; then
    mkdir -p "$WS/.auditooor"
    R64_LOG="$WS/.auditooor/codex_subagent_spawn_gate.jsonl"
    PROMPT_PATH=""
    PROMPT_INLINE=""
    SUB_SEEN=0
    for arg in "$@"; do
      case "$arg" in
        --prompt-file=*) PROMPT_PATH="${arg#--prompt-file=}" ;;
        --prompt=*)      PROMPT_INLINE="${arg#--prompt=}" ;;
        -*) ;;
        *)
          if [ "$SUB_SEEN" -eq 0 ] && [ "$arg" = "$SUB" ]; then
            SUB_SEEN=1
            continue
          fi
          if [ "$SUB_SEEN" -eq 1 ] && [ -z "$PROMPT_INLINE" ] && [ -z "$PROMPT_PATH" ]; then
            # Take first positional arg after subcommand as inline prompt
            PROMPT_INLINE="$arg"
          fi
          ;;
      esac
    done
    # Materialise the prompt to a tmp file for the verifier
    PROMPT_TMP=""
    if [ -n "$PROMPT_PATH" ] && [ -f "$PROMPT_PATH" ]; then
      PROMPT_TMP="$PROMPT_PATH"
    elif [ -n "$PROMPT_INLINE" ]; then
      PROMPT_TMP="$(mktemp -t codex-subagent-prompt.XXXXXX)"
      printf '%s' "$PROMPT_INLINE" > "$PROMPT_TMP"
    fi
    if [ -n "$PROMPT_TMP" ] && [ -f "$PROMPT_TMP" ]; then
      # AUDITOOOR_R64_REBUTTAL env shortcut (logged)
      if [ -n "${AUDITOOOR_R64_REBUTTAL:-}" ]; then
        echo "[$WRAPPER_NAME] pre-subagent-spawn OK: AUDITOOOR_R64_REBUTTAL set (logged)" >&2
        printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"ok-rebuttal-env","reason":"AUDITOOOR_R64_REBUTTAL"}\n' \
          "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
      else
        # In-prompt rebuttal marker shortcut
        if grep -qE 'r64-rebuttal:\s*\S' "$PROMPT_TMP" 2>/dev/null; then
          echo "[$WRAPPER_NAME] pre-subagent-spawn OK: r64-rebuttal marker in prompt" >&2
          printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"ok-rebuttal-marker"}\n' \
            "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
        else
          # Run R64 verifier with --strict and --json. The verdict is
          # parsed from the JSON body; exit code is incidental (rc=1 on
          # unverified, rc=0 on pass).
          R64_JSON="$(python3 "$R64_TOOL" "$PROMPT_TMP" --json --strict 2>/dev/null || true)"
          R64_VERDICT="$(printf '%s' "$R64_JSON" | python3 -c 'import json,sys
try:
  d=json.loads(sys.stdin.read() or "{}")
  print(d.get("overall_verdict",""))
except Exception:
  pass' 2>/dev/null)"
          if [ -z "$R64_VERDICT" ]; then
            R64_VERDICT="error-verifier-unreachable"
          fi
          case "$R64_VERDICT" in
            pass-all-verified|pass-no-claims|ok-rebuttal)
              echo "[$WRAPPER_NAME] pre-subagent-spawn OK: $R64_VERDICT" >&2
              printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"%s"}\n' \
                "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$R64_VERDICT" >> "$R64_LOG"
              ;;
            *)
              echo "[$WRAPPER_NAME] REJECTED (Gap #76 / R64): prompt contains unverified claim ($R64_VERDICT)" >&2
              echo "[$WRAPPER_NAME] Re-run manually: python3 $R64_TOOL $PROMPT_TMP --strict" >&2
              echo "[$WRAPPER_NAME] Override: add '<!-- r64-rebuttal: <reason> -->' to prompt OR export AUDITOOOR_R64_REBUTTAL=<reason> OR export CODEX_NO_SUBAGENT_CHECK=1" >&2
              printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"fail-codex-subagent-unverified-claim","r64_verdict":"%s"}\n' \
                "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" "$R64_VERDICT" >> "$R64_LOG"
              # Clean up tmp prompt if we created it
              if [ -n "$PROMPT_INLINE" ] && [ -f "$PROMPT_TMP" ] && [[ "$PROMPT_TMP" == */codex-subagent-prompt.* ]]; then
                rm -f "$PROMPT_TMP"
              fi
              if [ "${AUDITOOOR_MCP_REQUIRED:-1}" = "0" ]; then
                echo "[$WRAPPER_NAME] AUDITOOOR_MCP_REQUIRED=0 bypass (logged)" >&2
              else
                exit 1
              fi
              ;;
          esac
        fi
      fi
      inject_meta1_into_codex_prompt
      # Clean up tmp prompt if we created it from inline
      if [ -n "$PROMPT_INLINE" ] && [ -f "$PROMPT_TMP" ] && [[ "$PROMPT_TMP" == */codex-subagent-prompt.* ]]; then
        rm -f "$PROMPT_TMP"
      fi
    else
      # No prompt detected (e.g. `codex resume --last` with no new prompt) -
      # safe to passthrough.
      printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"pass-no-prompt-detected"}\n' \
        "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$R64_LOG"
    fi
  fi
elif [ -n "${CODEX_NO_SUBAGENT_CHECK:-}" ] && is_subagent_spawn "$SUB"; then
  WS="${AUDITOOOR_WS_ROOT:-$WORKSPACE}"
  mkdir -p "$WS/.auditooor"
  printf '{"ts":"%s","tool":"%s","subcmd":"%s","verdict":"bypass-env","reason":"CODEX_NO_SUBAGENT_CHECK=1"}\n' \
    "$(date -u +%FT%TZ)" "$WRAPPER_NAME" "$SUB" >> "$WS/.auditooor/codex_subagent_spawn_gate.jsonl"
  echo "[$WRAPPER_NAME] Gap #76 BYPASS (pre-subagent-spawn): CODEX_NO_SUBAGENT_CHECK=1 (logged)" >&2
fi

# ---------------------------------------------------------------------------
# MCP native-usage enforcement (2026-05-28): warn when Codex shells out to
# vault-mcp-server.py --call <name> instead of using the native MCP tool.
# Runs the same hook logic as the Claude Desktop PreToolUse hook.
# Bypass: AUDITOOOR_MCP_NATIVE_STRICT=0 (default warn-only).
#         Add <!-- mcp-native-rebuttal: <reason> --> in the prompt/command to skip.
# ---------------------------------------------------------------------------
MCP_NATIVE_HOOK="$(dirname "$0")/hooks/mcp-native-usage-enforce.sh"
if [ ! -f "$MCP_NATIVE_HOOK" ]; then
  MCP_NATIVE_HOOK="/Users/wolf/auditooor-mcp/tools/hooks/mcp-native-usage-enforce.sh"
fi
if [ -x "$MCP_NATIVE_HOOK" ]; then
  # Scan the full command line for vault-mcp-server.py --call patterns
  FULL_CMD="$*"
  for arg in "$@"; do
    if printf '%s' "$arg" | grep -qE 'vault-mcp-server\.py.*--call\s+vault_'; then
      bash "$MCP_NATIVE_HOOK" "$FULL_CMD" || true
      break
    fi
  done
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
[mcp-gate:$WRAPPER_NAME] BLOCKED: 'codex $SUB' requires a valid MCP session token (scope=$REQUIRE_SCOPE)
   Set AUDITOOOR_MCP_SESSION_TOKEN env var, or pass --mcp-token=<token>
   Issue token:
     python3 ${SCRIPT_DIR}/auditooor_mcp_token.py issue --workspace \$PWD
   Or override (audit-logged):
     AUDITOOOR_MCP_REQUIRED=0 codex $SUB ...
EOF
    exit 1
  fi
fi

if [ "$SUB" = "apply" ]; then
  "$REAL_CODEX" "${FILTERED[@]}"
  CODEX_RC=$?
  trigger_corpus_refresh_after_apply "$CODEX_RC"
  exit "$CODEX_RC"
fi

exec "$REAL_CODEX" "${FILTERED[@]}"
