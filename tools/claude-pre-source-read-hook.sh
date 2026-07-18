#!/usr/bin/env bash
# Claude Code PreToolUse hook for the Read tool — Wave-6 Track B Phase C
# (PUSH-mode mindset injection).
#
# Wired by exporting AUDITOOOR_PRE_READ_HOOK in the operator's settings, then
# the harness invokes this script with the source file path as $1. The hook
# emits a JSON payload (Claude Code hook spec) of per-function attack-class
# hypotheses for the file BEFORE the worker Reads the source body.
#
# Exits 0 with no output for files outside the supported extensions, missing
# files, or any internal error — never blocks the worker's Read.

set -euo pipefail

FILE_PATH="${1:-}"
# Skip when no path passed
[ -z "$FILE_PATH" ] && exit 0
# Skip when path does not resolve to a regular file
[ ! -f "$FILE_PATH" ] && exit 0

# Source-extension gate: only fire for .go / .rs / .sol (Wave-6 Phase C scope).
case "$FILE_PATH" in
  *.go|*.rs|*.sol) ;;
  *) exit 0 ;;
esac

# Resolve the auditooor workspace (worktree containing the tools/).
WS="$(git -C "$(dirname "$FILE_PATH")" rev-parse --show-toplevel 2>/dev/null || true)"
if [ -z "$WS" ] || [ ! -f "$WS/tools/auditooor-pre-source-read-injector.py" ]; then
  # Fall back to the env-provided AUDITOOOR_WORKTREE (set in the operator's
  # session profile), then the global default.
  WS="${AUDITOOOR_WORKTREE:-/Users/wolf/auditooor-worktrees/dlt-workflow-gaps-main}"
fi
[ -f "$WS/tools/auditooor-pre-source-read-injector.py" ] || exit 0

# TARGET_REPO is optional; if absent the injector emits target_repo="unknown/unknown".
TARGET_REPO="${TARGET_REPO:-}"

# Invoke the injector. Suppress stderr so a parse/ranker hiccup never blocks
# the worker's Read. The live hook emits Claude PreToolUse output JSON with a
# bounded systemMessage so the hypotheses are actually surfaced in-context.
# Tests/operator scripts can set AUDITOOOR_PRE_SOURCE_READ_RAW_JSON=1 to keep
# the historical raw auditooor.pre_source_read_injection.v1 payload.
if [ "${AUDITOOOR_PRE_SOURCE_READ_RAW_JSON:-}" = "1" ]; then
  python3 "$WS/tools/auditooor-pre-source-read-injector.py" \
      "$FILE_PATH" \
      ${TARGET_REPO:+--target-repo "$TARGET_REPO"} \
      --top-n 3 \
      --min-confidence 0.5 \
      --max-functions 20 \
      --json 2>/dev/null || exit 0
else
  python3 "$WS/tools/auditooor-pre-source-read-injector.py" \
      "$FILE_PATH" \
      ${TARGET_REPO:+--target-repo "$TARGET_REPO"} \
      --top-n 3 \
      --min-confidence 0.5 \
      --max-functions 20 \
      --claude-hook-output \
      --hook-max-chars "${AUDITOOOR_PRE_SOURCE_READ_HOOK_MAX_CHARS:-2000}" \
      2>/dev/null || exit 0
fi
