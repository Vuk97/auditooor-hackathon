#!/usr/bin/env bash
# pre-source-read-inject.sh — wrapper for tools/auditooor-pre-source-read-injector.py
#
# Usage:
#   bash scripts/pre-source-read-inject.sh <source-file-path> [<workspace>]
#
# Prints Claude hook JSON with bounded pre-source-read hacker questions.
# Exit 0 on success (including "no match" / empty output).
# Exit 1 on bad arguments.
#
# Can be wired into a Claude .claude/hooks/ PreToolUse config by the operator:
#   {
#     "hooks": {
#       "PreToolUse": [{
#         "matcher": "Read",
#         "hooks": [{"type": "command",
#                    "command": "bash /path/to/scripts/pre-source-read-inject.sh \"$TOOL_INPUT_FILE_PATH\""}]
#       }]
#     }
#   }

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SOURCE_PATH="${1:-}"
WORKSPACE="${2:-${REPO_ROOT}}"

if [[ -z "${SOURCE_PATH}" ]]; then
  echo "Usage: $0 <source-file-path> [<workspace>]" >&2
  exit 1
fi

args=(
  "${REPO_ROOT}/tools/auditooor-pre-source-read-injector.py"
  "${SOURCE_PATH}"
  --workspace "${WORKSPACE}"
  --claude-hook-output
  --hook-max-chars "${AUDITOOOR_PRE_SOURCE_READ_HOOK_MAX_CHARS:-2000}"
)

if [[ -n "${TARGET_REPO:-}" ]]; then
  args+=(--target-repo "${TARGET_REPO}")
fi

if [[ -n "${AUDITOOOR_PRE_SOURCE_READ_STRICT_PERSISTENCE:-}" || -n "${AUDITOOOR_PRE_SOURCE_READ_STRICT:-}" ]]; then
  args+=(--strict-persistence)
fi

exec python3 "${args[@]}"
