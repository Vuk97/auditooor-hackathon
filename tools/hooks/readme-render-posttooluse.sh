#!/usr/bin/env bash
# readme-render-posttooluse.sh — Claude Code PostToolUse hook
#
# Triggered after Edit / Write / NotebookEdit tool calls. Runs
# tools/readme-render.py when the modified file is one of the tracked
# inputs that readme-render reads.
#
# ADVISORY HOOK: always exits 0. Never blocks tool execution.
#
# Protocol: Claude Code passes a JSON payload on stdin with at minimum:
#   { "tool_name": "Edit", "tool_input": { "file_path": "/abs/path" } }
#
# Usage:
#   echo '{"tool_name":"Edit","tool_input":{"file_path":"/repo/reference/outcomes.jsonl"}}' \
#     | bash tools/hooks/readme-render-posttooluse.sh
#
# Dry-run mode (for tests):
#   DRY_RUN=1 <same invocation>  → prints "would-run" instead of executing

set -euo pipefail

# ------------------------------------------------------------------
# 0. Locate repo root (directory containing this script's parent dir)
# ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOG_DIR="${REPO_ROOT}/.auditooor"
LOG_FILE="${LOG_DIR}/readme-render-hook.log"
RENDER_SCRIPT="${REPO_ROOT}/tools/readme-render.py"

# ------------------------------------------------------------------
# 1. Parse stdin JSON — extract tool_name and file_path
# ------------------------------------------------------------------
payload="$(cat)"

# Extract tool_name
tool_name="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null || true)"

# Extract tool_input.file_path (may be absent for some tools)
file_path="$(printf '%s' "${payload}" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('file_path',''))" 2>/dev/null || true)"

# ------------------------------------------------------------------
# 2. Gate 1: only react to Edit / Write / NotebookEdit
# ------------------------------------------------------------------
case "${tool_name}" in
  Edit|Write|NotebookEdit) ;;   # fall through
  *) exit 0 ;;                  # silent pass for everything else
esac

# ------------------------------------------------------------------
# 3. Gate 2: only react when file_path is a tracked readme-render dep
#
#    Tracked inputs (relative to REPO_ROOT):
#      reference/outcomes.jsonl   — filing outcomes ledger
#      README.md                  — contains AUDITOOOR_AUTO markers
# ------------------------------------------------------------------
if [[ -z "${file_path}" ]]; then
  exit 0
fi

# Normalize: strip trailing slash, resolve to absolute if relative
# (Claude Code typically supplies absolute paths, but guard anyway)
if [[ "${file_path}" != /* ]]; then
  file_path="${REPO_ROOT}/${file_path}"
fi

# Build the set of watched absolute paths
watched_outcomes="${REPO_ROOT}/reference/outcomes.jsonl"
watched_readme="${REPO_ROOT}/README.md"

matched=0
if [[ "${file_path}" == "${watched_outcomes}" ]] || \
   [[ "${file_path}" == "${watched_readme}" ]]; then
  matched=1
fi

if [[ "${matched}" -eq 0 ]]; then
  exit 0
fi

# ------------------------------------------------------------------
# 4. Dry-run mode (used by tests)
# ------------------------------------------------------------------
if [[ "${DRY_RUN:-0}" == "1" ]]; then
  echo "would-run: python3 ${RENDER_SCRIPT}"
  exit 0
fi

# ------------------------------------------------------------------
# 5. Run readme-render.py — advisory; swallow all errors
# ------------------------------------------------------------------
mkdir -p "${LOG_DIR}"

{
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] triggered by tool=${tool_name} file=${file_path}"
  python3 "${RENDER_SCRIPT}" --quiet 2>&1 && \
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] render OK" || \
    echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] render FAILED (advisory; ignored)"
} >> "${LOG_FILE}" 2>&1

exit 0
