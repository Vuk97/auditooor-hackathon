#!/usr/bin/env bash
# session-end-aggregate-verdict-bus.sh - advisory SessionEnd/PostToolUse hook.
#
# Refreshes <workspace>/.auditooor/lane_verdict_bus/aggregated.json by
# delegating to tools/lane-verdict-bus.py aggregate. The bus tool owns merge
# semantics and idempotency. This hook never blocks session teardown.

set -uo pipefail

if [[ "${AUDITOOOR_LANE_VERDICT_BUS_HOOK_DISABLE:-0}" == "1" ]]; then
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUS_TOOL="${AUDITOOOR_LANE_VERDICT_BUS_TOOL:-${REPO_ROOT}/tools/lane-verdict-bus.py}"

if [[ -n "${AUDITOOOR_WS:-}" ]]; then
  WS="${AUDITOOOR_WS}"
elif [[ -n "${CLAUDE_PROJECT_DIR:-}" ]]; then
  WS="${CLAUDE_PROJECT_DIR}"
else
  WS="$(pwd)"
fi

WS="$(cd "${WS}" 2>/dev/null && pwd || printf '%s' "${WS}")"

if [[ ! -f "${BUS_TOOL}" ]]; then
  echo "[session-end-aggregate-verdict-bus] lane-verdict-bus-tool-missing path=${BUS_TOOL}" >&2
  exit 0
fi

tmp_err="$(mktemp 2>/dev/null || printf '/tmp/lane_verdict_bus_aggregate_%s.err' "$$")"
python3 "${BUS_TOOL}" aggregate --workspace "${WS}" >/dev/null 2>"${tmp_err}" || true
if [[ -s "${tmp_err}" ]]; then
  while IFS= read -r line; do
    echo "[session-end-aggregate-verdict-bus] ${line}" >&2
  done <"${tmp_err}"
fi
rm -f "${tmp_err}" 2>/dev/null || true

exit 0
