#!/usr/bin/env bash
# Auditooor PostToolUse hook on the Workflow tool. When a Workflow that touches
# an audit workspace launches, this records a VERDICT-PERSISTENCE OBLIGATION to
# ~/.auditooor/verdict_obligations.jsonl. The obligation is satisfied only when
# tools/verdict-sink.py is later run on that run's journal (which writes a
# resolution to <repo>/.auditooor/verdict_sink_log.jsonl). The chokepoint gate
# tools/hunt-verdict-persistence-gate.py (wired into audit-done-guard.py +
# pre-commit) FAILS while any obligation is unresolved - so a hunt workflow's
# verdicts can never silently evaporate before a done / audit-complete claim.
#
# Receives the full tool-call JSON on stdin (PostToolUse: tool_name, tool_input,
# tool_response). NEVER blocks - PostToolUse exit codes are advisory; always 0.
# Kill-switch: AUDITOOOR_VERDICT_OBLIGATION_DISABLE=1 -> exit 0.

set -u

if [ -n "${AUDITOOOR_VERDICT_OBLIGATION_DISABLE:-}" ]; then
  exit 0
fi

PAYLOAD="$(cat 2>/dev/null || true)"
if [ -z "${PAYLOAD}" ]; then
  exit 0
fi

LEDGER="${AUDITOOOR_VERDICT_OBLIGATION_LEDGER:-${HOME}/.auditooor/verdict_obligations.jsonl}"
HERE="$(cd "$(dirname "$0")" && pwd)"

printf '%s' "${PAYLOAD}" | python3 "${HERE}/_workflow_verdict_obligation.py" "${LEDGER}" 2>/dev/null || true

exit 0
