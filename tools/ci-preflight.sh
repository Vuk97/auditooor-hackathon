#!/usr/bin/env bash
# ci-preflight.sh — compact report of which external binaries are available.
#
# Invoked by `make ci-preflight`. See docs/CI_SETUP.md and PR 212.
#
# Exit codes:
#   0  — all critical tools (forge + python3) are present.
#        Optional gaps (medusa/echidna/halmos/mythril/slither/jq/timeout) are
#        listed but DO NOT fail the preflight — the dependent offline tests
#        skip cleanly.
#   1  — a critical tool is missing. CI should fail fast here rather than let
#        the full test suite scream later.
#
# Status vocabulary (kept narrow on purpose — see tool-availability.sh):
#     ✓   present
#     ✗   missing
#     YES all critical tools present
#     NO  at least one critical tool missing
#
# No other status strings leak into submission gating. The preflight output
# is operator-visible planning info, not proof.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/tool-availability.sh
. "$here/lib/tool-availability.sh"

printf '[ci-preflight]\n'
tool_availability_report_line forge   "$HAS_FORGE"   "$FORGE_VERSION"
tool_availability_report_line cast    "$HAS_CAST"    "$CAST_VERSION"
tool_availability_report_line anvil   "$HAS_ANVIL"   "$ANVIL_VERSION"
tool_availability_report_line medusa  "$HAS_MEDUSA"  "$MEDUSA_VERSION"
tool_availability_report_line echidna "$HAS_ECHIDNA" "$ECHIDNA_VERSION"
tool_availability_report_line halmos  "$HAS_HALMOS"  "$HALMOS_VERSION"
tool_availability_report_line mythril "$HAS_MYTHRIL" "$MYTHRIL_VERSION"
tool_availability_report_line slither "$HAS_SLITHER" "$SLITHER_VERSION"
tool_availability_report_line jq      "$HAS_JQ"      "$JQ_VERSION"
tool_availability_report_line python3 "$HAS_PYTHON3" "$PYTHON3_VERSION"
tool_availability_report_line timeout "$HAS_TIMEOUT" "$TIMEOUT_VERSION"

gaps=""
for pair in \
    "medusa:$HAS_MEDUSA" \
    "echidna:$HAS_ECHIDNA" \
    "halmos:$HAS_HALMOS" \
    "mythril:$HAS_MYTHRIL" \
    "slither:$HAS_SLITHER" \
    "jq:$HAS_JQ" \
    "timeout:$HAS_TIMEOUT" \
    "cast:$HAS_CAST" \
    "anvil:$HAS_ANVIL"
do
    name="${pair%%:*}"
    has="${pair##*:}"
    if [ "$has" != "1" ]; then
        if [ -z "$gaps" ]; then gaps="$name"; else gaps="$gaps, $name"; fi
    fi
done

if tool_availability_critical_ok; then
    printf 'All critical tools present: YES\n'
    if [ -n "$gaps" ]; then
        printf 'Optional gaps: %s\n' "$gaps"
    else
        printf 'Optional gaps: none\n'
    fi
    exit 0
else
    printf 'All critical tools present: NO\n'
    missing_critical=""
    if [ "${HAS_FORGE:-0}" != "1" ]; then
        missing_critical="forge"
    fi
    if [ "${HAS_PYTHON3:-0}" != "1" ]; then
        if [ -n "$missing_critical" ]; then
            missing_critical="$missing_critical, python3"
        else
            missing_critical="python3"
        fi
    fi
    printf 'Missing critical: %s\n' "$missing_critical"
    if [ -n "$gaps" ]; then
        printf 'Optional gaps: %s\n' "$gaps"
    fi
    exit 1
fi
