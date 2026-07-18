#!/usr/bin/env bash
# adversarial-live-run.sh — operator-gating wrapper around iter-v3-5 T1's
# live adversarial dispatcher.
#
# Checks both environment gates and, only if BOTH are present, shells out to
#   SWARM_REAL_DISPATCH=1 python3 scripts/_capv3_iter5_T1_driver.py
# Otherwise writes an honest `cannot-run` record and exits 0.
#
# Output JSON: agent_outputs/capv3_iter6_T1_live_wrapper.json
#
# Vocabulary (tool-local, not §5):
#   status  ∈ {"ran", "cannot-run"}
#   reason  ∈ {"no-api-key", "operator-not-consented"}  (only when cannot-run)
#   driver_exit_code: int  (only when ran)
#
# The wrapper ALWAYS exits 0. Driver exit code surfaces via the JSON field.
# NO repo-mutating calls. NO key logging. NO request/response persistence.
# The driver owns its own audit trails via tools/llm-dispatch.py.
#
# Capability v3 iter-006 T1. Plan: docs/CAPABILITY_V3_ITER_006_PLAN.md §T1.

set -euo pipefail

# ---------------------------------------------------------------------------
# Banner (stderr) — operator-readable semantics
# ---------------------------------------------------------------------------

cat >&2 <<'BANNER'
This wrapper runs the live adversarial dispatcher against 18 parseable DROPPED drafts. Requires BOTH `ANTHROPIC_API_KEY` (provides real Anthropic API credentials) AND `ADVERSARIAL_LIVE_CONSENT=1` (operator consent). Either absent → honest cannot-run JSON + exit 0.
BANNER

# ---------------------------------------------------------------------------
# Resolve repo root + output path (honor AUDITOOOR_ROOT override for tests)
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="${AUDITOOOR_ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
OUT_DIR="$ROOT/agent_outputs"
OUT_JSON="$OUT_DIR/capv3_iter6_T1_live_wrapper.json"
DRIVER="${ADVERSARIAL_LIVE_RUN_DRIVER:-$ROOT/scripts/_capv3_iter5_T1_driver.py}"

mkdir -p "$OUT_DIR"

# ISO-8601 UTC timestamp, stdlib-only.
TS="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

write_json() {
    # $1 = one-line JSON body (no outer braces)
    printf '{"ts": "%s", %s, "wrapper_version": "v1"}\n' "$TS" "$1" > "$OUT_JSON"
}

# ---------------------------------------------------------------------------
# Gate 1: ANTHROPIC_API_KEY must be non-empty
# ---------------------------------------------------------------------------

if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    write_json '"status": "cannot-run", "reason": "no-api-key"'
    echo "[adversarial-live-run] cannot-run: no-api-key (wrote $OUT_JSON)" >&2
    exit 0
fi

# ---------------------------------------------------------------------------
# Gate 2: ADVERSARIAL_LIVE_CONSENT must be exactly "1"
# ---------------------------------------------------------------------------

if [ "${ADVERSARIAL_LIVE_CONSENT:-}" != "1" ]; then
    write_json '"status": "cannot-run", "reason": "operator-not-consented"'
    echo "[adversarial-live-run] cannot-run: operator-not-consented (wrote $OUT_JSON)" >&2
    exit 0
fi

# ---------------------------------------------------------------------------
# Both gates open — dispatch to the driver.
# We do NOT echo ANTHROPIC_API_KEY. We do NOT trap the driver's stdout/stderr
# into our JSON (the driver has its own per-draft artefacts + summary).
# ---------------------------------------------------------------------------

export SWARM_REAL_DISPATCH=1

echo "[adversarial-live-run] gates open — dispatching to driver: $DRIVER" >&2

set +e
python3 "$DRIVER"
DRIVER_EXIT=$?
set -e

write_json "$(printf '"status": "ran", "driver_exit_code": %d' "$DRIVER_EXIT")"
echo "[adversarial-live-run] ran: driver_exit_code=$DRIVER_EXIT (wrote $OUT_JSON)" >&2

# Wrapper always exits 0 — driver exit code surfaces in JSON only.
exit 0
