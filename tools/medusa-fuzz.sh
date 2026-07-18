#!/usr/bin/env bash
# medusa-fuzz.sh - hermetic Medusa wrapper for A4 deep-mode tests.

set -uo pipefail

# Shared deep-engine binary resolver: env override -> tools/deep-engine-bin/
# (hermetic provisioned) -> PATH. Falls back gracefully when absent.
_MEDUSA_RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/deep-engine-resolve.sh
. "$_MEDUSA_RUNNER_DIR/lib/deep-engine-resolve.sh"

ENGINE="medusa"
ENGINE_DIR="medusa"
SKIP_VAR="AUDITOOOR_DEEP_SKIP_MEDUSA"
ENGINE_STATUS="ok"
ENGINE_REASON="completed"
ENGINE_BIN=""
ENGINE_VERSION=""
ENGINE_RC=""
# Per-harness timeout (seconds). Prefer AUDITOOOR_DEEP_MEDUSA_TIMEOUT, fall back
# to the global AUDITOOOR_DEEP_ENGINE_TIMEOUT, then the built-in default.
_DEFAULT_MEDUSA_TIMEOUT=900
_MEDUSA_TIMEOUT="${AUDITOOOR_DEEP_MEDUSA_TIMEOUT:-${AUDITOOOR_DEEP_ENGINE_TIMEOUT:-$_DEFAULT_MEDUSA_TIMEOUT}}"
# Resolve the timeout binary: prefer system timeout -> gtimeout -> bash watchdog.
_TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    _TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    _TIMEOUT_BIN="gtimeout"
fi

usage() {
    cat <<'EOF'
usage: tools/medusa-fuzz.sh <workspace> [medusa-args...]

Writes <workspace>/.auditooor/medusa/artifact.json by default and exits 0
on tool-unavailable, env-skip, or engine execution. Set
AUDITOOOR_DEEP_ARTIFACT_ROOT to redirect artifact roots for per-harness runs.
EOF
}

if [ $# -lt 1 ]; then
    usage >&2
    exit 2
fi

WORKSPACE="$1"
shift
ENGINE_ARGS=("$@")

if [ ! -d "$WORKSPACE" ]; then
    echo "[medusa-fuzz] workspace not found: $WORKSPACE" >&2
    exit 2
fi

ARTIFACT_ROOT="${AUDITOOOR_DEEP_ARTIFACT_ROOT:-$WORKSPACE/.auditooor}"
ARTIFACT_DIR="$ARTIFACT_ROOT/$ENGINE_DIR"
ARTIFACT_PATH="$ARTIFACT_DIR/artifact.json"
mkdir -p "$ARTIFACT_DIR"

STDOUT_PATH="$(mktemp "$ARTIFACT_DIR/.stdout.XXXXXX")"
STDERR_PATH="$(mktemp "$ARTIFACT_DIR/.stderr.XXXXXX")"
trap 'rm -f "$STDOUT_PATH" "$STDERR_PATH"' EXIT

if [ "${AUDITOOOR_DEEP_SKIP_MEDUSA:-}" = "1" ]; then
    ENGINE_STATUS="skipped"
    ENGINE_REASON="${SKIP_VAR}=1"
    echo "[medusa-fuzz] ${SKIP_VAR}=1 -> skipping Medusa invocation" >&2
elif ! resolve_deep_engine medusa; then
    ENGINE_STATUS="tool-unavailable"
    ENGINE_REASON="medusa not found (env override, tools/deep-engine-bin/, or PATH)"
    echo "[medusa-fuzz] status tool-unavailable: medusa not found; run 'make deep-engines-provision'" >&2
else
    ENGINE_BIN="$DEEP_ENGINE_BIN"
    echo "[medusa-fuzz] using medusa: $ENGINE_BIN (source: $DEEP_ENGINE_SOURCE)" >&2
    ENGINE_VERSION="$("$ENGINE_BIN" --version 2>/dev/null | awk 'NF {print; exit}')"
    if [ -z "$ENGINE_VERSION" ]; then
        ENGINE_VERSION="version-unknown"
    fi
    # Use a portable wrapper: run engine in background, wait with timeout via watchdog.
    _engine_pid=""
    _watchdog_fired=0
    if [ -n "$_TIMEOUT_BIN" ]; then
        "$_TIMEOUT_BIN" "$_MEDUSA_TIMEOUT" \
            "$ENGINE_BIN" ${ENGINE_ARGS[@]+"${ENGINE_ARGS[@]}"} \
            >"$STDOUT_PATH" 2>"$STDERR_PATH"
        ENGINE_RC=$?
        # GNU timeout exits 124 on timeout; BSD timeout exits the signal (e.g. 143).
        if [ "$ENGINE_RC" -eq 124 ] || [ "$ENGINE_RC" -eq 143 ]; then
            ENGINE_STATUS="timeout"
            ENGINE_REASON="medusa exceeded per-harness timeout of ${_MEDUSA_TIMEOUT}s"
            ENGINE_RC=124
        fi
    else
        # Bash bg+watchdog fallback.
        "$ENGINE_BIN" ${ENGINE_ARGS[@]+"${ENGINE_ARGS[@]}"} \
            >"$STDOUT_PATH" 2>"$STDERR_PATH" &
        _engine_pid=$!
        # Watchdog: sleep, then kill engine. Trap TERM/INT so the subshell exits
        # immediately when the parent kills it after engine completes early.
        (
            trap 'kill "$_sleep_pid" 2>/dev/null || true; exit 0' TERM INT
            sleep "$_MEDUSA_TIMEOUT" &
            _sleep_pid=$!
            wait "$_sleep_pid" 2>/dev/null || true
            kill "$_engine_pid" 2>/dev/null || true
        ) &
        _watchdog_pid=$!
        wait "$_engine_pid" && ENGINE_RC=0 || ENGINE_RC=$?
        kill "$_watchdog_pid" 2>/dev/null || true
        wait "$_watchdog_pid" 2>/dev/null || true
        # kill sends SIGTERM (rc=143) or SIGKILL (rc=137)
        if [ "$ENGINE_RC" -eq 143 ] || [ "$ENGINE_RC" -eq 137 ]; then
            ENGINE_STATUS="timeout"
            ENGINE_REASON="medusa exceeded per-harness timeout of ${_MEDUSA_TIMEOUT}s (bash watchdog)"
            _watchdog_fired=1
        fi
    fi
    if [ "${ENGINE_STATUS}" != "timeout" ]; then
        if [ "$ENGINE_RC" -eq 0 ]; then
            # Execution floor: rc=0 alone does NOT mean any fuzz tests ran. A silent
            # rc=0 with no "Test summary:" output is a non-execution and must not
            # certify (deep-freshness keys on status). C1: no-target -> its OWN status.
            if grep -Eqi "no assertion, property, optimization, or custom tests were found to fuzz" "$STDOUT_PATH" "$STDERR_PATH"; then
                # C1: a no-target result is NOT ok - the property contract was never
                # compiled/fuzzed (silent false-OK). Distinct status so deep-freshness /
                # coverage gates cannot mistake an unexecuted harness for a real pass.
                ENGINE_STATUS="no-target"
                ENGINE_REASON="no-target: medusa found no assertion, property, optimization, or custom fuzz target"
            elif grep -Eq "Test summary:" "$STDOUT_PATH"; then
                ENGINE_STATUS="ok"
            else
                ENGINE_STATUS="no-execution"
                ENGINE_REASON="medusa exited 0 but produced no test summary (no property or assertion tests ran)"
            fi
        else
            if grep -Eqi "no assertion, property, optimization, or custom tests were found to fuzz" "$STDOUT_PATH" "$STDERR_PATH"; then
                ENGINE_STATUS="no-target"
                ENGINE_REASON="no-target: medusa found no assertion, property, optimization, or custom fuzz target"
                ENGINE_RC=0
            else
                ENGINE_STATUS="engine-error"
                ENGINE_REASON="medusa exited with code $ENGINE_RC"
            fi
        fi
    fi
fi

python3 - "$ARTIFACT_PATH" "$WORKSPACE" "$ARTIFACT_DIR" "$ENGINE" "$ENGINE_STATUS" \
    "$ENGINE_REASON" "$ENGINE_BIN" "$ENGINE_VERSION" "$ENGINE_RC" \
    "$STDOUT_PATH" "$STDERR_PATH" -- ${ENGINE_ARGS[@]+"${ENGINE_ARGS[@]}"} <<'PY'
from __future__ import annotations

import json
import os
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

artifact_path = Path(sys.argv[1])
workspace = sys.argv[2]
artifact_dir = sys.argv[3]
engine = sys.argv[4]
status = sys.argv[5]
reason = sys.argv[6]
engine_bin = sys.argv[7] or None
engine_version = sys.argv[8] or None
engine_rc_raw = sys.argv[9]
stdout_path = Path(sys.argv[10])
stderr_path = Path(sys.argv[11])
engine_args = sys.argv[13:]

engine_rc = int(engine_rc_raw) if engine_rc_raw else None

def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""

payload = {
    "schema_version": "auditooor.deep_engine_artifact.v1",
    "engine": engine,
    "workspace": workspace,
    "artifact_dir": artifact_dir,
    "artifact_path": str(artifact_path),
    "run_id": os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID") or None,
    "status": status,
    "reason": reason,
    "invoked": status in {"ok", "engine-error", "timeout"},
    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "tool": {
        "path": engine_bin,
        "version": engine_version,
    },
    "engine_rc": engine_rc,
    "args": engine_args,
    "command": shlex.join([engine_bin or engine, *engine_args]),
    "stdout": read_text(stdout_path),
    "stderr": read_text(stderr_path),
}

artifact_path.parent.mkdir(parents=True, exist_ok=True)
artifact_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY

# Bug A fix: propagate real engine outcome as script exit code under STRICT mode.
# - skipped / tool-unavailable / no-execution / no-target / ok  -> always exit 0
#   (typed artifact records the truth; caller decides)
# - engine-error / timeout -> exit non-zero only when AUDITOOOR_L37_STRICT=1;
#   under non-STRICT the artifact is the source of truth and we exit 0 so the
#   outer all-harnesses loop can continue without crashing.
_SCRIPT_RC=0
case "$ENGINE_STATUS" in
    engine-error|timeout)
        if [ "${AUDITOOOR_L37_STRICT:-0}" = "1" ]; then
            _SCRIPT_RC="${ENGINE_RC:-1}"
            [ "$_SCRIPT_RC" -eq 0 ] && _SCRIPT_RC=1
        fi
        ;;
esac
exit "$_SCRIPT_RC"
