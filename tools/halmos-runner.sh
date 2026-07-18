#!/usr/bin/env bash
# halmos-runner.sh - hermetic Halmos wrapper for A4 deep-mode tests.

set -uo pipefail

# Shared deep-engine binary resolver: env override -> tools/deep-engine-bin/
# (hermetic provisioned) -> PATH. Falls back gracefully when absent.
_HALMOS_RUNNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/deep-engine-resolve.sh
. "$_HALMOS_RUNNER_DIR/lib/deep-engine-resolve.sh"

ENGINE="halmos"
ENGINE_DIR="halmos"
SKIP_VAR="AUDITOOOR_DEEP_SKIP_HALMOS"
ENGINE_STATUS="ok"
ENGINE_REASON="completed"
ENGINE_BIN=""
ENGINE_VERSION=""
ENGINE_RC=""
# Per-harness timeout (seconds). Prefer AUDITOOOR_DEEP_HALMOS_TIMEOUT, fall back
# to the global AUDITOOOR_DEEP_ENGINE_TIMEOUT, then the built-in default.
_DEFAULT_HALMOS_TIMEOUT=600
_HALMOS_TIMEOUT="${AUDITOOOR_DEEP_HALMOS_TIMEOUT:-${AUDITOOOR_DEEP_ENGINE_TIMEOUT:-$_DEFAULT_HALMOS_TIMEOUT}}"
# Resolve the timeout binary: prefer system timeout -> gtimeout -> bash watchdog.
_TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    _TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    _TIMEOUT_BIN="gtimeout"
fi

usage() {
    cat <<'EOF'
usage: tools/halmos-runner.sh <workspace> [halmos-args...]

Writes <workspace>/.auditooor/halmos/artifact.json by default and exits 0
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
EFFECTIVE_ENGINE_ARGS=()
if [ "$#" -gt 0 ]; then
    EFFECTIVE_ENGINE_ARGS=("$@")
fi

if [ ! -d "$WORKSPACE" ]; then
    echo "[halmos-runner] workspace not found: $WORKSPACE" >&2
    exit 2
fi

ARTIFACT_ROOT="${AUDITOOOR_DEEP_ARTIFACT_ROOT:-$WORKSPACE/.auditooor}"
ARTIFACT_DIR="$ARTIFACT_ROOT/$ENGINE_DIR"
ARTIFACT_PATH="$ARTIFACT_DIR/artifact.json"
mkdir -p "$ARTIFACT_DIR"

has_engine_arg() {
    local needle="$1"
    local arg
    for arg in ${EFFECTIVE_ENGINE_ARGS[@]+"${EFFECTIVE_ENGINE_ARGS[@]}"}; do
        if [ "$arg" = "$needle" ] || [[ "$arg" == "$needle="* ]]; then
            return 0
        fi
    done
    return 1
}

foundry_build_out() {
    local foundry_toml="$PWD/foundry.toml"
    [ -f "$foundry_toml" ] || return 1
    python3 - "$foundry_toml" "${FOUNDRY_PROFILE:-default}" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
profile = sys.argv[2] or "default"

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - compatibility with older Python.
    tomllib = None

if tomllib is not None:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        data = {}
    profile_data = ((data.get("profile") or {}).get(profile) or {})
    default_profile = ((data.get("profile") or {}).get("default") or {})
    value = profile_data.get("out") or default_profile.get("out") or data.get("out")
    if isinstance(value, str) and value.strip():
        print(value.strip())
        raise SystemExit(0)

current = ""
for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#"):
        continue
    if line.startswith("[") and line.endswith("]"):
        current = line[1:-1].strip()
        continue
    match = re.match(r"out\s*=\s*(['\"])(.*?)\1", line)
    if match and current in {"", f"profile.{profile}", "profile.default"}:
        print(match.group(2).strip())
        raise SystemExit(0)
PY
}

if [ -f "$PWD/foundry.toml" ]; then
    if ! has_engine_arg "--root"; then
        EFFECTIVE_ENGINE_ARGS+=("--root" "$PWD")
    fi
    if ! has_engine_arg "--forge-build-out"; then
        FOUNDRY_BUILD_OUT="$(foundry_build_out || true)"
        if [ -n "$FOUNDRY_BUILD_OUT" ]; then
            EFFECTIVE_ENGINE_ARGS+=("--forge-build-out" "$FOUNDRY_BUILD_OUT")
        fi
    fi
fi

# Bug B fix: inject a bounded --loop argument so halmos completes bounded work
# on handler-heavy Invariants.t.sol harnesses instead of timing out to zero.
# Default is 8 iterations - enough to catch single-hop bugs without blowing the
# wall-clock budget on workspaces with many selectors. Override via
# AUDITOOOR_HALMOS_LOOP_BOUND=N (0 to suppress injection entirely).
_DEFAULT_HALMOS_LOOP_BOUND=8
_HALMOS_LOOP_BOUND="${AUDITOOOR_HALMOS_LOOP_BOUND:-$_DEFAULT_HALMOS_LOOP_BOUND}"
if [ "${_HALMOS_LOOP_BOUND}" != "0" ] && ! has_engine_arg "--loop"; then
    EFFECTIVE_ENGINE_ARGS+=("--loop" "$_HALMOS_LOOP_BOUND")
fi

STDOUT_PATH="$(mktemp "$ARTIFACT_DIR/.stdout.XXXXXX")"
STDERR_PATH="$(mktemp "$ARTIFACT_DIR/.stderr.XXXXXX")"
trap 'rm -f "$STDOUT_PATH" "$STDERR_PATH"' EXIT

if [ "${AUDITOOOR_DEEP_SKIP_HALMOS:-}" = "1" ]; then
    ENGINE_STATUS="skipped"
    ENGINE_REASON="${SKIP_VAR}=1"
    echo "[halmos-runner] ${SKIP_VAR}=1 -> skipping Halmos invocation" >&2
elif ! resolve_deep_engine halmos; then
    ENGINE_STATUS="tool-unavailable"
    ENGINE_REASON="halmos not found (env override, tools/deep-engine-bin/, or PATH)"
    echo "[halmos-runner] status tool-unavailable: halmos not found; run 'make deep-engines-provision'" >&2
else
    ENGINE_BIN="$DEEP_ENGINE_BIN"
    echo "[halmos-runner] using halmos: $ENGINE_BIN (source: $DEEP_ENGINE_SOURCE)" >&2
    ENGINE_VERSION="$("$ENGINE_BIN" --version 2>/dev/null | awk 'NF {print; exit}')"
    if [ -z "$ENGINE_VERSION" ]; then
        ENGINE_VERSION="version-unknown"
    fi
    # Use a portable wrapper: run engine in background, wait with timeout via watchdog.
    _engine_pid=""
    _watchdog_fired=0
    if [ -n "$_TIMEOUT_BIN" ]; then
        "$_TIMEOUT_BIN" "$_HALMOS_TIMEOUT" \
            "$ENGINE_BIN" ${EFFECTIVE_ENGINE_ARGS[@]+"${EFFECTIVE_ENGINE_ARGS[@]}"} \
            >"$STDOUT_PATH" 2>"$STDERR_PATH"
        ENGINE_RC=$?
        # GNU timeout exits 124 on timeout; BSD timeout exits the signal (e.g. 143).
        if [ "$ENGINE_RC" -eq 124 ] || [ "$ENGINE_RC" -eq 143 ]; then
            ENGINE_STATUS="timeout"
            ENGINE_REASON="halmos exceeded per-harness timeout of ${_HALMOS_TIMEOUT}s"
            ENGINE_RC=124
        fi
    else
        # Bash bg+watchdog fallback.
        "$ENGINE_BIN" ${EFFECTIVE_ENGINE_ARGS[@]+"${EFFECTIVE_ENGINE_ARGS[@]}"} \
            >"$STDOUT_PATH" 2>"$STDERR_PATH" &
        _engine_pid=$!
        # Watchdog: sleep, then kill engine. Trap TERM/INT so the subshell exits
        # immediately when the parent kills it after engine completes early.
        (
            trap 'kill "$_sleep_pid" 2>/dev/null || true; exit 0' TERM INT
            sleep "$_HALMOS_TIMEOUT" &
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
            ENGINE_REASON="halmos exceeded per-harness timeout of ${_HALMOS_TIMEOUT}s (bash watchdog)"
            _watchdog_fired=1
        fi
    fi
    if [ "${ENGINE_STATUS}" != "timeout" ]; then
        if [ "$ENGINE_RC" -eq 0 ]; then
            # Execution floor: rc=0 alone does NOT mean symbolic checks ran. A silent
            # rc=0 with no "Symbolic test result:" summary is a non-execution and must
            # not certify (deep-freshness keys on status). no-target stays ok.
            if grep -Eq "No tests with .*\\^\\(check\\|invariant\\)_" "$STDOUT_PATH" "$STDERR_PATH"; then
                ENGINE_STATUS="ok"
                ENGINE_REASON="no-target: halmos found no check_ or invariant_ symbolic tests"
            elif grep -Eq "Symbolic test result:" "$STDOUT_PATH"; then
                ENGINE_STATUS="ok"
            else
                ENGINE_STATUS="no-execution"
                ENGINE_REASON="halmos exited 0 but produced no symbolic test result summary"
            fi
        else
            if grep -Eq "No tests with .*\\^\\(check\\|invariant\\)_" "$STDOUT_PATH" "$STDERR_PATH"; then
                ENGINE_STATUS="ok"
                ENGINE_REASON="no-target: halmos found no check_ or invariant_ symbolic tests"
                ENGINE_RC=0
            else
                ENGINE_STATUS="engine-error"
                ENGINE_REASON="halmos exited with code $ENGINE_RC"
            fi
        fi
    fi
fi

python3 - "$ARTIFACT_PATH" "$WORKSPACE" "$ARTIFACT_DIR" "$ENGINE" "$ENGINE_STATUS" \
    "$ENGINE_REASON" "$ENGINE_BIN" "$ENGINE_VERSION" "$ENGINE_RC" \
    "$STDOUT_PATH" "$STDERR_PATH" -- ${EFFECTIVE_ENGINE_ARGS[@]+"${EFFECTIVE_ENGINE_ARGS[@]}"} <<'PY'
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

command_parts = [engine_bin or engine, *engine_args]

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
    "tool": {
        "path": engine_bin,
        "version": engine_version,
    },
    "engine_rc": engine_rc,
    "args": engine_args,
    "command": shlex.join(command_parts),
    "stdout": read_text(stdout_path),
    "stderr": read_text(stderr_path),
    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
