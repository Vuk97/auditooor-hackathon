#!/usr/bin/env bash
# fuzz-runner.sh — PR 107 bounded fuzz-engine runner (medusa | echidna | auto).
#
# Runs a single fuzzing session against a workspace under a hard wall-clock
# timeout, stores the command, engine version, status, and (if found) a failing
# call sequence under <workspace>/fuzz_runs/<timestamp>/, and emits a
# machine-readable manifest.json.
#
# ADVISORY ONLY: this runner is not wired into any blocking gate. A
# counterexample here upgrades a candidate to "proven" ONLY when paired with a
# passing Forge PoC demonstrating the same sequence and its economic outcome.
#
# Usage:
#   tools/fuzz-runner.sh <workspace>
#     [--engine medusa|echidna|auto]   # default: auto
#     [--timeout 600]                  # seconds; default 600, hard cap 3600
#     [--test-contract <Name>]         # passed through to the engine
#     [--config <path>]                # override medusa.json / echidna.yaml
#     [--out-dir <path>]               # default: <workspace>/fuzz_runs/<ts>/
#     [--project-root <path>]          # forge project root (auto-detected if absent)
#     [--dry-run]                      # print command that WOULD run, exit 0
#     [--help]
#
# Exit-code discipline (advisory):
#   0  → any engine outcome (pass | counterexample | timeout | error | skipped)
#   1+ → misconfiguration (invalid args, missing workspace, missing timeout utility)
#
# Output layout:
#   <out-dir>/
#     command.txt             argv-quoted command line
#     engine.txt              "medusa" | "echidna" | "SKIPPED"
#     engine_version.txt      captured via `<engine> --version` (best-effort)
#     timeout_seconds.txt     e.g. "600"
#     status.txt              "pass" | "counterexample" | "timeout" | "error" | "skipped"
#     stdout.log              engine stdout
#     stderr.log              engine stderr
#     manifest.json           machine-readable summary
#     failing_sequence.txt    counterexample trace (only on status=counterexample)

set -uo pipefail

usage() {
    cat <<'EOF'
usage: tools/fuzz-runner.sh <workspace> [options]

Options:
  --engine medusa|echidna|auto   Engine to run (default: auto).
  --timeout <sec>                Wall-clock timeout in seconds (default: 600, cap: 3600).
  --test-contract <Name>         Forwarded to the engine (medusa --test-contract / echidna --contract).
  --config <path>                Override config (medusa.json or echidna.yaml).
  --out-dir <path>               Override output directory.
  --project-root <path>          Forge project root (where foundry.toml + out/ live).
                                 Engine runs from this directory so crytic-compile
                                 finds the build artifacts. Auto-detected when absent
                                 by walking <workspace>/foundry.toml then
                                 <workspace>/src/<repo>/foundry.toml (shallowest non-lib).
                                 Required for multi-project workspaces (e.g. morpho,
                                 centrifuge with multiple cloned repos under src/).
                                 I13 (#328) fix.
  --dry-run                      Render the command to command.txt and exit 0 without invoking.
  -h, --help                     Show this help.

Advisory runner; exits 0 on any engine outcome. Non-zero exit only on
misconfiguration (missing timeout utility, invalid args, missing workspace).
EOF
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
ENGINE="auto"
TIMEOUT_SEC="600"
TEST_CONTRACT=""
CONFIG_PATH=""
OUT_DIR_OVERRIDE=""
DRY_RUN=0
WORKSPACE=""
PROJECT_ROOT_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --engine)
            [ $# -ge 2 ] || { echo "[fuzz-runner] --engine requires a value" >&2; exit 2; }
            ENGINE="$2"; shift 2 ;;
        --timeout)
            [ $# -ge 2 ] || { echo "[fuzz-runner] --timeout requires a value" >&2; exit 2; }
            TIMEOUT_SEC="$2"; shift 2 ;;
        --test-contract)
            [ $# -ge 2 ] || { echo "[fuzz-runner] --test-contract requires a value" >&2; exit 2; }
            TEST_CONTRACT="$2"; shift 2 ;;
        --config)
            [ $# -ge 2 ] || { echo "[fuzz-runner] --config requires a value" >&2; exit 2; }
            CONFIG_PATH="$2"; shift 2 ;;
        --out-dir)
            [ $# -ge 2 ] || { echo "[fuzz-runner] --out-dir requires a value" >&2; exit 2; }
            OUT_DIR_OVERRIDE="$2"; shift 2 ;;
        --project-root)
            # I13 fix (#328): same project-root resolver as symbolic-runner.
            # Medusa/Echidna look for `out/`, `foundry.toml`, and target
            # contract artifacts under CWD. Without this, fuzz-runner used
            # to fail in <1s with "X was specified in the target contracts
            # but was not found in the compilation artifacts".
            [ $# -ge 2 ] || { echo "[fuzz-runner] --project-root requires a value" >&2; exit 2; }
            PROJECT_ROOT_OVERRIDE="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        --*)
            echo "[fuzz-runner] unknown flag: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -z "$WORKSPACE" ]; then
                WORKSPACE="$1"; shift
            else
                echo "[fuzz-runner] unexpected positional arg: $1" >&2; usage >&2; exit 2
            fi ;;
    esac
done

if [ -z "$WORKSPACE" ]; then
    echo "[fuzz-runner] missing <workspace>" >&2
    usage >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

case "$ENGINE" in
    medusa|echidna|auto) ;;
    *) echo "[fuzz-runner] invalid --engine '$ENGINE' (expected medusa|echidna|auto)" >&2; exit 2 ;;
esac

# timeout numeric + cap check
if ! [[ "$TIMEOUT_SEC" =~ ^[0-9]+$ ]]; then
    echo "[fuzz-runner] --timeout must be a non-negative integer (got: $TIMEOUT_SEC)" >&2
    exit 2
fi
if [ "$TIMEOUT_SEC" -gt 3600 ]; then
    echo "[fuzz-runner] --timeout capped at 3600s (got: $TIMEOUT_SEC); using 3600" >&2
    TIMEOUT_SEC=3600
fi
if [ "$TIMEOUT_SEC" -eq 0 ]; then
    echo "[fuzz-runner] --timeout 0 is not supported (would be unbounded)" >&2
    exit 2
fi

if [ ! -d "$WORKSPACE" ]; then
    echo "[fuzz-runner] workspace not found: $WORKSPACE" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Auto-pick --test-contract from mining_priorities.json if not provided.
#
# I16 (#332): when audit-deep --live invokes fuzz-runner without an explicit
# target, medusa exits at startup with "no targets specified" (and echidna
# refuses to compile against a multi-contract workspace). We mirror the
# symbolic-runner I15 fallback: prefer entry.contract → entry.contracts[] →
# title regex. Unlike symbolic-runner we do NOT filter by --angle (fuzzers are
# angle-agnostic); the highest-ranked entry with any extractable contract wins.
# ---------------------------------------------------------------------------
if [ -z "$TEST_CONTRACT" ]; then
    MP_PATH="$WORKSPACE/swarm/mining_priorities.json"
    if [ -f "$MP_PATH" ] && command -v python3 >/dev/null 2>&1; then
        TEST_CONTRACT="$(
            python3 - "$MP_PATH" <<'PY' 2>/dev/null || true
import json, re, sys
path = sys.argv[1]
try:
    data = json.loads(open(path).read())
except Exception:
    sys.exit(0)
if not isinstance(data, list):
    sys.exit(0)
for entry in data:
    if not isinstance(entry, dict):
        continue
    c = entry.get("contract")
    if isinstance(c, str) and c.strip():
        print(c.strip()); sys.exit(0)
    cs = entry.get("contracts")
    if isinstance(cs, list):
        for x in cs:
            if isinstance(x, str) and x.strip():
                print(x.strip()); sys.exit(0)
    title = entry.get("title") or ""
    if isinstance(title, str) and title:
        m = re.search(r":\s+([A-Z][A-Za-z0-9_]+)\.[a-zA-Z_]", title)
        if not m:
            m = re.search(r"\b([A-Z][A-Za-z0-9_]+)\.[a-zA-Z_]", title)
        if m:
            print(m.group(1)); sys.exit(0)
PY
        )"
    fi
fi

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -n "$OUT_DIR_OVERRIDE" ]; then
    OUT_DIR="$OUT_DIR_OVERRIDE"
else
    OUT_DIR="$WORKSPACE/fuzz_runs/$TS"
fi
mkdir -p "$OUT_DIR" || { echo "[fuzz-runner] failed to create out-dir: $OUT_DIR" >&2; exit 2; }

WS_BASENAME="$(basename "$WORKSPACE")"
STDOUT_LOG="$OUT_DIR/stdout.log"
STDERR_LOG="$OUT_DIR/stderr.log"
MANIFEST="$OUT_DIR/manifest.json"
FAILING_SEQ="$OUT_DIR/failing_sequence.txt"

# ---------------------------------------------------------------------------
# Engine selection
# ---------------------------------------------------------------------------
chosen_engine=""
if [ "$ENGINE" = "auto" ]; then
    if command -v medusa >/dev/null 2>&1; then
        chosen_engine="medusa"
    elif command -v echidna >/dev/null 2>&1; then
        chosen_engine="echidna"
    else
        chosen_engine=""
    fi
elif [ "$ENGINE" = "medusa" ]; then
    if command -v medusa >/dev/null 2>&1; then chosen_engine="medusa"; else chosen_engine=""; fi
elif [ "$ENGINE" = "echidna" ]; then
    if command -v echidna >/dev/null 2>&1; then chosen_engine="echidna"; else chosen_engine=""; fi
fi

# ---------------------------------------------------------------------------
# JSON helpers (avoid python/jq dep — simple string escaper)
# ---------------------------------------------------------------------------
json_escape() {
    # stdin → stdout with JSON-escaped string contents (no surrounding quotes)
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    # Strip CR and encode \n/\t via printf handling — keep it simple: replace
    # newlines and tabs with spaces so manifest.json stays single-line-safe.
    s="${s//$'\n'/ }"
    s="${s//$'\t'/ }"
    s="${s//$'\r'/ }"
    printf '%s' "$s"
}

# argv-quote a list (space-separated, individual args single-quoted if they
# contain spaces or special chars).
quote_argv() {
    local out=""
    local a
    for a in "$@"; do
        if [[ "$a" =~ [[:space:]\'\"\\\$] ]]; then
            # wrap in single-quotes, escape embedded single-quotes
            local esc="${a//\'/\'\\\'\'}"
            out+="'$esc' "
        else
            out+="$a "
        fi
    done
    printf '%s' "${out% }"
}

iso_now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

write_manifest() {
    local engine="$1"
    local engine_version="$2"
    local status="$3"
    local command_str="$4"
    local started="$5"
    local ended="$6"
    local duration="$7"
    local ce_path="$8"        # empty → null
    local stdout_bytes="$9"
    local stderr_bytes="${10}"
    local notes="${11}"

    local ce_json='null'
    if [ -n "$ce_path" ]; then
        ce_json="\"$(json_escape "$ce_path")\""
    fi

    cat > "$MANIFEST" <<EOF
{
  "schema_version": 1,
  "workspace": "$(json_escape "$WS_BASENAME")",
  "engine": "$(json_escape "$engine")",
  "engine_version": "$(json_escape "$engine_version")",
  "timeout_seconds": ${TIMEOUT_SEC},
  "status": "$(json_escape "$status")",
  "command": "$(json_escape "$command_str")",
  "started_at": "$(json_escape "$started")",
  "ended_at": "$(json_escape "$ended")",
  "duration_seconds": ${duration},
  "counterexample_path": ${ce_json},
  "stdout_bytes": ${stdout_bytes},
  "stderr_bytes": ${stderr_bytes},
  "notes": "$(json_escape "$notes")"
}
EOF
}

# ---------------------------------------------------------------------------
# SKIPPED path: no engine available
# ---------------------------------------------------------------------------
if [ -z "$chosen_engine" ]; then
    echo "[fuzz-runner] No fuzz engine found — run install per docs/WORKFLOW.md"
    printf 'SKIPPED\n' > "$OUT_DIR/engine.txt"
    printf '%s\n' "$TIMEOUT_SEC" > "$OUT_DIR/timeout_seconds.txt"
    printf 'skipped\n' > "$OUT_DIR/status.txt"
    printf '' > "$OUT_DIR/engine_version.txt"
    printf '(no engine; no command rendered)\n' > "$OUT_DIR/command.txt"
    : > "$STDOUT_LOG"
    : > "$STDERR_LOG"
    NOW="$(iso_now)"
    write_manifest \
        "SKIPPED" "" "skipped" "" "$NOW" "$NOW" "0" "" "0" "0" \
        "No fuzz engine found — run install per docs/WORKFLOW.md"
    exit 0
fi

# ---------------------------------------------------------------------------
# Timeout utility detection
# ---------------------------------------------------------------------------
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
else
    echo "[fuzz-runner] no timeout utility — running unbounded is unsafe; aborting" >&2
    exit 3
fi

# ---------------------------------------------------------------------------
# Build engine command
# ---------------------------------------------------------------------------
# Capture version best-effort
ENGINE_VERSION=""
if _v="$("$chosen_engine" --version 2>/dev/null)"; then
    ENGINE_VERSION="${_v%%$'\n'*}"
fi

# Auto-discover config if not provided
AUTO_CONFIG=""
if [ -z "$CONFIG_PATH" ]; then
    case "$chosen_engine" in
        medusa)
            for cand in "$WORKSPACE/medusa.json" "$WORKSPACE/fuzz/medusa.json"; do
                [ -f "$cand" ] && AUTO_CONFIG="$cand" && break
            done ;;
        echidna)
            for cand in "$WORKSPACE/echidna.yaml" "$WORKSPACE/fuzz/echidna.yaml"; do
                [ -f "$cand" ] && AUTO_CONFIG="$cand" && break
            done ;;
    esac
fi
EFFECTIVE_CONFIG="${CONFIG_PATH:-$AUTO_CONFIG}"

# I19 (#339) + I20 (#341) + I21 (#342): when an I17 scaffold exists, resolve
# the harness from the workspace's configured Foundry test dir (instead of
# the old hardcoded poc-tests/). For medusa, prefer Property_<TEST_CONTRACT>
# over Invariant_<TEST_CONTRACT> because medusa discovers property_* tests.
TEST_DIR="test"
if command -v python3 >/dev/null 2>&1; then
    TEST_DIR="$(python3 "$HERE/lib/resolve-forge-test-dir.py" "$WORKSPACE" 2>/dev/null || echo test)"
fi

EFFECTIVE_TEST_CONTRACT="$TEST_CONTRACT"
if [ -n "$TEST_CONTRACT" ]; then
    INV_FILE="$WORKSPACE/$TEST_DIR/Invariant_$TEST_CONTRACT.t.sol"
    PROP_FILE="$WORKSPACE/$TEST_DIR/Property_$TEST_CONTRACT.t.sol"
    if [ "$chosen_engine" = "medusa" ] && [ -f "$PROP_FILE" ]; then
        EFFECTIVE_TEST_CONTRACT="Property_$TEST_CONTRACT"
    elif [ -f "$INV_FILE" ]; then
        EFFECTIVE_TEST_CONTRACT="Invariant_$TEST_CONTRACT"
    fi
fi

# Engine argv
ENGINE_ARGV=()
case "$chosen_engine" in
    medusa)
        ENGINE_ARGV=("medusa" "fuzz")
        [ -n "$EFFECTIVE_CONFIG" ]        && ENGINE_ARGV+=("--config" "$EFFECTIVE_CONFIG")
        [ -n "$EFFECTIVE_TEST_CONTRACT" ] && ENGINE_ARGV+=("--target-contracts" "$EFFECTIVE_TEST_CONTRACT")
        ;;
    echidna)
        ENGINE_ARGV=("echidna" "$WORKSPACE")
        [ -n "$EFFECTIVE_CONFIG" ]        && ENGINE_ARGV+=("--config" "$EFFECTIVE_CONFIG")
        [ -n "$EFFECTIVE_TEST_CONTRACT" ] && ENGINE_ARGV+=("--contract" "$EFFECTIVE_TEST_CONTRACT")
        ;;
esac

# I13 fix (#328): resolve forge project root for medusa/echidna.
# Resolution order:
#   1. --project-root (operator override)
#   2. <WORKSPACE>/foundry.toml (single-project workspace)
#   3. <WORKSPACE>/src/<repo>/foundry.toml (multi-project; shallowest non-lib)
#   4. fail loudly with cannot-run: no-forge-project
PROJECT_ROOT=""
if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
    PROJECT_ROOT="$PROJECT_ROOT_OVERRIDE"
elif [ -f "$WORKSPACE/foundry.toml" ]; then
    PROJECT_ROOT="$WORKSPACE"
else
    if [ -d "$WORKSPACE/src" ]; then
        for cand in "$WORKSPACE/src"/*/foundry.toml; do
            [ -f "$cand" ] || continue
            # Skip a project literally named `lib` (rare but possible).
            # Basename match (not substring) so `library-foo` etc. are
            # not falsely skipped (Kimi review).
            if [ "$(basename "$(dirname "$cand")")" = "lib" ]; then
                continue
            fi
            PROJECT_ROOT="$(dirname "$cand")"
            break
        done
    fi
fi
if [ -z "$PROJECT_ROOT" ] || [ ! -f "$PROJECT_ROOT/foundry.toml" ]; then
    echo "[fuzz-runner] cannot-run: no-forge-project (no foundry.toml under $WORKSPACE; pass --project-root <path>)" >&2
    NOW="$(iso_now)"
    write_manifest \
        "$ENGINE" "n/a" "skipped" "(no engine invocation)" \
        "$NOW" "$NOW" "0" "" "0" "0" \
        "cannot-run: no-forge-project — pass --project-root or place foundry.toml under workspace"
    exit 2
fi
printf '%s\n' "$PROJECT_ROOT" > "$OUT_DIR/project_root.txt"

# I22 (#344): Foundry/crytic-compile skips `test/**` by default, so a
# scaffolded Medusa property harness can be selected via --target-contracts yet
# never compiled, yielding "no property tests found". When we auto-resolved a
# Property_<X>.t.sol harness, force Medusa's compilation target to that file.
if [ "$chosen_engine" = "medusa" ] && [ -n "${PROP_FILE:-}" ] && [ -f "$PROP_FILE" ] && [ "$EFFECTIVE_TEST_CONTRACT" = "Property_$TEST_CONTRACT" ]; then
    ENGINE_ARGV+=("--compilation-target" "$PROP_FILE")
fi

FULL_ARGV=("$TIMEOUT_BIN" "${TIMEOUT_SEC}s" "${ENGINE_ARGV[@]}")
COMMAND_STR="$(quote_argv "${FULL_ARGV[@]}")"

# Always write pre-computed files
printf '%s\n' "$chosen_engine" > "$OUT_DIR/engine.txt"
printf '%s\n' "$ENGINE_VERSION" > "$OUT_DIR/engine_version.txt"
printf '%s\n' "$TIMEOUT_SEC" > "$OUT_DIR/timeout_seconds.txt"
printf '%s\n' "$COMMAND_STR" > "$OUT_DIR/command.txt"

# ---------------------------------------------------------------------------
# Dry-run path
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    printf 'skipped\n' > "$OUT_DIR/status.txt"
    NOW="$(iso_now)"
    write_manifest \
        "$chosen_engine" "$ENGINE_VERSION" "skipped" "$COMMAND_STR" \
        "$NOW" "$NOW" "0" "" "0" "0" \
        "dry-run: engine was NOT invoked"
    echo "[fuzz-runner] dry-run: would execute: $COMMAND_STR"
    echo "[fuzz-runner] out-dir: $OUT_DIR"
    exit 0
fi

# ---------------------------------------------------------------------------
# Invoke engine under timeout
# ---------------------------------------------------------------------------
STARTED_AT="$(iso_now)"
START_EPOCH="$(date -u +%s)"

# I13 fix (#328): cd into the forge project root so medusa/echidna find
# `out/`, `lib/`, `foundry.toml` under CWD. Subshell isolates the cd.
set +e
( cd "$PROJECT_ROOT" && "${FULL_ARGV[@]}" ) >"$STDOUT_LOG" 2>"$STDERR_LOG"
ENGINE_EXIT=$?
set -e

ENDED_AT="$(iso_now)"
END_EPOCH="$(date -u +%s)"
DURATION=$(( END_EPOCH - START_EPOCH ))

# Byte counts (portable)
stdout_bytes=$(wc -c < "$STDOUT_LOG" 2>/dev/null | tr -d ' ' || echo 0)
stderr_bytes=$(wc -c < "$STDERR_LOG" 2>/dev/null | tr -d ' ' || echo 0)
stdout_bytes="${stdout_bytes:-0}"
stderr_bytes="${stderr_bytes:-0}"

# ---------------------------------------------------------------------------
# Classify status
# ---------------------------------------------------------------------------
STATUS="error"
CE_PATH=""
NOTES=""

# Counterexample markers first (may coexist with nonzero exit)
ce_found=0
case "$chosen_engine" in
    medusa)
        if grep -qE 'Counterexample:|call sequence' "$STDOUT_LOG" 2>/dev/null; then ce_found=1; fi ;;
    echidna)
        if grep -qE 'failed!|crashed' "$STDOUT_LOG" 2>/dev/null; then ce_found=1; fi ;;
esac

if [ "$ce_found" -eq 1 ]; then
    STATUS="counterexample"
    # Extract failing sequence: take counterexample block + following lines
    case "$chosen_engine" in
        medusa)
            awk '
                /Counterexample:|call sequence/ { hit=1 }
                hit { print }
            ' "$STDOUT_LOG" > "$FAILING_SEQ" 2>/dev/null || true ;;
        echidna)
            awk '
                /failed!|crashed/ { hit=1 }
                hit { print }
            ' "$STDOUT_LOG" > "$FAILING_SEQ" 2>/dev/null || true ;;
    esac
    if [ ! -s "$FAILING_SEQ" ]; then
        # Fallback: full stdout as the sequence
        cp "$STDOUT_LOG" "$FAILING_SEQ" 2>/dev/null || true
    fi
    CE_PATH="failing_sequence.txt"
elif [ "$ENGINE_EXIT" -eq 124 ] || [ "$ENGINE_EXIT" -eq 137 ]; then
    STATUS="timeout"
    NOTES="engine killed by ${TIMEOUT_BIN} at ${TIMEOUT_SEC}s (exit ${ENGINE_EXIT})"
elif [ "$ENGINE_EXIT" -eq 0 ]; then
    STATUS="pass"
else
    STATUS="error"
    NOTES="engine exited non-zero (${ENGINE_EXIT}) with no counterexample markers"
fi

printf '%s\n' "$STATUS" > "$OUT_DIR/status.txt"

write_manifest \
    "$chosen_engine" "$ENGINE_VERSION" "$STATUS" "$COMMAND_STR" \
    "$STARTED_AT" "$ENDED_AT" "$DURATION" \
    "$CE_PATH" "$stdout_bytes" "$stderr_bytes" "$NOTES"

echo "[fuzz-runner] engine=$chosen_engine status=$STATUS duration=${DURATION}s out=$OUT_DIR"

# Advisory: always exit 0 on any engine outcome.
exit 0
