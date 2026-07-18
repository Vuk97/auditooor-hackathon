#!/usr/bin/env bash
# hydra-runner.sh — multi-engine aggregator (auditooor's answer to
# Trail of Bits' Hydra meta-tool).
#
# Background
# ----------
# Trail of Bits' upstream `hydra` orchestrates multiple smart-contract
# security tools (slither, manticore, echidna, mythx) against a single
# target and merges their reports. Auditooor's V3 Slice 4 plan mentioned
# `tools/hydra-runner.sh` but it was never built — `docs/TOOL_COST_BENEFIT.md`
# until 2026-04-27 falsely claimed it "exists today" (#327 / I12).
#
# This script is the live wrapper. It:
#   1. Runs each available auditooor deep-engine wrapper sequentially:
#        - slither (via `tools/slither-resilient.sh`)
#        - halmos  (via `tools/symbolic-runner.sh --engine halmos --live`)
#        - medusa  (via `tools/fuzz-runner.sh --engine medusa`)
#   2. Captures per-engine status + manifest path + duration.
#   3. Calls `tools/cross-lane-correlate.py` to join any typed
#      `deep_candidate.v1` records the engines emitted (file-overlap join).
#   4. Writes a single aggregated manifest at
#      `<workspace>/hydra_runs/<ts>/hydra_manifest.json` plus a
#      human-readable `hydra_report.md`.
#
# This is NOT the upstream Trail of Bits Hydra (which targets live
# devnets with mempool/sequencer dynamics). It's a multi-engine
# aggregator that gives operators ONE entry point + ONE merged report
# for the engines auditooor already supports. The upstream Hydra-style
# live-devnet flow is still out of scope (no devnet provisioning
# automation) — see `docs/TOOL_COST_BENEFIT.md` "Hydra (live adversarial
# run against a running node)" for the cost/setup discussion.
#
# Usage:
#   tools/hydra-runner.sh <workspace>
#     [--contract <Name>]           # passed through to halmos
#     [--test-contract <Name>]      # passed through to medusa
#     [--symbolic-timeout 600]      # halmos wall-clock cap
#     [--fuzz-timeout 600]          # medusa wall-clock cap
#     [--project-root <path>]       # forge project root (auto-detected)
#     [--engines slither,halmos,medusa]  # default: all three
#     [--out-dir <path>]            # default: <workspace>/hydra_runs/<ts>/
#     [--dry-run]                   # print plan, exit 0 without invoking
#     [-h|--help]
#
# Exit codes:
#   0 — every engine completed (any per-engine outcome including
#       counterexample, timeout, error is rolled up; all are advisory)
#   2 — misconfiguration (bad args, missing workspace, no engines selected)
#
# Hard rules (Codex review-gate):
#   - Stdlib + already-vendored auditooor wrappers only. No new
#     dependencies.
#   - Per-engine errors do NOT abort the aggregator — Trail of Bits
#     Hydra's whole point is to keep going even when one tool fails.
#   - Manifest schema is `auditooor.hydra_runner.v1` so future telemetry
#     can join across runs.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"

usage() {
    cat <<'EOF'
hydra-runner.sh — multi-engine deep-audit aggregator

Usage:
  tools/hydra-runner.sh <workspace> [options]

Options:
  --contract <Name>        Forwarded to halmos (`--contract`).
  --test-contract <Name>   Forwarded to medusa (`--test-contract`).
  --symbolic-timeout <sec> Halmos wall-clock budget (default: 600).
  --fuzz-timeout <sec>     Medusa wall-clock budget (default: 600).
  --project-root <path>    Forge project root (where foundry.toml + out/
                            live). Auto-detected if absent. Required for
                            multi-project workspaces (morpho, centrifuge).
  --engines <list>         Comma-separated subset of {slither,halmos,medusa}.
                            Default: all three.
  --out-dir <path>         Override output directory.
  --dry-run                Print the planned engine invocations and exit.
  -h, --help               Show this help.

Output:
  <out>/
    hydra_manifest.json    Aggregated machine-readable summary.
    hydra_report.md        Human-readable rollup with per-engine status.
    slither.log            slither stdout/stderr.
    symbolic_runs/         per-engine sub-manifests from symbolic-runner.
    fuzz_runs/             per-engine sub-manifests from fuzz-runner.

This is auditooor's local multi-engine aggregator (NOT the upstream
Trail of Bits Hydra). For live-devnet adversarial flows see
`docs/TOOL_COST_BENEFIT.md` "Hydra (live adversarial run against a
running node)".
EOF
}

WORKSPACE=""
CONTRACT=""
TEST_CONTRACT=""
SYMBOLIC_TIMEOUT="600"
FUZZ_TIMEOUT="600"
PROJECT_ROOT_OVERRIDE=""
ENGINES_REQUESTED="slither,halmos,medusa"
OUT_DIR_OVERRIDE=""
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --contract)
            [ $# -ge 2 ] || { echo "[hydra-runner] --contract requires a value" >&2; exit 2; }
            CONTRACT="$2"; shift 2 ;;
        --test-contract)
            [ $# -ge 2 ] || { echo "[hydra-runner] --test-contract requires a value" >&2; exit 2; }
            TEST_CONTRACT="$2"; shift 2 ;;
        --symbolic-timeout)
            [ $# -ge 2 ] || { echo "[hydra-runner] --symbolic-timeout requires a value" >&2; exit 2; }
            SYMBOLIC_TIMEOUT="$2"; shift 2 ;;
        --fuzz-timeout)
            [ $# -ge 2 ] || { echo "[hydra-runner] --fuzz-timeout requires a value" >&2; exit 2; }
            FUZZ_TIMEOUT="$2"; shift 2 ;;
        --project-root)
            [ $# -ge 2 ] || { echo "[hydra-runner] --project-root requires a value" >&2; exit 2; }
            PROJECT_ROOT_OVERRIDE="$2"; shift 2 ;;
        --engines)
            [ $# -ge 2 ] || { echo "[hydra-runner] --engines requires a value" >&2; exit 2; }
            ENGINES_REQUESTED="$2"; shift 2 ;;
        --out-dir)
            [ $# -ge 2 ] || { echo "[hydra-runner] --out-dir requires a value" >&2; exit 2; }
            OUT_DIR_OVERRIDE="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        --*)
            echo "[hydra-runner] unknown flag: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -z "$WORKSPACE" ]; then
                WORKSPACE="$1"; shift
            else
                echo "[hydra-runner] unexpected positional arg: $1" >&2; exit 2
            fi ;;
    esac
done

if [ -z "$WORKSPACE" ]; then
    echo "[hydra-runner] missing <workspace>" >&2
    usage >&2
    exit 2
fi
if [ ! -d "$WORKSPACE" ]; then
    echo "[hydra-runner] workspace not found: $WORKSPACE" >&2
    exit 2
fi

# Engine selection — case-insensitive split on commas, dedupe.
SELECT_SLITHER=0; SELECT_HALMOS=0; SELECT_MEDUSA=0
_engines_arr=()
if [ -n "$ENGINES_REQUESTED" ]; then
    IFS=',' read -ra _engines_arr <<< "$ENGINES_REQUESTED"
fi
for e in "${_engines_arr[@]:-}"; do
    e_lc="$(echo "$e" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    case "$e_lc" in
        slither) SELECT_SLITHER=1 ;;
        halmos)  SELECT_HALMOS=1 ;;
        medusa)  SELECT_MEDUSA=1 ;;
        "")      ;;
        *)
            echo "[hydra-runner] unknown engine: $e (expected slither|halmos|medusa)" >&2; exit 2 ;;
    esac
done
if [ $((SELECT_SLITHER + SELECT_HALMOS + SELECT_MEDUSA)) -eq 0 ]; then
    echo "[hydra-runner] --engines must select at least one of slither|halmos|medusa" >&2
    exit 2
fi

TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -n "$OUT_DIR_OVERRIDE" ]; then
    OUT_DIR="$OUT_DIR_OVERRIDE"
else
    OUT_DIR="$WORKSPACE/hydra_runs/$TS"
fi
mkdir -p "$OUT_DIR"

iso_now() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }

# Per-engine runner with status capture. Echoes `name|status|duration|manifest_path`.
_run_slither() {
    local started ended dur out_log
    out_log="$OUT_DIR/slither.log"
    started="$(iso_now)"
    local start_epoch=$(date -u +%s)
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[hydra-runner] dry-run: would run slither-resilient.sh against $WORKSPACE" > "$out_log"
        echo "slither|skipped|0|$out_log"
        return 0
    fi
    if [ ! -x "$HERE/slither-resilient.sh" ]; then
        echo "[hydra-runner] slither-resilient.sh not found at $HERE" > "$out_log"
        echo "slither|missing|0|$out_log"
        return 0
    fi
    bash "$HERE/slither-resilient.sh" --timeout 120 -- "$WORKSPACE" \
        > "$out_log" 2>&1 || true
    ended="$(iso_now)"
    local end_epoch=$(date -u +%s)
    dur=$((end_epoch - start_epoch))
    echo "slither|completed|$dur|$out_log"
}

_run_halmos() {
    local started ended dur sub_out_dir
    sub_out_dir="$OUT_DIR/symbolic_runs"
    mkdir -p "$sub_out_dir"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "halmos|skipped|0|"
        return 0
    fi
    started="$(iso_now)"
    local start_epoch=$(date -u +%s)
    local symbolic_args=(--engine halmos --angle A-AUTH --timeout "$SYMBOLIC_TIMEOUT" --out-dir "$sub_out_dir/$(date -u +%Y%m%dT%H%M%SZ)")
    [ -n "$CONTRACT" ]            && symbolic_args+=(--contract "$CONTRACT")
    [ -n "$PROJECT_ROOT_OVERRIDE" ] && symbolic_args+=(--project-root "$PROJECT_ROOT_OVERRIDE")
    bash "$HERE/symbolic-runner.sh" "$WORKSPACE" "${symbolic_args[@]}" \
        >> "$OUT_DIR/halmos.stdout.log" 2>> "$OUT_DIR/halmos.stderr.log" || true
    ended="$(iso_now)"
    local end_epoch=$(date -u +%s)
    dur=$((end_epoch - start_epoch))
    # Find the most recent sub-manifest the runner just wrote.
    local manifest
    manifest="$(find "$sub_out_dir" -name manifest.json -print 2>/dev/null | tail -1)"
    echo "halmos|completed|$dur|${manifest:-$OUT_DIR/halmos.stdout.log}"
}

_run_medusa() {
    local started ended dur sub_out_dir
    sub_out_dir="$OUT_DIR/fuzz_runs"
    mkdir -p "$sub_out_dir"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "medusa|skipped|0|"
        return 0
    fi
    started="$(iso_now)"
    local start_epoch=$(date -u +%s)
    local fuzz_args=(--engine medusa --timeout "$FUZZ_TIMEOUT" --out-dir "$sub_out_dir/$(date -u +%Y%m%dT%H%M%SZ)")
    [ -n "$TEST_CONTRACT" ]       && fuzz_args+=(--test-contract "$TEST_CONTRACT")
    [ -n "$PROJECT_ROOT_OVERRIDE" ] && fuzz_args+=(--project-root "$PROJECT_ROOT_OVERRIDE")
    bash "$HERE/fuzz-runner.sh" "$WORKSPACE" "${fuzz_args[@]}" \
        >> "$OUT_DIR/medusa.stdout.log" 2>> "$OUT_DIR/medusa.stderr.log" || true
    ended="$(iso_now)"
    local end_epoch=$(date -u +%s)
    dur=$((end_epoch - start_epoch))
    local manifest
    manifest="$(find "$sub_out_dir" -name manifest.json -print 2>/dev/null | tail -1)"
    echo "medusa|completed|$dur|${manifest:-$OUT_DIR/medusa.stdout.log}"
}

# Sequence engines.
RESULTS=()
HYDRA_STARTED="$(iso_now)"
HYDRA_START_EPOCH=$(date -u +%s)

[ "$SELECT_SLITHER" -eq 1 ] && RESULTS+=("$(_run_slither)")
[ "$SELECT_HALMOS"  -eq 1 ] && RESULTS+=("$(_run_halmos)")
[ "$SELECT_MEDUSA"  -eq 1 ] && RESULTS+=("$(_run_medusa)")

# Cross-lane-correlate — best-effort, not a gate.
CROSS_LANE_STATUS="skipped"
CROSS_LANE_OUTPUT=""
if [ "$DRY_RUN" -ne 1 ] && [ -x "$HERE/cross-lane-correlate.py" ]; then
    if python3 "$HERE/cross-lane-correlate.py" --workspace "$WORKSPACE" \
            > "$OUT_DIR/cross_lane.stdout.log" 2>&1; then
        CROSS_LANE_STATUS="completed"
        CROSS_LANE_OUTPUT="$WORKSPACE/.audit_logs/cross_lane_correlations.json"
    else
        CROSS_LANE_STATUS="error"
    fi
fi

HYDRA_ENDED="$(iso_now)"
HYDRA_END_EPOCH=$(date -u +%s)
HYDRA_DURATION=$((HYDRA_END_EPOCH - HYDRA_START_EPOCH))

# Write manifest.
MANIFEST="$OUT_DIR/hydra_manifest.json"
{
    printf '{\n'
    printf '  "schema_version": "auditooor.hydra_runner.v1",\n'
    printf '  "workspace": "%s",\n' "$WORKSPACE"
    printf '  "started_at": "%s",\n' "$HYDRA_STARTED"
    printf '  "ended_at": "%s",\n' "$HYDRA_ENDED"
    printf '  "duration_seconds": %d,\n' "$HYDRA_DURATION"
    printf '  "dry_run": %s,\n' "$([ "$DRY_RUN" -eq 1 ] && echo true || echo false)"
    printf '  "engines_requested": "%s",\n' "$ENGINES_REQUESTED"
    printf '  "out_dir": "%s",\n' "$OUT_DIR"
    printf '  "engines": [\n'
    local_first=1
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r name status dur manifest_path <<< "$row"
        if [ "$local_first" -eq 1 ]; then
            local_first=0
        else
            printf ',\n'
        fi
        printf '    {"name": "%s", "status": "%s", "duration_seconds": %d, "manifest_or_log": "%s"}' \
            "$name" "$status" "$dur" "$manifest_path"
    done
    printf '\n  ],\n'
    printf '  "cross_lane_correlate": {"status": "%s", "output": "%s"}\n' \
        "$CROSS_LANE_STATUS" "$CROSS_LANE_OUTPUT"
    printf '}\n'
} > "$MANIFEST"

# Human-readable report. Use printf '%s\n' for any line starting with
# `-` so `-` isn't interpreted as a printf flag.
REPORT="$OUT_DIR/hydra_report.md"
{
    printf '%s\n\n' "# Hydra Runner Report"
    printf '%s\n' "- workspace: \`$WORKSPACE\`"
    printf '%s\n' "- started: \`$HYDRA_STARTED\`"
    printf '%s\n' "- ended: \`$HYDRA_ENDED\`"
    printf '%s\n' "- duration: ${HYDRA_DURATION}s"
    printf '%s\n' "- engines: \`$ENGINES_REQUESTED\`"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%s\n' "- dry-run: true (no engines actually invoked)"
    fi
    printf '\n%s\n\n' "## Per-engine results"
    printf '%s\n' "| Engine | Status | Duration (s) | Manifest / Log |"
    printf '%s\n' "|---|---|---:|---|"
    for row in "${RESULTS[@]}"; do
        IFS='|' read -r name status dur manifest_path <<< "$row"
        printf '%s\n' "| $name | $status | $dur | \`$manifest_path\` |"
    done
    printf '\n%s\n\n' "## Cross-lane correlation"
    printf '%s\n' "- status: \`$CROSS_LANE_STATUS\`"
    if [ -n "$CROSS_LANE_OUTPUT" ]; then
        printf '%s\n' "- output: \`$CROSS_LANE_OUTPUT\`"
    fi
    printf '\n%s\n\n' "## Notes"
    printf '%s\n' "This is auditooor's local multi-engine aggregator. It runs Slither + Halmos + Medusa and joins their typed \`deep_candidate.v1\` records via \`tools/cross-lane-correlate.py\`. It does NOT replicate the upstream Trail of Bits Hydra (live-devnet adversarial flow) — see \`docs/TOOL_COST_BENEFIT.md\` for that."
} > "$REPORT"

echo "[hydra-runner] OK manifest=$MANIFEST report=$REPORT engines=${#RESULTS[@]}"
exit 0
