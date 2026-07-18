#!/usr/bin/env bash
# symbolic-runner.sh — symbolic-execution slice (halmos | kontrol | auto).
#
# Phase C kickoff (PR 109) + Phase H multi-angle expansion (PR 202).
#
# Supported angles (iter3 T5 / PR 202):
#   A-AUTH    — access-control counterexamples (PR 109, fully wired against
#               halmos/kontrol).
#   A-ORACLE  — price manipulation / staleness / decimals drift (PR 202,
#               SCAFFOLDED-ONLY: halmos + mythril stub commands are rendered
#               but never actually invoked unless SYMBOLIC_DRY_RUN=0 is
#               explicitly set in the env). Default env behavior is a
#               scaffolded-only manifest with status=skipped.
#   A-REENT   — classic reentrancy + cross-function state invariants (PR 202,
#               SCAFFOLDED-ONLY; same SYMBOLIC_DRY_RUN discipline as A-ORACLE).
#
# ADVISORY only — exits 0 on every engine outcome; never wired into any
# blocking gate (ci-check-all.py, pre-submit-check.sh, make all are
# untouched). A-ORACLE / A-REENT manifests MUST NOT contribute to
# evidence-matrix.verdict = READY until PR 206 promotes them; PR 202 only
# ships scaffolding.
#
# Env switches:
#   SYMBOLIC_DRY_RUN=1 (default)   — A-ORACLE / A-REENT render their halmos
#                                     and mythril stub command strings into
#                                     the manifest but do NOT exec anything.
#                                     Manifest status is `skipped` with
#                                     reason `dry-run: scaffolded`.
#   SYMBOLIC_DRY_RUN=0              — reserved for future real invocation of
#                                     halmos/mythril against the new angles.
#                                     Not exercised by the offline test suite;
#                                     requires operator approval.
#
# Status vocabulary (locked — see docs/10_OF_10_PLAYBOOK.md §5):
#   {pass, counterexample, no-counterexample, timeout, error, skipped,
#    blocked_unsupported_cheatcode, incomplete_timeout_or_bound}
# No new strings are introduced by this expansion.
#
# Mirrors the style/contract of tools/fuzz-runner.sh from PR 107: writes a
# self-contained per-invocation record under
# <workspace>/symbolic_runs/<timestamp>/ (command.txt, engine.txt,
# engine_version.txt, angle.txt, contract.txt, timeout_seconds.txt, status.txt,
# stdout.log, stderr.log, manifest.json, and counterexample.txt only on a
# counterexample).
#
# Usage:
#   tools/symbolic-runner.sh <workspace>
#     [--engine halmos|kontrol|auto]   # default: auto
#     [--angle A-AUTH|A-ORACLE|A-REENT] # default: A-AUTH
#     [--contract <Name>]               # auto-pick from mining_priorities.json if absent
#     [--test-contract <Name>]          # explicit symbolic harness/test contract target
#     [--timeout 300]                   # seconds; default 300, hard cap 1800 (30 min)
#     [--out-dir <path>]                # default: <workspace>/symbolic_runs/<ts>/
#     [--project-root <path>]           # forge project root (auto-detected if absent)
#     [--dry-run]
#     [--help]
#
# Exit-code discipline (advisory):
#   0  → any engine outcome (no-counterexample | counterexample | timeout | error | skipped)
#        AND any valid-angle scaffolded skip (A-ORACLE / A-REENT under dry-run)
#   1+ → misconfiguration only (invalid --angle, invalid --engine, missing --contract
#        with no auto-pick, bad --timeout, missing workspace, missing timeout utility).
#        Unknown --angle writes a manifest with status=error before exiting non-zero.

set -uo pipefail

usage() {
    cat <<'EOF'
usage: tools/symbolic-runner.sh <workspace> [options]

Options:
  --engine halmos|kontrol|auto   Engine to run (default: auto). Ignored for
                                 A-ORACLE / A-REENT under SYMBOLIC_DRY_RUN=1.
  --angle A-AUTH|A-ORACLE|A-REENT
                                 Angle family. A-AUTH is fully wired (PR 109).
                                 A-ORACLE and A-REENT are scaffolded-only
                                 (PR 202): dry-run default emits a manifest
                                 with status=skipped, reason=dry-run: scaffolded.
  --contract <Name>              Target contract. Auto-picked from
                                 <workspace>/swarm/mining_priorities.json when absent.
                                 Optional for A-ORACLE / A-REENT scaffolded runs.
  --test-contract <Name>         Explicit Halmos/Kontrol match target. Use this
                                 for hand-written Solidity harnesses/tests
                                 (for example Invariant_Vault or MyHalmosTest).
                                 Overrides Invariant_/Property_ discovery while
                                 leaving --contract as the production target.
  --timeout <sec>                Wall-clock timeout in seconds (default: 300, cap: 1800).
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

Env:
  SYMBOLIC_DRY_RUN=1 (default)   A-ORACLE / A-REENT stay scaffolded-only; no
                                 real halmos/mythril process is launched.
  SYMBOLIC_DRY_RUN=0              Reserved for future real invocation of the
                                 scaffolded angles. Not exercised offline.

Advisory runner; exits 0 on any engine outcome. Non-zero exit only on
misconfiguration (invalid args, missing workspace, missing timeout utility,
missing --contract with no auto-pick candidate for A-AUTH). Unknown --angle
values write a status=error manifest before exiting non-zero.
EOF
}

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------
ENGINE="auto"
ANGLE="A-AUTH"
CONTRACT=""
TEST_CONTRACT=""
TIMEOUT_SEC="300"
OUT_DIR_OVERRIDE=""
DRY_RUN=0
WORKSPACE=""
PROJECT_ROOT_OVERRIDE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --engine)
            [ $# -ge 2 ] || { echo "[symbolic-runner] --engine requires a value" >&2; exit 2; }
            ENGINE="$2"; shift 2 ;;
        --angle)
            [ $# -ge 2 ] || { echo "[symbolic-runner] --angle requires a value" >&2; exit 2; }
            ANGLE="$2"; shift 2 ;;
        --contract)
            [ $# -ge 2 ] || { echo "[symbolic-runner] --contract requires a value" >&2; exit 2; }
            CONTRACT="$2"; shift 2 ;;
        --test-contract|--target-contract)
            [ $# -ge 2 ] || { echo "[symbolic-runner] $1 requires a value" >&2; exit 2; }
            TEST_CONTRACT="$2"; shift 2 ;;
        --timeout)
            [ $# -ge 2 ] || { echo "[symbolic-runner] --timeout requires a value" >&2; exit 2; }
            TIMEOUT_SEC="$2"; shift 2 ;;
        --out-dir)
            [ $# -ge 2 ] || { echo "[symbolic-runner] --out-dir requires a value" >&2; exit 2; }
            OUT_DIR_OVERRIDE="$2"; shift 2 ;;
        --project-root)
            # I13 fix (#328): the engine (halmos/kontrol) needs to run from a
            # forge-project root (where `out/`, `lib/`, `foundry.toml` live).
            # Workspaces with multiple cloned repos under `src/` need the
            # operator to point at one. Auto-detect if not provided.
            [ $# -ge 2 ] || { echo "[symbolic-runner] --project-root requires a value" >&2; exit 2; }
            PROJECT_ROOT_OVERRIDE="$2"; shift 2 ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        --*)
            echo "[symbolic-runner] unknown flag: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -z "$WORKSPACE" ]; then
                WORKSPACE="$1"; shift
            else
                echo "[symbolic-runner] unexpected positional arg: $1" >&2; usage >&2; exit 2
            fi ;;
    esac
done

if [ -z "$WORKSPACE" ]; then
    echo "[symbolic-runner] missing <workspace>" >&2
    usage >&2
    exit 2
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

case "$ENGINE" in
    halmos|kontrol|auto) ;;
    *) echo "[symbolic-runner] invalid --engine '$ENGINE' (expected halmos|kontrol|auto)" >&2; exit 2 ;;
esac

# PR 202: angle allowlist. A-AUTH is fully wired (PR 109). A-ORACLE and A-REENT
# are scaffolded-only (SYMBOLIC_DRY_RUN=1 default; the halmos/mythril exec path
# is not yet implemented for these angles). Any other --angle is rejected. An
# `error`-status manifest is written for unknown angles so consumers (and the
# regression test) can key off the manifest rather than only stderr.
#
# Known-unsupported angle defense: this block also maintains the PR-109-era
# invariant that no real halmos/kontrol invocation occurs for an unsupported
# angle. No engine spawn happens along this path.
case "$ANGLE" in
    A-AUTH|A-ORACLE|A-REENT) ;;
    *)
        # Write a minimal error manifest so downstream consumers (and the
        # regression test) can read status=error rather than relying on
        # stderr parsing. We intentionally do NOT use <workspace>/symbolic_runs/
        # unless --out-dir was supplied — the workspace may not even be writable,
        # and we've validated nothing else about it yet.
        _err_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        _err_angle="$ANGLE"
        _err_msg="unsupported --angle '$_err_angle' (expected A-AUTH|A-ORACLE|A-REENT)"
        echo "[symbolic-runner] $_err_msg" >&2
        if [ -n "$OUT_DIR_OVERRIDE" ]; then
            if mkdir -p "$OUT_DIR_OVERRIDE" 2>/dev/null; then
                # Use a minimal JSON writer — no helpers defined yet above.
                _esc_angle="${_err_angle//\\/\\\\}"; _esc_angle="${_esc_angle//\"/\\\"}"
                _esc_msg="${_err_msg//\\/\\\\}"; _esc_msg="${_esc_msg//\"/\\\"}"
                cat > "$OUT_DIR_OVERRIDE/manifest.json" <<EOF_ERR
{
  "schema_version": 1,
  "phase": "H",
  "pr": 202,
  "angle": "$_esc_angle",
  "status": "error",
  "reason": "$_esc_msg",
  "advisory": true,
  "timestamp": "$_err_ts"
}
EOF_ERR
                printf 'error\n' > "$OUT_DIR_OVERRIDE/status.txt"
                printf '%s\n' "$_err_angle" > "$OUT_DIR_OVERRIDE/angle.txt"
            fi
        fi
        exit 2
        ;;
esac

# timeout numeric + cap check
if ! [[ "$TIMEOUT_SEC" =~ ^[0-9]+$ ]]; then
    echo "[symbolic-runner] --timeout must be a non-negative integer (got: $TIMEOUT_SEC)" >&2
    exit 2
fi
if [ "$TIMEOUT_SEC" -gt 1800 ]; then
    echo "[symbolic-runner] --timeout capped at 1800s (got: $TIMEOUT_SEC); using 1800" >&2
    TIMEOUT_SEC=1800
fi
if [ "$TIMEOUT_SEC" -eq 0 ]; then
    echo "[symbolic-runner] --timeout 0 is not supported (would be unbounded)" >&2
    exit 2
fi

if [ ! -d "$WORKSPACE" ]; then
    echo "[symbolic-runner] workspace not found: $WORKSPACE" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Auto-pick --contract from mining_priorities.json if not provided.
#
# Expected shape: JSON list of entries. For each entry we accept all of:
#   { "angle": "A-AUTH", "contract": "Name" }                  (roadmap shape)
#   { "id": "A-AUTH",    "contracts": ["Name", ...] }          (mining-prioritizer)
#   { "id": "A-AUTH",    "contracts": [], "title": "...: Name.method" }
#                                                              (title regex fallback)
# Pick the highest-ranked entry (first one whose angle matches the requested
# --angle). I15 (#331): the title-regex fallback is required because the
# mining-prioritizer can emit `contracts: []` even when the contract name is
# embedded in the title. Without it, audit-deep --live with halmos hits
# "A-AUTH target not provided" on workspaces like monetrix and base-azul.
# ---------------------------------------------------------------------------
if [ -z "$CONTRACT" ]; then
    MP_PATH="$WORKSPACE/swarm/mining_priorities.json"
    if [ -f "$MP_PATH" ] && command -v python3 >/dev/null 2>&1; then
        CONTRACT="$(
            python3 - "$MP_PATH" "$ANGLE" <<'PY' 2>/dev/null || true
import json, re, sys
path, want = sys.argv[1], sys.argv[2]
try:
    data = json.loads(open(path).read())
except Exception:
    sys.exit(0)
if not isinstance(data, list):
    sys.exit(0)
# Two passes: first collect angle-matching entries (preserve rank order),
# then walk fallbacks per entry. A title-regex hit on entry-1 still beats
# a contracts[] hit on entry-2 because the prioritizer ranks by score.
for entry in data:
    if not isinstance(entry, dict):
        continue
    angle = entry.get("angle") or entry.get("id") or ""
    if angle != want:
        continue
    c = entry.get("contract")
    if isinstance(c, str) and c.strip():
        print(c.strip()); sys.exit(0)
    cs = entry.get("contracts")
    if isinstance(cs, list):
        for x in cs:
            if isinstance(x, str) and x.strip():
                print(x.strip()); sys.exit(0)
    # I15 fallback: extract contract name from the title.
    # Titles emitted by the mining-prioritizer follow the shape
    #   "<verb phrase>: <ContractName>.<methodName>"
    # e.g. "Unauthenticated state write: MonetrixAccountant.initialize"
    #      "Cross-contract reentrancy: BalanceSheet.submitQueuedAssets"
    # Capture the first PascalCase identifier followed by `.method`.
    title = entry.get("title") or ""
    if isinstance(title, str) and title:
        # Prefer the colon-anchored form so a stray leading word is not
        # captured; otherwise fall back to a bare PascalCase.method match.
        m = re.search(r":\s+([A-Z][A-Za-z0-9_]+)\.[a-zA-Z_]", title)
        if not m:
            m = re.search(r"\b([A-Z][A-Za-z0-9_]+)\.[a-zA-Z_]", title)
        if m:
            print(m.group(1)); sys.exit(0)
PY
        )"
    fi
fi

NO_TARGET=0
if [ -z "$CONTRACT" ]; then
    # A-AUTH requires a concrete target because halmos/kontrol must bind the
    # symbolic exploration to one contract. An explicit --test-contract is also
    # a valid target for hand-written Solidity harnesses. A-ORACLE / A-REENT
    # under PR 202 are scaffolded-only and do NOT require either target — the
    # manifest simply records `contract: ""` to make that explicit.
    if [ "$ANGLE" = "A-AUTH" ] && [ -z "$TEST_CONTRACT" ]; then
        NO_TARGET=1
    fi
fi

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
TS="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -n "$OUT_DIR_OVERRIDE" ]; then
    OUT_DIR="$OUT_DIR_OVERRIDE"
else
    OUT_DIR="$WORKSPACE/symbolic_runs/$TS"
fi
mkdir -p "$OUT_DIR" || { echo "[symbolic-runner] failed to create out-dir: $OUT_DIR" >&2; exit 2; }

WS_BASENAME="$(basename "$WORKSPACE")"
STDOUT_LOG="$OUT_DIR/stdout.log"
STDERR_LOG="$OUT_DIR/stderr.log"
MANIFEST="$OUT_DIR/manifest.json"
CE_FILE="$OUT_DIR/counterexample.txt"

# ---------------------------------------------------------------------------
# Engine selection
# ---------------------------------------------------------------------------
chosen_engine=""
if [ "$ENGINE" = "auto" ]; then
    if command -v halmos >/dev/null 2>&1; then
        chosen_engine="halmos"
    elif command -v kontrol >/dev/null 2>&1; then
        chosen_engine="kontrol"
    else
        chosen_engine=""
    fi
elif [ "$ENGINE" = "halmos" ]; then
    if command -v halmos >/dev/null 2>&1; then chosen_engine="halmos"; else chosen_engine=""; fi
elif [ "$ENGINE" = "kontrol" ]; then
    if command -v kontrol >/dev/null 2>&1; then chosen_engine="kontrol"; else chosen_engine=""; fi
fi

# ---------------------------------------------------------------------------
# JSON / quoting helpers (same shape as fuzz-runner.sh)
# ---------------------------------------------------------------------------
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/ }"
    s="${s//$'\t'/ }"
    s="${s//$'\r'/ }"
    printf '%s' "$s"
}

quote_argv() {
    local out=""
    local a
    for a in "$@"; do
        if [[ "$a" =~ [[:space:]\'\"\\\$] ]]; then
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
    local ce_path="$8"
    local notes="$9"

    local ce_json='null'
    if [ -n "$ce_path" ]; then
        ce_json="\"$(json_escape "$ce_path")\""
    fi

    cat > "$MANIFEST" <<EOF
{
  "schema_version": 1,
  "phase": "C",
  "pr": 109,
  "workspace": "$(json_escape "$WS_BASENAME")",
  "engine": "$(json_escape "$engine")",
  "engine_version": "$(json_escape "$engine_version")",
  "angle": "$(json_escape "$ANGLE")",
  "contract": "$(json_escape "$CONTRACT")",
  "test_contract": "$(json_escape "${TEST_CONTRACT:-}")",
  "engine_contract": "$(json_escape "${ENGINE_CONTRACT:-}")",
  "project_root": "$(json_escape "${PROJECT_ROOT:-}")",
  "timeout_seconds": ${TIMEOUT_SEC},
  "status": "$(json_escape "$status")",
  "command": "$(json_escape "$command_str")",
  "started_at": "$(json_escape "$started")",
  "ended_at": "$(json_escape "$ended")",
  "duration_seconds": ${duration},
  "counterexample_path": ${ce_json},
  "advisory": true,
  "notes": "$(json_escape "$notes")"
}
EOF
}

# Always record angle + contract early — true on SKIPPED too.
printf '%s\n' "$ANGLE"    > "$OUT_DIR/angle.txt"
printf '%s\n' "$CONTRACT" > "$OUT_DIR/contract.txt"
printf '%s\n' "$TEST_CONTRACT" > "$OUT_DIR/test_contract.txt"
printf '%s\n' "$TIMEOUT_SEC" > "$OUT_DIR/timeout_seconds.txt"

# ---------------------------------------------------------------------------
# Distinct no-target path.
# ---------------------------------------------------------------------------
if [ "$NO_TARGET" -eq 1 ]; then
    echo "[symbolic-runner] cannot-run: no-target (A-AUTH target not provided and no suitable mining-priorities entry found; pass --contract <Name> or --test-contract <Name>)" >&2
    printf 'SKIPPED\n' > "$OUT_DIR/engine.txt"
    printf 'skipped\n' > "$OUT_DIR/status.txt"
    printf '' > "$OUT_DIR/engine_version.txt"
    printf '(no target; no command rendered)\n' > "$OUT_DIR/command.txt"
    : > "$STDOUT_LOG"
    : > "$STDERR_LOG"
    NOW="$(iso_now)"
    write_manifest \
        "SKIPPED" "" "skipped" "" "$NOW" "$NOW" "0" "" \
        "cannot-run: no-target — pass --contract, --test-contract, or provide swarm/mining_priorities.json"
    exit 2
fi

# ---------------------------------------------------------------------------
# PR 202: A-ORACLE / A-REENT scaffolded-only handler.
#
# These angles are deliberately mocked in iter3 T5 / PR 202. Real halmos or
# mythril invocation is reserved for a later PR; the current responsibility
# is only to prove the CLI surface (flag parsing + manifest shape + status
# vocabulary) and to lock the "advisory, never proof" constraint via a
# packager regression test.
#
# Under SYMBOLIC_DRY_RUN=1 (the default and the ONLY path exercised by the
# offline test suite) we:
#   * render the *would-be* halmos and mythril command strings into the
#     manifest for later reference (simulated command, not exec'd),
#   * write status=skipped + reason="dry-run: scaffolded",
#   * exit 0 (advisory discipline).
#
# Under SYMBOLIC_DRY_RUN=0 the branch logs that real invocation is not yet
# implemented for these angles and exits with status=error. This guards
# against a future accidental promotion before the engine wiring lands.
# No branch below under either SYMBOLIC_DRY_RUN value spawns a real
# halmos/mythril process for A-ORACLE / A-REENT in PR 202.
# ---------------------------------------------------------------------------
if [ "$ANGLE" = "A-ORACLE" ] || [ "$ANGLE" = "A-REENT" ]; then
    SYM_DRY_RUN_VAL="${SYMBOLIC_DRY_RUN:-1}"

    # Build a *simulated* command string (never exec'd here). Document both
    # engines the future real-exec branch would consider.
    case "$ANGLE" in
        A-ORACLE)
            # A-ORACLE: target price oracle manipulation — stale price reads,
            # decimals drift between feeds, pushed-price chainlink fallbacks.
            SIM_HALMOS_CMD="halmos --function 'check_oracle_freshness_*' --contract ${CONTRACT:-<auto>}"
            SIM_MYTHRIL_CMD="myth analyze --execution-timeout ${TIMEOUT_SEC} --strategy dfs -t 3 <contract.sol>"
            SCAFFOLD_NOTES="A-ORACLE scaffolded (PR 202): price manipulation / staleness / decimals drift"
            ;;
        A-REENT)
            # A-REENT: target reentrancy + cross-function state invariants.
            SIM_HALMOS_CMD="halmos --function 'check_no_reentrancy_*' --contract ${CONTRACT:-<auto>}"
            SIM_MYTHRIL_CMD="myth analyze --execution-timeout ${TIMEOUT_SEC} --strategy bfs -t 5 <contract.sol>"
            SCAFFOLD_NOTES="A-REENT scaffolded (PR 202): classic reentrancy + cross-function state"
            ;;
    esac

    NOW_ISO="$(iso_now)"

    if [ "$SYM_DRY_RUN_VAL" = "0" ]; then
        # SYMBOLIC_DRY_RUN=0 path exists but is NOT implemented in PR 202.
        # Emit status=error so nothing downstream misreads a partial run.
        printf 'error\n' > "$OUT_DIR/status.txt"
        printf 'SCAFFOLDED\n' > "$OUT_DIR/engine.txt"
        printf '' > "$OUT_DIR/engine_version.txt"
        printf '%s\n' "$SIM_HALMOS_CMD" > "$OUT_DIR/command.txt"
        : > "$STDOUT_LOG"; : > "$STDERR_LOG"
        # Use a minimal manifest writer (write_manifest uses CONTRACT + ANGLE
        # globals which we want preserved; we just override status + notes).
        cat > "$MANIFEST" <<EOF
{
  "schema_version": 1,
  "phase": "H",
  "pr": 202,
  "workspace": "$(json_escape "$WS_BASENAME")",
  "engine": "SCAFFOLDED",
  "engine_version": "",
  "angle": "$(json_escape "$ANGLE")",
  "contract": "$(json_escape "$CONTRACT")",
  "timeout_seconds": ${TIMEOUT_SEC},
  "status": "error",
  "reason": "SYMBOLIC_DRY_RUN=0 path not implemented for $(json_escape "$ANGLE") in PR 202; real halmos/mythril wiring lands in a follow-up",
  "halmos_cmd": "$(json_escape "$SIM_HALMOS_CMD")",
  "mythril_cmd": "$(json_escape "$SIM_MYTHRIL_CMD")",
  "command": "",
  "started_at": "$(json_escape "$NOW_ISO")",
  "ended_at": "$(json_escape "$NOW_ISO")",
  "duration_seconds": 0,
  "counterexample_path": null,
  "advisory": true,
  "notes": "$(json_escape "$SCAFFOLD_NOTES (real-run path not yet implemented)")",
  "timestamp": "$(json_escape "$NOW_ISO")"
}
EOF
        echo "[symbolic-runner] angle=$ANGLE SYMBOLIC_DRY_RUN=0 real-run path not yet implemented (PR 202 scaffolding only)" >&2
        exit 0
    fi

    # Default: SYMBOLIC_DRY_RUN=1 — scaffolded manifest, no engine exec.
    printf 'skipped\n' > "$OUT_DIR/status.txt"
    printf 'SCAFFOLDED\n' > "$OUT_DIR/engine.txt"
    printf '' > "$OUT_DIR/engine_version.txt"
    printf '%s\n' "$SIM_HALMOS_CMD" > "$OUT_DIR/command.txt"
    : > "$STDOUT_LOG"; : > "$STDERR_LOG"
    cat > "$MANIFEST" <<EOF
{
  "schema_version": 1,
  "phase": "H",
  "pr": 202,
  "workspace": "$(json_escape "$WS_BASENAME")",
  "engine": "SCAFFOLDED",
  "engine_version": "",
  "angle": "$(json_escape "$ANGLE")",
  "contract": "$(json_escape "$CONTRACT")",
  "timeout_seconds": ${TIMEOUT_SEC},
  "status": "skipped",
  "reason": "dry-run: scaffolded",
  "halmos_cmd": "$(json_escape "$SIM_HALMOS_CMD")",
  "mythril_cmd": "$(json_escape "$SIM_MYTHRIL_CMD")",
  "command": "",
  "started_at": "$(json_escape "$NOW_ISO")",
  "ended_at": "$(json_escape "$NOW_ISO")",
  "duration_seconds": 0,
  "counterexample_path": null,
  "advisory": true,
  "notes": "$(json_escape "$SCAFFOLD_NOTES")",
  "timestamp": "$(json_escape "$NOW_ISO")"
}
EOF
    echo "[symbolic-runner] angle=$ANGLE status=skipped reason=dry-run:scaffolded out=$OUT_DIR"
    exit 0
fi

# ---------------------------------------------------------------------------
# SKIPPED path: no engine available
# ---------------------------------------------------------------------------
if [ -z "$chosen_engine" ]; then
    echo "[symbolic-runner] No symbolic engine found — install halmos or kontrol per docs/WORKFLOW.md"
    printf 'SKIPPED\n' > "$OUT_DIR/engine.txt"
    printf 'skipped\n' > "$OUT_DIR/status.txt"
    printf '' > "$OUT_DIR/engine_version.txt"
    printf '(no engine; no command rendered)\n' > "$OUT_DIR/command.txt"
    : > "$STDOUT_LOG"
    : > "$STDERR_LOG"
    NOW="$(iso_now)"
    write_manifest \
        "SKIPPED" "" "skipped" "" "$NOW" "$NOW" "0" "" \
        "No symbolic engine found — install halmos or kontrol per docs/WORKFLOW.md"
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
    echo "[symbolic-runner] no timeout utility — running unbounded is unsafe; aborting" >&2
    exit 3
fi

# ---------------------------------------------------------------------------
# Build engine command
# ---------------------------------------------------------------------------
ENGINE_VERSION=""
if _v="$("$chosen_engine" --version 2>/dev/null)"; then
    ENGINE_VERSION="${_v%%$'\n'*}"
fi

# I13 fix (#328): resolve the forge project root the engine should run from.
# Halmos / Kontrol look for `out/`, `lib/`, `foundry.toml` under CWD via
# crytic-compile. Without this resolver they fail in <1s with
# "Build output directory ... does not exist". The wrapper used to
# invoke from auditooor's repo CWD, which never matches a target's
# project root.
#
# Resolution order:
#   1. --project-root <path>  (operator override, absolute path)
#   2. <WORKSPACE>/foundry.toml (single-project workspace)
#   3. <WORKSPACE>/src/<repo>/foundry.toml (multi-project; pick shallowest non-lib match)
#   4. fail loudly with "cannot-run: no-forge-project"
PROJECT_ROOT=""
if [ -n "$PROJECT_ROOT_OVERRIDE" ]; then
    PROJECT_ROOT="$PROJECT_ROOT_OVERRIDE"
elif [ -f "$WORKSPACE/foundry.toml" ]; then
    PROJECT_ROOT="$WORKSPACE"
else
    # Walk depth=2 under src/ and pick the shallowest non-lib match.
    if [ -d "$WORKSPACE/src" ]; then
        for cand in "$WORKSPACE/src"/*/foundry.toml; do
            [ -f "$cand" ] || continue
            # Skip a project literally named `lib` (rare but possible).
            # Using basename match (not substring) so legitimate names
            # like `library-foo` are NOT falsely skipped — Kimi review
            # caught the substring false-match.
            if [ "$(basename "$(dirname "$cand")")" = "lib" ]; then
                continue
            fi
            PROJECT_ROOT="$(dirname "$cand")"
            break
        done
    fi
fi
if [ -z "$PROJECT_ROOT" ] || [ ! -f "$PROJECT_ROOT/foundry.toml" ]; then
    echo "[symbolic-runner] cannot-run: no-forge-project (no foundry.toml under $WORKSPACE; pass --project-root <path>)" >&2
    # Still emit a manifest so the caller has structured evidence.
    NOW="$(iso_now)"
    write_manifest \
        "$ENGINE" "n/a" "skipped" "(no engine invocation)" \
        "$NOW" "$NOW" "0" "" \
        "cannot-run: no-forge-project — pass --project-root or place foundry.toml under workspace"
    exit 2
fi
printf '%s\n' "$PROJECT_ROOT" > "$OUT_DIR/project_root.txt"

# I19 (#339) + I20 (#341) + I21 (#342): when an I17 scaffold exists, resolve
# the harness contract name from the configured Foundry test dir. Use the
# resolved project root, not the audit workspace root, so nested Solidity
# projects can pass --project-root cleanly. Also allow an explicit
# --test-contract to target hand-written Halmos/Kontrol harnesses directly.
TEST_DIR="test"
if command -v python3 >/dev/null 2>&1; then
    TEST_DIR="$(python3 "$HERE/lib/resolve-forge-test-dir.py" "$PROJECT_ROOT" 2>/dev/null || echo test)"
fi
case "$TEST_DIR" in
    /*) TEST_DIR_PATH="$TEST_DIR" ;;
    *)  TEST_DIR_PATH="$PROJECT_ROOT/$TEST_DIR" ;;
esac

if [ -n "$TEST_CONTRACT" ]; then
    ENGINE_CONTRACT="$TEST_CONTRACT"
    TARGET_SOURCE="explicit-test-contract"
else
    HARNESS_FILE="$TEST_DIR_PATH/Invariant_$CONTRACT.t.sol"
    PROPERTY_FILE="$TEST_DIR_PATH/Property_$CONTRACT.t.sol"
    if [ -f "$HARNESS_FILE" ]; then
        ENGINE_CONTRACT="Invariant_$CONTRACT"
        TARGET_SOURCE="discovered-invariant"
    elif [ -f "$PROPERTY_FILE" ]; then
        ENGINE_CONTRACT="Property_$CONTRACT"
        TARGET_SOURCE="discovered-property"
    else
        ENGINE_CONTRACT="$CONTRACT"
        TARGET_SOURCE="contract"
    fi
fi
printf '%s\n' "$ENGINE_CONTRACT" > "$OUT_DIR/engine_contract.txt"
printf '%s\n' "$TARGET_SOURCE" > "$OUT_DIR/target_source.txt"
printf '%s\n' "$TEST_DIR_PATH" > "$OUT_DIR/test_dir.txt"

ENGINE_ARGV=()
case "$chosen_engine" in
    halmos)
        # halmos --contract <Name>  (runs Foundry-style symbolic tests)
        ENGINE_ARGV=("halmos" "--contract" "$ENGINE_CONTRACT")
        ;;
    kontrol)
        # kontrol prove --match-contract <Name>  (best-effort generic invocation)
        ENGINE_ARGV=("kontrol" "prove" "--match-contract" "$ENGINE_CONTRACT")
        ;;
esac

FULL_ARGV=("$TIMEOUT_BIN" "${TIMEOUT_SEC}s" "${ENGINE_ARGV[@]}")
COMMAND_STR="$(quote_argv "${FULL_ARGV[@]}")"

printf '%s\n' "$chosen_engine"   > "$OUT_DIR/engine.txt"
printf '%s\n' "$ENGINE_VERSION"  > "$OUT_DIR/engine_version.txt"
printf '%s\n' "$COMMAND_STR"     > "$OUT_DIR/command.txt"

# ---------------------------------------------------------------------------
# Dry-run path
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 1 ]; then
    printf 'skipped\n' > "$OUT_DIR/status.txt"
    NOW="$(iso_now)"
    write_manifest \
        "$chosen_engine" "$ENGINE_VERSION" "skipped" "$COMMAND_STR" \
        "$NOW" "$NOW" "0" "" \
        "dry-run: engine was NOT invoked"
    echo "[symbolic-runner] dry-run: would execute: $COMMAND_STR"
    echo "[symbolic-runner] out-dir: $OUT_DIR"
    exit 0
fi

# ---------------------------------------------------------------------------
# Invoke engine under timeout
# ---------------------------------------------------------------------------
STARTED_AT="$(iso_now)"
START_EPOCH="$(date -u +%s)"

# I13 fix (#328): cd into the forge project root so halmos/kontrol/crytic
# find `out/`, `lib/`, `foundry.toml` under CWD. Subshell isolates the
# directory change from the rest of the script (we still want to write
# logs to the absolute paths under $OUT_DIR).
set +e
( cd "$PROJECT_ROOT" && "${FULL_ARGV[@]}" ) >"$STDOUT_LOG" 2>"$STDERR_LOG"
ENGINE_EXIT=$?
set -e

ENDED_AT="$(iso_now)"
END_EPOCH="$(date -u +%s)"
DURATION=$(( END_EPOCH - START_EPOCH ))

# ---------------------------------------------------------------------------
# Classify status
#   halmos stdout contains "Counterexample:" or "Failed:"  → counterexample
#   kontrol stdout contains "FAILED: "                     → counterexample
#   exit 124 or 137                                        → timeout
#   unsupported Foundry cheatcode                          → blocked_unsupported_cheatcode
#   bounded/incomplete symbolic exploration                 → incomplete_timeout_or_bound
#   exit 0, no counterexample markers                      → no-counterexample
#   else                                                   → error
# ---------------------------------------------------------------------------
STATUS="error"
CE_PATH=""
NOTES=""

ce_found=0
case "$chosen_engine" in
    halmos)
        if grep -qE 'Counterexample:|Failed:' "$STDOUT_LOG" 2>/dev/null; then ce_found=1; fi ;;
    kontrol)
        if grep -qE 'FAILED: ' "$STDOUT_LOG" 2>/dev/null; then ce_found=1; fi ;;
esac

if [ "$ce_found" -eq 1 ]; then
    STATUS="counterexample"
    case "$chosen_engine" in
        halmos)
            awk '
                /Counterexample:|Failed:/ { hit=1 }
                hit { print }
            ' "$STDOUT_LOG" > "$CE_FILE" 2>/dev/null || true ;;
        kontrol)
            awk '
                /FAILED: / { hit=1 }
                hit { print }
            ' "$STDOUT_LOG" > "$CE_FILE" 2>/dev/null || true ;;
    esac
    if [ ! -s "$CE_FILE" ]; then
        cp "$STDOUT_LOG" "$CE_FILE" 2>/dev/null || true
    fi
    CE_PATH="counterexample.txt"
elif [ "$ENGINE_EXIT" -eq 124 ] || [ "$ENGINE_EXIT" -eq 137 ]; then
    STATUS="timeout"
    NOTES="engine killed by ${TIMEOUT_BIN} at ${TIMEOUT_SEC}s (exit ${ENGINE_EXIT})"
elif grep -qiE 'unsupported (cheat ?code|vm cheatcode)|copyStorage\(address,address\)|copyStorage' "$STDOUT_LOG" "$STDERR_LOG" 2>/dev/null; then
    STATUS="blocked_unsupported_cheatcode"
    NOTES="engine blocked by unsupported Foundry cheatcode; inspect stderr/stdout for the exact cheatcode"
elif grep -qiE 'incomplete execution|loop (unrolling )?bound|specified limit|path explosion|max depth|maximum depth|reached.*bound|bounded.*incomplete' "$STDOUT_LOG" "$STDERR_LOG" 2>/dev/null; then
    STATUS="incomplete_timeout_or_bound"
    NOTES="engine produced no counterexample but did not fully close the target due to an exploration limit/bound"
elif [ "$ENGINE_EXIT" -eq 0 ]; then
    STATUS="no-counterexample"
else
    STATUS="error"
    NOTES="engine exited non-zero (${ENGINE_EXIT}) with no counterexample markers"
fi

printf '%s\n' "$STATUS" > "$OUT_DIR/status.txt"

write_manifest \
    "$chosen_engine" "$ENGINE_VERSION" "$STATUS" "$COMMAND_STR" \
    "$STARTED_AT" "$ENDED_AT" "$DURATION" \
    "$CE_PATH" "$NOTES"

echo "[symbolic-runner] engine=$chosen_engine angle=$ANGLE contract=$CONTRACT status=$STATUS duration=${DURATION}s out=$OUT_DIR"

# Advisory: always exit 0 on any engine outcome.
exit 0
