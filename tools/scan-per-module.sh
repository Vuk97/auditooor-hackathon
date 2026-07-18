#!/usr/bin/env bash
# scan-per-module.sh — per-module Slither fallback for complex targets.
#
# Motivation (Issues #133, #138):
#   When Slither fails IR-gen on a single function (e.g. Centrifuge's
#   Hub.initializeHolding on solc 0.8.28 / Cancun), the entire scan aborts
#   with 0 hits, killing the detector library's signal. The workaround is
#   to scan each source module separately: one failure skips that module,
#   the rest still produce output.
#
# Usage:
#   ./tools/scan-per-module.sh <workspace> [--src-root PATH] [--tier S,E,D] [--force]
#
# Behavior:
#   1. Locates <workspace>/src/<repo>/foundry.toml (one subdir under src/)
#   2. Iterates every immediate subdir of <repo>/src/ (or --src-root if given)
#   3. For each module, invokes run_custom.py with a 600s timeout
#   4. Aggregates per-module output into <workspace>/custom-detectors.log
#   5. Failures go to <workspace>/custom-detectors-errors.log (continue on fail)
#   6. Emits a summary and picks a tiered exit code
#
# Exit codes:
#   0  at least one module scanned OK AND at least one hit found
#   1  usage error
#   2  all modules failed
#   3  some modules failed (or all OK) but no hits found anywhere

set -u
set -o pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RUN_CUSTOM="$AUDITOOOR_DIR/detectors/run_custom.py"
TIMEOUT_SECS=600

usage() {
    cat <<EOF >&2
Usage: $0 <workspace> [--src-root PATH] [--tier S,E,D] [--force]

  <workspace>     Path to audit workspace (must contain src/<repo>/foundry.toml)
  --src-root DIR  Override module discovery root (default: <repo>/src/)
  --tier S,E,D    Detector tier filter passed to run_custom.py (default: S,E)
  --force         Overwrite existing custom-detectors.log even if non-empty

Exit:
  0 = at least one module OK with >=1 hit
  1 = usage error
  2 = all modules failed
  3 = some modules failed / no hits
EOF
    exit 1
}

# ----- args -----
WORKSPACE=""
SRC_ROOT=""
TIER=""
FORCE=0
PER_FILE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --src-root)
            [ $# -ge 2 ] || usage
            SRC_ROOT="$2"
            shift 2
            ;;
        --tier)
            [ $# -ge 2 ] || usage
            TIER="$2"
            shift 2
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --per-file)
            PER_FILE=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        --*)
            echo "[err] unknown flag: $1" >&2
            usage
            ;;
        *)
            if [ -z "$WORKSPACE" ]; then
                WORKSPACE="$1"
            else
                echo "[err] unexpected arg: $1" >&2
                usage
            fi
            shift
            ;;
    esac
done

[ -n "$WORKSPACE" ] || usage
[ -d "$WORKSPACE" ] || { echo "[err] workspace not a directory: $WORKSPACE" >&2; exit 1; }
[ -x "$RUN_CUSTOM" ] || [ -f "$RUN_CUSTOM" ] || { echo "[err] missing run_custom.py at $RUN_CUSTOM" >&2; exit 1; }

# ----- locate foundry project -----
# Spec: <ws>/src/<repo>/foundry.toml
FOUNDRY_TOML=""
REPO_DIR=""
if [ -d "$WORKSPACE/src" ]; then
    for cand in "$WORKSPACE/src"/*/; do
        [ -d "$cand" ] || continue
        if [ -f "${cand}foundry.toml" ]; then
            FOUNDRY_TOML="${cand}foundry.toml"
            REPO_DIR="${cand%/}"
            break
        fi
    done
fi
if [ -z "$FOUNDRY_TOML" ]; then
    echo "[err] could not find <workspace>/src/<repo>/foundry.toml under $WORKSPACE/src" >&2
    exit 1
fi

# ----- module discovery -----
if [ -n "$SRC_ROOT" ]; then
    MODULE_ROOT="$SRC_ROOT"
else
    MODULE_ROOT="$REPO_DIR/src"
fi
[ -d "$MODULE_ROOT" ] || { echo "[err] module root not a directory: $MODULE_ROOT" >&2; exit 1; }

MODULES=()
# shellcheck disable=SC2066
for d in "$MODULE_ROOT"/*/; do
    [ -d "$d" ] || continue
    MODULES+=("${d%/}")
done
if [ "${#MODULES[@]}" -eq 0 ]; then
    echo "[err] no module subdirs found under $MODULE_ROOT" >&2
    exit 1
fi

# ----- output log handling -----
AGG_LOG="$WORKSPACE/custom-detectors.log"
ERR_LOG="$WORKSPACE/custom-detectors-errors.log"

if [ -s "$AGG_LOG" ] && [ "$FORCE" -eq 0 ]; then
    echo "[err] $AGG_LOG already has content — pass --force to overwrite" >&2
    exit 1
fi

: > "$AGG_LOG"
: > "$ERR_LOG"

echo "[info] workspace : $WORKSPACE"
echo "[info] foundry   : $FOUNDRY_TOML"
echo "[info] modules   : ${#MODULES[@]} under $MODULE_ROOT"
echo "[info] tier      : ${TIER:-S,E (default)}"
echo "[info] agg log   : $AGG_LOG"
echo "[info] err log   : $ERR_LOG"
echo

# ----- tier flag -----
TIER_ARGS=()
if [ -n "$TIER" ]; then
    TIER_ARGS=(--tier "$TIER")
fi

# ----- run each module -----
OK_COUNT=0
FAIL_COUNT=0
OK_MODULES=()
FAIL_MODULES=()

# Timeout wrapper: perl alarm fallback (BSD bash, no `timeout` on macOS)
run_with_timeout() {
    local secs="$1"; shift
    perl -e '
        my $secs = shift @ARGV;
        my $pid = fork();
        die "fork: $!" unless defined $pid;
        if ($pid == 0) {
            exec @ARGV or die "exec: $!";
        }
        local $SIG{ALRM} = sub {
            kill("TERM", $pid);
            sleep 2;
            kill("KILL", $pid);
            exit 124;
        };
        alarm($secs);
        waitpid($pid, 0);
        exit($? >> 8);
    ' "$secs" "$@"
}

for mod_path in "${MODULES[@]}"; do
    mod_name="$(basename "$mod_path")"
    echo "[scan] $mod_name  ($mod_path)"

    tmp_out="$(mktemp -t "perm-scan-${mod_name}.XXXXXX")"
    trap 'rm -f "$tmp_out"' EXIT

    rc=0
    if [ "${#TIER_ARGS[@]:-0}" -gt 0 ]; then
        run_with_timeout "$TIMEOUT_SECS" \
            python3 "$RUN_CUSTOM" "$mod_path" "${TIER_ARGS[@]}" >"$tmp_out" 2>&1 || rc=$?
    else
        run_with_timeout "$TIMEOUT_SECS" \
            python3 "$RUN_CUSTOM" "$mod_path" >"$tmp_out" 2>&1 || rc=$?
    fi

    if [ $rc -eq 0 ]; then
        {
            echo "=== module: $mod_name ==="
            cat "$tmp_out"
            echo
        } >> "$AGG_LOG"
        OK_COUNT=$((OK_COUNT + 1))
        OK_MODULES+=("$mod_name")
        echo "  -> OK"
    else
        {
            echo "=== module: $mod_name (exit=$rc) ==="
            echo "--- first 20 lines ---"
            head -n 20 "$tmp_out"
            echo "--- last 20 lines (where the actual failure usually lives) ---"
            tail -n 20 "$tmp_out"
            echo "--- end ---"
            echo
        } >> "$ERR_LOG"
        # Preserve a tombstone in the aggregate log so reviewers can see the gap
        {
            echo "=== module: $mod_name (FAILED exit=$rc, see custom-detectors-errors.log) ==="
            echo
        } >> "$AGG_LOG"
        FAIL_COUNT=$((FAIL_COUNT + 1))
        FAIL_MODULES+=("$mod_name")
        echo "  -> FAIL (exit=$rc)"

        # R40 Issue #141: per-file fallback. On module failure, iterate every .sol
        # in the module and scan one file at a time. Skip files that individually
        # fail Slither; aggregate the others.
        if [ "$PER_FILE" = 1 ]; then
            echo "  [per-file] falling back to per-file scan of $mod_name"
            pf_ok=0; pf_fail=0
            # 120s per file is plenty for Slither on one contract
            while IFS= read -r sol_file; do
                [ -z "$sol_file" ] && continue
                sol_rel="${sol_file#$mod_path/}"
                pf_tmp=$(mktemp)
                pf_rc=0
                if [ "${#TIER_ARGS[@]:-0}" -gt 0 ]; then
                    run_with_timeout 120 python3 "$RUN_CUSTOM" "$sol_file" "${TIER_ARGS[@]}" >"$pf_tmp" 2>&1 || pf_rc=$?
                else
                    run_with_timeout 120 python3 "$RUN_CUSTOM" "$sol_file" >"$pf_tmp" 2>&1 || pf_rc=$?
                fi
                if [ $pf_rc -eq 0 ]; then
                    {
                        echo "=== module: $mod_name (per-file: $sol_rel) ==="
                        cat "$pf_tmp"
                        echo
                    } >> "$AGG_LOG"
                    pf_ok=$((pf_ok + 1))
                else
                    echo "  [per-file FAIL exit=$pf_rc] $sol_rel" >> "$ERR_LOG"
                    pf_fail=$((pf_fail + 1))
                fi
                rm -f "$pf_tmp"
            done < <(find "$mod_path" -name "*.sol" -type f -not -path "*/test/*" -not -path "*/lib/*" 2>/dev/null | sort)
            echo "  [per-file] module $mod_name: $pf_ok files OK / $pf_fail files FAIL"
            # If per-file recovered ANY signal, recount the module as partial-OK
            if [ $pf_ok -gt 0 ]; then
                OK_COUNT=$((OK_COUNT + 1))
                OK_MODULES+=("$mod_name (per-file)")
                # Do not decrement FAIL_COUNT — FAILED-then-recovered is still noted
            fi
        fi
    fi

    rm -f "$tmp_out"
    trap - EXIT
done

# ----- summary -----
# Count hits: lines containing "INFO:Detectors:" are Slither hit headers in
# run_custom.py output. Fall back to lines starting with detector argument
# markers if that format changes.
HIT_COUNT=0
DET_COUNT=0
if [ -s "$AGG_LOG" ]; then
    # run_custom.py emits one "[done] total hits: N" line per module. Sum them.
    HIT_COUNT=$(awk '/^\[done\] total hits:/ { s += $NF } END { print s+0 }' "$AGG_LOG")
    [ -z "$HIT_COUNT" ] && HIT_COUNT=0
    # Unique detectors that fired. run_custom.py emits hit lines of the form:
    #   "  [SEVERITY] <contract>.<fn>(...) (<file>#L) — <detector-name>: <msg>"
    # Extract the token between "— " and ":" on hit lines.
    DET_COUNT=$(grep -oE "— [a-z][a-z0-9-]+:" "$AGG_LOG" 2>/dev/null | sort -u | wc -l | tr -d ' \n')
    [ -z "$DET_COUNT" ] && DET_COUNT=0
fi

echo
echo "========== SUMMARY =========="
echo "Modules scanned OK : $OK_COUNT"
if [ "$OK_COUNT" -gt 0 ]; then
    printf '  -> %s\n' "${OK_MODULES[@]}"
fi
echo "Modules failed     : $FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    printf '  -> %s\n' "${FAIL_MODULES[@]}"
fi
echo "Total hits         : $HIT_COUNT"
echo "Detectors fired    : $DET_COUNT"
echo "Aggregate log      : $AGG_LOG"
echo "Error log          : $ERR_LOG"
echo "============================="

# ----- exit code -----
if [ "$OK_COUNT" -eq 0 ]; then
    exit 2
fi
if [ "$HIT_COUNT" -eq 0 ]; then
    exit 3
fi
exit 0
