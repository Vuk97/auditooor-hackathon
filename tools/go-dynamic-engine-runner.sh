#!/usr/bin/env bash
# go-dynamic-engine-runner.sh — Go DYNAMIC engine adapter.
#
# This is the Go deep-engine arm, the sibling of
# tools/rust-proptest-engine-runner.sh. The EVM deep engines
# (medusa/echidna/halmos) skip on a Go target with "no-forge-project",
# leaving a "no Critical found" verdict that rests on detectors-found-nothing
# rather than an engine that actually searched the input space.
#
# For Go consensus / cosmos / crypto targets (e.g. dYdX v4-chain, Spark
# statechain coordinator) the real dynamic engines are:
#   (1) the project's OWN native go-fuzz targets (`func FuzzXxx(f *testing.F)`),
#       which go test drives with `-fuzz=<name> -fuzztime=<dur>`. A fuzz
#       FAILURE on a core-tenet surface (margin/value balance, amount bounds,
#       serialization round-trip, overflow/panic) is the CRITICAL-class signal
#       the EVM engines could never produce here.
#   (2) staticcheck (honnef.co/go/tools) - the canonical Go static analyzer.
#       A staticcheck finding on an in-scope package is corroborating evidence.
#   (3) where present, the project's cosmos production-harness test
#       (`simapp.Setup` / `app.FinalizeBlock` / `BroadcastTxSync` etc.),
#       which exercises the real ABCI/state-machine write path (Rule 18/19).
#
# RELATED TOOLS (tool-duplication preflight per ~/.claude/CLAUDE.md):
#   - tools/rust-proptest-engine-runner.sh   the Rust sibling (proptest arm).
#     This file mirrors its CLI/manifest contract for the Go ecosystem.
#   - tools/fuzz-runner.sh                   the generic fuzz-runner whose
#     manifest schema we mirror so audit-deep-manifest / engine-harness signal
#     parse uniformly.
#   - tools/engine-harness-proof-gate.py     consumes the emitted harness
#     source for tautology/stub detection (PR4a).
#   - tools/audit-completeness-check.py      signal (c2) reads
#     fuzz_runs/*/manifest.json via _collect_engine_steps; the positive count
#     fields below (`tests_passed`, `executed_harnesses`) make L37 credit the
#     Go engine arm.
#   GAP this fills: none of the above runs `go test -fuzz` + staticcheck +
#   the cosmos production-harness on a Go workspace and emits the
#   fuzz_runs manifest. The rust runner is cargo-only; the generic
#   fuzz-runner is not Go-fuzz-aware. This is the Go-specific adapter.
#
# Usage:
#   tools/go-dynamic-engine-runner.sh <workspace> [options]
#
# Options:
#   --module-root <path>    Go module root (dir holding go.mod). Repeatable.
#                           Auto-discovered: every go.mod under <ws> (depth 4,
#                           excluding vendor/) whose package declares >=1
#                           `func Fuzz...(f *testing.F)` target.
#   --fuzz-filter <regex>   go test -fuzz argument (default ".", all fuzz fns).
#   --fuzztime <dur>        Per-target fuzz duration (default 30s, cap 600s).
#   --run-staticcheck       Run staticcheck on the discovered modules (default
#                           on if staticcheck is on PATH; honest tool-not-
#                           installed step otherwise).
#   --no-staticcheck        Skip the staticcheck step entirely.
#   --prod-harness-pkg <p>  Run a cosmos production-harness go-test package
#                           (the real ABCI surface) as an extra engine step.
#                           Repeatable. Auto-detected when a discovered module
#                           contains simapp.Setup / app.FinalizeBlock /
#                           BroadcastTxSync markers.
#   --no-prod-harness       Skip the cosmos production-harness step.
#   --timeout <sec>         Wall-clock timeout for the WHOLE run (default 1800,
#                           cap 5400).
#   --out-dir <path>        Override output dir (default <ws>/fuzz_runs/<ts>/).
#   --dry-run               Render commands and exit 0 without invoking go.
#   -h, --help
#
# Exit codes:
#   0  engine ran to a terminal state (pass / counterexample / timeout /
#      skipped / tool-not-installed)
#   2  misconfiguration (missing workspace, bad args)
#
# Advisory: a fuzz counterexample upgrades a candidate to "proven" only when
# paired with a minimized reproducer; go test persists the failing corpus
# entry under testdata/fuzz/<Fn>/<hash> which this runner captures so the
# drill lane can replay it with `go test -run=<Fn>/<hash>`.

set -uo pipefail

usage() { sed -n '2,76p' "$0" | sed 's/^# \{0,1\}//'; }

WORKSPACE=""
MODULE_ROOTS=()
FUZZ_FILTER="."
FUZZTIME="30s"
RUN_STATICCHECK="auto"     # auto | yes | no
PROD_HARNESS_PKGS=()
RUN_PROD_HARNESS="auto"     # auto | yes | no
TIMEOUT_SEC="1800"
OUT_DIR_OVERRIDE=""
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --module-root)     [ $# -ge 2 ] || { echo "[go-dynamic] --module-root needs value" >&2; exit 2; }; MODULE_ROOTS+=("$2"); shift 2 ;;
        --fuzz-filter)     [ $# -ge 2 ] || { echo "[go-dynamic] --fuzz-filter needs value" >&2; exit 2; }; FUZZ_FILTER="$2"; shift 2 ;;
        --fuzztime)        [ $# -ge 2 ] || { echo "[go-dynamic] --fuzztime needs value" >&2; exit 2; }; FUZZTIME="$2"; shift 2 ;;
        --run-staticcheck) RUN_STATICCHECK="yes"; shift ;;
        --no-staticcheck)  RUN_STATICCHECK="no"; shift ;;
        --prod-harness-pkg)[ $# -ge 2 ] || { echo "[go-dynamic] --prod-harness-pkg needs value" >&2; exit 2; }; PROD_HARNESS_PKGS+=("$2"); RUN_PROD_HARNESS="yes"; shift 2 ;;
        --no-prod-harness) RUN_PROD_HARNESS="no"; shift ;;
        --timeout)         [ $# -ge 2 ] || { echo "[go-dynamic] --timeout needs value" >&2; exit 2; }; TIMEOUT_SEC="$2"; shift 2 ;;
        --out-dir)         [ $# -ge 2 ] || { echo "[go-dynamic] --out-dir needs value" >&2; exit 2; }; OUT_DIR_OVERRIDE="$2"; shift 2 ;;
        --dry-run)         DRY_RUN=1; shift ;;
        --strict)          STRICT_FLAG=1; shift ;;  # wave-2 C2: accept (no-op; runner self-classifies offline-safe). Makefile audit-deep-go-engine passes --strict under STRICT=1; without this case the runner aborted rc2 -> swallowed by '|| echo WARN' -> the WHOLE Go fuzz arm silently never ran.
        -h|--help)         usage; exit 0 ;;
        --*)               echo "[go-dynamic] unknown option: $1" >&2; exit 2 ;;
        *)                 if [ -z "$WORKSPACE" ]; then WORKSPACE="$1"; shift; else echo "[go-dynamic] unexpected arg: $1" >&2; exit 2; fi ;;
    esac
done

[ -n "$WORKSPACE" ] || { echo "[go-dynamic] missing <workspace>" >&2; usage; exit 2; }
[ -d "$WORKSPACE" ] || { echo "[go-dynamic] workspace not a dir: $WORKSPACE" >&2; exit 2; }

# timeout utility (timeout on Linux, gtimeout on macOS via coreutils)
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout";
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"; fi

# cap timeout
case "$TIMEOUT_SEC" in (*[!0-9]*) echo "[go-dynamic] --timeout must be integer" >&2; exit 2 ;; esac
[ "$TIMEOUT_SEC" -gt 5400 ] && TIMEOUT_SEC=5400

# validate / cap fuzztime (parse integer prefix; accept go duration suffix s/m)
_ft_num="$(printf '%s' "$FUZZTIME" | grep -oE '^[0-9]+' || true)"
_ft_unit="$(printf '%s' "$FUZZTIME" | grep -oE '[a-z]+$' || true)"
[ -n "$_ft_num" ] || { echo "[go-dynamic] --fuzztime must start with an integer (e.g. 30s)" >&2; exit 2; }

# Build tags for `go test -fuzz` + the build-health check. Cosmos-SDK/CometBFT
# fuzz targets (mempool/p2p/rpc) are gated behind `//go:build gofuzz`, so a
# TAGLESS `go test -fuzz` hits "build constraints exclude all Go files" and the
# target is wrongly recorded as a build error / unbuildable. The source-grep
# discovery above DOES find them, so they must also COMPILE. Default to `gofuzz`
# (the ubiquitous cosmos/tendermint convention; a harmless no-op for packages
# that do not declare that tag). Override or clear via env GO_BUILD_TAGS (empty
# = tagless). Reproduced: `go test -tags gofuzz -fuzz=^FuzzMempool$` -> PASS.
GO_BUILD_TAGS="${GO_BUILD_TAGS-gofuzz}"
GO_TAGS_ARGS=()
[ -n "$GO_BUILD_TAGS" ] && GO_TAGS_ARGS=(-tags "$GO_BUILD_TAGS")
[ -z "$_ft_unit" ] && { FUZZTIME="${_ft_num}s"; _ft_unit="s"; }
# cap to 600s
_ft_sec="$_ft_num"
[ "$_ft_unit" = "m" ] && _ft_sec=$((_ft_num * 60))
if [ "$_ft_sec" -gt 600 ]; then FUZZTIME="600s"; fi

WS_NAME="$(basename "$WORKSPACE")"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_DIR="${OUT_DIR_OVERRIDE:-$WORKSPACE/fuzz_runs/$TS}"
mkdir -p "$OUT_DIR"

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# ---------------------------------------------------------------------------
# Manifest emitter — mirrors the rust-proptest runner / fuzz-runner schema so
# audit-completeness-check.py _collect_engine_steps + audit-deep-manifest parse
# it uniformly. The positive count fields (tests_passed, executed_harnesses)
# are read by L37 signal (c2) _step_executed_harnesses.
#   $1=status $2=notes $3=ce_path(json) $4=command $5=engine_version
#   $6=modules_csv $7=duration $8=tests_passed(int) $9=fuzz_targets(int)
#   $10=staticcheck_findings(int or "n/a") $11=prod_harness_status
# ---------------------------------------------------------------------------
emit_manifest() {
    local executed_harnesses sc_field ph_field
    executed_harnesses="${8:-0}"
    sc_field="${10:-\"n/a\"}"
    ph_field="${11:-n/a}"
    cat > "$OUT_DIR/manifest.json" <<JSON
{
  "schema_version": 1,
  "workspace": "$WS_NAME",
  "engine": "go-dynamic",
  "engine_version": "$5",
  "modules": "$6",
  "fuzz_filter": "$FUZZ_FILTER",
  "fuzztime": "$FUZZTIME",
  "fuzz_targets": $9,
  "timeout_seconds": $TIMEOUT_SEC,
  "status": "$1",
  "command": "$4",
  "started_at": "$STARTED_AT",
  "ended_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "duration_seconds": $7,
  "tests_passed": $8,
  "executed_harnesses": $executed_harnesses,
  "staticcheck_findings": $sc_field,
  "prod_harness_status": "$ph_field",
  "counterexample_path": $3,
  "advisory": true,
  "notes": "$2"
}
JSON
    echo "$1" > "$OUT_DIR/status.txt"
    echo "$4" > "$OUT_DIR/command.txt"
    echo "go-dynamic" > "$OUT_DIR/engine.txt"
    echo "[go-dynamic] manifest: $OUT_DIR/manifest.json (status=$1)"
}

# ---------------------------------------------------------------------------
# Preconditions: go toolchain
# ---------------------------------------------------------------------------
if ! command -v go >/dev/null 2>&1; then
    emit_manifest "tool-not-installed" "cannot-run: go not found on PATH (install Go toolchain)" "null" "(no engine invocation)" "n/a" "" 0 0 0 "\"n/a\"" "n/a"
    exit 0
fi
GO_VER="$(go version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------------
# Module discovery: every go.mod whose package declares a Fuzz target.
# ---------------------------------------------------------------------------
if [ "${#MODULE_ROOTS[@]}" -eq 0 ]; then
    while IFS= read -r gomod; do
        mdir="$(dirname "$gomod")"
        # package declares >=1 native go-fuzz target?
        if grep -rqsE 'func[[:space:]]+Fuzz[A-Za-z0-9_]*[[:space:]]*\([[:space:]]*[A-Za-z0-9_]+[[:space:]]+\*testing\.F' "$mdir" --include='*_test.go' 2>/dev/null; then
            MODULE_ROOTS+=("$mdir")
        fi
    done < <(find "$WORKSPACE" -maxdepth 4 -name go.mod -not -path '*/vendor/*' 2>/dev/null | sort)
fi

if [ "${#MODULE_ROOTS[@]}" -eq 0 ]; then
    emit_manifest "skipped" "cannot-run: no go.mod with a native go-fuzz target (func FuzzXxx(f *testing.F)) found under <ws> depth 4 — pass --module-root, or this target has no Go fuzz harness" "null" "(no engine invocation)" "$GO_VER" "" 0 0 0 "\"n/a\"" "n/a"
    exit 0
fi

MODULES_CSV=""
for m in "${MODULE_ROOTS[@]}"; do
    rel="$m"
    case "$m" in "$WORKSPACE"/*) rel="${m#"$WORKSPACE"/}" ;; esac
    MODULES_CSV="${MODULES_CSV:+$MODULES_CSV,}$rel"
done

# Build a human-readable command summary for the manifest / dry-run.
FUZZ_CMD_SUMMARY="(per package per target) go test -run=^\$ -fuzz=^<Name>\$ -fuzztime=$FUZZTIME ./<pkg>"
STATICCHECK_PLANNED="no"
if [ "$RUN_STATICCHECK" != "no" ]; then
    if command -v staticcheck >/dev/null 2>&1; then STATICCHECK_PLANNED="yes"; else STATICCHECK_PLANNED="tool-not-installed"; fi
fi
PRODH_PLANNED="no"
if [ "$RUN_PROD_HARNESS" != "no" ]; then
    if [ "${#PROD_HARNESS_PKGS[@]}" -gt 0 ]; then PRODH_PLANNED="yes"; else PRODH_PLANNED="auto"; fi
fi
CMD_STR="modules=[$MODULES_CSV]; fuzz=[$FUZZ_CMD_SUMMARY]; staticcheck=$STATICCHECK_PLANNED; prod-harness=$PRODH_PLANNED"
echo "$CMD_STR" > "$OUT_DIR/command.txt"

if [ "$DRY_RUN" -eq 1 ]; then
    # args: status notes ce cmd ver modules duration tests_passed fuzz_targets staticcheck prod_harness
    emit_manifest "skipped" "dry-run: commands rendered, not invoked" "null" "$CMD_STR" "$GO_VER" "$MODULES_CSV" 0 0 "${#MODULE_ROOTS[@]}" "\"$STATICCHECK_PLANNED\"" "$PRODH_PLANNED"
    exit 0
fi

echo "[go-dynamic] discovered ${#MODULE_ROOTS[@]} fuzz module(s): $MODULES_CSV"
echo "[go-dynamic] running (timeout=${TIMEOUT_SEC}s, fuzztime=${FUZZTIME}/target)"
START_EPOCH="$(date +%s)"
STEPS_LOG="$OUT_DIR/steps.log"
: > "$STEPS_LOG"

# Per-run wall-clock budget shared across all steps via a deadline epoch.
DEADLINE_EPOCH=$((START_EPOCH + TIMEOUT_SEC))

run_with_budget() {
    # Run "$@" under the remaining wall-clock budget. Echoes rc.
    local remaining now
    now="$(date +%s)"
    remaining=$((DEADLINE_EPOCH - now))
    [ "$remaining" -lt 1 ] && remaining=1
    if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" "$remaining" "$@"
    else
        "$@"
    fi
}

TOTAL_PASSED=0
TOTAL_FUZZ_TARGETS=0
COUNTEREXAMPLE_FOUND=0
CE_CAPTURE="$OUT_DIR/failing_sequence.txt"
ANY_BUILD_ERROR=0

# --- Step group 1: native go-fuzz, ONE target at a time ---------------------
# go test -fuzz requires EXACTLY ONE matching fuzz target AND exactly ONE
# package. Passing ./... (multiple packages) always errors with "cannot use
# -fuzz flag with multiple packages" even when the -fuzz regex would match only
# one function. Fix: enumerate (package-dir, target-name) pairs and run one
# `go test -fuzz=^Name$ ./relative/pkg` invocation per pair.
for mdir in "${MODULE_ROOTS[@]}"; do
    rel="$mdir"; case "$mdir" in "$WORKSPACE"/*) rel="${mdir#"$WORKSPACE"/}" ;; esac
    # Enumerate (package-dir, fuzz-target-name) pairs.
    # For each *_test.go file we record its directory and the Fuzz* names it
    # declares. This gives us per-package granularity without requiring `go
    # list` (which may fail when dependencies are missing).
    # Output format: "<pkgdir>:<FuzzName>" one entry per line, sorted unique.
    PKG_TARGET_PAIRS=()
    while IFS= read -r entry; do
        [ -n "$entry" ] && PKG_TARGET_PAIRS+=("$entry")
    done < <(
        find "$mdir" -name '*_test.go' -not -path '*/vendor/*' 2>/dev/null \
        | while IFS= read -r tfile; do
            pkgdir="$(dirname "$tfile")"
            grep -oE 'func[[:space:]]+Fuzz[A-Za-z0-9_]*[[:space:]]*\([[:space:]]*[A-Za-z0-9_]+[[:space:]]+\*testing\.F' "$tfile" 2>/dev/null \
            | sed -E 's/func[[:space:]]+(Fuzz[A-Za-z0-9_]*).*/\1/' \
            | while IFS= read -r fn; do
                [ -n "$fn" ] && printf '%s:%s\n' "$pkgdir" "$fn"
            done
        done | sort -u
    )

    # SCOPE: when scope.json names in_scope roots, restrict fuzz targets to
    # packages UNDER those roots. The OP monorepo is ONE go module spanning
    # op-node/op-dispute-mon (in-scope) + cannon/op-batcher/op-program (OOS);
    # without this we fuzz OOS targets. Empty scope -> no restriction (prior behavior).
    _GO_SCOPE_ROOTS="$(python3 -c "import json,os; p=os.path.join('$WORKSPACE','scope.json'); d=json.load(open(p)) if os.path.exists(p) else {}; print('\n'.join(os.path.join('$WORKSPACE',r) for r in d.get('in_scope',[])))" 2>/dev/null)"
    # Apply the user --fuzz-filter as a name-substring selector.
    SELECTED_PAIRS=()
    for entry in ${PKG_TARGET_PAIRS[@]+"${PKG_TARGET_PAIRS[@]}"}; do
        tn="${entry##*:}"
        if [ -n "$_GO_SCOPE_ROOTS" ]; then
            _pkg="${entry%:*}"; _inscope=0
            while IFS= read -r _gr; do [ -n "$_gr" ] && case "$_pkg/" in "$_gr"/*) _inscope=1 ;; esac; done <<< "$_GO_SCOPE_ROOTS"
            [ "$_inscope" -eq 1 ] || continue
        fi
        if [ "$FUZZ_FILTER" = "." ] || printf '%s' "$tn" | grep -qE "$FUZZ_FILTER" 2>/dev/null; then
            SELECTED_PAIRS+=("$entry")
        fi
    done
    n_targets="${#SELECTED_PAIRS[@]}"
    TOTAL_FUZZ_TARGETS=$((TOTAL_FUZZ_TARGETS + n_targets))
    echo "[go-dynamic] module=$rel fuzz-targets=$n_targets fuzztime=$FUZZTIME/target" | tee -a "$STEPS_LOG"
    for entry in ${SELECTED_PAIRS[@]+"${SELECTED_PAIRS[@]}"}; do
        pkgdir="${entry%%:*}"
        tn="${entry##*:}"
        [ "$(date +%s)" -ge "$DEADLINE_EPOCH" ] && { echo "  -> wall-clock budget reached before $tn" | tee -a "$STEPS_LOG"; break; }
        pkg_rel="${pkgdir#"$mdir"}"
        pkg_arg=".${pkg_rel:+/$pkg_rel}"
        pkg_arg="${pkg_arg%/}"
        safe_pkg="${pkg_rel//\//_}"
        tlog="$OUT_DIR/fuzz_${rel//\//_}__${safe_pkg}__${tn}.log"
        # -run=^$ disables ordinary tests; -fuzz=^Name$ drives exactly this
        # target; pkg_arg is the SINGLE package containing the target so Go
        # never sees "cannot use -fuzz flag with multiple packages".
        ( cd "$mdir" && run_with_budget go test ${GO_TAGS_ARGS[@]+"${GO_TAGS_ARGS[@]}"} -run='^$' -fuzz="^${tn}\$" -fuzztime="$FUZZTIME" "$pkg_arg" ) >"$tlog" 2>&1
        rc=$?
        now="$(date +%s)"
        # GENUINE counterexample: a fuzz failure that wrote a failing input /
        # printed "--- FAIL: Fuzz" / a panic. NOT the multi-match meta-error,
        # NOT a build error.
        if grep -qE 'Failing input written to|^[[:space:]]*--- FAIL: Fuzz|^panic:|^[[:space:]]+panic:' "$tlog" 2>/dev/null; then
            COUNTEREXAMPLE_FOUND=1
            {
                echo "# go-dynamic fuzz counterexample ($rel :: $tn)";
                grep -nE 'Failing input written to|--- FAIL: Fuzz|panic:|testdata/fuzz/' "$tlog" 2>/dev/null | head -40;
            } >> "$CE_CAPTURE"
            grep -oE 'testdata/fuzz/[A-Za-z0-9_/]+' "$tlog" 2>/dev/null >> "$OUT_DIR/replay_corpus_paths.txt" || true
            echo "  -> $tn: COUNTEREXAMPLE" | tee -a "$STEPS_LOG"
        elif grep -qE 'cannot find package|build failed|undefined:|cannot use [^ ]+ as|expected .* found|^# |no required module provides|will not fuzz' "$tlog" 2>/dev/null \
             && ! grep -qE '^ok|^PASS|fuzz: elapsed' "$tlog" 2>/dev/null; then
            ANY_BUILD_ERROR=1
            echo "  -> $tn: build/config error (see $(basename "$tlog"))" | tee -a "$STEPS_LOG"
        elif [ "$rc" -eq 124 ] && [ -n "$TIMEOUT_BIN" ] && [ "$now" -ge "$DEADLINE_EPOCH" ]; then
            echo "  -> $tn: hit wall-clock budget" | tee -a "$STEPS_LOG"
        elif grep -qE '^ok|^PASS|fuzz: elapsed.*execs:' "$tlog" 2>/dev/null; then
            # this target's seed corpus + generated inputs all held the property.
            TOTAL_PASSED=$((TOTAL_PASSED + 1))
            echo "  -> $tn: held" | tee -a "$STEPS_LOG"
        fi
    done
done

# --- Step group 2: staticcheck (honest tool-not-installed) ------------------
# STATICCHECK_FINDINGS = JSON value (quoted string OR bare int).
# SC_LABEL             = clean unquoted label for embedding in the notes string.
STATICCHECK_FINDINGS="\"n/a\""
SC_LABEL="n/a"
if [ "$RUN_STATICCHECK" != "no" ]; then
    if command -v staticcheck >/dev/null 2>&1; then
        sc_total=0
        for mdir in "${MODULE_ROOTS[@]}"; do
            sclog="$OUT_DIR/staticcheck_$(basename "$mdir").log"
            ( cd "$mdir" && run_with_budget staticcheck ./... ) >"$sclog" 2>&1
            # staticcheck emits one finding per line "file:line:col: message (CODE)"
            n="$(grep -cE '^[^[:space:]].*:[0-9]+:[0-9]+:' "$sclog" 2>/dev/null || echo 0)"
            sc_total=$((sc_total + n))
        done
        STATICCHECK_FINDINGS="$sc_total"
        SC_LABEL="$sc_total"
        echo "[go-dynamic] staticcheck: $sc_total finding(s) across ${#MODULE_ROOTS[@]} module(s)" | tee -a "$STEPS_LOG"
    else
        STATICCHECK_FINDINGS="\"tool-not-installed\""
        SC_LABEL="tool-not-installed"
        echo "[go-dynamic] staticcheck: NOT INSTALLED — skipping (install: go install honnef.co/go/tools/cmd/staticcheck@latest)" | tee -a "$STEPS_LOG"
    fi
fi

# --- Step group 3: cosmos production-harness (real ABCI surface) ------------
PROD_HARNESS_STATUS="not-run"
if [ "$RUN_PROD_HARNESS" != "no" ]; then
    # auto-detect prod-harness packages if none specified
    if [ "${#PROD_HARNESS_PKGS[@]}" -eq 0 ] && [ "$RUN_PROD_HARNESS" = "auto" ]; then
        for mdir in "${MODULE_ROOTS[@]}"; do
            if grep -rqsE 'simapp\.Setup|app\.FinalizeBlock|\.BroadcastTxSync|RequestFinalizeBlock|app\.RunTx' "$mdir" --include='*.go' 2>/dev/null; then
                PROD_HARNESS_PKGS+=("$mdir")
            fi
        done
    fi
    if [ "${#PROD_HARNESS_PKGS[@]}" -gt 0 ]; then
        ph_fail=0; ph_pass=0; ph_timeout=0
        # Bound EACH prod-harness `go test ./...` by its OWN tighter cap (default
        # 300s, env AUDITOOOR_PROD_HARNESS_TIMEOUT) instead of run_with_budget's
        # full remaining wall-clock. On a large cosmos vault the production-harness
        # `go test ./...` can run 10-20min, dominating the engine and holding the
        # fuzz_runs manifest (the live-engines gate-A evidence) hostage far behind
        # the already-completed fuzz step (observed NUVA 2026-07-06: fuzz held in
        # <1min, manifest still unwritten 11min later stuck in prod-harness). This
        # is a SEPARATE, best-effort ABCI-surface signal - it must never delay the
        # gate-A fuzz evidence. A timed-out harness is recorded, not hung.
        _ph_cap="${AUDITOOOR_PROD_HARNESS_TIMEOUT:-300}"
        for pkg in "${PROD_HARNESS_PKGS[@]}"; do
            phlog="$OUT_DIR/prod_harness_$(basename "$pkg").log"
            if [ -n "$TIMEOUT_BIN" ]; then
                ( cd "$pkg" && "$TIMEOUT_BIN" --kill-after=15 -s TERM "$_ph_cap" go test ${GO_TAGS_ARGS[@]+"${GO_TAGS_ARGS[@]}"} ./... ) >"$phlog" 2>&1
            else
                ( cd "$pkg" && run_with_budget go test ${GO_TAGS_ARGS[@]+"${GO_TAGS_ARGS[@]}"} ./... ) >"$phlog" 2>&1
            fi
            rc=$?
            if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then ph_timeout=$((ph_timeout+1))
            elif [ "$rc" -eq 0 ] && grep -qE '^ok|PASS' "$phlog" 2>/dev/null; then ph_pass=$((ph_pass+1))
            else ph_fail=$((ph_fail+1)); fi
        done
        if [ "$ph_timeout" -gt 0 ]; then PROD_HARNESS_STATUS="timeout(${ph_timeout};cap=${_ph_cap}s)"
        elif [ "$ph_fail" -gt 0 ]; then PROD_HARNESS_STATUS="failed($ph_fail)"; else PROD_HARNESS_STATUS="pass($ph_pass)"; fi
        echo "[go-dynamic] prod-harness: $PROD_HARNESS_STATUS over ${#PROD_HARNESS_PKGS[@]} package(s)" | tee -a "$STEPS_LOG"
    else
        PROD_HARNESS_STATUS="none-detected"
    fi
fi

END_EPOCH="$(date +%s)"
DURATION=$((END_EPOCH - START_EPOCH))

# ---------------------------------------------------------------------------
# Final classification.
# ---------------------------------------------------------------------------
CE_PATH="null"
if [ "$COUNTEREXAMPLE_FOUND" -eq 1 ]; then
    STATUS="counterexample"
    NOTES="go-fuzz FAILURE — counterexample found on a property; CRITICAL-class candidate, replay with go test -run=<Fn>/<hash>"
    CE_PATH="\"$CE_CAPTURE\""
elif [ "$END_EPOCH" -ge "$DEADLINE_EPOCH" ]; then
    STATUS="timeout"
    NOTES="engine wall-clock timeout after ${TIMEOUT_SEC}s (partial coverage; ${TOTAL_PASSED} target(s) held before budget)"
elif [ "$ANY_BUILD_ERROR" -eq 1 ] && [ "$TOTAL_PASSED" -eq 0 ]; then
    STATUS="error"
    NOTES="go build/test error in every module — see *.log (toolchain/dep mismatch; not a finding)"
elif [ "$TOTAL_PASSED" -gt 0 ]; then
    STATUS="pass"
    NOTES="all ${TOTAL_PASSED} go-fuzz target(s) held under -fuzztime=${FUZZTIME} (PROPTEST-grade dynamic coverage); core invariants HOLD; staticcheck=${SC_LABEL}; prod-harness=${PROD_HARNESS_STATUS}"
else
    STATUS="error"
    NOTES="go test -fuzz produced no recognizable pass/fail across ${#MODULE_ROOTS[@]} module(s) — see steps.log + *.log"
fi

emit_manifest "$STATUS" "$NOTES" "$CE_PATH" "$CMD_STR" "$GO_VER" "$MODULES_CSV" "$DURATION" "$TOTAL_PASSED" "$TOTAL_FUZZ_TARGETS" "$STATICCHECK_FINDINGS" "$PROD_HARNESS_STATUS"
echo "[go-dynamic] done: status=$STATUS duration=${DURATION}s passed=$TOTAL_PASSED targets=$TOTAL_FUZZ_TARGETS"
exit 0
