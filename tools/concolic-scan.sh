#!/usr/bin/env bash
# concolic-scan.sh — concolic/symbolic execution wiring for auditooor (U10)
#
# Runs Halmos (preferred) or Mythril (fallback) against the top-3 hottest
# contracts in a workspace — ranked by LoC × external-function-count.
#
# Finds bugs the 240-pattern library can't reach because they require
# path-sensitive reasoning: assertion violations, unreachable invariants,
# integer over/underflow along specific paths, counter-examples to symbolic
# properties. Pattern matching surfaces known shapes; concolic surfaces
# path-dependent bugs.
#
# Usage:
#   ./tools/concolic-scan.sh <workspace> [--tool halmos|mythril] [--timeout N]
#
# Outputs:
#   <ws>/concolic/<contract>_<tool>_<date>.log  — raw tool output
#   <ws>/concolic/findings.yaml                 — normalized findings list
#   <ws>/concolic/SUMMARY.md                    — triage summary
#
# Exit codes:
#   0  success (0 or more findings)
#   2  usage error
#   3  neither halmos nor mythril installed (prints install guidance)

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
    cat >&2 <<'USAGE'
Usage: ./tools/concolic-scan.sh <workspace> [--tool halmos|mythril] [--timeout N]

Runs concolic/symbolic execution on the top-3 hottest contracts in <workspace>,
ranked by LoC * external-function-count.

Options:
  --tool halmos|mythril    Which engine to use (default: halmos if installed, else mythril).
  --timeout N              Seconds per contract (default: 300).

Example:
  ./tools/concolic-scan.sh ~/audits/polymarket --tool halmos --timeout 180
USAGE
    exit 2
}

[ $# -lt 1 ] && usage

WS="$1"; shift
TOOL=""
TIMEOUT=300
while [ $# -gt 0 ]; do
    case "$1" in
        --tool) TOOL="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "[error] unknown arg: $1" >&2; usage ;;
    esac
done

[ -d "$WS" ] || { echo "[error] workspace not found: $WS" >&2; exit 2; }

# ---- Find source directory ----
SRC_DIR=""
for candidate in "$WS/src" "$WS/contracts" "$WS"; do
    [ -d "$candidate" ] || continue
    if find "$candidate" -name "*.sol" -not -path "*/test/*" -not -path "*/lib/*" -print -quit 2>/dev/null | grep -q .; then
        SRC_DIR="$candidate"
        break
    fi
done
[ -z "$SRC_DIR" ] && { echo "[error] no Solidity source found under $WS" >&2; exit 2; }

# ---- Tool detection & install guidance ----
HAVE_HALMOS=0; HAVE_MYTHRIL=0
command -v halmos >/dev/null 2>&1 && HAVE_HALMOS=1
command -v myth    >/dev/null 2>&1 && HAVE_MYTHRIL=1

if [ -z "$TOOL" ]; then
    if   [ "$HAVE_HALMOS"  -eq 1 ]; then TOOL="halmos"
    elif [ "$HAVE_MYTHRIL" -eq 1 ]; then TOOL="mythril"
    else TOOL=""
    fi
fi

if [ "$TOOL" = "halmos"  ] && [ "$HAVE_HALMOS"  -eq 0 ]; then TOOL=""; fi
if [ "$TOOL" = "mythril" ] && [ "$HAVE_MYTHRIL" -eq 0 ]; then TOOL=""; fi

# Resolve a portable `timeout` — prefer GNU coreutils on macOS (gtimeout).
TIMEOUT_BIN=""
if   command -v timeout  >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
fi
# Wrapper: if no timeout binary, just run the command (concolic tools enforce
# their own --execution-timeout / --solver-timeout internally).
run_with_timeout() {
    local secs="$1"; shift
    if [ -n "$TIMEOUT_BIN" ]; then
        "$TIMEOUT_BIN" "$secs" "$@"
    else
        "$@"
    fi
}

if [ -z "$TOOL" ]; then
    cat >&2 <<'NOTOOL'
[error] neither halmos nor mythril is installed.

Install one of:

  # Halmos — Foundry-style symbolic execution, fast, good for property tests
  pip install halmos
  # Requires solc + foundry in PATH.
  # Usage: halmos --contract <Name> --function <sig>

  # Mythril — EVM symbolic analyzer, SWC catalogue
  pip install mythril
  # Usage: myth analyze <file.sol>

  # Manticore (optional alternative) — deeper but slow
  pip install manticore

Then re-run: ./tools/concolic-scan.sh <workspace> [--tool halmos|mythril]
NOTOOL
    exit 3
fi

OUT_DIR="$WS/concolic"
mkdir -p "$OUT_DIR"
DATE_TAG=$(date -u +%Y%m%d)

echo "============================================================================"
echo "  concolic-scan — $(basename "$WS")"
echo "  Engine: $TOOL   Timeout: ${TIMEOUT}s/contract   Source: $SRC_DIR"
echo "============================================================================"

# ---- Rank contracts by LoC * (external|public function count) ----
echo "[1/3] Ranking contracts by LoC * extern-funcs..."

RANK_TMP=$(mktemp)
# Exclude interfaces, mocks, test, lib, node_modules, script/ — audit-real code only
while IFS= read -r sol; do
    name=$(basename "$sol" .sol)
    case "$name" in I*|*Mock*|*Test*|*Script*|*.snap) continue ;; esac
    case "$sol" in *.snap.sol|*/snapshots/*) continue ;; esac
    loc=$(wc -l < "$sol" | tr -d ' ')
    # External/public function count — tolerate indentation + modifiers in between.
    # `grep -c` returns 1 on 0-matches; swallow that to a clean 0.
    fns=$(grep -cE '^[[:space:]]*function[[:space:]].*\b(external|public)\b' "$sol" 2>/dev/null)
    fns=${fns:-0}
    [ "$fns" -eq 0 ] && continue
    score=$(( loc * fns ))
    printf "%d\t%d\t%d\t%s\n" "$score" "$loc" "$fns" "$sol" >> "$RANK_TMP"
done < <(find "$SRC_DIR" -name "*.sol" -not -path "*/test/*" -not -path "*/lib/*" -not -path "*/node_modules/*" -not -path "*/mock*/*" -not -path "*/script/*" 2>/dev/null)

if [ ! -s "$RANK_TMP" ]; then
    echo "[error] no rankable contracts found in $SRC_DIR" >&2
    rm -f "$RANK_TMP"
    exit 2
fi

TOP_CONTRACTS=$(sort -rn "$RANK_TMP" | head -3)
echo ""
echo "  Top-3 hottest (LoC × extern_funcs):"
echo "$TOP_CONTRACTS" | awk -F'\t' '{ printf "    %-40s  LoC=%d  fns=%d  score=%d\n", $4, $2, $3, $1 }'
echo ""

rm -f "$RANK_TMP"

# ---- Initialize findings.yaml ----
FINDINGS="$OUT_DIR/findings.yaml"
cat > "$FINDINGS" <<EOF
# Normalized concolic findings — generated by concolic-scan.sh
# Workspace: $(basename "$WS")
# Engine: $TOOL
# Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
#
# Schema: list of { contract, function, severity, kind, ref, log }
findings:
EOF

# ---- Run the tool per contract ----
echo "[2/3] Running $TOOL on top-3 (timeout ${TIMEOUT}s each)..."

SUMMARY_ROWS=""
TOTAL_FINDINGS=0

while IFS=$'\t' read -r score loc fns sol; do
    [ -z "$sol" ] && continue
    name=$(basename "$sol" .sol)
    log="$OUT_DIR/${name}_${TOOL}_${DATE_TAG}.log"
    echo ""
    echo "  --- $name (score=$score) ---"
    echo "      log → $log"

    case "$TOOL" in
        halmos)
            # Halmos expects a foundry project. Try WS itself first, fall back to running
            # from $WS with --contract filter. If no foundry project, note it and skip.
            if [ -f "$WS/foundry.toml" ]; then
                (
                    cd "$WS" && \
                    run_with_timeout "$TIMEOUT" halmos --contract "$name" --loop 2 --solver-timeout-assertion 10000 2>&1
                ) > "$log" || true
            else
                cat > "$log" <<EOF
[skipped] halmos requires a foundry project (foundry.toml) at $WS.
Initialize foundry or move contracts into a foundry workspace, then re-run.
Contract: $sol
EOF
            fi
            # Parse halmos counter-examples: lines starting with "Counterexample:" or "[FAIL]"
            ce_count=$(grep -cE '^(Counterexample:|\[FAIL\])' "$log" 2>/dev/null); ce_count=${ce_count:-0}
            if [ "$ce_count" -gt 0 ]; then
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + ce_count))
                # Extract the failing function names
                grep -E '^\[FAIL\]' "$log" 2>/dev/null | head -20 | while IFS= read -r line; do
                    fn=$(echo "$line" | sed -E 's/^\[FAIL\][[:space:]]+([A-Za-z_][A-Za-z0-9_]*)\(.*/\1/')
                    [ -z "$fn" ] && fn="unknown"
                    cat >> "$FINDINGS" <<EOF
  - contract: "$name"
    function: "$fn"
    severity: "unknown"
    kind: "counterexample"
    ref: "halmos"
    log: "${name}_${TOOL}_${DATE_TAG}.log"
EOF
                done
            fi
            SUMMARY_ROWS="${SUMMARY_ROWS}| $name | $loc | $fns | $ce_count counter-examples |"$'\n'
            ;;
        mythril)
            # Mythril — point at the .sol file. Uses solc from PATH.
            run_with_timeout "$TIMEOUT" myth analyze "$sol" --execution-timeout "$((TIMEOUT - 10))" > "$log" 2>&1 || true
            # Parse SWC refs: "SWC ID: 107"
            swc_hits=$(grep -cE 'SWC ID:' "$log" 2>/dev/null); swc_hits=${swc_hits:-0}
            if [ "$swc_hits" -gt 0 ]; then
                TOTAL_FINDINGS=$((TOTAL_FINDINGS + swc_hits))
                # Extract issue blocks: "==== <title> ====" followed by SWC / Severity
                awk '
                    /^==== / { title=$0; gsub(/^==== | ====$/, "", title) }
                    /^Severity:/ { sev=$2 }
                    /^SWC ID:/ { swc=$3; printf "%s\t%s\tSWC-%s\n", title, sev, swc }
                ' "$log" | while IFS=$'\t' read -r title sev swc; do
                    [ -z "$title" ] && continue
                    cat >> "$FINDINGS" <<EOF
  - contract: "$name"
    function: "$title"
    severity: "${sev:-unknown}"
    kind: "mythril-issue"
    ref: "$swc"
    log: "${name}_${TOOL}_${DATE_TAG}.log"
EOF
                done
            fi
            SUMMARY_ROWS="${SUMMARY_ROWS}| $name | $loc | $fns | $swc_hits SWC hits |"$'\n'
            ;;
    esac
done <<< "$TOP_CONTRACTS"

# ---- Write SUMMARY.md ----
echo ""
echo "[3/3] Writing SUMMARY.md..."

SUMMARY="$OUT_DIR/SUMMARY.md"
cat > "$SUMMARY" <<EOF
# Concolic-scan Summary — $(basename "$WS")

**Engine:** \`$TOOL\`
**Timeout:** ${TIMEOUT}s per contract
**Source:** \`$SRC_DIR\`
**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## Top-3 hottest contracts

| Contract | LoC | Ext/Pub Fns | Concolic result |
|----------|-----|-------------|-----------------|
$SUMMARY_ROWS

**Total findings:** $TOTAL_FINDINGS (see \`findings.yaml\`)

## Parsing rules used

- **Halmos**: counts \`[FAIL]\` and \`Counterexample:\` lines — each represents a path
  that violates a symbolic property or assertion.
- **Mythril**: counts \`SWC ID:\` references — each corresponds to an entry in the
  [SWC registry](https://swcregistry.io/). Severity is the tool's self-reported field.

## Next actions

1. For each finding in \`findings.yaml\`, open the log file and read the full
   counter-example / trace. Concolic findings are path-dependent — the value
   is in the input vector, not just the line number.
2. Cross-check counter-examples against the 240-pattern library. Genuinely
   novel path-sensitive bugs are the prize; pattern duplicates can be dropped.
3. If Halmos was used but \`foundry.toml\` wasn't present, move the contracts
   into a foundry workspace to get real symbolic results.
4. For deeper invariant work, write halmos property tests
   (\`function check_<name>(...) public\`) and re-run.
EOF

rm -f "$RANK_TMP" 2>/dev/null

echo ""
echo "============================================================================"
echo "  concolic-scan complete."
echo "  Summary:   $SUMMARY"
echo "  Findings:  $FINDINGS  ($TOTAL_FINDINGS entries)"
echo "  Raw logs:  $OUT_DIR/*_${TOOL}_${DATE_TAG}.log"
echo "============================================================================"
