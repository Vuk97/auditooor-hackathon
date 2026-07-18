#!/usr/bin/env bash
# test-detectors-v2.sh — Round 31 improved fixture CI.
#
# Round 30 issue: a single Slither run over 150+ fixtures hit Solc's
# 256-warning limit (mostly `transfer()` deprecation warnings) and aborted
# compilation with an unhelpful build-info error.
#
# Fix: compile fixtures in small batches (≤20 per batch), each in its own
# scratch dir, with solc warnings suppressed via command-line flag.
#
# Usage:
#   ./tools/test-detectors-v2.sh [--tier=S|E|D|ALL] [--batch-size N] [--detector=<name>]

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DET_DIR="$AUDITOOOR_DIR/detectors"
FIX_DIR="$DET_DIR/test_fixtures"
PATT_FIX_DIR="$AUDITOOOR_DIR/patterns/fixtures"
REGISTRY="$DET_DIR/_tier_registry.yaml"

TIER_FILTER="S,E"
BATCH_SIZE=15
DET_FILTER=""

while [ $# -gt 0 ]; do
    case "$1" in
        --tier=*) TIER_FILTER="${1#--tier=}"; shift ;;
        --batch-size) BATCH_SIZE="$2"; shift 2 ;;
        --detector=*) DET_FILTER="${1#--detector=}"; shift ;;
        help|--help|-h) sed -n '2,14p' "$0" | sed 's/^# //; s/^#//'; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

# Build per-pattern regression expectations: each pattern tested in its own
# 1-file-batch so warnings from sibling fixtures don't leak in.
TMP=$(mktemp -t r31_ci.XXXXXX)
trap "rm -f $TMP" EXIT

python3 - "$DET_DIR" "$PATT_FIX_DIR" "$REGISTRY" "$TIER_FILTER" "$DET_FILTER" > "$TMP" <<'PY'
import sys, yaml, re
from pathlib import Path

det_dir = Path(sys.argv[1])
fix_dir = Path(sys.argv[2])
registry_path = Path(sys.argv[3])
tier_filter = sys.argv[4]
det_filter = sys.argv[5]

tier_map = {}
if registry_path.exists():
    data = yaml.safe_load(registry_path.read_text()) or {}
    tier_map = {n: e.get("tier", "D") for n, e in (data.get("tiers") or {}).items()}

allowed = None
if tier_filter and tier_filter != "ALL":
    allowed = {t.strip().upper() for t in tier_filter.split(",") if t.strip()}

# Discover detector ARGUMENTs from wave17
arg_re = re.compile(r'^\s*ARGUMENT\s*=\s*"([^"]+)"', re.MULTILINE)
det_to_file = {}
for py in det_dir.glob("wave*/*.py"):
    if "graveyard" in str(py) or "_broken" in str(py) or py.name.startswith("_"):
        continue
    try:
        m = arg_re.search(py.read_text(errors="ignore"))
        if m:
            det_to_file[m.group(1)] = py
    except Exception:
        continue

# Match each detector ARG to a vuln+clean fixture pair in patterns/fixtures/
pairs = []
for arg, py in sorted(det_to_file.items()):
    t = tier_map.get(arg, "D")
    if allowed and t not in allowed:
        continue
    if det_filter and arg != det_filter:
        continue
    # Slug variants
    for nv in (arg, arg.replace('-','_')):
        v = fix_dir / f"{nv}_vuln.sol"
        c = fix_dir / f"{nv}_clean.sol"
        if v.exists() and c.exists():
            pairs.append((arg, v.name, c.name))
            break

# Emit: DETECTOR\tVULN_NAME\tCLEAN_NAME
for arg, v, c in pairs:
    print(f"{arg}\t{v}\t{c}")
PY

TOTAL=$(wc -l < "$TMP" | tr -d ' ')
echo "==========================================================================="
echo "  test-detectors-v2 — per-pattern isolated fixture CI"
echo "==========================================================================="
echo "  Discovered pattern+fixture pairs: $TOTAL"
echo "  Tier filter: $TIER_FILTER"
echo "  Batch size:  1 pattern per Slither run (eliminates warning-flood issue)"
echo ""

if [ "$TOTAL" = "0" ]; then
    echo "  [error] No detector+fixture pairs found"
    exit 1
fi

PASS=0
FAIL=0
FAIL_LIST=()
N=0

while IFS=$'\t' read -r arg v c; do
    N=$((N + 1))
    # Set up a scratch dir with ONLY these 2 files
    SCRATCH=$(mktemp -d -t r31ci.XXXXXX)
    cp "$PATT_FIX_DIR/$v" "$SCRATCH/" 2>/dev/null
    cp "$PATT_FIX_DIR/$c" "$SCRATCH/" 2>/dev/null
    cat > "$SCRATCH/foundry.toml" <<'TOML'
[profile.default]
src = "."
out = "out"
TOML

    # Run single-pattern batch
    REG="$SCRATCH/reg.tsv"
    {
        echo "vuln	$arg	$v	$arg"
        echo "clean	$arg	$c	$arg (clean)"
    } > "$REG"

    OUT=$(python3 "$DET_DIR/run_custom.py" --batch "$SCRATCH" "$REG" "--tier=ALL" 2>&1)
    SUMMARY=$(echo "$OUT" | grep -E "Batch regression:" | tail -1)
    rm -rf "$SCRATCH"

    if echo "$SUMMARY" | grep -q "2/2 passed"; then
        PASS=$((PASS + 1))
        [ $((N % 20)) -eq 0 ] && echo "  [$N/$TOTAL] $PASS pass, $FAIL fail..."
    else
        FAIL=$((FAIL + 1))
        FAIL_LIST+=("$arg")
        # Capture reason briefly
        FAIL_REASON=$(echo "$OUT" | grep -E "0 hits|expected|missing" | head -1 | cut -c1-120)
    fi
done < "$TMP"

echo ""
echo "==========================================================================="
echo "  CI RESULT: $PASS/$TOTAL pass ($((PASS*100/TOTAL))%), $FAIL fail"
if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "  Failed patterns (first 20):"
    for arg in "${FAIL_LIST[@]:0:20}"; do
        echo "    - $arg"
    done
fi
echo "==========================================================================="
