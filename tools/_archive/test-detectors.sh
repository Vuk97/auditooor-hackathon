#!/usr/bin/env bash
# test-detectors.sh — fixture-backed CI for auditooor detectors (Issue #77)
#
# For every detector, runs:
#   - vuln fixture (expected: ≥1 hit)
#   - clean fixture (expected: 0 hits)
#
# Reports pass/fail per detector. Exit non-zero if any regression.
#
# Usage:
#   ./tools/test-detectors.sh                    # test all detectors with fixture pairs
#   ./tools/test-detectors.sh --tier=S           # test only Tier-S detectors
#   ./tools/test-detectors.sh --tier=S,E         # test Tier-S and Tier-E
#   ./tools/test-detectors.sh --detector=<name>  # test one detector
#   ./tools/test-detectors.sh --generate-tsv > regression.tsv
#       generate a regression TSV from all discovered fixture pairs
#
# Writes _test_results.yaml alongside _hits_ledger.yaml.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DET_DIR="$AUDITOOOR_DIR/detectors"
FIX_DIR="$DET_DIR/test_fixtures"
REGISTRY="$DET_DIR/_tier_registry.yaml"

TIER_FILTER=""
DET_FILTER=""
GEN_TSV=0

while [ $# -gt 0 ]; do
    case "$1" in
        --tier=*) TIER_FILTER="${1#--tier=}"; shift ;;
        --detector=*) DET_FILTER="${1#--detector=}"; shift ;;
        --generate-tsv) GEN_TSV=1; shift ;;
        help|--help|-h) sed -n '2,18p' "$0" | sed 's/^# //; s/^#//'; exit 0 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [ ! -d "$FIX_DIR" ]; then
    echo "[error] fixture directory not found: $FIX_DIR" >&2
    exit 1
fi

# Build detector ARGUMENT → path map.
# Discovers pairs by matching <name>_vulnerable.sol with <name>_clean.sol.
TMP=$(mktemp -t testdet.XXXXXX)
trap "rm -f $TMP" EXIT

python3 - "$DET_DIR" "$FIX_DIR" "$REGISTRY" "$TIER_FILTER" "$DET_FILTER" "$GEN_TSV" > "$TMP" <<'PY'
import sys, yaml, re
from pathlib import Path

det_dir = Path(sys.argv[1])
fix_dir = Path(sys.argv[2])
registry_path = Path(sys.argv[3])
tier_filter = sys.argv[4]
det_filter = sys.argv[5]
gen_tsv = int(sys.argv[6])

# Load tier map
tier_map = {}
if registry_path.exists():
    data = yaml.safe_load(registry_path.read_text()) or {}
    tier_map = {n: e.get("tier", "D") for n, e in (data.get("tiers") or {}).items()}

allowed = None
if tier_filter:
    allowed = {t.strip().upper() for t in tier_filter.split(",") if t.strip()}
    if "ALL" in allowed:
        allowed = None

# Discover detectors: scan all wave*/ (non-graveyard, non-broken) for class ARGUMENT
det_to_file = {}
arg_re = re.compile(r'^\s*ARGUMENT\s*=\s*"([^"]+)"', re.MULTILINE)
for py in det_dir.glob("wave*/*.py"):
    if "graveyard" in str(py) or "_broken" in str(py) or py.name.startswith("_"):
        continue
    try:
        m = arg_re.search(py.read_text(errors="ignore"))
        if m:
            arg_name = m.group(1)
            det_to_file[arg_name] = py
    except Exception:
        continue

# Find fixture pairs by filename convention: <slug>_vulnerable.sol + <slug>_clean.sol
fixtures = {}
for sol in fix_dir.glob("*_vulnerable.sol"):
    slug = sol.name.rsplit("_vulnerable.sol", 1)[0]
    clean = fix_dir / f"{slug}_clean.sol"
    if clean.exists():
        fixtures[slug] = (sol, clean)

# Map detector ARGUMENT to fixture slug. Convention: slugify(ARGUMENT) ≈ slug.
def slugify(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")

pairs = []  # (detector_arg, vuln_path, clean_path)
for arg, py in det_to_file.items():
    # Tier filter
    t = tier_map.get(arg, "D")
    if allowed and t not in allowed:
        continue
    # Name filter
    if det_filter and arg != det_filter:
        continue
    # Try match — slugify and also try common suffixes
    slug = slugify(arg)
    matched = None
    if slug in fixtures:
        matched = fixtures[slug]
    else:
        # Try truncated match (detectors' slugs often get truncated in fixture names)
        for fslug, fpair in fixtures.items():
            if fslug.startswith(slug[:40]) or slug.startswith(fslug[:40]):
                matched = fpair
                break
    if matched:
        pairs.append((arg, str(matched[0]), str(matched[1])))

if gen_tsv:
    # Output TSV suitable for `run_custom.py --batch <fixture_dir> <tsv>`
    for arg, vuln, clean in pairs:
        print(f"vuln\t{arg}\t{Path(vuln).name}\t{arg}")
        print(f"clean\t{arg}\t{Path(clean).name}\t{arg} (clean)")
    sys.exit(0)

# Default: just print the discovered pairs count + stash for shell
print(f"TOTAL_PAIRS={len(pairs)}")
print(f"TOTAL_DETECTORS={len(det_to_file)}")
for arg, vuln, clean in pairs:
    print(f"PAIR\t{arg}\t{Path(vuln).name}\t{Path(clean).name}")
PY

if [ "$GEN_TSV" = "1" ]; then
    cat "$TMP"
    exit 0
fi

TOTAL_PAIRS=$(grep '^TOTAL_PAIRS=' "$TMP" | cut -d= -f2)
TOTAL_DETECTORS=$(grep '^TOTAL_DETECTORS=' "$TMP" | cut -d= -f2)

echo "==========================================================================="
echo "  test-detectors — fixture-backed CI"
echo "==========================================================================="
echo "  Detectors discovered:    $TOTAL_DETECTORS"
echo "  With fixture pairs:      $TOTAL_PAIRS"
if [ "$TIER_FILTER" != "" ]; then
    echo "  Tier filter:             $TIER_FILTER"
fi
echo ""

if [ "$TOTAL_PAIRS" = "0" ]; then
    echo "  [info] No detector+fixture pairs found matching the filter."
    echo "  Tier-S and Tier-E detectors SHOULD have fixture pairs."
    echo "  To backfill, see: reference/detector_fixture_authoring.md"
    exit 0
fi

# Generate regression TSV and run via run_custom.py --batch
REG_TSV=$(mktemp -t regtsv.XXXXXX)
trap "rm -f $TMP $REG_TSV" EXIT
grep '^PAIR\t' "$TMP" | awk -F'\t' '{
    print "vuln\t" $2 "\t" $3 "\t" $2
    print "clean\t" $2 "\t" $4 "\t" $2 " (clean)"
}' > "$REG_TSV"

PAIR_COUNT=$(wc -l < "$REG_TSV" | tr -d ' ')
echo "  Running $PAIR_COUNT test expectations through run_custom.py --batch..."
echo ""

# Run batch in isolated fixture dir — only test files exist there.
# Slither on the whole test_fixtures/ is expensive; scope to a minimal temp
# subdir containing only the fixtures we need.
SCRATCH=$(mktemp -d -t detfix.XXXXXX)
trap "rm -rf $SCRATCH $TMP $REG_TSV" EXIT

grep '^PAIR\t' "$TMP" | while IFS=$'\t' read -r _ arg vuln clean; do
    cp "$FIX_DIR/$vuln" "$SCRATCH/" 2>/dev/null || true
    cp "$FIX_DIR/$clean" "$SCRATCH/" 2>/dev/null || true
done

# Touch a foundry.toml so Slither treats it as a flat source dir
cat > "$SCRATCH/foundry.toml" <<'TOML'
[profile.default]
src = "."
out = "out"
TOML

BATCH_TIER_ARG=""
if [ -n "$TIER_FILTER" ]; then
    BATCH_TIER_ARG="--tier=$TIER_FILTER"
fi
python3 "$DET_DIR/run_custom.py" --batch "$SCRATCH" "$REG_TSV" $BATCH_TIER_ARG
RC=$?

# Save result summary to YAML
RESULTS="$DET_DIR/_test_results.yaml"
python3 - "$RESULTS" "$RC" "$PAIR_COUNT" <<PY
import sys, datetime, yaml
from pathlib import Path
p = Path(sys.argv[1])
rc = int(sys.argv[2])
pc = int(sys.argv[3])
data = {
    "last_run": datetime.datetime.now().isoformat(timespec="seconds"),
    "expectations_run": pc,
    "exit_code": rc,
    "status": "PASS" if rc == 0 else "FAIL",
}
p.write_text(yaml.safe_dump(data, sort_keys=False))
print(f"  [ok] wrote {p}")
PY

exit $RC
