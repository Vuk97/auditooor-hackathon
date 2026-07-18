#!/usr/bin/env bash
# wire-and-promote-with-guards.sh — safe chain runner for any FP-repair-style
# wirer + bulk-promote, with the wirer-output-diversity-check gate inserted
# between wirer and promote.
#
# Background (2026-05-04):
#   fp_repair_v2 wire pass produced 162 smoke-passing fakes — 91 newly-
#   emitted YAMLs all collapsed to the same `body_not_contains_regex:
#   "require\\s*\\("` trick. Smoke passed; detector was fake. Manual
#   inspection caught it before they shipped to verified count, but the
#   default chain (wirer → bulk-promote) would have shipped them.
#
#   This wrapper inserts wirer-output-diversity-check.py BEFORE bulk-
#   promote. If too many emitted YAMLs share a canonical predicate, the
#   chain stops and emits a quarantine pointer.
#
# Usage:
#   bash tools/wire-and-promote-with-guards.sh \
#     --wirer  tools/false-positive-batch-wirer.py \
#     --queue  /private/tmp/auditooor-inventory/fp_repair_v2_full_queue.jsonl \
#     --label  fp_repair_v2 \
#     [--max-share 0.30] [--min-cohort 5]
#
# Steps:
#   1. Snapshot YAMLs in reference/patterns.dsl/ (mtime cutoff = now)
#   2. Run the wirer (emits promote queue + refined YAMLs)
#   3. Diversity check on the YAMLs newer than the cutoff
#   4. If PASS: run inventory-bulk-promote
#   5. If FAIL: stop, emit /tmp/<label>_diversity_BLOCKED.json, exit 1
#
# Exit codes:
#   0  full chain succeeded
#   1  diversity violation; promote NOT run
#   2  bad args / wirer failed / promote failed

set -euo pipefail

REPO=$(cd "$(dirname "$0")/.." && pwd)

WIRER=""
QUEUE=""
LABEL=""
MAX_SHARE=0.30
MIN_COHORT=5
DSL_DIR="${REPO}/reference/patterns.dsl"
ENFORCE_SEMANTIC_LINT=1   # Layer C of harness hardening v1; default ON
RULE4_HARD=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --wirer)      WIRER="$2"; shift 2 ;;
    --queue)      QUEUE="$2"; shift 2 ;;
    --label)      LABEL="$2"; shift 2 ;;
    --max-share)  MAX_SHARE="$2"; shift 2 ;;
    --min-cohort) MIN_COHORT="$2"; shift 2 ;;
    --dsl-dir)    DSL_DIR="$2"; shift 2 ;;
    --no-semantic-lint) ENFORCE_SEMANTIC_LINT=0; shift ;;
    --rule4-hard) RULE4_HARD=1; shift ;;
    -h|--help)    sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[ -z "$WIRER" ] && { echo "--wirer required" >&2; exit 2; }
[ -z "$QUEUE" ] && { echo "--queue required" >&2; exit 2; }
[ -z "$LABEL" ] && { echo "--label required" >&2; exit 2; }

CUTOFF=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PROMOTE_QUEUE="/tmp/${LABEL}_promote_queue.json"
RETRY_QUEUE="/tmp/${LABEL}_retry_queue.jsonl"
WIRE_SUMMARY="/tmp/${LABEL}_wire_summary.json"
DIVERSITY_REPORT="/tmp/${LABEL}_diversity_report.json"
SEMANTIC_LINT_REPORT="/tmp/${LABEL}_semantic_lint_report.json"
SEMANTIC_LINT_LIST="/tmp/${LABEL}_semantic_lint_yamls.txt"
PROMOTE_SUMMARY="/tmp/${LABEL}_promote_summary.json"
BLOCKED_MARKER="/tmp/${LABEL}_diversity_BLOCKED.json"
SEMLINT_BLOCKED="/tmp/${LABEL}_semantic_lint_BLOCKED.json"

echo "[chain] cutoff=$CUTOFF wirer=$WIRER label=$LABEL"

# Step 1: run the wirer (different wirers have slightly different flags;
# fall through to a generic invocation that works for false-positive-batch-wirer)
echo "[chain] step 1: run wirer..."
WIRER_BASENAME="$(basename "$WIRER")"
case "$WIRER_BASENAME" in
  false-positive-batch-wirer.py)
    python3 "$WIRER" \
      --queue "$QUEUE" \
      --promote-queue-out "$PROMOTE_QUEUE" \
      --retry-queue-out  "$RETRY_QUEUE" \
      --summary-out      "$WIRE_SUMMARY"
    ;;
  phase-b-prime-wirer.py)
    python3 "$WIRER" \
      --inputs-dir "$QUEUE" \
      --summary-out "$WIRE_SUMMARY" \
      --promote-queue-out "$PROMOTE_QUEUE"
    ;;
  architectural-mismatch-wirer.py)
    # arch-mismatch wirer needs --outputs-dir parallel to --queue; assume
    # caller passes --queue=<queue.jsonl> and infer outputs-dir from queue
    # name (drop _queue.jsonl, append _outputs/)
    OUTPUTS_DIR=$(echo "$QUEUE" | sed 's|_queue\.jsonl$|_outputs|')
    if [ ! -d "$OUTPUTS_DIR" ]; then
      echo "[chain] inferred outputs dir does not exist: $OUTPUTS_DIR" >&2
      exit 2
    fi
    python3 "$WIRER" \
      --queue "$QUEUE" \
      --outputs-dir "$OUTPUTS_DIR" \
      --summary-out "$WIRE_SUMMARY"
    # arch-mismatch wirer writes its promote queue inside the summary;
    # extract it (or it shipped to a known path; check the wirer's source)
    if [ ! -f "$PROMOTE_QUEUE" ]; then
      # arch-mismatch wirer may have written promote-queue to default path;
      # fall back: try to extract from summary
      python3 -c "import json; s=json.load(open('$WIRE_SUMMARY')); open('$PROMOTE_QUEUE','w').write(json.dumps(s.get('promote_payload',[]), indent=2))"
    fi
    ;;
  no-yaml-synthesis-wirer.py)
    python3 "$WIRER" \
      --inputs-dir "$QUEUE" \
      --summary-out "$WIRE_SUMMARY" \
      --update-registry
    # no-yaml-synthesis-wirer writes its promote queue separately
    if [ ! -f "$PROMOTE_QUEUE" ]; then
      python3 -c "import json; s=json.load(open('$WIRE_SUMMARY')); open('$PROMOTE_QUEUE','w').write(json.dumps([r for r in s.get('results',[]) if r.get('status')=='pass'], indent=2))"
    fi
    ;;
  *)
    echo "[chain] unknown wirer: $WIRER_BASENAME — please add a case branch" >&2
    exit 2
    ;;
esac

# Step 2: diversity check on the YAMLs emitted since the cutoff
echo "[chain] step 2: diversity check (max_share=$MAX_SHARE, min_cohort=$MIN_COHORT)..."
if python3 "$REPO/tools/wirer-output-diversity-check.py" \
  --emitted-yaml-dir "$DSL_DIR" \
  --emitted-since "$CUTOFF" \
  --max-share "$MAX_SHARE" \
  --min-cohort "$MIN_COHORT" \
  --json-out "$DIVERSITY_REPORT"; then
  echo "[chain] step 2 PASS: diversity OK"
else
  rc=$?
  if [ "$rc" -eq 1 ]; then
    cp "$DIVERSITY_REPORT" "$BLOCKED_MARKER"
    echo "[chain] ❌ DIVERSITY VIOLATION — promote BLOCKED"
    echo "       see $BLOCKED_MARKER"
    echo "       see $DIVERSITY_REPORT"
    exit 1
  else
    echo "[chain] diversity check error rc=$rc"
    exit 2
  fi
fi

# Step 2b (Layer C of harness hardening v1): per-yaml semantic lint on
# the emitted YAMLs. Catches per-row failure modes (single-textual-no-
# semantic, scope-only) the diversity check misses.
if [ "$ENFORCE_SEMANTIC_LINT" -eq 1 ]; then
  echo "[chain] step 2b: predicate-semantic-lint (Layer C)..."
  python3 - <<PYEOF >"$SEMANTIC_LINT_LIST"
import datetime
from pathlib import Path
cutoff = datetime.datetime.strptime("$CUTOFF", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
for p in Path("$DSL_DIR").glob("*.yaml"):
    mtime = datetime.datetime.fromtimestamp(p.stat().st_mtime, tz=datetime.timezone.utc)
    if mtime >= cutoff:
        print(p)
PYEOF
  emitted_count=$(wc -l < "$SEMANTIC_LINT_LIST" | tr -d ' ')
  if [ "$emitted_count" -eq 0 ]; then
    echo "[chain] step 2b: no emitted YAMLs to lint; skipping"
  else
    LINT_ARGS=("--yaml-list" "$SEMANTIC_LINT_LIST" "--json-out" "$SEMANTIC_LINT_REPORT" "--quiet")
    if [ "$RULE4_HARD" -eq 1 ]; then
      LINT_ARGS+=("--rule4-hard")
    fi
    if python3 "$REPO/tools/predicate-semantic-lint.py" "${LINT_ARGS[@]}"; then
      echo "[chain] step 2b PASS: all emitted YAMLs are semantically anchored"
    else
      rc=$?
      if [ "$rc" -eq 1 ]; then
        cp "$SEMANTIC_LINT_REPORT" "$SEMLINT_BLOCKED"
        python3 - <<PYEOF
import json
data = json.load(open("$SEMANTIC_LINT_REPORT"))
fails = [r for r in data["reports"] if not r.get("passes", True)]
print(f"[chain] semantic-lint failures: {len(fails)} / {data['totals']['checked']} yamls")
for r in fails[:10]:
    print(f"  - {r['yaml']}")
    for v in r.get("violations", []):
        print(f"      rule {v['rule']} ({v['name']}): {v['message'][:160]}")
if len(fails) > 10:
    print(f"  ...({len(fails)-10} more in $SEMANTIC_LINT_REPORT)")
PYEOF
        echo "[chain] SEMANTIC LINT VIOLATION — promote BLOCKED"
        echo "       see $SEMLINT_BLOCKED"
        exit 1
      else
        echo "[chain] semantic-lint error rc=$rc"
        exit 2
      fi
    fi
  fi
fi

# Step 3: bulk-promote (with --enforce-semantic-lint as defense-in-depth)
echo "[chain] step 3: inventory-bulk-promote..."
PROMOTE_ARGS=("--promote-queue" "$PROMOTE_QUEUE" "--summary-out" "$PROMOTE_SUMMARY")
if [ "$ENFORCE_SEMANTIC_LINT" -eq 1 ]; then
  PROMOTE_ARGS+=("--enforce-semantic-lint")
  if [ "$RULE4_HARD" -eq 1 ]; then
    PROMOTE_ARGS+=("--semantic-lint-rule4-hard")
  fi
fi
python3 "$REPO/tools/inventory-bulk-promote.py" "${PROMOTE_ARGS[@]}"

echo "[chain] full chain COMPLETE"
echo "  promote summary: $PROMOTE_SUMMARY"
exit 0
