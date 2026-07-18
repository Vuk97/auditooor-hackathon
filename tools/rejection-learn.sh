#!/usr/bin/env bash
# rejection-learn.sh — U4 learning-loop one-shot wrapper
#
# For a given workspace (or set of workspaces), this tool:
#   1. Walks the active workspace submission ledger, finds already-filed
#      findings that do NOT yet have a <ws>/findings/<id>/rationale.txt on
#      disk, and
#      writes a PLACEHOLDER rationale.txt ("TRIAGER RATIONALE PENDING — fill in
#      after outcome") so the learning loop can be primed before real triage
#      text is available. Existing rationale files are never overwritten.
#   2. Runs tools/rejection-classifier.py --retrain-incremental against the
#      enriched corpus.
#   3. Emits a delta report (accuracy N → M, top-10 new vocab terms).
#
# The intended operational flow is: after triage, the operator calls
#   ./tools/post-audit-review.sh <ws> --finding <id> --outcome <x> \
#       --rationale "<exact triager text>"
# and then runs this script to refresh the classifier.
#
# Usage:
#   ./tools/rejection-learn.sh <workspace> [<workspace> ...]
#   ./tools/rejection-learn.sh --workspaces /path/to/ws1,/path/to/ws2
#   ./tools/rejection-learn.sh --dry-run <workspace>   # scan + report only

set -o pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$AUDITOOOR_DIR/tools"
CLASSIFIER="$TOOLS/rejection-classifier.py"
REJ_TABLE="$AUDITOOOR_DIR/reference/rejection_causes_table.md"

DRY_RUN=0
WORKSPACES=()

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --workspaces)
            IFS=',' read -r -a _wss <<< "$2"
            for w in "${_wss[@]}"; do WORKSPACES+=("$w"); done
            shift 2
            ;;
        -h|--help)
            sed -n '2,25p' "$0" | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *) WORKSPACES+=("$1"); shift ;;
    esac
done

if [ ${#WORKSPACES[@]} -eq 0 ]; then
    echo "[error] no workspace given. usage: $0 <workspace> [<workspace> ...]" >&2
    exit 1
fi

# -------- Step 1: prime rationale.txt for submitted-but-unreviewed findings --
prime_count=0
for WS in "${WORKSPACES[@]}"; do
    if [ ! -d "$WS" ]; then
        echo "[warn] workspace not found: $WS (skipping)" >&2
        continue
    fi
    WS_ABS="$(cd "$WS" && pwd)"
    WS_NAME="$(basename "$WS_ABS")"
    SUB_FILE="$WS_ABS/submissions/SUBMISSIONS.md"
    if [ ! -f "$SUB_FILE" ] && [ -f "$WS_ABS/SUBMISSIONS.md" ]; then
        SUB_FILE="$WS_ABS/SUBMISSIONS.md"
    fi
    if [ ! -f "$SUB_FILE" ]; then
        echo "[$WS_NAME] no submission ledger — skipping prime step"
        continue
    fi

    IDS_RAW=$(python3 - "$SUB_FILE" "$TOOLS" <<'PY'
import sys
from pathlib import Path

sub_file = Path(sys.argv[1])
tools_dir = Path(sys.argv[2])
sys.path.insert(0, str(tools_dir))

from submission_ledger import load_submission_entries

entries = load_submission_entries(sub_file)
ids = []
for entry in entries:
    fid = (entry.get("id") or "").strip()
    if fid:
        ids.append(f"#{fid}")
print("\n".join(sorted(set(ids))))
PY
)

    if [ -z "$IDS_RAW" ]; then
        echo "[$WS_NAME] submitted findings detected: <none>"
        continue
    fi

    echo "[$WS_NAME] submitted findings detected: $(echo "$IDS_RAW" | tr '\n' ' ')"

    for fid in $IDS_RAW; do
        # Strip leading '#' for directory name
        dir_id="${fid#\#}"
        fdir="$WS_ABS/findings/$dir_id"
        rat="$fdir/rationale.txt"
        if [ -f "$rat" ]; then
            continue  # real or placeholder rationale already present
        fi
        if [ "$DRY_RUN" = "1" ]; then
            echo "  [dry-run] would prime $rat"
            continue
        fi
        mkdir -p "$fdir"
        cat > "$rat" <<EOF
TRIAGER RATIONALE PENDING — fill in via post-audit-review.sh --rationale after outcome.
finding-id: $fid
workspace: $WS_NAME
primed-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
        prime_count=$((prime_count + 1))
        echo "  [primed] $rat"
    done
done
echo "[primer] created ${prime_count} placeholder rationale file(s)"

if [ "$DRY_RUN" = "1" ]; then
    echo "[dry-run] skipping classifier retrain"
    exit 0
fi

# -------- Step 2: retrain ---------------------------------------------------
ws_list=""
for WS in "${WORKSPACES[@]}"; do
    ws_abs="$(cd "$WS" && pwd 2>/dev/null)" || continue
    # Pass each ws parent — the classifier auto-discovers findings/ dirs.
    if [ -n "$ws_list" ]; then ws_list="$ws_list,$ws_abs"; else ws_list="$ws_abs"; fi
done

echo ""
echo "=== rejection-classifier.py --retrain-incremental ==="
python3 "$CLASSIFIER" --retrain-incremental --workspaces "$ws_list"
rc=$?

if [ $rc -ne 0 ]; then
    echo "[error] classifier retrain exited $rc" >&2
    exit $rc
fi

# -------- Step 3: echo summary of causes table ------------------------------
if [ -f "$REJ_TABLE" ]; then
    rows=$(grep -c '^| 20' "$REJ_TABLE" 2>/dev/null || echo 0)
    echo ""
    echo "[causes-table] $REJ_TABLE — $rows outcome row(s)"
fi

echo "[done] rejection-learn.sh complete"
