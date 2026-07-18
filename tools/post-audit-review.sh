#!/usr/bin/env bash
# post-audit-review.sh — close the loop on submitted findings (Issue #80)
#
# For every already-filed finding in the active submission ledger, interactively
# (or via CLI flags) capture the outcome: paid / dupe / rejected / pending.
# Feed the data back into:
#   - detectors/_hits_ledger.yaml (via record-triage.sh) — for PAID findings
#   - reference/DUPE_CAUSES.md — for DUPE findings
#   - reference/REJECTION_CAUSES.md — for REJECTED findings
#
# Usage (interactive):
#   ./tools/post-audit-review.sh <workspace>
#
# Usage (CLI, one finding at a time):
#   ./tools/post-audit-review.sh <workspace> --finding <id> --outcome paid \
#       [--detector <name>] [--severity High] [--payout 5000]
#   ./tools/post-audit-review.sh <workspace> --finding <id> --outcome dupe \
#       --prior-audit <name> --prior-finding-id <id> --reason "<text>"
#   ./tools/post-audit-review.sh <workspace> --finding <id> --outcome rejected \
#       --reason "<text>" [--rationale "<triager text>"]
#
# The --rationale flag captures the triager's EXACT rationale text. It is
# persisted to:
#   - <workspace>/findings/<id>/rationale.txt  (verbatim; fed into the
#     learning-loop classifier by tools/rejection-classifier.py)
#   - reference/rejection_causes.md            (class-level aggregation table,
#     pipe-separated columns, 100-char excerpt)
# See U4 / Issue #88 for the learning-loop design.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$AUDITOOOR_DIR/tools"
DUPE_CAUSES="$AUDITOOOR_DIR/reference/DUPE_CAUSES.md"
REJ_CAUSES="$AUDITOOOR_DIR/reference/REJECTION_CAUSES.md"
REJ_CAUSES_TABLE="$AUDITOOOR_DIR/reference/rejection_causes_table.md"

if [ $# -lt 1 ]; then
    sed -n '2,18p' "$0" | sed 's/^# //; s/^#//'
    exit 1
fi

WS="$1"
shift

FINDING=""
OUTCOME=""
DETECTOR=""
SEVERITY=""
PAYOUT=""
PRIOR_AUDIT=""
PRIOR_FINDING=""
REASON=""
RATIONALE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --finding) FINDING="$2"; shift 2 ;;
        --outcome) OUTCOME="$2"; shift 2 ;;
        --detector) DETECTOR="$2"; shift 2 ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        --payout) PAYOUT="$2"; shift 2 ;;
        --prior-audit) PRIOR_AUDIT="$2"; shift 2 ;;
        --prior-finding-id) PRIOR_FINDING="$2"; shift 2 ;;
        --reason) REASON="$2"; shift 2 ;;
        --rationale) RATIONALE="$2"; shift 2 ;;
        *) shift ;;
    esac
done

# --- Helper: capture triager's rationale (U4 learning-loop) -------------------
# Writes the verbatim rationale to <ws>/findings/<id>/rationale.txt and appends
# a row to reference/rejection_causes.md (pipe-separated, 100-char excerpt).
capture_rationale() {
    local outcome_tag="$1"
    [ -z "$RATIONALE" ] && return 0
    local fdir="$WS/findings/$FINDING"
    mkdir -p "$fdir"
    printf '%s\n' "$RATIONALE" > "$fdir/rationale.txt"
    echo "  [rationale] wrote $fdir/rationale.txt ($(wc -c <"$fdir/rationale.txt" | tr -d ' ') bytes)"

    # Excerpt: first 100 chars, newline-stripped
    local excerpt
    excerpt=$(printf '%s' "$RATIONALE" | tr '\n|' '  ' | cut -c1-100)

    # Initialize the aggregation table on first write
    if [ ! -f "$REJ_CAUSES_TABLE" ]; then
        cat > "$REJ_CAUSES_TABLE" <<'HDR'
# rejection_causes — class-level triager rationale table (U4 learning-loop)

Appended by `tools/post-audit-review.sh --rationale` whenever a finding's
outcome is recorded. The verbatim rationale text lives at
`<workspace>/findings/<id>/rationale.txt`; this file holds one row per
outcome for fast grep/aggregation. Fed into
`tools/rejection-classifier.py --retrain-incremental`.

| date | finding-id | workspace | detector | severity-claimed | outcome | rationale-excerpt-100chars |
|------|------------|-----------|----------|------------------|---------|-----------------------------|
HDR
    fi
    printf '| %s | %s | %s | %s | %s | %s | %s |\n' \
        "$DATE" "$FINDING" "$WS_NAME" "${DETECTOR:-_}" "${SEVERITY:-_}" \
        "$outcome_tag" "$excerpt" >> "$REJ_CAUSES_TABLE"
    echo "  [rationale] appended row → $REJ_CAUSES_TABLE"
}

if [ ! -d "$WS" ]; then
    echo "[error] workspace not found: $WS" >&2
    exit 1
fi

# --- Interactive mode: no --finding given, summarize the active tracker ---
if [ -z "$FINDING" ]; then
    SUB_FILE="$WS/submissions/SUBMISSIONS.md"
    if [ ! -f "$SUB_FILE" ] && [ -f "$WS/SUBMISSIONS.md" ]; then
        SUB_FILE="$WS/SUBMISSIONS.md"
    fi
    if [ ! -f "$SUB_FILE" ]; then
        echo "[error] no SUBMISSIONS.md found under $WS or $WS/submissions/" >&2
        exit 1
    fi
    echo "Interactive post-audit review for $(basename "$WS")"
    echo "  Active tracker: $SUB_FILE"
    python3 - "$SUB_FILE" "$TOOLS" <<'PY'
import sys
from pathlib import Path

sub_file = Path(sys.argv[1])
tools_dir = Path(sys.argv[2])
sys.path.insert(0, str(tools_dir))

from submission_ledger import load_submission_entries

entries = load_submission_entries(sub_file)
if not entries:
    print("  Filed findings: <none parsed>")
else:
    print("  Filed findings:")
    for entry in entries[:20]:
        fid = entry.get("id") or "?"
        sev = entry.get("severity", "") or "?"
        status = entry.get("status", "") or "?"
        title = entry.get("title", "").strip() or "<untitled>"
        print(f"    #{fid:<6} {sev:<8} {status:<18} {title}")
    if len(entries) > 20:
        print(f"    ... ({len(entries) - 20} more)")
PY
    echo ""
    echo "  Contradiction summary:"
python3 - "$WS" "$TOOLS" <<'PY'
import json
import re
import sys
from pathlib import Path

ws = Path(sys.argv[1])

def is_pro_bug(text: str) -> bool:
    return bool(re.search(
        r"\b(Critical|High|Medium|Impact|Likelihood|PoC|exploit|revert|reverts|brick|bricks|permanent|drain|loss|vulnerable|novel)\b",
        text,
        flags=re.IGNORECASE,
    ))

def extract_title_from_draft(path: Path) -> str:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except Exception:
        pass
    return path.stem

def surface_key(title: str, fallback: str) -> str:
    camel = re.findall(r"\b(?:[A-Z][a-z0-9]+){2,}\b", title)
    if camel:
        return max(camel, key=len)
    words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", title) if len(w) >= 4]
    if words:
        return max(words, key=len)
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", fallback) if len(p) >= 4]
    return max(parts, key=len) if parts else fallback

def negative_hit(text: str) -> bool:
    return bool(re.search(
        r"\b(no bug|not a bug|not exploitable|false positive|deployment-only|deployment only|cleared|clear|no new bug|no vulnerability|not a vuln|investigated)\b",
        text,
        flags=re.IGNORECASE,
    ))

staging = ws / "submissions" / "staging"
if not staging.exists():
    staging = None

drafts = []
for path in sorted((staging.glob("*.md") if staging is not None else [])):
    if path.name.endswith(".block.md"):
        continue
    if re.match(r"R\d+-[A-Z]", path.stem):
        continue
    try:
        text = path.read_text()
    except Exception:
        continue
    if not is_pro_bug(text):
        continue
    drafts.append((path, extract_title_from_draft(path), text))

targets = [ws / "STATUS.md", ws / "FINAL_REPORT.md"]
notes_dir = ws / "notes"
if notes_dir.exists():
    targets.extend(sorted(notes_dir.glob("*verdict*.md")))

hits = []
for path, title, draft_text in drafts:
    key = surface_key(title or "", path.stem)
    for target in targets:
        if not target.exists():
            continue
        try:
            lines = target.read_text().splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, 1):
            if key.lower() not in line.lower():
                continue
            if not negative_hit(line):
                continue
            hits.append((path, key, target, lineno, line.strip()))
            break

if hits:
    print(f"    Potential staging-vs-final contradictions: {len(hits)}")
    for draft, key, target, lineno, line in hits[:10]:
        print(f"      - {key} ({draft.relative_to(ws)}) vs {target.relative_to(ws)}:{lineno}")
        print(f"        {line}")
    if len(hits) > 10:
        print(f"      ... ({len(hits) - 10} more)")
else:
    print("    No obvious staging-vs-final contradictions detected")

live_dossier = ws / "live_topology_checks.json"
if live_dossier.exists():
    try:
        payload = json.loads(live_dossier.read_text())
    except Exception:
        print("    Live-proof contradictions: dossier malformed")
    else:
        contradictions = payload.get("proof_contradictions", [])
        if not isinstance(contradictions, list):
            contradictions = []
        if contradictions:
            print(f"    Live-proof contradictions: {len(contradictions)}")
            for item in contradictions[:10]:
                if not isinstance(item, dict):
                    continue
                claim = item.get("claim_key", {}) if isinstance(item.get("claim_key"), dict) else {}
                contract = str(claim.get("contract") or "?")
                check_kind = str(claim.get("check_kind") or "?")
                block = str(item.get("block") or "?")
                row_ids = [
                    str(row_id).strip()
                    for row_id in item.get("row_ids", [])
                    if str(row_id).strip()
                ]
                print(f"      - {contract}.{check_kind} @ block {block}")
                if row_ids:
                    print(f"        rows: {', '.join(row_ids[:6])}")
            if len(contradictions) > 10:
                print(f"      ... ({len(contradictions) - 10} more)")
        else:
            print("    No live-proof contradictions detected")
else:
    print("    No live-proof dossier found")
PY
    echo ""
    echo "Non-interactive usage: $0 <ws> --finding <id> --outcome <paid|dupe|rejected>"
    exit 0
fi

# Validate outcome
case "$OUTCOME" in
    paid|dupe|rejected|pending) ;;
    *) echo "[error] --outcome must be paid/dupe/rejected/pending (got: $OUTCOME)" >&2; exit 1 ;;
esac

WS_NAME=$(basename "$WS")
DATE=$(date -u +%Y-%m-%d)

case "$OUTCOME" in
    paid)
        echo "[paid] $WS_NAME/$FINDING (${SEVERITY:-unknown}, ${PAYOUT:+\$$PAYOUT})"
        if [ -n "$DETECTOR" ]; then
            bash "$TOOLS/record-triage.sh" "$DETECTOR" "$WS_NAME" "$FINDING" TP "$SEVERITY"
        else
            echo "  [warn] no --detector given; skipping ledger promotion"
            echo "  (If a specific detector flagged this finding, log it with:"
            echo "    bash $TOOLS/record-triage.sh <detector> $WS_NAME $FINDING TP $SEVERITY)"
        fi
        # Trigger auto-audit so the detector can promote to Tier-S
        bash "$TOOLS/detector-tier.sh" audit | head -6
        capture_rationale paid
        ;;

    dupe)
        if [ -z "$PRIOR_AUDIT" ] || [ -z "$PRIOR_FINDING" ]; then
            echo "[error] --prior-audit and --prior-finding-id required for dupe outcome" >&2
            exit 1
        fi
        echo "[dupe] $WS_NAME/$FINDING dupe'd with $PRIOR_AUDIT/$PRIOR_FINDING"
        # Append to DUPE_CAUSES.md
        cat >> "$DUPE_CAUSES" <<EOF

### $WS_NAME/$FINDING — DUPE (logged $DATE)
- **Contract:** <grep FINDINGS.md for contract>
- **Function:** <grep FINDINGS.md for function>
- **Outcome class:** <classify>
- **Prior finding that dedup'd:** $PRIOR_AUDIT / $PRIOR_FINDING
- **Triager rationale:** $REASON
- **Reframing that would have survived:** <add after triage conversation>
- **Rule learned:** <derive rule — append to "Meta-rules" section above>
EOF
        echo "  [ok] appended to $DUPE_CAUSES"
        # Log as FP in ledger if detector specified
        if [ -n "$DETECTOR" ]; then
            bash "$TOOLS/record-triage.sh" "$DETECTOR" "$WS_NAME" "$FINDING" FP
        fi
        capture_rationale dupe
        ;;

    rejected)
        echo "[rejected] $WS_NAME/$FINDING — $REASON"
        cat >> "$REJ_CAUSES" <<EOF

### $WS_NAME/$FINDING — REJECTED (logged $DATE)
- **Contract:** <grep FINDINGS.md>
- **Function:** <grep FINDINGS.md>
- **Claimed severity:** $SEVERITY
- **Rejection reason:** $REASON
- **Triager rationale:** <quote>
- **Lesson:** <derive rule>
EOF
        echo "  [ok] appended to $REJ_CAUSES"
        if [ -n "$DETECTOR" ]; then
            bash "$TOOLS/record-triage.sh" "$DETECTOR" "$WS_NAME" "$FINDING" FP
        fi
        capture_rationale rejected
        ;;

    pending)
        echo "[pending] $WS_NAME/$FINDING — no action (awaiting triage)"
        if [ -n "$DETECTOR" ]; then
            bash "$TOOLS/record-triage.sh" "$DETECTOR" "$WS_NAME" "$FINDING" UNKNOWN
        fi
        capture_rationale pending
        ;;
esac
