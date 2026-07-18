#!/usr/bin/env bash
# submit.sh — legacy submission wrapper for root-ledger/manual workflows.
#
# This script still handles the older "paste to platform, copy filed draft,
# write rationale.txt, sync detector history" loop. The canonical close-out
# path for current workspaces is staging drafts + tools/engage.py +
# submissions/SUBMISSIONS.md. When a nested submissions tracker already exists,
# submit.sh leaves it alone instead of trying to manage that newer flow.
#
# Usage:
#   ./tools/submit.sh [--allow-nested-manual] <workspace> <draft.md> <cantina-id>
#
# Example:
#   ./tools/submit.sh ~/audits/centrifuge-v3 \
#       drafts/R64-01-oracle-stale-freshness.md 175
#
# What this does (in order, any failure stops the chain):
#   1. Validates workspace + draft exist
#   2. Runs tools/pre-submit-check.sh — 20-check gate (forge test --pass-required,
#      scope-review-inline, originality-grep, rubric-citation, etc.)
#   3. Extracts detector name + severity from the draft frontmatter
#   4. Copies draft to <ws>/submissions/<finding-id>-<slug>.md
#   5. Creates <ws>/findings/<finding-id>/rationale.txt with outcome=submitted
#   6. Invokes tools/record-triage.sh with verdict=UNKNOWN (pending Cantina triage)
#   7. Updates <ws>/.auditooor-state.yaml with the new open submission entry
#   8. Prints a reminder: "Cantina URL: update rationale.txt when triager decides"
#
# Exit codes:
#   0 — submission logged atomically
#   1 — usage error
#   2 — pre-submit-check failed (fix the finding before running submit again)
#   3 — workspace state invalid (no SCOPE.md, etc.)

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDITOOOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat >&2 <<'EOF'
usage: submit.sh [--allow-nested-manual] <workspace> <draft.md> <cantina-id>

Legacy submission wrapper. Keeps the older post-submission bookkeeping loop
honest without claiming to own the canonical nested submissions workflow.

By default this refuses workspaces that already have
<workspace>/submissions/SUBMISSIONS.md, because that nested ledger is the
active source of truth and submit.sh will not update it. Pass
--allow-nested-manual only if you intentionally want the legacy bookkeeping
side effects and will keep the nested ledger current yourself.

Arguments:
  workspace   path to the audit workspace (e.g. ~/audits/centrifuge-v3)
  draft.md    path to the Cantina-format draft inside the workspace
  cantina-id  the Cantina submission number (e.g. 175)

Side effects:
  - <workspace>/submissions/<finding-id>-*.md is created (or stays if already there)
  - <workspace>/findings/<cantina-id>/rationale.txt is created with outcome=submitted
  - detectors/_hits_ledger.yaml gets an UNKNOWN entry for this submission
  - <workspace>/.auditooor-state.yaml records the open submission
  - <workspace>/SUBMISSIONS.md is created/updated only for legacy root-ledger
    workspaces; nested submissions/SUBMISSIONS.md trackers are left untouched

Reversibility: the workspace files are idempotent (re-running just updates);
the ledger entry is idempotent-overwrite (per record-triage.sh design). No
external side effects until operator pastes into Cantina.
EOF
    exit 1
}

ALLOW_NESTED_MANUAL=0
if [ "${1:-}" = "--allow-nested-manual" ]; then
    ALLOW_NESTED_MANUAL=1
    shift
fi

[ "$#" -lt 3 ] && usage

WS="$1"
DRAFT="$2"
CANTINA_ID="$3"
NESTED_SUBMISSIONS_MD="$WS/submissions/SUBMISSIONS.md"

[ -d "$WS" ] || { echo "[err] workspace not found: $WS" >&2; exit 3; }
[ -f "$DRAFT" ] || { echo "[err] draft not found: $DRAFT" >&2; exit 1; }
[ -f "$WS/SCOPE.md" ] || { echo "[err] $WS/SCOPE.md missing — not an audit workspace" >&2; exit 3; }
if [ -f "$NESTED_SUBMISSIONS_MD" ] && [ "$ALLOW_NESTED_MANUAL" -ne 1 ]; then
    echo "[err] nested tracker present at $NESTED_SUBMISSIONS_MD" >&2
    echo "[err] submit.sh will not update the active nested ledger." >&2
    echo "[err] use the canonical close-out flow, or re-run with --allow-nested-manual if you will keep that ledger current yourself." >&2
    exit 3
fi
if [ -f "$NESTED_SUBMISSIONS_MD" ] && [ "$ALLOW_NESTED_MANUAL" -eq 1 ]; then
    echo "[submit] WARN: --allow-nested-manual enabled; keeping $NESTED_SUBMISSIONS_MD current is still your responsibility"
fi

# ── 1. pre-submit-check — 11 gates including forge test --pass-required ──
if [ -x "$AUDITOOOR_DIR/tools/pre-submit-check.sh" ]; then
    echo "[submit] running pre-submit-check.sh …"
    if ! bash "$AUDITOOOR_DIR/tools/pre-submit-check.sh" "$DRAFT"; then
        echo "[submit] FAIL pre-submit-check — fix the finding + re-run submit" >&2
        exit 2
    fi
else
    echo "[submit] WARN: pre-submit-check.sh not found; skipping (unsafe)"
fi

# ── 2. extract detector + severity from draft ──
# Draft format: severity marked in "## Severity" section with bolded Low/Medium/High/Critical
DETECTOR=$(grep -oE '`[a-z][a-z0-9-]+`' "$DRAFT" | head -20 | grep -oE '[a-z][a-z0-9-]+' | \
           grep -vE '^(the|this|that|bug|fix|addr|src|here)$' | head -1)
[ -z "$DETECTOR" ] && DETECTOR="manual-review"

SEVERITY=$(grep -oE '→ Severity: [A-Z][a-z]+' "$DRAFT" | head -1 | awk '{print $NF}')
[ -z "$SEVERITY" ] && SEVERITY=$(grep -oE '\*\*Severity:\*\* [A-Z][a-z]+' "$DRAFT" | head -1 | awk '{print $NF}')
# R65d: canonical Severity/Likelihood/Impact section format uses a "## Severity"
# header followed by the bare word on the next non-blank line.
if [ -z "$SEVERITY" ]; then
    SEVERITY=$(awk '/^## *Severity *$/{flag=1;next} flag && NF{print;exit}' "$DRAFT" | \
               grep -oE 'Critical|High|Medium|Low|Info' | head -1)
fi
[ -z "$SEVERITY" ] && SEVERITY="Low"

# Title: support both the old "### Finding Title" placeholder and the canonical
# "## Finding Title" section (bare title on the next non-blank line).
TITLE=$(awk '/^## *Finding Title *$/{flag=1;next} flag && NF{print;exit}' "$DRAFT")
if [ -z "$TITLE" ]; then
    TITLE=$(grep -m1 '^### Finding Title' "$DRAFT" -A2 | grep -v 'Finding Title' | grep -v '^```' | head -1)
fi
# Final fallback: first H1 in the draft.
[ -z "$TITLE" ] && TITLE=$(grep -m1 '^# ' "$DRAFT" | sed 's/^# //')
SLUG=$(echo "$TITLE" | tr '[:upper:] ' '[:lower:]-' | tr -cd 'a-z0-9-' | cut -c1-60)
[ -z "$SLUG" ] && SLUG="finding-$CANTINA_ID"

FINDING_ID="#$CANTINA_ID"

echo "[submit] detector: $DETECTOR"
echo "[submit] severity: $SEVERITY"
echo "[submit] finding-id: $FINDING_ID"
echo "[submit] slug: $SLUG"

# ── 3. copy to submissions/ ──
mkdir -p "$WS/submissions"
SUB_FILE="$WS/submissions/${CANTINA_ID}-${SLUG}.md"
if [ -f "$SUB_FILE" ]; then
    echo "[submit] submissions/ file already exists: $(basename "$SUB_FILE") — not overwriting"
else
    cp "$DRAFT" "$SUB_FILE"
    echo "[submit] copied to $(basename "$SUB_FILE")"
fi

# ── 4. findings/<id>/rationale.txt — pending marker ──
mkdir -p "$WS/findings/$CANTINA_ID"
RATIONALE="$WS/findings/$CANTINA_ID/rationale.txt"
if [ -f "$RATIONALE" ] && grep -q "^outcome:" "$RATIONALE"; then
    echo "[submit] rationale already has an outcome line — leaving alone"
else
    cat > "$RATIONALE" <<RATEOF
finding-id: $FINDING_ID
workspace: $(basename "$WS")
outcome: submitted
detector: $DETECTOR
severity-claimed: $SEVERITY
submitted-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)

TRIAGER RATIONALE PENDING — replace "outcome: submitted" with one of:
  - outcome: paid
  - outcome: rejected
  - outcome: dupe
when Cantina triages. Then update the active SUBMISSIONS.md ledger for this
workspace (manually for curated/root trackers, or via engage.py track-submissions
for auditooor-managed nested trackers). Run: tools/ledger-sync.sh afterwards if
you also need detector history or a legacy root-level tracker refreshed.
RATEOF
    echo "[submit] wrote $RATIONALE"
fi

# ── 5. record-triage.sh UNKNOWN ──
if [ -x "$AUDITOOOR_DIR/tools/record-triage.sh" ]; then
    echo "[submit] running record-triage.sh $DETECTOR $(basename "$WS") $CANTINA_ID UNKNOWN $SEVERITY …"
    bash "$AUDITOOOR_DIR/tools/record-triage.sh" "$DETECTOR" "$(basename "$WS")" "$CANTINA_ID" UNKNOWN "$SEVERITY" \
        || echo "[submit] WARN: record-triage.sh failed — add entry manually"
fi

# ── 6. .auditooor-state.yaml ──
STATE="$WS/.auditooor-state.yaml"
if [ ! -f "$STATE" ]; then
    cat > "$STATE" <<STATEOF
workspace: $(basename "$WS")
auditooor_commit: $(cd "$AUDITOOOR_DIR" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
initialized_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
open_submissions: []
closed_submissions: []
last_ledger_sync: never
last_classifier_retrain: never
last_scan: never
STATEOF
fi

# Append open-submission block (idempotent append; deduplicate by cantina-id)
python3 - "$STATE" "$CANTINA_ID" "$DETECTOR" "$SEVERITY" <<'PY'
import sys, yaml, datetime
state_file, cid, det, sev = sys.argv[1:]
d = yaml.safe_load(open(state_file)) or {}
opens = d.setdefault('open_submissions', []) or []
# Dedupe
opens = [o for o in opens if str(o.get('cantina_id')) != str(cid)]
opens.append({
    'cantina_id': int(cid),
    'detector': det,
    'severity': sev,
    'submitted_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'outcome_logged': False,
    'rationale_updated': False,
})
d['open_submissions'] = opens
open(state_file, 'w').write(yaml.dump(d, sort_keys=False))
print(f"[submit] state updated: {len(opens)} open submission(s)")
PY

# ── 7. Legacy root-level SUBMISSIONS.md tracker ──
# The canonical nested submissions/SUBMISSIONS.md workflow is managed elsewhere.
# Only maintain a root-level tracker when no nested tracker exists.
SUBMISSIONS_MD="$WS/SUBMISSIONS.md"
if [ -f "$NESTED_SUBMISSIONS_MD" ]; then
    echo "[submit] nested tracker present at $NESTED_SUBMISSIONS_MD — leaving it untouched"
    echo "[submit] keep the active nested ledger current manually or via engage.py track-submissions when appropriate"
else
if [ ! -f "$SUBMISSIONS_MD" ]; then
    cat > "$SUBMISSIONS_MD" <<SMDHEAD
# $(basename "$WS") — Submissions Tracker

Workspace: \`$WS\`
Auditooor commit: $(cd "$AUDITOOOR_DIR" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
Tracker format: every submitted finding gets one block with the canonical
**Severity / Likelihood / Impact** triad at the top (Cantina submission format).

Legend for **Status**:
- \`READY_TO_SUBMIT\` — pre-submit-check green, PoC passes, draft frozen
- \`SUBMITTED\` — pasted to Cantina, ID logged, submit.sh ran
- \`TRIAGED_PAID\` · \`TRIAGED_REJECTED\` · \`TRIAGED_DUPE\` — Cantina decision logged
- \`WITHDRAWN\` — pulled before triage

---
SMDHEAD
    echo "[submit] created $SUBMISSIONS_MD"
fi

# Extract title + severity + likelihood + impact from the draft, then upsert.
python3 - "$SUBMISSIONS_MD" "$DRAFT" "$CANTINA_ID" "$DETECTOR" "$SEVERITY" "$SUB_FILE" <<'PY'
import sys, re, datetime, pathlib
md, draft, cid, det, sev, sub_file = sys.argv[1:]
text = pathlib.Path(draft).read_text()

def section(hdr):
    m = re.search(rf'^##\s+{re.escape(hdr)}\s*\n(.*?)(?=\n##\s|\Z)', text, flags=re.M|re.S)
    return m.group(1).strip() if m else ''

title = section('Finding Title') or det
severity = section('Severity') or sev or 'Unknown'
likelihood = section('Likelihood') or 'Unknown'
impact = section('Impact') or ''
# Keep Impact to one paragraph at most for the tracker.
impact_short = (impact.split('\n\n')[0] if impact else '').strip()
if len(impact_short) > 1200:
    impact_short = impact_short[:1200] + ' …'

now_utc = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
marker_start = f'<!-- CANTINA-ID:{cid} -->'
marker_end = f'<!-- /CANTINA-ID:{cid} -->'

block = f"""{marker_start}
## #{cid} — {title.splitlines()[0]}

- **Severity**
  {severity.splitlines()[0]}
- **Likelihood**
  {likelihood.splitlines()[0]}
- **Impact**
  {impact_short}
- **Detector**
  `{det}`
- **Draft**
  `{pathlib.Path(draft).relative_to(pathlib.Path(md).parent) if str(pathlib.Path(draft)).startswith(str(pathlib.Path(md).parent)) else draft}`
- **Submission copy**
  `submissions/{pathlib.Path(sub_file).name}`
- **Status**
  SUBMITTED
- **Submitted at**
  {now_utc}
- **Outcome**
  PENDING
{marker_end}
"""

current = pathlib.Path(md).read_text()
# Idempotent upsert by marker pair.
pattern = re.compile(re.escape(marker_start) + r'.*?' + re.escape(marker_end) + r'\n?', re.S)
if pattern.search(current):
    current = pattern.sub(block.rstrip() + '\n', current)
else:
    # Append before any trailing "---" footer, else at EOF.
    if current.rstrip().endswith('---'):
        current = current.rstrip()[:-3].rstrip() + '\n\n' + block + '\n---\n'
    else:
        current = current.rstrip() + '\n\n' + block

pathlib.Path(md).write_text(current)
print(f"[submit] SUBMISSIONS.md upserted block for #{cid}")
PY
fi

echo ""
echo "=============================================================="
echo "[submit] $FINDING_ID logged as open submission"
echo ""
echo "NEXT STEPS (all enforced by tools/loop-gate.sh before next round):"
echo "  1. Paste $(basename "$SUB_FILE") body into Cantina submission form"
echo "  2. When Cantina triages, edit $RATIONALE"
echo "     Replace 'outcome: submitted' with paid | rejected | dupe"
if [ -f "$NESTED_SUBMISSIONS_MD" ]; then
    echo "  3. Update the active ledger for this workspace"
    echo "     (curated/manual nested ledgers stay manual; auditooor-managed ones use engage.py track-submissions)"
    echo "  4. If rationale.txt changed, run: bash $AUDITOOOR_DIR/tools/ledger-sync.sh"
    echo "     (syncs rationale.txt → _hits_ledger.yaml; nested ledgers are still not auto-updated here)"
else
    echo "  3. Run: bash $AUDITOOOR_DIR/tools/ledger-sync.sh"
    echo "     (syncs rationale.txt → _hits_ledger.yaml and refreshes the legacy root SUBMISSIONS.md tracker)"
fi
echo "=============================================================="
exit 0
