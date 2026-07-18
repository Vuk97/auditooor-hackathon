#!/usr/bin/env bash
# ledger-sync.sh — sync rationale.txt outcomes into detector history and legacy root-level trackers.
#
# SKILL_ISSUES #164 follow-up (R59): record-triage.sh is the native append
# path, but it requires manual invocation. Ops drift: submissions get filed
# via auto-draft.sh → time-engagement.sh, rationale.txt gets updated after
# triage outcome, but nobody remembers to also run record-triage.sh. Result:
# the ledger drifts behind reality.
#
# This tool closes the gap. It walks every <workspace>/findings/*/rationale.txt,
# parses the canonical `outcome:` and `detector:` fields, and calls
# record-triage.sh for any (detector, workspace, finding) row not yet in the
# ledger _history arrays. It always stamps workspace reconciliation state in
# .auditooor-state.yaml and can also refresh legacy root-level SUBMISSIONS.md
# trackers, but it intentionally does not mutate nested submissions/SUBMISSIONS.md
# ledgers used by the canonical close-out flow.
#
# Usage:
#   ./tools/ledger-sync.sh [--audits-dir PATH] [--dry-run]
#
# Default audits-dir: ~/audits/ (or $AUDITS_DIR when exported)
#
# Rationale.txt format (per finding):
#   finding-id: #<ID>
#   workspace: <name>
#   outcome: paid | rejected | dupe | pending | PENDING
#   detector: <slug>
#   severity-claimed: Critical | High | Medium | Low | Info
#
# Verdict mapping:
#   outcome=paid     → TP  (record-triage TP <severity>)
#   outcome=rejected → FP
#   outcome=dupe     → UNKNOWN (dupe of another finding, not a detector-precision signal)
#   outcome=pending  → UNKNOWN
#   outcome=PENDING  → UNKNOWN (or skip — record-triage.sh handles idempotently)
#
# Exit codes:
#   0 — sync OK
#   1 — usage error
#   2 — no rationale files found

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDITOOOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_AUDITS_DIR="${AUDITS_DIR:-$HOME/audits}"
AUDITS_DIR="$DEFAULT_AUDITS_DIR"
DRY_RUN=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --audits-dir) AUDITS_DIR="$2"; shift 2 ;;
        --audits-dir=*) AUDITS_DIR="${1#--audits-dir=}"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help)
            cat >&2 <<EOF
ledger-sync.sh — sync rationale.txt → _hits_ledger.yaml (+ legacy root tracker status)

Usage:
  ./tools/ledger-sync.sh [--audits-dir PATH] [--dry-run]

Walks every <audits-dir>/<workspace>/findings/*/rationale.txt, parses the
canonical outcome/detector/severity fields, and invokes record-triage.sh
for any row not yet in the ledger. It always updates reconciliation fields in
.auditooor-state.yaml, also refreshes root-level SUBMISSIONS.md status/outcome
blocks when that legacy tracker exists, and leaves nested
submissions/SUBMISSIONS.md markdown ledgers untouched. Idempotent: safe to re-run.

Flags:
  --audits-dir PATH  default ~/audits/ (or \$AUDITS_DIR when exported)
  --dry-run          print intended record-triage.sh calls without invoking
EOF
            exit 0
            ;;
        *) echo "[err] unknown arg: $1" >&2; exit 1 ;;
    esac
done

[ -d "$AUDITS_DIR" ] || { echo "[err] audits-dir not found: $AUDITS_DIR" >&2; exit 1; }
RECORD_TRIAGE="$AUDITOOOR_DIR/tools/record-triage.sh"
[ -x "$RECORD_TRIAGE" ] || { echo "[err] record-triage.sh not executable at $RECORD_TRIAGE" >&2; exit 1; }

# ----- discover rationale.txt files -----
RATIONALES=()
while IFS= read -r f; do
    [ -z "$f" ] && continue
    RATIONALES+=("$f")
done < <(find "$AUDITS_DIR" -maxdepth 4 -path "*/findings/*/rationale.txt" 2>/dev/null | sort)

if [ "${#RATIONALES[@]}" -eq 0 ]; then
    echo "[info] no rationale.txt files under $AUDITS_DIR/*/findings/"
    exit 2
fi

echo "[info] found ${#RATIONALES[@]} rationale.txt files"
echo

# ----- extract field helper -----
# usage: get_field <file> <field_name>
get_field() {
    grep -m1 -E "^${2}:[[:space:]]*" "$1" 2>/dev/null | sed -E "s/^${2}:[[:space:]]*//" | tr -d '\n' | tr -d '\r'
}

# ----- outcome → verdict mapping -----
map_verdict() {
    local outcome="$1"
    case "$(echo "$outcome" | tr '[:upper:]' '[:lower:]')" in
        paid)                   echo "TP" ;;
        rejected)               echo "FP" ;;
        dupe|duplicate)         echo "UNKNOWN" ;;
        pending|submitted|draft) echo "UNKNOWN" ;;
        "")                     echo "" ;;
        *)                      echo "UNKNOWN" ;;
    esac
}

# ----- walk -----
SYNCED=0
SKIPPED=0

for f in "${RATIONALES[@]}"; do
    # Parse
    finding_id=$(get_field "$f" "finding-id")
    workspace=$(get_field "$f" "workspace")
    outcome=$(get_field "$f" "outcome")
    detector=$(get_field "$f" "detector")
    severity=$(get_field "$f" "severity-claimed")

    # Strip # prefix from finding-id
    finding_id="${finding_id#\#}"

    # Skip if missing detector (e.g. "PENDING" placeholder files)
    if [ -z "$detector" ] || [ -z "$finding_id" ] || [ -z "$workspace" ]; then
        echo "[skip] $f — missing detector/workspace/finding-id ($(basename "$(dirname "$f")"))"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    verdict=$(map_verdict "$outcome")
    if [ -z "$verdict" ]; then
        echo "[skip] $f — no outcome field (not yet triaged)"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    # severity defaults to Low if not present (record-triage accepts this)
    [ -z "$severity" ] && severity="Low"

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[dry-run] record-triage.sh $detector $workspace $finding_id $verdict $severity"
        SYNCED=$((SYNCED + 1))
        continue
    fi

    # Invoke record-triage.sh
    # record-triage.sh is idempotent: repeating (detector, workspace, finding) overwrites
    # — that's the designed correction path, so safe to call on every sync.
    bash "$RECORD_TRIAGE" "$detector" "$workspace" "$finding_id" "$verdict" "$severity" \
        >/dev/null 2>&1 && {
            echo "[synced] $workspace/$finding_id → $detector = $verdict ($severity)"
            SYNCED=$((SYNCED + 1))
        } || {
            echo "[err] record-triage.sh failed for $workspace/$finding_id"
            SKIPPED=$((SKIPPED + 1))
        }
done

echo
echo "========== SUMMARY =========="
echo "Rationale files walked: ${#RATIONALES[@]}"
echo "Synced to ledger      : $SYNCED"
echo "Skipped               : $SKIPPED"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "(dry-run mode — nothing actually written)"
fi
echo "============================="

# R64 enforcement: stamp every workspace's .auditooor-state.yaml with the sync
# timestamp so loop-gate.sh can tell when the ledger was last reconciled.
if [ "$DRY_RUN" -eq 0 ]; then
    NOW_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    for ws_dir in "$AUDITS_DIR"/*/; do
        state_file="${ws_dir%/}/.auditooor-state.yaml"
        if [ -f "$state_file" ]; then
            python3 - "$state_file" "$NOW_UTC" <<'PY'
import sys, yaml
f, now = sys.argv[1:]
d = yaml.safe_load(open(f)) or {}
d['last_ledger_sync'] = now
# Mark any open_submissions whose rationale.txt now has a non-pending outcome
# as outcome_logged=True (useful for loop-gate's staleness check).
for o in d.get('open_submissions', []) or []:
    cid = o.get('cantina_id')
    import pathlib
    rat = pathlib.Path(f).parent / 'findings' / str(cid) / 'rationale.txt'
    if rat.exists():
        txt = rat.read_text()
        for line in txt.splitlines():
            if line.startswith('outcome:'):
                val = line.split(':', 1)[1].strip()
                if val not in ('submitted', 'missing', 'pending', 'PENDING'):
                    o['outcome_logged'] = True
                    o['rationale_updated'] = True
                    o['outcome'] = val
                break
open(f, 'w').write(yaml.dump(d, sort_keys=False))
PY
        fi

        # R65c: propagate outcomes into legacy root-level SUBMISSIONS.md Status /
        # Outcome lines. Nested submissions/SUBMISSIONS.md ledgers are handled
        # by engage.py/submissions-tracker.py and remain manual/curated here.
        nested_submissions_md="${ws_dir%/}/submissions/SUBMISSIONS.md"
        submissions_md="${ws_dir%/}/SUBMISSIONS.md"
        if [ -f "$nested_submissions_md" ]; then
            echo "[ledger-sync] $(basename "${ws_dir%/}") uses nested submissions/SUBMISSIONS.md — leaving it untouched"
        elif [ -f "$submissions_md" ]; then
            python3 - "$submissions_md" "${ws_dir%/}" <<'PY'
import sys, re, pathlib
md, ws = sys.argv[1:]
md_p = pathlib.Path(md)
text = md_p.read_text()

# Map each rationale.txt outcome -> (status, outcome-label).
outcome_map = {}
for rat in pathlib.Path(ws).glob('findings/*/rationale.txt'):
    cid = rat.parent.name
    out = None
    for line in rat.read_text().splitlines():
        if line.startswith('outcome:'):
            out = line.split(':', 1)[1].strip().lower()
            break
    if not out:
        continue
    if out == 'paid':
        outcome_map[cid] = ('TRIAGED_PAID', 'PAID')
    elif out == 'rejected':
        outcome_map[cid] = ('TRIAGED_REJECTED', 'REJECTED')
    elif out in ('dupe', 'duplicate'):
        outcome_map[cid] = ('TRIAGED_DUPE', 'DUPE')
    elif out in ('submitted', 'pending'):
        outcome_map[cid] = ('SUBMITTED', 'PENDING')

changed = False
for cid, (status, outcome) in outcome_map.items():
    marker_start = f'<!-- CANTINA-ID:{cid} -->'
    marker_end   = f'<!-- /CANTINA-ID:{cid} -->'
    blk_re = re.compile(re.escape(marker_start) + r'(.*?)' + re.escape(marker_end), re.S)
    m = blk_re.search(text)
    if not m:
        continue
    block = m.group(0)
    new_block = re.sub(r'(- \*\*Status\*\*\s*\n\s+)[A-Z_]+', rf'\g<1>{status}', block)
    new_block = re.sub(r'(- \*\*Outcome\*\*\s*\n\s+)[A-Z_]+', rf'\g<1>{outcome}', new_block)
    if new_block != block:
        text = text[:m.start()] + new_block + text[m.end():]
        changed = True

if changed:
    md_p.write_text(text)
    print(f"[ledger-sync] SUBMISSIONS.md updated for {pathlib.Path(ws).name}")
PY
        fi
    done
    echo "[ledger-sync] stamped .auditooor-state.yaml in every workspace with last_ledger_sync=$NOW_UTC"
fi
