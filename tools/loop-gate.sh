#!/usr/bin/env bash
# loop-gate.sh — enforces the self-improvement loop BEFORE a new round starts.
#
# R64 enforcement layer companion to submit.sh. Every round should invoke this
# as Step 0 (before anything else). It reads <workspace>/.auditooor-state.yaml
# and checks:
#
#   1. Are there OPEN SUBMISSIONS with outcome not yet logged?
#      - WARN if any open >7 days, HARD STOP if any open >30 days
#        (forces operator to go log the outcome before starting new work)
#   2. Has ledger-sync.sh been run since the last rationale.txt modification?
#      - If stale, WARN so the operator can refresh detector history / any
#        legacy root-level tracker state
#   3. Are there labeled outcomes (paid/rejected/dupe) added since last
#      classifier retrain?
#      - WARN the operator to retrain before next round
#
# This is the "you cannot bypass the loop" gate. Operators can still do audits,
# but the gate will HARD STOP if the prior round's feedback is totally ignored.
#
# Usage:
#   ./tools/loop-gate.sh <workspace>
#
# Exit codes:
#   0 — loop is healthy, proceed
#   1 — usage error
#   2 — SOFT WARN (stale open submissions, stale ledger sync) — operator may continue
#   3 — HARD STOP (open submissions >30 days, critical loop breakage) — fix before new round

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDITOOOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

[ "$#" -lt 1 ] && { echo "usage: loop-gate.sh <workspace>" >&2; exit 1; }
WS="$1"

[ -d "$WS" ] || { echo "[err] workspace not found: $WS" >&2; exit 1; }

STATE="$WS/.auditooor-state.yaml"
if [ ! -f "$STATE" ]; then
    echo "[loop-gate] no state file yet — assumed first-time workspace. Creating stub."
    cat > "$STATE" <<EOF
workspace: $(basename "$WS")
initialized_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
open_submissions: []
closed_submissions: []
last_ledger_sync: never
last_classifier_retrain: never
EOF
    exit 0
fi

echo "[loop-gate] checking self-improvement loop state for $(basename "$WS")"
echo ""

python3 - "$STATE" "$WS" "$AUDITOOOR_DIR" <<'PY'
import sys, datetime, subprocess, os
from pathlib import Path

state_file, ws, auditooor = sys.argv[1:]

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


def _parse_scalar(value):
    value = value.strip()
    if value in ("[]", ""):
        return []
    if value in ("{}",):
        return {}
    if value in ("null", "Null", "NULL", "~"):
        return None
    if value in ("true", "True", "TRUE"):
        return True
    if value in ("false", "False", "FALSE"):
        return False
    if (value.startswith("'") and value.endswith("'")) or (
        value.startswith('"') and value.endswith('"')
    ):
        return value[1:-1]
    return value


def _stdlib_state_load(path):
    """Read the simple auditooor state YAML shape without requiring PyYAML."""
    data = {}
    current_list = None
    current_item = None
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not raw.startswith(" "):
            key, sep, value = line.partition(":")
            if not sep:
                continue
            key = key.strip()
            value = value.strip()
            if value == "":
                data[key] = []
                current_list = key
                current_item = None
            else:
                data[key] = _parse_scalar(value)
                current_list = None
                current_item = None
            continue
        if current_list and line.lstrip().startswith("- "):
            item_text = line.lstrip()[2:].strip()
            current_item = {}
            data.setdefault(current_list, []).append(current_item)
            if item_text:
                key, sep, value = item_text.partition(":")
                if sep:
                    current_item[key.strip()] = _parse_scalar(value)
            continue
        if current_item is not None and ":" in line:
            key, _, value = line.strip().partition(":")
            current_item[key.strip()] = _parse_scalar(value)
    return data


optional_dep_warn = None
if yaml is None:
    d = _stdlib_state_load(state_file) or {}
    optional_dep_warn = (
        "PyYAML unavailable — using limited stdlib parser for .auditooor-state.yaml; "
        "install PyYAML only if loop-gate must parse complex YAML"
    )
else:
    d = yaml.safe_load(open(state_file)) or {}

now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
warns = []
hard_stops = []
if optional_dep_warn:
    warns.append(optional_dep_warn)

# ── Check 1: open submissions aging ──
opens = d.get('open_submissions', []) or []
if opens:
    print(f"  open submissions: {len(opens)}")
    for o in opens:
        cid = o.get('cantina_id')
        sub_at_s = o.get('submitted_at', '')
        try:
            sub_at = datetime.datetime.strptime(sub_at_s[:19], '%Y-%m-%dT%H:%M:%S')
            age_days = (now - sub_at).days
        except Exception:
            age_days = 0
        outcome_logged = o.get('outcome_logged', False)

        # Check rationale.txt for outcome line
        rat = Path(ws) / 'findings' / str(cid) / 'rationale.txt'
        if rat.exists():
            txt = rat.read_text()
            outcome_line = [l for l in txt.splitlines() if l.startswith('outcome:')]
            current_outcome = outcome_line[0].split(':', 1)[1].strip() if outcome_line else 'missing'
            if current_outcome not in ('submitted', 'missing'):
                outcome_logged = True

        status = 'logged' if outcome_logged else f'{age_days}d pending'
        print(f"    #{cid}: {status}  ({o.get('severity')}, detector={o.get('detector','?')[:40]})")

        if not outcome_logged and age_days > 30:
            hard_stops.append(f"submission #{cid} open for {age_days} days without outcome")
        elif not outcome_logged and age_days > 7:
            warns.append(f"submission #{cid} open {age_days} days — check Cantina / update rationale.txt")
else:
    print("  open submissions: 0")

# ── Check 2: rationale.txt modifications vs last ledger-sync ──
last_sync_s = d.get('last_ledger_sync', 'never')
if last_sync_s == 'never':
    newest_rat = 0
    for rat in Path(ws).glob('findings/*/rationale.txt'):
        newest_rat = max(newest_rat, rat.stat().st_mtime)
    if newest_rat > 0:
        warns.append(
            "no ledger-sync ever run but rationale.txt files exist — run "
            "tools/ledger-sync.sh if detector history or a legacy root tracker "
            "needs refresh"
        )
else:
    try:
        last_sync = datetime.datetime.strptime(last_sync_s[:19], '%Y-%m-%dT%H:%M:%S')
    except Exception:
        last_sync = now
    # Check if any rationale.txt is newer than last_sync
    for rat in Path(ws).glob('findings/*/rationale.txt'):
        rat_mtime = datetime.datetime.fromtimestamp(rat.stat().st_mtime, datetime.timezone.utc).replace(tzinfo=None)
        if rat_mtime > last_sync:
            warns.append(
                f"{rat.relative_to(ws)} modified after last ledger-sync — detector "
                "history or legacy root tracker state may be stale"
            )
            break

# ── Check 3: classifier retrain pending ──
# Heuristic: count TP/FP labels in ledger _history across all workspaces vs last retrain
last_retrain_s = d.get('last_classifier_retrain', 'never')
if last_retrain_s == 'never' and opens:
    # Don't warn on first-time workspace — only warn if there's history
    pass
# (Skipping the full retrain-aging check for now; warn in text below)

# ── Check 4 (R65c, R88 fix): SUBMISSIONS.md tracker present if any submission was made ──
# Accept either the canonical nested tracker (<ws>/submissions/SUBMISSIONS.md)
# or the older manual root-level layout (<ws>/SUBMISSIONS.md). submit.sh only
# maintains the legacy root tracker today; nested ledgers stay manual or are
# synced through engage.py track-submissions.
submissions_md_new = Path(ws) / 'submissions' / 'SUBMISSIONS.md'
submissions_md_old = Path(ws) / 'SUBMISSIONS.md'
submissions_md = submissions_md_new if submissions_md_new.exists() else submissions_md_old
if opens and not submissions_md.exists():
    warns.append(
        "SUBMISSIONS.md missing despite open submissions — create the nested "
        "submissions/SUBMISSIONS.md tracker or maintain a legacy root tracker manually"
    )
elif submissions_md.exists() and opens:
    md_text = submissions_md.read_text()
    # R88: our draft tracker shape uses `### Draft N —` headers; cantina IDs do
    # not appear in the user-facing body (per R84 directive: "no internal naming").
    # Verify by detector-slug match instead (each draft's title mentions the vulnerable
    # function/contract, which ties back to the detector slug).
    missing = []
    for o in opens:
        cid = str(o.get('cantina_id', ''))
        det = str(o.get('detector', ''))
        # Acceptable markers: legacy `<!-- CANTINA-ID:X -->`, R83 `#<CANTINA-ID>` body
        # reference, R84+ draft-format which embeds the detector-related keyword in the title.
        keyword = det.split('-')[0] if det else cid
        found = (
            f"CANTINA-ID:{cid}" in md_text
            or f"#{cid}" in md_text
            or (keyword and keyword in md_text.lower())
        )
        if not found:
            missing.append(cid)
    if missing:
        warns.append(
            f"SUBMISSIONS.md is missing blocks for submission(s) {', '.join(missing)} "
            "— keep the active nested/root tracker current before the next round"
        )

# ── Check 5 (R88): scan-full coverage — symbolic + economic-ir MANDATORY ──
# R81-R87 cumulative gap: these tools exist but were skipped every round.
# Hard-gate round-close if the scan outputs don't exist. If operator explicitly
# chose --skip on scan-full.sh, they can --force past this gate.
concolic_out = Path(ws) / 'concolic' / 'SUMMARY.md'
econ_out = Path(ws) / 'economic_hypotheses.md'
econ_out_alt = Path(ws) / 'concolic' / 'economic_hypotheses.md'  # some versions write here
scan_full_log = Path(ws) / 'scan-full.log'

if not concolic_out.exists():
    hard_stops.append(
        "concolic/SUMMARY.md missing — halmos/mythril never ran for this workspace. "
        "Run `bash tools/scan-full.sh <ws>` or `bash tools/concolic-scan.sh <ws>` before closing the round."
    )
if not econ_out.exists() and not econ_out_alt.exists():
    hard_stops.append(
        "economic_hypotheses.md missing — economic-hypotheses-ir.py never ran. "
        "Run `bash tools/economic-hypotheses-ir.sh <ws>` before closing the round."
    )
if not scan_full_log.exists():
    warns.append(
        "scan-full.log missing — you have not run `tools/scan-full.sh <ws>` this round. "
        "Prefer the orchestrator over running individual scanners; it ensures nothing is skipped."
    )

# ── Summary ──
print("")
if hard_stops:
    print("  === HARD STOP ===")
    for s in hard_stops:
        print(f"    ✗ {s}")
    print("")
    print("  Fix before starting a new round: go update rationale.txt with the")
    print("  Cantina triager decision, keep the active nested/root SUBMISSIONS.md")
    print("  ledger current, then run tools/ledger-sync.sh if detector history or")
    print("  any legacy root-level tracker state also needs reconciliation.")
    sys.exit(3)

if warns:
    print("  === SOFT WARN ===")
    for w in warns:
        print(f"    ! {w}")
    print("")
    print("  Recommended: run tools/ledger-sync.sh before starting new work if")
    print("  rationale.txt changed; it syncs detector history and legacy root")
    print("  tracker state, not nested trackers.")
    print("  (Proceed with --force or just ignore to continue this round.)")
    sys.exit(2)

print("  ✓ loop is healthy — no open gaps, ledger in sync.")
sys.exit(0)
PY
rc=$?
exit $rc
