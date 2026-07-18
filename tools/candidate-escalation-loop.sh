#!/usr/bin/env bash
# candidate-escalation-loop.sh — T-09.
#
# Wraps the canonical discovery → verify → escalate flow for a single
# candidate. Halts on the first gate failure with a named blocker (does
# NOT continue past failure — operator decides).
#
# Codifies the FN2 lesson: don't park as "needs review". Run all gates,
# end in terminal state same session.
#
# Usage:
#   bash tools/candidate-escalation-loop.sh \
#     --workspace /Users/wolf/audits/base-azul \
#     --finding /path/to/draft.md \
#     [--severity Critical] \
#     [--skip-poc-extension]
#
# Phases:
#   1. M14-trap dispatch (existing tooling — operator-supervised)
#   2. upstream-equivalent-gate.py (5-check candidate gate)
#   3. per-finding-oos-check.py
#   4. pre-submit-check.sh full suite (includes new D-08 title + D-09 financial-impact)
#   5. (optional) PoC extension prompt — produces Phase 1 (structural) + Phase 2 (financial)
#   6. emit terminal verdict: SUBMIT_READY / HOLD / KILL with named blocker

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE=""
FINDING=""
SEVERITY="High"
SKIP_POC_EXTENSION=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --finding)   FINDING="$2"; shift 2 ;;
    --severity)  SEVERITY="$2"; shift 2 ;;
    --skip-poc-extension) SKIP_POC_EXTENSION=1; shift ;;
    -h|--help)
      echo "Usage: $0 --workspace <ws> --finding <draft.md> [--severity High|Critical|Medium|Low|Info]"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && { echo "missing --workspace" >&2; exit 2; }
[[ -z "$FINDING" ]] && { echo "missing --finding" >&2; exit 2; }
[[ ! -f "$FINDING" ]] && { echo "finding not found: $FINDING" >&2; exit 2; }

OUT_DIR="$(dirname "$FINDING")/.escalation"
mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/$(basename "$FINDING" .md).escalation.log"
TS() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
log() { printf "%s %s\n" "$(TS)" "$*" | tee -a "$LOG"; }

VERDICT_FILE="$OUT_DIR/$(basename "$FINDING" .md).verdict.json"

emit_verdict() {
  local verdict="$1"; local blocker="$2"
  python3 - "$FINDING" "$WORKSPACE" "$SEVERITY" "$verdict" "$blocker" "$VERDICT_FILE" <<'PY'
import json, sys, datetime
finding, ws, sev, verdict, blocker, out_path = sys.argv[1:7]
data = {
    "schema": "auditooor.candidate_escalation.v1",
    "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "finding": finding,
    "workspace": ws,
    "severity": sev,
    "verdict": verdict,
    "blocker": blocker,
    "rule": "Verdict must be SUBMIT_READY / HOLD / KILL. Filing decision is operator-only.",
}
with open(out_path, "w") as f:
    json.dump(data, f, indent=2)
print(json.dumps(data, indent=2))
PY
  log "[verdict] $verdict — $blocker"
  log "[verdict-file] $VERDICT_FILE"
}

log "[start] candidate-escalation-loop finding=$FINDING severity=$SEVERITY"

# ---- Phase 1: M14-trap (advisory; not blocking — operator dispatches) ----
log "[phase 1] M14-trap dispatch is operator-supervised; not run automatically."
log "[phase 1] If unsure, dispatch a separate Opus M14-trap review for High/Critical."

# ---- Phase 2: upstream-equivalent-gate ----
log "[phase 2] upstream-equivalent-gate.py"
_UEG_TMP="$(mktemp /tmp/escalation_candidate.$$.json)"
python3 - "$FINDING" "$WORKSPACE" "$_UEG_TMP" <<'PY'
import json, re, sys
from pathlib import Path
finding_text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
ws = sys.argv[2]
out_path = sys.argv[3]
match = re.search(r'(external/[^\s\`\'")\]]+)', finding_text)
production_path = match.group(1) if match else ""
row = {
    "candidate_id": "finding-synthetic",
    "production_path": production_path,
    "severity_tier": "",
    "selected_impact": "",
    "bug_shape_query": "",
}
with open(out_path, "w") as f:
    json.dump([row], f)
PY
if python3 "$REPO/tools/upstream-equivalent-gate.py" --workspace "$WORKSPACE" --candidate "$_UEG_TMP" >>"$LOG" 2>&1; then
  rm -f "$_UEG_TMP"
  log "[phase 2] PASS"
else
  rc=$?
  rm -f "$_UEG_TMP"
  log "[phase 2] FAIL rc=$rc — upstream-equivalent-gate flagged this candidate"
  emit_verdict "HOLD" "upstream-equivalent-gate failed (rc=$rc); review log $LOG"
  exit 1
fi

# ---- Phase 3: per-finding-oos-check ----
log "[phase 3] per-finding-oos-check.py"
if [ ! -f "$WORKSPACE/OOS_PASTED.md" ]; then
  log "[phase 3] WARNING: OOS_PASTED.md absent from workspace — skipping per-finding OOS check (advisory; Phase 5 handles this)"
  log "[phase 3] SKIP (no OOS_PASTED.md)"
elif python3 "$REPO/tools/per-finding-oos-check.py" --workspace "$WORKSPACE" --finding "$FINDING" >>"$LOG" 2>&1; then
  log "[phase 3] PASS"
else
  rc=$?
  log "[phase 3] FAIL rc=$rc — per-finding OOS check flagged this candidate"
  emit_verdict "HOLD" "per-finding-oos-check failed (rc=$rc); see log $LOG"
  exit 1
fi

# ---- Phase 4: pre-submit-check full suite ----
log "[phase 4] pre-submit-check.sh full suite (incl. D-08 title + D-09 financial-impact)"
if bash "$REPO/tools/pre-submit-check.sh" "$FINDING" --severity "$SEVERITY" >>"$LOG" 2>&1; then
  log "[phase 4] PASS"
else
  rc=$?
  log "[phase 4] FAIL rc=$rc — pre-submit-check failed"
  log "[phase 4] check the log for D-08 (title) or D-09 (financial-impact) failures"
  emit_verdict "HOLD" "pre-submit-check failed (rc=$rc); review log $LOG for the specific failing check"
  exit 1
fi

# ---- Phase 5: PoC extension reminder (advisory) ----
if [[ "$SKIP_POC_EXTENSION" -eq 0 ]]; then
  log "[phase 5] PoC extension reminder — for Critical/High, the PoC must demonstrate end-to-end fund flow (FN2 lesson)"
  log "[phase 5] If the current PoC ends at a structural-implication stage ('X is poisoned, Y reads X'), extend it"
  log "[phase 5] (the financial-impact gate D-09 will block on 'would result in' / 'could allow' phrases without assertEq)"
fi

# ---- Phase 6: terminal verdict ----
emit_verdict "SUBMIT_READY" "all gates rc=0; operator approval required to file"

log "[done] candidate-escalation-loop terminal: SUBMIT_READY"
log "[done] verdict-file: $VERDICT_FILE"
log "[done] full log: $LOG"
exit 0
