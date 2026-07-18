#!/usr/bin/env bash
# oos-pre-answer-gate.sh — T-05.
#
# Before any agent answers a fileability/OOS question, run all 3 OOS gates
# in sequence and emit a single JSON summary. This codifies the rule from
# feedback_oos_judgment_must_use_tooling.md: never vibe-check OOS.
#
# Usage:
#   bash tools/oos-pre-answer-gate.sh \
#     --workspace /Users/wolf/audits/base-azul \
#     --finding /path/to/draft.md \
#     [--severity High]
#
# Output (stdout): single JSON object with rcs and one-line summaries from
# each of: pre-submit-check.sh, per-finding-oos-check.py, upstream-equivalent-gate.py
# Exit code: 0 if all 3 ran (independent of their internal rcs); 2 on missing args.

set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE=""
FINDING=""
SEVERITY="High"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --finding)   FINDING="$2"; shift 2 ;;
    --severity)  SEVERITY="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 --workspace <ws> --finding <draft.md> [--severity <Severity>]"
      exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$WORKSPACE" ]] || [[ -z "$FINDING" ]]; then
  echo '{"reason":"missing args","required":["workspace","finding"]}' >&2
  exit 2
fi

if [[ ! -f "$FINDING" ]]; then
  echo "{\"reason\":\"finding file not found\",\"path\":\"$FINDING\"}" >&2
  exit 2
fi

run_check() {
  local name="$1"; shift
  local out err rc
  out="$("$@" 2>/tmp/_oos_pre_answer_err.$$)" ; rc=$?
  err="$(cat /tmp/_oos_pre_answer_err.$$ 2>/dev/null || true)"
  rm -f /tmp/_oos_pre_answer_err.$$
  # Tail of stderr is more useful than full stdout for one-line summary
  local tail_summary
  tail_summary="$(printf '%s' "$err" | tail -3 | tr '\n' '|' | sed 's/|$//')"
  if [[ -z "$tail_summary" ]]; then
    tail_summary="$(printf '%s' "$out" | tail -3 | tr '\n' '|' | sed 's/|$//')"
  fi
  python3 - "$name" "$rc" "$tail_summary" <<'PY'
import json, sys
print(json.dumps({"name": sys.argv[1], "rc": int(sys.argv[2]), "summary": sys.argv[3][:400]}, separators=(',', ':')))
PY
}

GATE1="$(run_check pre-submit-check bash "$REPO/tools/pre-submit-check.sh" "$FINDING" --severity "$SEVERITY")"
GATE2="$(run_check per-finding-oos python3 "$REPO/tools/per-finding-oos-check.py" --workspace "$WORKSPACE" --finding "$FINDING")"
# Build a synthetic candidate JSON for upstream-equivalent-gate (needs --workspace + --candidate)
_GATE3_TMP="$(mktemp /tmp/oos_pre_answer_candidate.$$.json)"
python3 - "$FINDING" "$WORKSPACE" "$_GATE3_TMP" <<'PY'
import json, re, sys
from pathlib import Path
finding_text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
ws = sys.argv[2]
out_path = sys.argv[3]
# Extract first external/... path mention from the finding
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
GATE3="$(run_check upstream-equivalent python3 "$REPO/tools/upstream-equivalent-gate.py" --workspace "$WORKSPACE" --candidate "$_GATE3_TMP")"
rm -f "$_GATE3_TMP"

python3 - "$GATE1" "$GATE2" "$GATE3" "$FINDING" "$WORKSPACE" "$SEVERITY" <<'PY'
import json, sys, datetime
g1, g2, g3 = (json.loads(s) for s in sys.argv[1:4])
finding, ws, sev = sys.argv[4:7]
all_rc0 = (g1["rc"] == 0) and (g2["rc"] == 0) and (g3["rc"] == 0)
fileable_signal = "fileable" if all_rc0 else "blocked"
out = {
    "schema": "auditooor.oos_pre_answer.v1",
    "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "finding": finding,
    "workspace": ws,
    "severity": sev,
    "gates": [g1, g2, g3],
    "all_rc0": all_rc0,
    "fileable_signal": fileable_signal,
    "rule": "if any gate rc != 0, agent MUST NOT verbally claim 'fileable' — review the gate output, name the blocker, then propose remediation.",
}
print(json.dumps(out, indent=2))
PY
