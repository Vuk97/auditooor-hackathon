#!/usr/bin/env bash
# agent-dispatch-enforced.sh — gatekeeper for Task-dispatch flow (Issue #151 fix).
# HARD STOPS if OOS/CAPS/PRIOR_CONCERNS/DIGESTS missing before any Task dispatch.
# Wraps tools/dispatch-brief.sh to guarantee every agent receives prior-audit context.
#
# LEGACY: superseded by spawn-worker.sh -> dispatch-agent-with-prebriefing.py for
# brief injection. Retained because agent-worktree-dispatch.py calls this script
# as the OOS/CAPS/PRIOR hard-stop gate.

set -u
WS="${1:-}"; CONTRACT="${2:-}"; HYP="${3:-}"
if [ -z "$WS" ] || [ -z "$CONTRACT" ] || [ -z "$HYP" ]; then
  echo "usage: $0 <workspace> <contract> <hypothesis-text>" >&2; exit 2
fi
AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Agent dispatch enforcement ==="
HARD=0

[ -f "$WS/OOS_CHECKLIST.md" ]   || { echo "[HARD] OOS_CHECKLIST.md missing — run extract-oos.sh"; HARD=1; }
[ -f "$WS/SEVERITY_CAPS.md" ]   || { echo "[HARD] SEVERITY_CAPS.md missing — run extract-oos.sh"; HARD=1; }
[ -f "$WS/PRIOR_CONCERNS.md" ]  || { echo "[HARD] PRIOR_CONCERNS.md missing — run orient-from-audits.sh"; HARD=1; }

if [ -d "$WS/prior_audits" ] && ls "$WS/prior_audits/"*.txt >/dev/null 2>&1; then
  if ! ls "$WS/prior_audits/DIGEST_"*.md >/dev/null 2>&1; then
    echo "[HARD] prior_audits/ has .txt but no DIGEST_*.md — dispatch digest agents first"; HARD=1
  fi
fi

[ -f "$AUDITOOOR_DIR/reference/recurring_bug_families.md" ] \
  || echo "[SOFT] recurring_bug_families.md missing — run digest-aggregate.sh"

if [ $HARD -gt 0 ]; then echo "=== HARD STOP ==="; exit 1; fi

TS=$(date -u +%Y%m%dT%H%M%SZ)
BRIEF="$WS/agent_outputs/brief_${TS}_$(basename "$CONTRACT" .sol).md"
mkdir -p "$(dirname "$BRIEF")"

"$AUDITOOOR_DIR/tools/dispatch-brief.sh" "$WS" "$CONTRACT" "$HYP" --brief-file "$BRIEF"
[ -s "$BRIEF" ] || { echo "[ERROR] brief empty"; exit 4; }

MISS=""
grep -qE "OOS-[0-9]+" "$BRIEF"                  || MISS="$MISS OOS"
grep -qE "CAP-[0-9]+|Critical|High|Medium|Low|Blockchain / DLT|Blockchain/DLT" "$BRIEF" \
  || MISS="$MISS CAPS"
grep -qiE "prior[-_]concern|PRIOR_CONCERN" "$BRIEF" || MISS="$MISS PRIOR_CONCERNS"
[ -n "$MISS" ] && echo "[WARN] brief missing blocks:$MISS"

echo ""
echo "=== READY FOR DISPATCH ==="
echo "  Brief: $BRIEF"
echo "  Lines: $(wc -l < "$BRIEF")"
echo "  Must paste brief verbatim into Task tool. Capture output via dispatch-capture.sh."
exit 0
