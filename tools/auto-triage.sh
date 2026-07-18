#!/usr/bin/env bash
# auto-triage.sh — batch-agent triage of a scan log (Issue #101).
#
# Parses run_custom.py / scan.sh output, groups hits by detector, and emits a
# paste-ready multi-Task block for Claude Code with one agent brief per
# detector cluster. Human dispatches; agents return verdicts; human records
# them via record-triage.sh.
#
# Usage:
#   ./tools/auto-triage.sh <scan-log.txt> <workspace-name> [--dispatch-file out.md]
#
# Produces:
#   - stdout (or --dispatch-file): multi-agent brief block
#   - <workspace>/AUTO_TRIAGE_QUEUE.md: human-readable triage queue
#
# Design note: this tool does NOT dispatch agents itself. Agent dispatch
# requires Claude Code's Task tool, invoked by the assistant in the main
# conversation. What this tool DOES is produce the structured brief text
# that the assistant then pastes into its own message (one Task call per
# cluster). This separation keeps the tool deterministic and testable.

set -u
LOG="${1:-}"
WS_NAME="${2:-}"
DISPATCH_FILE=""

shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --dispatch-file) DISPATCH_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$LOG" ] || [ ! -f "$LOG" ] || [ -z "$WS_NAME" ]; then
  echo "usage: $0 <scan-log.txt> <workspace-name> [--dispatch-file out.md]" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Group hits by detector. Output: detector:count:first_3_hits
# SKILL_ISSUES #145 — tolerate `scan-per-module.sh` section headers
# (`=== module: <name> ===`) that interleave with hit lines. The grep
# already skips the section lines (they don't match `[LEVEL]`), but we
# also build an auxiliary per-module tag file so downstream triage can
# attribute each hit back to its originating module.
GROUPED=$(grep -oE '^\s*\[[A-Z]+\].*— [a-z0-9-]+:' "$LOG" | \
  sed -E 's/.*— ([a-z0-9-]+):.*/\1/' | sort | uniq -c | \
  awk '{printf "%s %s\n", $2, $1}' | sort -k2 -n -r)

# Walk the log once to tag each hit with its surrounding module header
# (empty string if the log isn't scan-per-module style). Written to
# a sibling file for record-triage.sh / dispatch-brief.sh consumption.
MODULE_TAGS="${LOG%.log}.modules.tsv"
awk '
  /^=== module: / {
    mod = $0
    sub(/^=== module: /, "", mod)
    sub(/ ===.*$/, "", mod)
    sub(/ \(.*\)$/, "", mod)
    next
  }
  /^[[:space:]]*\[[A-Z]+\].*— [a-z0-9-]+:/ {
    # extract detector and file:line tail
    det = $0
    sub(/.*— /, "", det)
    sub(/:.*/, "", det)
    printf "%s\t%s\t%s\n", (mod == "" ? "-" : mod), det, $0
  }
' "$LOG" > "$MODULE_TAGS" 2>/dev/null || true

if [ -z "$GROUPED" ]; then
  echo "[auto-triage] no hits found in $LOG" >&2
  exit 1
fi

TOTAL_HITS=$(echo "$GROUPED" | awk '{sum+=$2} END {print sum}')
TOTAL_DETECTORS=$(echo "$GROUPED" | wc -l | tr -d ' ')

write() {
  if [ -n "$DISPATCH_FILE" ]; then echo "$@" >> "$DISPATCH_FILE"
  else echo "$@"
  fi
}

[ -n "$DISPATCH_FILE" ] && : > "$DISPATCH_FILE"

write "# Auto-triage dispatch for $WS_NAME"
write ""
write "Parsed $TOTAL_HITS hits across $TOTAL_DETECTORS detectors from \`$LOG\`."
# SKILL_ISSUES #145 — surface module attribution when the log came from
# scan-per-module.sh so operators can target agent dispatch per-module.
if [ -s "$MODULE_TAGS" ] && awk -F'\t' '$1 != "-"' "$MODULE_TAGS" | head -1 | grep -q .; then
  MOD_COUNT=$(awk -F'\t' '$1 != "-" { print $1 }' "$MODULE_TAGS" | sort -u | wc -l | tr -d ' ')
  write "Per-module attribution: $MOD_COUNT modules detected; see \`$(basename "$MODULE_TAGS")\` for module/detector/hit triples."
fi
write "Dispatch each brief below as a parallel Task agent; aggregate verdicts into ledger via \`record-triage.sh\`."
write ""

CLUSTER_NUM=0
while IFS= read -r line; do
  DET=$(echo "$line" | awk '{print $1}')
  CNT=$(echo "$line" | awk '{print $2}')
  CLUSTER_NUM=$((CLUSTER_NUM + 1))

  # Extract first 5 hits for this detector with file:line
  HITS=$(grep -E "— ${DET}:" "$LOG" 2>/dev/null | head -5 | sed 's/^  /    /')

  write "---"
  write ""
  write "## Cluster $CLUSTER_NUM — \`$DET\` ($CNT hits)"
  write ""
  write "### Agent brief"
  write ""
  write "\`\`\`"
  write "You are auditing workspace $WS_NAME. Triage hits from the \`$DET\` Slither detector."
  write ""
  write "Hits (first 5; full list at $LOG):"
  write "$HITS"
  write ""
  write "Task: for each hit above, read the source at exact file:line and answer:"
  write "1. What is the detector complaining about? (1-line paraphrase of the hit)"
  write "2. Read the source around the line. Is the concern real? (TP / FP / NEEDS-VERIFY)"
  write "3. If TP: describe the exploit in 2-3 lines + severity estimate per standard DeFi rubric"
  write "4. If FP: name the specific guard / design choice that makes it safe (1 line)"
  write "5. If NEEDS-VERIFY: name the specific next check (e.g. 'drill into fn X to confirm Y')"
  write ""
  write "Known rubric exclusions for $WS_NAME (if applicable):"
  write "- Polymarket: admin-centralization by-design is OOS"
  write "- Morpho: inverse-CEI / optimistic-state is by-design (user/bundler contract responsibility)"
  write ""
  write "Report format per hit:"
  write "  [FILE:LINE] VERDICT — 1-line justification"
  write ""
  write "Final line: 'CLUSTER VERDICT: MAJORITY_FP | MAJORITY_TP | MIXED' + 1-sentence summary."
  write ""
  write "Do NOT write code. Read only. ≤400 words total."
  write "\`\`\`"
  write ""
done <<< "$GROUPED"

write "---"
write ""
write "## After agents return"
write ""
write "For each cluster's verdict, record via:"
write ""
write "\`\`\`bash"
while IFS= read -r line; do
  DET=$(echo "$line" | awk '{print $1}')
  write "./tools/record-triage.sh $DET $WS_NAME auto-$DET <TP|FP|UNKNOWN>"
done <<< "$GROUPED"
write "\`\`\`"
write ""

if [ -n "$DISPATCH_FILE" ]; then
  echo "[auto-triage] wrote $DISPATCH_FILE"
  echo "[auto-triage] $TOTAL_HITS hits / $TOTAL_DETECTORS clusters"
fi
