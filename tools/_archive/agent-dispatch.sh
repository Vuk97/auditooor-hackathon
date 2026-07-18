#!/usr/bin/env bash
# agent-dispatch.sh — generate a parallel-agent dispatch block + capture outputs (Issue #82)
#
# This makes parallel Sonnet fan-out the default instead of serial main-context
# reading. Produces a ready-to-paste block of Task() invocations for Claude Code,
# plus staged input/output directories.
#
# Usage:
#   ./tools/agent-dispatch.sh <workspace> <brief-dir>
#       <brief-dir> contains N brief files (*.md). One per agent.
#
# Output:
#   <workspace>/agent-runs/<iter>/briefs/*.md    (copies of briefs)
#   <workspace>/agent-runs/<iter>/DISPATCH.md    (ready-to-paste block)
#   <workspace>/agent-runs/<iter>/outputs/       (where agent outputs land)
#
# Usage flow:
#   1. Operator writes 3-7 brief files in a temp dir (or hand-picks from
#      reference/agent_briefs.md templates)
#   2. ./tools/agent-dispatch.sh <ws> <brief-dir>
#   3. Paste the block printed to DISPATCH.md into Claude Code
#   4. Agent outputs land in outputs/
#   5. ./tools/agent-dispatch.sh <ws> --aggregate <iter>
#      merges outputs into agg.md
#
# Fixes SKILL_ISSUE #82.

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ $# -lt 2 ]; then
    sed -n '2,24p' "$0" | sed 's/^# //; s/^#//'
    exit 1
fi

WS="$1"
SUB="$2"

if [ ! -d "$WS" ]; then
    echo "[error] workspace not found: $WS" >&2
    exit 1
fi

# --aggregate mode
if [ "$SUB" = "--aggregate" ]; then
    ITER_NUM="${3:-}"
    if [ -z "$ITER_NUM" ]; then
        # Use latest
        ITER_NUM=$(ls -d "$WS/agent-runs/"[0-9]* 2>/dev/null | sort -V | tail -1 | xargs basename 2>/dev/null || echo "")
    fi
    RUN_DIR="$WS/agent-runs/$ITER_NUM"
    if [ ! -d "$RUN_DIR/outputs" ]; then
        echo "[error] outputs dir not found: $RUN_DIR/outputs" >&2
        exit 1
    fi
    AGG="$RUN_DIR/agg.md"
    echo "# Aggregated agent outputs — iter $ITER_NUM" > "$AGG"
    echo "" >> "$AGG"
    echo "Dispatched at: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$AGG"
    echo "" >> "$AGG"
    for out in "$RUN_DIR/outputs"/*.md; do
        [ -f "$out" ] || continue
        echo "" >> "$AGG"
        echo "---" >> "$AGG"
        echo "" >> "$AGG"
        echo "## $(basename "$out" .md)" >> "$AGG"
        echo "" >> "$AGG"
        cat "$out" >> "$AGG"
    done
    echo "[ok] aggregated $(ls "$RUN_DIR/outputs"/*.md 2>/dev/null | wc -l | tr -d ' ') outputs to $AGG"
    exit 0
fi

BRIEF_DIR="$SUB"
if [ ! -d "$BRIEF_DIR" ]; then
    echo "[error] brief directory not found: $BRIEF_DIR" >&2
    exit 1
fi

# Determine next iter number for agent-runs/
mkdir -p "$WS/agent-runs"
EXISTING_ITERS=$(ls -d "$WS/agent-runs/"[0-9]* 2>/dev/null | xargs -n1 basename 2>/dev/null | sort -n)
if [ -z "$EXISTING_ITERS" ]; then
    ITER_NUM=1
else
    ITER_NUM=$(( $(echo "$EXISTING_ITERS" | tail -1) + 1 ))
fi

RUN_DIR="$WS/agent-runs/$ITER_NUM"
mkdir -p "$RUN_DIR/briefs" "$RUN_DIR/outputs"

# Copy briefs + count
BRIEF_COUNT=0
for b in "$BRIEF_DIR"/*.md; do
    [ -f "$b" ] || continue
    cp "$b" "$RUN_DIR/briefs/"
    BRIEF_COUNT=$((BRIEF_COUNT + 1))
done

if [ "$BRIEF_COUNT" = "0" ]; then
    echo "[error] no *.md briefs found in $BRIEF_DIR" >&2
    exit 1
fi

if [ "$BRIEF_COUNT" -gt 10 ]; then
    echo "[warn] $BRIEF_COUNT briefs — output processing gets unwieldy >10" >&2
fi

# Generate DISPATCH.md
DISP="$RUN_DIR/DISPATCH.md"
cat > "$DISP" <<EOF
# Parallel agent dispatch — $(basename "$WS") iter $ITER_NUM

**Briefs:** $BRIEF_COUNT
**Output dir:** \`agent-runs/$ITER_NUM/outputs/\`
**Dispatched:** $(date -u +%Y-%m-%dT%H:%M:%SZ)

## How to use

1. In the Claude Code main conversation, paste the block below as-is. It
   dispatches all $BRIEF_COUNT agents in parallel.
2. Each agent writes its report to \`agent-runs/$ITER_NUM/outputs/<brief-slug>.md\`.
3. When all agents return, run:
   \`\`\`
   bash $0 $WS --aggregate $ITER_NUM
   \`\`\`
   That produces \`agent-runs/$ITER_NUM/agg.md\`.

## Dispatch block (paste into Claude Code main conversation)

Use a single assistant turn with multiple Task tool calls. Each agent loads
one brief, executes its investigation, and writes its output to the
specified path.

EOF

for b in "$RUN_DIR/briefs"/*.md; do
    SLUG=$(basename "$b" .md)
    # Extract first header line or filename
    TITLE=$(head -1 "$b" | sed 's/^#* *//' || echo "$SLUG")
    cat >> "$DISP" <<EOF

### Agent: $SLUG

**Description:** $TITLE
**Brief:** \`$b\`
**Expected output:** \`$RUN_DIR/outputs/$SLUG.md\`

\`\`\`
Task(
  subagent_type="general-purpose",
  description="$SLUG (sonnet, ~5 min)",
  prompt=$(printf '%s' "Read the full brief at $b.

Execute the investigation described in the brief.

When done, write your complete report (in markdown) to: $RUN_DIR/outputs/$SLUG.md

Your report should follow any format the brief specifies. If the brief gives no format, use:
- ## Summary (3-5 sentences)
- ## Findings (structured list with evidence)
- ## Confidence (HIGH/MEDIUM/LOW per finding)
- ## Suggested next steps

Do NOT modify any other files. Do NOT submit findings. Just write the report.

After writing the report, reply with a one-paragraph summary (< 100 words)
confirming the report was written and listing any HIGH-confidence findings.")
)
\`\`\`

EOF
done

cat >> "$DISP" <<EOF

## After agents return

\`\`\`
bash $0 $WS --aggregate $ITER_NUM
\`\`\`

Produces \`agent-runs/$ITER_NUM/agg.md\` — a single file with all agent reports.
Triage HIGH-confidence findings through source verification (anti-pattern #2).
EOF

echo "[ok] dispatch generated: $DISP"
echo "  Briefs copied to:  $RUN_DIR/briefs/"
echo "  Output will land:  $RUN_DIR/outputs/"
echo "  Agent count:       $BRIEF_COUNT"
echo ""
echo "Next step: paste the DISPATCH.md block into Claude Code."
echo ""
echo "When agents finish:"
echo "  bash $0 $WS --aggregate $ITER_NUM"
