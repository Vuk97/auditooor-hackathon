#!/usr/bin/env bash
# check-novel-vector.sh — enforce the novel-vector scoping rule (Issue #97).
#
# A finding title SHOULD name:
#   1. a specific function (e.g., `setRate`, `_settleTakerOrder`)
#   2. a specific vector (e.g., "via 1271 callback", "during rebalance")
#   3. a specific impact (e.g., "drains collateral", "allows replay")
#
# Titles of the form "Missing reentrancy guard in Trading.sol" fail the rule.
# Titles of the form "Trading._settleTakerOrder refund flushes exchange collateral
# to next BUY-taker" pass the rule.
#
# Usage: ./tools/check-novel-vector.sh <finding.md>
# Exit 0 on pass, 1 on fail. Designed to be wired into pre-submit-check.sh as Check #9.

set -u
F="${1:-}"
if [ -z "$F" ] || [ ! -f "$F" ]; then
  echo "usage: $0 <finding.md>" >&2
  exit 2
fi

# Extract title (first H1 or "Title:" line)
TITLE=$(grep -m1 -E '^# |^Title:' "$F" 2>/dev/null | sed -e 's/^# //' -e 's/^Title:[[:space:]]*//' || echo "")

if [ -z "$TITLE" ]; then
  echo "[novel-vector] FAIL — no title found in $F" >&2
  exit 1
fi

# Heuristic 1: title must contain a function-like identifier (camelCase or dot.notation)
if ! echo "$TITLE" | grep -qE '[a-z][A-Z][a-zA-Z]+|\.[a-z_][a-zA-Z_]+\('; then
  echo "[novel-vector] WARN — title lacks specific function identifier"
  echo "    Title: $TITLE"
  echo "    Rule:  include the function, e.g., '_settleTakerOrder', 'Trading.unwrap()'"
  echo "    (see Morpho #I2.A rejection — class-level titles fail novelty)"
  exit 1
fi

# Heuristic 2: title should contain an action verb (drains / allows / enables / reverts / overflows)
if ! echo "$TITLE" | grep -qiE '(drain|allow|enable|revert|overflow|bypass|steal|lock|strand|block|grief|forge|replay|loss|flush|fill|corrupt|break|fail|censor)'; then
  echo "[novel-vector] WARN — title lacks impact verb"
  echo "    Title: $TITLE"
  echo "    Rule:  include the mechanism outcome, e.g., 'drains collateral', 'allows replay'"
  exit 1
fi

# Heuristic 3: title length — ≥8 words is proxy for specificity
WORD_COUNT=$(echo "$TITLE" | wc -w | tr -d ' ')
if [ "$WORD_COUNT" -lt 6 ]; then
  echo "[novel-vector] WARN — title is $WORD_COUNT words, rule prefers ≥6 for specificity"
  echo "    Title: $TITLE"
  exit 1
fi

echo "[novel-vector] PASS — title contains function id, impact verb, and ≥6 words"
exit 0
