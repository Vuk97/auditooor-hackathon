#!/usr/bin/env bash
# attack-tree.sh — STRIDE-style attack-tree expansion for a contract (Issue #106).
#
# Given a Solidity contract, produces an agent brief that asks Sonnet to
# enumerate:
#   1. The contract's assets (tokens, state, roles, off-chain signatures)
#   2. The attacker-goal space (Spoofing / Tampering / Repudiation / Info-disclosure / DoS / Elevation)
#   3. For each (asset, goal) pair: 2-3 plausible attack paths
#   4. Per path: what pattern/detector would catch it (or NONE if novel)
#
# Output: <workspace>/ATTACK_TREE_<contract>.md — a triaged attack-tree that
# surfaces novelty the pattern matcher misses.
#
# Usage:
#   ./tools/attack-tree.sh <contract.sol> <workspace> [--brief-file out.md]

set -u
CONTRACT="${1:-}"
WS="${2:-}"
BRIEF_FILE=""
shift 2 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --brief-file) BRIEF_FILE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$CONTRACT" ] || [ ! -f "$CONTRACT" ] || [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <contract.sol> <workspace-dir> [--brief-file out.md]" >&2
  exit 2
fi

CONTRACT_NAME=$(basename "$CONTRACT" .sol)
OUT="$WS/ATTACK_TREE_${CONTRACT_NAME}.md"

write() {
  if [ -n "$BRIEF_FILE" ]; then echo "$@" >> "$BRIEF_FILE"
  else echo "$@"
  fi
}

[ -n "$BRIEF_FILE" ] && : > "$BRIEF_FILE"

write "# STRIDE attack-tree brief — $CONTRACT_NAME"
write ""
write "Target: \`$CONTRACT\`"
write "Output: \`$OUT\`"
write ""
write "## Task"
write ""
write "Produce a STRIDE attack tree for this contract. STRIDE categories:"
write ""
write "| Acronym | Category | Smart-contract translation |"
write "|---|---|---|"
write "| S | Spoofing | Signature forgery, address impersonation, proxy confusion |"
write "| T | Tampering | State corruption, storage collision, re-entrancy, bit-packing overflow |"
write "| R | Repudiation | Event parity bugs, missing emits, topic collisions (Polymarket EV.F1 class) |"
write "| I | Info disclosure | Sensitive data in events/storage, MEV leakage, timing oracles |"
write "| D | DoS | Unbounded loops, gas griefing, zero-amount revert, stuck-state |"
write "| E | Elevation | Missing access control, role-grant bugs (Polymarket OFF.A class), init-reentry |"
write ""
write "## Deliverable format"
write ""
write "Per the 6 STRIDE categories, produce ≥2 concrete attack paths for THIS contract:"
write ""
write "\`\`\`"
write "## S — Spoofing"
write ""
write "### S1: <short attack name>"
write "- **Asset targeted**: <what's stolen/corrupted>"
write "- **Attacker capability**: <who can do this>"
write "- **Path**:"
write "  1. Attacker does X"
write "  2. Contract does Y"
write "  3. Invariant Z breaks"
write "- **Existing-detector coverage**: <pattern-slug OR 'NONE — novel'>"
write "- **Rubric severity**: Critical/High/Medium/Low"
write ""
write "### S2: ..."
write "\`\`\`"
write ""
write "Repeat for T, R, I, D, E — 2-3 paths each. Total: 12-18 paths."
write ""
write "## Prioritization"
write ""
write "After the full tree, output a ranked list:"
write ""
write "1. TOP-5 paths ranked by (severity × novelty × likelihood)"
write "2. For top-3: recommend a specific drill (read function X, write foundry test, etc.)"
write ""
write "## Novelty scoring"
write ""
write "For each path mark it with one of:"
write "- \`[PATTERN-COVERED]\` — existing detector slug from the 186-pattern library catches this"
write "- \`[HYPOTHESIS]\` — plausible but needs source-level verification"
write "- \`[NOVEL]\` — pattern library doesn't cover; worth fresh adversarial read"
write ""
write "## Source"
write ""
write "\`\`\`solidity"
head -400 "$CONTRACT" >> "${BRIEF_FILE:-/dev/stdout}"
write "\`\`\`"
write ""
write "(read the full file for complete context; output ≤800 words)"
write ""

if [ -n "$BRIEF_FILE" ]; then
  echo "[attack-tree] wrote brief → $BRIEF_FILE"
  echo "[attack-tree] agent will write tree → $OUT"
fi
