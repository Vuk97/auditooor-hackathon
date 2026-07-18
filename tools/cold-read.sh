#!/usr/bin/env bash
# cold-read.sh — Generate a cold-read agent brief for a Solidity contract.
# Usage: cold-read.sh <workspace-dir> <contract-file.sol> [--out <output-dir>] [--dispatch]
set -euo pipefail

usage() {
  echo "Usage: $0 <workspace-dir> <contract-file.sol> [--out <output-dir>] [--dispatch]" >&2
  exit 1
}

# ── Argument parsing ──────────────────────────────────────────────────────────
WORKSPACE=""
CONTRACT_FILE=""
OUTPUT_DIR=""
DISPATCH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)    OUTPUT_DIR="$2"; shift 2 ;;
    --dispatch) DISPATCH=1; shift ;;
    -*)       usage ;;
    *)
      if [[ -z "$WORKSPACE" ]];     then WORKSPACE="$1"
      elif [[ -z "$CONTRACT_FILE" ]]; then CONTRACT_FILE="$1"
      else usage; fi
      shift ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$CONTRACT_FILE" ]] && usage

# ── Validation ────────────────────────────────────────────────────────────────
[[ -d "$WORKSPACE" ]] || { echo "ERROR: workspace '$WORKSPACE' is not a directory" >&2; exit 1; }
[[ -f "$CONTRACT_FILE" ]] || { echo "ERROR: contract file '$CONTRACT_FILE' not found" >&2; exit 1; }

BASENAME=$(basename "$CONTRACT_FILE" .sol)
OUTPUT_DIR="${OUTPUT_DIR:-$WORKSPACE/cold_reads}"
mkdir -p "$OUTPUT_DIR"
BRIEF="$OUTPUT_DIR/${BASENAME}.brief.md"

# ── SCOPE.md excerpt (3-5 sentence summary) ───────────────────────────────────
SCOPE_EXCERPT=""
if [[ -f "$WORKSPACE/SCOPE.md" ]]; then
  # Grab first 25 lines; collapse to ~5 sentences for the brief
  SCOPE_EXCERPT=$(head -25 "$WORKSPACE/SCOPE.md")
fi

# ── Resolve 1-level imports ───────────────────────────────────────────────────
CONTRACT_DIR=$(dirname "$CONTRACT_FILE")

collect_imports() {
  local file="$1"
  grep -E '^\s*import\s*' "$file" 2>/dev/null \
    | sed -E 's|.*"([^"]+)".*|\1|; s|.*'"'"'([^'"'"']+)'"'"'.*|\1|' \
    | sort -u
}

INTERFACE_CONTENT=""
while IFS= read -r imp; do
  [[ -z "$imp" ]] && continue

  # Resolve relative path from the contract's directory
  candidate="$CONTRACT_DIR/$imp"
  if [[ ! -f "$candidate" ]]; then
    # Also try from workspace root
    candidate="$WORKSPACE/$imp"
  fi
  [[ -f "$candidate" ]] || continue

  fname=$(basename "$candidate")
  # Only include interfaces (filename starts with I or lives in interfaces/)
  if [[ "$fname" =~ ^I[A-Z] ]] || [[ "$candidate" == *"/interfaces/"* ]]; then
    INTERFACE_CONTENT+="
### Import: $fname
\`\`\`solidity
$(cat "$candidate")
\`\`\`
"
  fi
done < <(collect_imports "$CONTRACT_FILE")

# ── Write the brief ───────────────────────────────────────────────────────────
cat > "$BRIEF" <<BRIEF_EOF
# Cold-Read Agent Brief: ${BASENAME}.sol

> **This brief is for a cold-read analysis agent.**
> Do NOT reference pattern libraries, CVE databases, known bug classes by name,
> or any prior audit findings. Reason fresh from the source code only.

---

## Target Contract

File: \`${CONTRACT_FILE}\`

\`\`\`solidity
$(cat "$CONTRACT_FILE")
\`\`\`

---

## Interface-Level Imports (1-level, interfaces only)
${INTERFACE_CONTENT:-_No interface-level imports resolved._}

---

## Context from SCOPE.md

${SCOPE_EXCERPT:-_No SCOPE.md found in workspace._}

---

## Agent Instructions

You are performing a security analysis of the contract above. Your goal is to find problems that a pattern-matching tool CANNOT find — problems that arise from fresh reasoning about what the code ASSUMES and what happens when those assumptions are violated.

**Rules:**
1. Ignore pattern libraries, checklists, and named bug classes. Do not reference "reentrancy", "oracle manipulation", or any other named category — describe the mechanism directly.
2. Work through the code top-to-bottom. For EVERY assumption you find — about callers, external contract behavior, token semantics, block state, storage layout, gas limits, proxy/wallet behavior, or admin intent — write it down.
3. For each assumption, write:
   - What the code assumes
   - What happens if that assumption is violated (step by step, no hand-waving)
   - Whether the violation is reachable by an unprivileged caller, and how
4. Pay special attention to:
   - State transitions that have no inverse (what can get permanently stuck)
   - External calls whose return value is unused or whose side effects are not checked
   - Arithmetic paths where truncation or rounding changes who benefits
   - Conditions checked before an external call that are NOT re-checked after
   - Flows where the same hash or ID is used across two different contexts
   - Approval or allowance grants that survive beyond their intended scope
   - Anything emitted in events that doesn't match the actual state change
5. Do NOT skip "obvious" assumptions. The assumption that \`block.number\` increases monotonically, that a trusted admin won't grief, that an ERC-20 returns \`true\` — all are fair game.
6. Be honest about reachability. If a violation path requires admin cooperation, say so. If it requires zero privileges, say so.

**Output format** (repeat for each assumption, 10-20 total):

\`\`\`
## Assumption N: <one-line label>

**Code location:** <file>:<line(s)>

**What the code assumes:**
<1-3 sentences>

**What happens if violated:**
<step-by-step, what state changes, who is harmed, by how much>

**Reachability:**
<who can trigger this, what preconditions are needed, estimated difficulty>
\`\`\`

End with a summary section titled **## IN-SCOPE-SUBMITTABLE Candidates** listing any assumption whose violation looks reachable by an unprivileged caller, is in scope, and does not appear to be covered by **this specific protocol's prior audits**. If none exist, say "0 in-scope-submittable candidates."

### Framing (R67 lesson — important)

"IN-SCOPE-SUBMITTABLE" = **not already disclosed in a prior audit of THIS protocol** (check \`prior_audits/\` digests if present). A bug class known elsewhere in DeFi (Morpho / Compound / Aave / Uniswap / etc.) but LIVE in the scoped code and NOT covered by this protocol's audit history is **submittable**. Do NOT filter out "known classes" just because they exist in the broader corpus.

Valid filter-out reasons (use these explicit labels):

- \`KNOWN-OOS\` — matches an OOS-N bullet in \`OOS_CHECKLIST.md\`
- \`PRIOR-AUDIT-DUPE\` — semantic match (not keyword) to a specific \`prior_audits/\` entry — cite it
- \`NOT-A-BUG\` — verified non-exploitable by code trace; cite where the attack is preempted

### Payout context

Most bug bounties pay across severity bands. If the operator's \`SEVERITY_CAPS.md\` notes a payout range, surface even Low-severity findings rather than discarding them. The rule: **honest-NO is first-class, but so is a cleanly-verified Low** ($200 floor typical, positive EV vs submission deposit).
BRIEF_EOF

echo "Brief written: $BRIEF"

# ── Optional dispatch ─────────────────────────────────────────────────────────
if [[ "$DISPATCH" -eq 1 ]]; then
  echo "Dispatching agent on brief..." >&2
  if command -v claude &>/dev/null; then
    claude --print < "$BRIEF"
  else
    echo "ERROR: --dispatch requires the 'claude' CLI to be installed" >&2
    exit 1
  fi
fi
