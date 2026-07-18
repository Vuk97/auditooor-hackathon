#!/usr/bin/env bash
# adversarial-read.sh — generate an attacker-perspective prompt for a Solidity contract
#
# Usage:
#   ./tools/adversarial-read.sh <workspace-dir> <relative-contract-path>
#
# Example:
#   ./tools/adversarial-read.sh ~/audit/polymarket src/exchange/mixins/Trading.sol
#
# Behavior:
#   1. Validate workspace + contract file exist.
#   2. Read the full contract source (with line numbers).
#   3. Read the workspace FINDINGS.md to see what's already known.
#   4. Build a prompt that instructs an LLM to narrate 10 specific, step-by-step
#      attack scenarios against THIS contract's actual functions and state.
#   5. Write the prompt to <workspace>/adversarial_<contract-slug>.md.
#   6. Print the next-step command for the operator.
#
# Output prompt file: <workspace>/adversarial_<contract-slug>.md
# Operator pastes prompt into Claude, saves response to:
#              <workspace>/ADVERSARIAL_<contract-slug>.md
#
# Fixes SKILL_ISSUE #40 — scenario-level adversarial narration complementing
# the class-level hypothesis generator (#37).

set -uo pipefail

# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

if [ $# -lt 2 ]; then
    echo "Usage: $0 <workspace-dir> <relative-contract-path>"
    echo "Example: $0 ~/audit/polymarket src/exchange/mixins/Trading.sol"
    exit 1
fi

WS="$1"
CONTRACT_REL="$2"

if [ ! -d "$WS" ]; then
    echo "Error: workspace directory '$WS' not found"
    exit 1
fi

# Resolve contract path — try as-is first, then relative to workspace
CONTRACT_ABS=""
if [ -f "$CONTRACT_REL" ]; then
    CONTRACT_ABS="$(cd "$(dirname "$CONTRACT_REL")" && pwd)/$(basename "$CONTRACT_REL")"
elif [ -f "$WS/$CONTRACT_REL" ]; then
    CONTRACT_ABS="$(cd "$WS/$(dirname "$CONTRACT_REL")" && pwd)/$(basename "$CONTRACT_REL")"
else
    echo "Error: contract file not found at '$CONTRACT_REL' or '$WS/$CONTRACT_REL'"
    exit 1
fi

if [ ! -s "$CONTRACT_ABS" ]; then
    echo "Error: contract file '$CONTRACT_ABS' is empty"
    exit 1
fi

# ---------------------------------------------------------------------------
# Derive names and paths
# ---------------------------------------------------------------------------

CONTRACT_FILENAME="$(basename "$CONTRACT_ABS")"
CONTRACT_NAME="${CONTRACT_FILENAME%.sol}"

# Slug: lowercase, replace non-alphanumeric with underscores
CONTRACT_SLUG="$(echo "$CONTRACT_NAME" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9' '_' | sed 's/_*$//')"

# Resolve AUDITOOOR_DIR relative to this script FIRST so DUPE_CAUSES_FILE can
# reference it on first use. Previously the DUPE_CAUSES_FILE definition ran
# under `set -u` before AUDITOOOR_DIR was defined, crashing the script with
# an "unbound variable" error (surfaced by Phase 44b's wiring into engage.py).
AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

FINDINGS_FILE="$WS/FINDINGS.md"
PATTERN_HITS_FILE="$WS/PATTERN_HITS.md"
PRIOR_CONCERNS_FILE="$WS/PRIOR_CONCERNS.md"
DUPE_CAUSES_FILE="$AUDITOOOR_DIR/reference/DUPE_CAUSES.md"
PROMPT_OUT="$WS/adversarial_${CONTRACT_SLUG}.md"
RESPONSE_TARGET="$WS/ADVERSARIAL_$(echo "$CONTRACT_SLUG" | tr '[:lower:]' '[:upper:]').md"

# ---------------------------------------------------------------------------
# Read contract source with line numbers
# ---------------------------------------------------------------------------

CONTRACT_LINED="$(awk '{printf "%4d  %s\n", NR, $0}' "$CONTRACT_ABS")"
CONTRACT_LINE_COUNT="$(wc -l < "$CONTRACT_ABS" | tr -d ' ')"

# ---------------------------------------------------------------------------
# Extract relevant findings from FINDINGS.md
# ---------------------------------------------------------------------------

FINDINGS_SECTION="(no FINDINGS.md found in workspace)"

if [ -f "$FINDINGS_FILE" ]; then
    # Grab lines that mention the contract name (case-insensitive), plus the
    # 3 lines that follow each match for context.
    MATCHING="$(grep -in "$CONTRACT_NAME" "$FINDINGS_FILE" 2>/dev/null | head -40 || true)"
    if [ -n "$MATCHING" ]; then
        FINDINGS_SECTION="Grep of FINDINGS.md for '${CONTRACT_NAME}' (line:content):

${MATCHING}"
    else
        FINDINGS_SECTION="FINDINGS.md exists but contains no entries referencing '${CONTRACT_NAME}'."
    fi
fi

# --- Issue #81: pattern-context priming ---
# Priming block 1: top PATTERN_HITS for THIS contract (if apply-patterns.sh was run)
PATTERN_HITS_SECTION="(no PATTERN_HITS.md — run tools/apply-patterns.sh to produce one)"
if [ -f "$PATTERN_HITS_FILE" ]; then
    PATTERN_HITS_MATCHES="$(grep -iE "${CONTRACT_NAME}|${CONTRACT_FILENAME}" "$PATTERN_HITS_FILE" 2>/dev/null | head -20 || true)"
    if [ -n "$PATTERN_HITS_MATCHES" ]; then
        PATTERN_HITS_SECTION="Top PATTERN_HITS.md rows referencing ${CONTRACT_NAME}:

${PATTERN_HITS_MATCHES}"
    else
        PATTERN_HITS_SECTION="PATTERN_HITS.md exists but no pattern hits on ${CONTRACT_NAME}. Consider running apply-patterns.sh --target-type <t>."
    fi
fi

# Priming block 2: PRIOR_CONCERNS.md (prior audit closures on this contract)
PRIOR_CONCERNS_SECTION="(no PRIOR_CONCERNS.md — run tools/orient-from-audits.sh to produce one)"
if [ -f "$PRIOR_CONCERNS_FILE" ]; then
    PRIOR_MATCH="$(grep -iE -A 3 "${CONTRACT_NAME}" "$PRIOR_CONCERNS_FILE" 2>/dev/null | head -30 || true)"
    if [ -n "$PRIOR_MATCH" ]; then
        PRIOR_CONCERNS_SECTION="Prior-audit closures on ${CONTRACT_NAME}:

${PRIOR_MATCH}"
    else
        PRIOR_CONCERNS_SECTION="No prior-audit closures mention ${CONTRACT_NAME}."
    fi
fi

# Priming block 3: novel-vector scoping rule (fixed text — Issue #58 / #81)
NOVEL_VECTOR_RULE='**Novel-vector scoping rule (from auditooor Issue #58):**

If you find a VARIANT of a known bug class (e.g., the known class is "reentrancy in withdraw()" and you find atomic callback reentrancy in a DIFFERENT function), it is a NOVEL finding eligible for submission. Do NOT dismiss an instance just because the CLASS is already documented. The test is:

- Is the (contract, function, attack-vector) tuple distinct from prior findings? → NOVEL
- Is the (contract, function) tuple identical to a prior finding, even via different code path? → HIGH DUPE RISK (see reference/DUPE_CAUSES.md — Issue #79)

Submit distinct (contract, function, attack-vector) tuples. Run tools/dupe-risk.sh before filing.'

# ---------------------------------------------------------------------------
# Assemble the prompt
# ---------------------------------------------------------------------------

{
cat <<HEADER
# Adversarial read prompt — ${CONTRACT_NAME}

**Generated by:** \`tools/adversarial-read.sh\`
**Contract:** \`${CONTRACT_ABS}\`
**Lines:** ${CONTRACT_LINE_COUNT}
**Workspace:** \`${WS}\`

Paste the entire contents of this file into Claude (or your preferred LLM).
Save the response to: \`${RESPONSE_TARGET}\`

---

## Instructions for the LLM

You are a senior smart-contract security researcher conducting an adversarial
read of the Solidity contract below. Your job is to think like a motivated,
technically capable attacker — not a generic checklist reviewer.

### Attacker capabilities to assume

The attacker is:
- An EOA with effectively unlimited on-chain capital (can flash-loan any amount)
- Able to call ANY externally-visible function in any order and with any arguments
- Able to deploy arbitrary helper contracts (reentrancy hooks, custom ERC20/ERC1155 tokens, callback receivers)
- Able to frontrun or sandwich any pending transaction (full mempool visibility)
- Able to receive ETH/ERC20/ERC1155 callbacks and re-enter from within them
- Able to control \`msg.sender\`, \`msg.value\`, calldata, and call sequence

The attacker CANNOT:
- Social-engineer off-chain signers or API operators
- Compromise private keys
- Bribe or coerce validators / block proposers
- Modify contract bytecode after deployment

### Economic goals (pick whichever applies to each scenario)

- **Extract value**: drain collateral, inflate own token balance, steal fees
- **Grief / DoS**: brick the contract, make key functions permanently revert for legitimate users
- **Replay state**: re-use a consumed order / signature / nonce
- **Privilege escalation**: gain OPERATOR or ADMIN role without authorization
- **Exfil**: force a transfer of assets to an attacker-controlled address

### Your task

Read the contract below like an attacker. For EACH of the 10 scenarios you
produce, output ALL of the following fields — no skipping:

\`\`\`
## Scenario N: <one-line title>

**Goal:** <what the attacker achieves — be specific, e.g. "drain 100% of USDC collateral held by the exchange">
**Capability needed:** <e.g. "ERC1155 receiver contract with reentrant transferFrom hook">
**Action sequence:**
1. Attacker deploys <X> implementing <Y>
2. Attacker calls <functionName>(<concrete args>)
3. Inside the callback, attacker calls <functionName2>(<args>)
4. <continue step by step until outcome is achieved>
**Required bug:** <which function would need to have a missing check / wrong ordering / absent guard for this attack to work — cite file:line>
**Economic outcome:** <$ extracted / users locked out / permanent DoS / etc — be specific>
**Probability this bug actually exists:** LOW / MEDIUM / HIGH  (based on your source review above)
\`\`\`

### Rules for quality

- Every scenario MUST reference at least one real function name from the source below.
- Every scenario MUST identify a specific line number (from the numbered source) where the required bug would live.
- Do NOT produce generic class descriptions ("there might be reentrancy"). Produce a concrete attack narrative specific to THIS contract's functions, state variables, and invariants.
- If a scenario requires a prerequisite external contract (e.g. CTF, collateral token), name the interface and the specific callback or function.
- Scenarios that require bugs you consider unlikely (LOW) are still useful — include them.
- Do NOT repeat scenarios that are already addressed by the Known Findings section below.

---

## Section 1 — Contract source (${CONTRACT_LINE_COUNT} lines, with line numbers)

\`\`\`solidity
${CONTRACT_LINED}
\`\`\`

---

## Section 2 — Known findings on this contract

The following findings are already documented in the workspace. Do NOT re-narrate
scenarios that exactly match a known finding — focus on novel angles.

\`\`\`
${FINDINGS_SECTION}
\`\`\`

---

## Section 2a — Pattern hits on this contract (Issue #81 priming)

These are concrete grep/pattern matches against this contract's source,
produced by \`tools/apply-patterns.sh\`. Use them as STARTING POINTS — for any
hit, trace whether the matched code path enables any of the attacker goals
above.

\`\`\`
${PATTERN_HITS_SECTION}
\`\`\`

---

## Section 2b — Prior-audit closures on this contract (Issue #81 priming)

These are classes the prior auditors explicitly investigated and closed. Do
NOT re-litigate these as "new" findings — but DO apply the novel-vector
scoping rule below.

\`\`\`
${PRIOR_CONCERNS_SECTION}
\`\`\`

---

## Section 2c — Scoping rule for "is this a re-find?"

${NOVEL_VECTOR_RULE}

---

## Section 3 — Begin adversarial scenarios

Now produce exactly 10 attack scenarios following the format above.
Label them ## Scenario 1 through ## Scenario 10.
HEADER

} > "$PROMPT_OUT"

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

PROMPT_LINES="$(wc -l < "$PROMPT_OUT" | tr -d ' ')"

echo "Prompt written: ${PROMPT_OUT}"
echo "Lines: ${PROMPT_LINES}"
echo ""
echo "Next step:"
echo "  Paste ${PROMPT_OUT} into Claude."
echo "  Save the response to: ${RESPONSE_TARGET}"
