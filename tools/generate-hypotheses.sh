#!/usr/bin/env bash
# generate-hypotheses.sh — scan-first hypothesis generator (SKILL_ISSUE #37)
#
# Runs BEFORE pattern-matching detectors to produce target-specific
# "what could go wrong" hypotheses.  Writes a prompt to
# <workspace>/HYPOTHESIS_PROMPT.md; the operator pastes it into Claude or
# feeds it to a sub-agent.  Zero LLM cost to run.
#
# Usage:
#   ./tools/generate-hypotheses.sh <workspace-dir> [--src <relative-src>] [--max <N>]
#
# Arguments:
#   <workspace-dir>   Audit workspace (must contain SCOPE.md, FINDINGS.md,
#                     static-analysis-summary.md).
#   --src <path>      Relative path inside <workspace-dir> to the Solidity
#                     source root.  Defaults to "src".
#   --max <N>         Number of hypotheses to request in the prompt.
#                     Defaults to 20.
#
# Output files written:
#   <workspace>/HYPOTHESIS_PROMPT.md  — ready-to-paste LLM prompt
#
# After running, the operator pastes HYPOTHESIS_PROMPT.md into Claude (or
# pipes it via the API) and saves the response to <workspace>/HYPOTHESES.md.
#
# Expected HYPOTHESES.md format (describe when sharing with teammates):
#
#   # Hypotheses for <project>
#   **Generated:** <date>
#   **Source:** `<workspace>/src/**/*.sol`
#
#   | # | Target | Class (P?) | Trigger | Impact |
#   |---|---|---|---|---|
#   | 1 | ContractA.fnX() | P5 guard-drift | mixin fn lacks nonReentrant | write-side reentrancy |
#   | 2 | ContractB.settle() | P8 partial-commit | try/catch skips rollback | phantom credit |
#   ...
#
# Why bash + manual paste, not agent invocation:
#   The operator's workflow is "scan-first, minimize agent tokens".  This
#   tool produces the prompt; the operator decides when and where to spend
#   the agent tokens.  Keeping it zero-cost to run means it can be run at
#   any point in the audit without token budget anxiety.
#
# Fixes SKILL_ISSUES.md #37.

set -uo pipefail

# ---- helpers ----------------------------------------------------------------

warn() { printf '[warn] %s\n' "$*" >&2; }
die()  { printf '[error] %s\n' "$*" >&2; exit 1; }

# ---- parse arguments --------------------------------------------------------

if [ $# -lt 1 ]; then
    cat >&2 <<'USAGE'
Usage: ./tools/generate-hypotheses.sh <workspace-dir> [--src <relative-src>] [--max <N>]

Arguments:
  <workspace-dir>   Audit workspace directory.
  --src <path>      Relative source root inside workspace (default: src).
  --max <N>         Number of hypotheses to request (default: 20).

Example:
  ./tools/generate-hypotheses.sh ~/audits/polymarket-v2
  ./tools/generate-hypotheses.sh ~/audits/aori --src src/exchange --max 30
USAGE
    exit 1
fi

WS="$1"; shift

SRC_REL="src"
MAX_HYPS=20

while [ $# -gt 0 ]; do
    case "$1" in
        --src)  SRC_REL="$2"; shift 2 ;;
        --max)  MAX_HYPS="$2"; shift 2 ;;
        *)      die "Unknown argument: $1" ;;
    esac
done

# ---- locate auditooor root --------------------------------------------------

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---- validate workspace -----------------------------------------------------

[ -d "$WS" ] || die "Workspace not found: $WS"

MISSING_DOCS=""
for doc in SCOPE.md FINDINGS.md static-analysis-summary.md; do
    if [ ! -f "$WS/$doc" ]; then
        warn "$WS/$doc missing — prompt will be incomplete"
        MISSING_DOCS="$MISSING_DOCS $doc"
    fi
done

SRC_DIR="$WS/$SRC_REL"
if [ ! -d "$SRC_DIR" ]; then
    warn "Source dir not found: $SRC_DIR — file list will be empty"
fi

PROJECT_NAME="$(basename "$WS")"
TODAY="$(date -u +%Y-%m-%d)"
PROMPT_OUT="$WS/HYPOTHESIS_PROMPT.md"

printf '\n=== generate-hypotheses: %s ===\n\n' "$PROJECT_NAME"
printf '  Source root : %s\n' "$SRC_DIR"
printf '  Hypotheses  : %d\n' "$MAX_HYPS"
printf '  Output      : %s\n\n' "$PROMPT_OUT"

# ---- collect source files (skip test/mock/lib/fixture) ----------------------

# Build the find command to collect .sol files, skipping non-production paths
if [ -d "$SRC_DIR" ]; then
    SOL_FILES="$(find "$SRC_DIR" -name "*.sol" \
        ! -path "*/test/*" \
        ! -path "*/tests/*" \
        ! -path "*/mock*" \
        ! -path "*/Mock*" \
        ! -path "*/lib/*" \
        ! -path "*/fixture*" \
        ! -path "*/Fixture*" \
        ! -path "*/script*" \
        2>/dev/null | sort)"
else
    SOL_FILES=""
fi

if [ -z "$SOL_FILES" ]; then
    warn "No .sol source files found under $SRC_DIR (excluding test/mock/lib/fixture)"
fi

FILE_COUNT=0
if [ -n "$SOL_FILES" ]; then
    FILE_COUNT=$(printf '%s\n' "$SOL_FILES" | wc -l | tr -d ' ')
fi
printf '  Source files: %d .sol files (excluding test/mock/lib/fixture)\n\n' "$FILE_COUNT"

# ---- build per-file skim (first 500 chars) ----------------------------------

SKIM_SECTION=""
if [ -n "$SOL_FILES" ]; then
    while IFS= read -r f; do
        rel="${f#$WS/}"
        snippet="$(head -c 500 "$f" 2>/dev/null | tr '\000-\010\013\014\016-\037' ' ')"
        SKIM_SECTION="${SKIM_SECTION}
### ${rel}

\`\`\`solidity
${snippet}
\`\`\`
"
    done <<< "$SOL_FILES"
fi

# ---- build full file list ---------------------------------------------------

FILE_LIST_SECTION=""
if [ -n "$SOL_FILES" ]; then
    while IFS= read -r f; do
        rel="${f#$WS/}"
        FILE_LIST_SECTION="${FILE_LIST_SECTION}- \`${rel}\`
"
    done <<< "$SOL_FILES"
fi

# ---- read workspace docs (graceful if missing) ------------------------------

SCOPE_CONTENT=""
if [ -f "$WS/SCOPE.md" ]; then
    SCOPE_CONTENT="$(cat "$WS/SCOPE.md")"
else
    SCOPE_CONTENT="(SCOPE.md not found — paste project description manually)"
fi

FINDINGS_CONTENT=""
if [ -f "$WS/FINDINGS.md" ]; then
    # Extract only the heading lines and class names (keep prompt compact)
    FINDINGS_CONTENT="$(grep -E '^#{1,3} |^\*\*Class\*\*|\*\*Severity\*\*|\*\*Status\*\*' "$WS/FINDINGS.md" | head -100 || true)"
    if [ -z "$FINDINGS_CONTENT" ]; then
        FINDINGS_CONTENT="(FINDINGS.md exists but no structured finding blocks found yet)"
    fi
else
    FINDINGS_CONTENT="(FINDINGS.md not found — no prior findings context)"
fi

STATIC_CONTENT=""
if [ -f "$WS/static-analysis-summary.md" ]; then
    STATIC_CONTENT="$(cat "$WS/static-analysis-summary.md")"
else
    STATIC_CONTENT="(static-analysis-summary.md not found — run ./tools/pre-iter-check.sh first)"
fi

# ---- read bug pattern catalog -----------------------------------------------

PAT_FILE="$AUDITOOOR_DIR/reference/bug_patterns_observed.md"
BUG_CATALOG=""
if [ -f "$PAT_FILE" ]; then
    BUG_CATALOG="$(cat "$PAT_FILE")"
else
    warn "Bug pattern catalog not found: $PAT_FILE"
    BUG_CATALOG="(bug_patterns_observed.md not found — install auditooor correctly)"
fi

# ---- emit prompt to HYPOTHESIS_PROMPT.md ------------------------------------

cat > "$PROMPT_OUT" <<PROMPT
# Hypothesis Generation Prompt — ${PROJECT_NAME}

**Generated:** ${TODAY}
**Workspace:** \`${WS}\`
**Source root:** \`${SRC_REL}/**/*.sol\`
**Files collected:** ${FILE_COUNT} .sol production files

> **Instructions for operator:** Paste this entire document into Claude (or
> send via API) and save the response to \`${WS}/HYPOTHESES.md\`.  The
> response MUST use the table format shown in the Task section below.

---

## Section 1 — Target context

### 1a. Scope

${SCOPE_CONTENT}

### 1b. Existing findings / known bug classes

The following classes have already been found or closed in this audit.
Do NOT re-generate hypotheses for these exact finding IDs — but DO look
for structurally similar variants in untouched code paths.

${FINDINGS_CONTENT}

### 1c. Static analysis summary

${STATIC_CONTENT}

---

## Section 2 — Bug pattern catalog (auditooor P1-P29)

The following are real bug classes observed in live audit engagements.
Each entry includes the class name, core mechanism, and code smell.
Use these as the canonical taxonomy for your hypothesis IDs.

${BUG_CATALOG}

---

## Section 3 — Source skim

Below is a file list followed by the first 500 characters of every
production Solidity file (test/mock/lib/fixture excluded).  Read the
skim to understand the codebase structure, then generate your hypotheses.

### File list

${FILE_LIST_SECTION}

### First-500-char skims

${SKIM_SECTION}

---

## Section 4 — Task

**Generate ${MAX_HYPS} hypotheses** about what could go wrong in THIS
codebase, structurally, matching one or more of the P1-P29 classes above.

Rules:
1. Each hypothesis MUST cite a real P-class from the catalog above.
2. Each hypothesis MUST name a specific function or code path in the
   source files listed — not a generic "any function".
3. Do NOT rehash findings already listed in Section 1b.
4. Prefer hypotheses with a concrete grep or cast command the auditor
   can run immediately to confirm or deny the trigger.
5. Order by estimated severity (highest first).

Output EXACTLY this Markdown table (add rows, keep the header):

\`\`\`markdown
# Hypotheses for ${PROJECT_NAME}

**Generated:** ${TODAY}
**Source:** \`${SRC_REL}/**/*.sol\`
**Prompt file:** \`${PROMPT_OUT}\`

| # | Target | Class (P?) | Trigger | Impact | Fast-check |
|---|---|---|---|---|---|
| 1 | ContractA.fnX() | P5 guard-drift | one-line description of the structural condition that would make this real | one-sentence impact if exploited | grep/cast command to confirm |
| 2 | ... | ... | ... | ... | ... |
\`\`\`

After the table, add a brief **Prioritization note** (3-5 sentences)
explaining which hypotheses to attack first and why.
PROMPT

# ---- summary ----------------------------------------------------------------

echo "Done."
echo ""
echo "  Prompt written to: $PROMPT_OUT"
if [ -n "$MISSING_DOCS" ]; then
    echo ""
    echo "  [warn] Missing docs (prompt will be less targeted):"
    for d in $MISSING_DOCS; do
        echo "           $WS/$d"
    done
fi
echo ""
echo "Next step:"
echo "  Now run the prompt through Claude and save output to ${WS}/HYPOTHESES.md"
echo ""
echo "  Quick API one-liner (requires ANTHROPIC_API_KEY):"
echo "    cat '${PROMPT_OUT}' | claude --model claude-opus-4-5 > '${WS}/HYPOTHESES.md'"
echo ""
echo "  Or paste HYPOTHESIS_PROMPT.md into Claude at claude.ai"
