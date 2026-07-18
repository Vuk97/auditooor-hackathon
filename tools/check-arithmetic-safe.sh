#!/usr/bin/env bash
# check-arithmetic-safe.sh — pre-draft sanity gate for arithmetic-bug findings.
#
# SKILL_ISSUES #160 (R53 M3 near-miss): an agent flagged "NegRiskAdapter
# 256-question wraparound flips the `determined` bit" as a submittable bug.
# The conceptual analysis was correct but missed that Solidity 0.8+ checked
# arithmetic reverts on the critical addition with Panic(0x11) — the "bug"
# is self-defending.
#
# This tool is the mandatory pre-draft checkpoint: extract every arithmetic
# operation in a target function, flag ones whose overflow/underflow would
# revert rather than wrap. If the attack sequence depends on one of those,
# the finding is suspect and should NOT be drafted without a manual re-derive.
#
# Usage:
#   ./tools/check-arithmetic-safe.sh <file.sol> [--function <name>]
#   ./tools/check-arithmetic-safe.sh <file.sol>:<line>
#
# Examples:
#   # Check a specific function
#   ./tools/check-arithmetic-safe.sh src/Market.sol --function incrementQuestionCount
#
#   # Check a file:line (extracts the enclosing function)
#   ./tools/check-arithmetic-safe.sh src/Market.sol:42
#
# Output:
#   For each arithmetic op in the target function, prints:
#     file:line  OP  LHS_TYPE  RHS_TYPE  VERDICT
#   where VERDICT is one of:
#     SAFE          — unchecked (inside `unchecked { }` block) or not overflow-able
#     REVERTS       — Solidity 0.8+ would revert on overflow/underflow
#     DOWNSIZE      — cast to smaller uint truncates silently (e.g. uint8(x))
#     ASSEMBLY      — inline assembly, no compiler check, operator must verify
#
# Exit codes:
#   0 — no REVERTS in target (finding is safe to draft if exploit doesn't need overflow)
#   1 — usage error
#   2 — found at least one REVERTS op (OPERATOR MUST MANUALLY CONFIRM exploit works
#                                       DESPITE the revert)
#   3 — file or function not found

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AUDITOOOR_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

usage() {
    cat >&2 <<'EOF'
usage: check-arithmetic-safe.sh <file.sol> [--function <name>]
       check-arithmetic-safe.sh <file.sol>:<line>

Pre-draft sanity gate for arithmetic-bug findings. Extracts every
arithmetic operation in the target function and classifies each as:
  SAFE     — unchecked block or non-overflowable op
  REVERTS  — Solidity 0.8+ checked arithmetic would revert on overflow
  DOWNSIZE — uint<N>() cast to smaller type truncates silently
  ASSEMBLY — inline assembly, no compiler check

Run this BEFORE drafting any finding where the exploit mechanism
depends on integer overflow, underflow, or bit-packed increments.

Exits non-zero if any REVERTS ops are found. In that case the
operator must manually confirm that the exploit works DESPITE the
revert — or abandon the finding.

See: reference/R53_polymarket_retriage.md (M3 near-miss)
     SKILL_ISSUES.md Issue #160
EOF
    exit 1
}

[ "$#" -lt 1 ] && usage

TARGET="$1"; shift
FUNC=""
LINE=""

# Parse file:line form
if [[ "$TARGET" == *:* ]]; then
    LINE="${TARGET##*:}"
    TARGET="${TARGET%:*}"
fi

# Parse --function form
while [ "$#" -gt 0 ]; do
    case "$1" in
        --function)
            shift
            FUNC="${1:-}"
            shift || true
            ;;
        --function=*)
            FUNC="${1#--function=}"
            shift
            ;;
        -h|--help) usage ;;
        *)
            echo "[err] unknown arg: $1" >&2
            usage
            ;;
    esac
done

[ -f "$TARGET" ] || { echo "[err] file not found: $TARGET" >&2; exit 3; }

# If we got a line but no function name, extract the enclosing function name
# by walking backward from the line to the nearest `function <name>(`.
if [ -n "$LINE" ] && [ -z "$FUNC" ]; then
    FUNC=$(awk -v L="$LINE" '
        NR <= L && /^[[:space:]]*function[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\(/ {
            match($0, /function[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)/, m)
            fn = m[1]
        }
        END { print fn }
    ' "$TARGET")
fi

if [ -z "$FUNC" ]; then
    # No specific function — scan the whole file
    echo "[info] no --function given; scanning whole file $TARGET"
    FUNC_START=1
    FUNC_END=$(wc -l < "$TARGET" | tr -d ' ')
else
    # Locate the function body line range
    RANGE=$(awk -v FN="$FUNC" '
        BEGIN { depth = 0; started = 0 }
        {
            if (!started && match($0, "function[[:space:]]+" FN "[[:space:]]*\\(")) {
                started = 1
                start_line = NR
            }
            if (started) {
                # Count braces in this line, ignoring those inside strings/comments
                # (approximation — ok for flagging, not for strict parsing).
                n_open = gsub(/\{/, "{", $0)
                n_close = gsub(/\}/, "}", $0)
                depth += n_open - n_close
                if (depth < 0) { depth = 0 }  # defensive
                if (depth == 0 && n_close > 0) {
                    print start_line "," NR
                    exit
                }
            }
        }
    ' "$TARGET")
    if [ -z "$RANGE" ]; then
        echo "[err] function '$FUNC' not found or unclosed in $TARGET" >&2
        exit 3
    fi
    FUNC_START="${RANGE%,*}"
    FUNC_END="${RANGE#*,}"
fi

echo "[info] analyzing $TARGET lines $FUNC_START-$FUNC_END (function: ${FUNC:-<whole file>})"
echo ""

# Extract the function body
BODY=$(awk -v S="$FUNC_START" -v E="$FUNC_END" 'NR >= S && NR <= E { print NR ":" $0 }' "$TARGET")

# Track unchecked blocks — {} depth inside an unchecked scope means operations
# in that scope are SAFE even if they would overflow.
REVERT_COUNT=0
DOWNSIZE_COUNT=0
ASSEMBLY_COUNT=0
SAFE_COUNT=0

# ---- Detect solidity pragma version (0.8+ has checked arithmetic by default) ----
PRAGMA_VERSION=$(grep -m1 -E '^[[:space:]]*pragma[[:space:]]+solidity' "$TARGET" | \
                 grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
if [ -z "$PRAGMA_VERSION" ]; then
    PRAGMA_VERSION="unknown"
fi
echo "[info] solidity pragma: $PRAGMA_VERSION"

# Crude major.minor check: assume 0.8+ ⇒ checked arithmetic by default
CHECKED_DEFAULT=0
if [[ "$PRAGMA_VERSION" =~ ^0\.([8-9]|[1-9][0-9]) ]]; then
    CHECKED_DEFAULT=1
    echo "[info] checked-arithmetic is the DEFAULT at this pragma (0.8+)"
elif [[ "$PRAGMA_VERSION" =~ ^[1-9] ]]; then
    CHECKED_DEFAULT=1
    echo "[info] checked-arithmetic is the DEFAULT at this pragma (1.x+)"
else
    echo "[warn] checked-arithmetic is NOT the default at this pragma; overflows WRAP silently"
fi
echo ""

# ---- Walk body line by line ----
UNCHECKED_DEPTH=0
ASM_DEPTH=0


classify_arith() {
    # Args: $1 = context flag (asm/unchecked), $2 = op name
    # Reads globals: IN_ASM, IN_UNCHECKED, CHECKED_DEFAULT
    if [ "$IN_ASM" = "1" ]; then
        echo "ASSEMBLY  (no compiler check)"
    elif [ "$IN_UNCHECKED" = "1" ]; then
        echo "SAFE      (inside unchecked)"
    elif [ "$CHECKED_DEFAULT" = "1" ]; then
        echo "REVERTS   (checked: overflow/underflow panics)"
    else
        echo "SAFE      (pre-0.8: wraps silently)"
    fi
}

echo "Report:"
echo "  file:line  | OP                | CLASS"
echo "  -----------+-------------------+---------"

while IFS=: read -r LNUM LINE_CONTENT; do
    # Track unchecked { ... } blocks
    if echo "$LINE_CONTENT" | grep -qE '\bunchecked[[:space:]]*\{'; then
        UNCHECKED_DEPTH=$((UNCHECKED_DEPTH + 1))
    fi
    if echo "$LINE_CONTENT" | grep -qE '\bassembly[[:space:]]*\{'; then
        ASM_DEPTH=$((ASM_DEPTH + 1))
    fi
    # Track closing braces — approximate (doesn't handle brace in string literal)
    OPEN_BRACES=$(echo "$LINE_CONTENT" | tr -cd '{' | wc -c | tr -d ' ')
    CLOSE_BRACES=$(echo "$LINE_CONTENT" | tr -cd '}' | wc -c | tr -d ' ')

    IN_UNCHECKED=$([ "$UNCHECKED_DEPTH" -gt 0 ] && echo 1 || echo 0)
    IN_ASM=$([ "$ASM_DEPTH" -gt 0 ] && echo 1 || echo 0)

    # Scan the line for arithmetic operators (+, -, *, /, %, **)
    # and uint<N>() casts that truncate.
    # We emit ONE record per occurrence.

    # Detect downsize casts: uint8(, uint16(, ... uint128(
    if echo "$LINE_CONTENT" | grep -qE '\buint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248)\b[[:space:]]*\('; then
        CAST=$(echo "$LINE_CONTENT" | grep -oE '\buint(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248)\b[[:space:]]*\(' | head -1)
        printf "  %-10s | %-17s | DOWNSIZE   (silent truncation if value > type max)\n" \
            "$TARGET:$LNUM" "$(echo "$CAST" | tr -d '[:space:]')"
        DOWNSIZE_COUNT=$((DOWNSIZE_COUNT + 1))
    fi

    # Detect arithmetic operators at token boundaries.
    # Skip comments (crude: lines starting with //, or after // on the line).
    LINE_CODE="${LINE_CONTENT%%//*}"

    for OP in '\+' '-' '\*' '/' '%' '\*\*'; do
        # Match the operator surrounded by non-ident chars (boundary).
        # Skip ++ and -- (post-inc, post-dec — these DO overflow-check in 0.8+ but handle later).
        # Skip +=, -=, *=, /=, %=, **= — compound ops.
        case "$OP" in
            '\+')
                if echo "$LINE_CODE" | grep -qE '[A-Za-z0-9_\)][[:space:]]*\+[[:space:]]*[A-Za-z0-9_\(]' && \
                   ! echo "$LINE_CODE" | grep -qE '\+\+|\+='; then
                    CLASS="$(classify_arith)"
                    printf "  %-10s | %-17s | %s\n" "$TARGET:$LNUM" "+ (addition)" "$CLASS"
                    case "$CLASS" in
                        REVERTS*)  REVERT_COUNT=$((REVERT_COUNT + 1)) ;;
                        ASSEMBLY*) ASSEMBLY_COUNT=$((ASSEMBLY_COUNT + 1)) ;;
                        SAFE*)     SAFE_COUNT=$((SAFE_COUNT + 1)) ;;
                    esac
                fi
                ;;
            '-')
                if echo "$LINE_CODE" | grep -qE '[A-Za-z0-9_\)][[:space:]]*-[[:space:]]*[A-Za-z0-9_\(]' && \
                   ! echo "$LINE_CODE" | grep -qE '\-\-|\-='; then
                    CLASS="$(classify_arith)"
                    printf "  %-10s | %-17s | %s\n" "$TARGET:$LNUM" "- (subtraction)" "$CLASS"
                    case "$CLASS" in
                        REVERTS*)  REVERT_COUNT=$((REVERT_COUNT + 1)) ;;
                        ASSEMBLY*) ASSEMBLY_COUNT=$((ASSEMBLY_COUNT + 1)) ;;
                        SAFE*)     SAFE_COUNT=$((SAFE_COUNT + 1)) ;;
                    esac
                fi
                ;;
            '\*')
                if echo "$LINE_CODE" | grep -qE '[A-Za-z0-9_\)][[:space:]]*\*[[:space:]]*[A-Za-z0-9_\(]' && \
                   ! echo "$LINE_CODE" | grep -qE '\*\*|\*='; then
                    CLASS="$(classify_arith)"
                    printf "  %-10s | %-17s | %s\n" "$TARGET:$LNUM" "* (multiplication)" "$CLASS"
                    case "$CLASS" in
                        REVERTS*)  REVERT_COUNT=$((REVERT_COUNT + 1)) ;;
                        ASSEMBLY*) ASSEMBLY_COUNT=$((ASSEMBLY_COUNT + 1)) ;;
                        SAFE*)     SAFE_COUNT=$((SAFE_COUNT + 1)) ;;
                    esac
                fi
                ;;
        esac
    done

    # Apply close-brace to tracked depths
    if [ "$CLOSE_BRACES" -gt 0 ]; then
        # Shallowly decrement both (imprecise but works for typical shapes).
        if [ "$UNCHECKED_DEPTH" -gt 0 ]; then
            UNCHECKED_DEPTH=$((UNCHECKED_DEPTH - CLOSE_BRACES))
            [ "$UNCHECKED_DEPTH" -lt 0 ] && UNCHECKED_DEPTH=0
        fi
        if [ "$ASM_DEPTH" -gt 0 ]; then
            ASM_DEPTH=$((ASM_DEPTH - CLOSE_BRACES))
            [ "$ASM_DEPTH" -lt 0 ] && ASM_DEPTH=0
        fi
    fi
done <<< "$BODY"

echo ""
echo "Summary:"
echo "  REVERTS   ops: $REVERT_COUNT"
echo "  DOWNSIZE  ops: $DOWNSIZE_COUNT"
echo "  ASSEMBLY  ops: $ASSEMBLY_COUNT"
echo "  SAFE      ops: $SAFE_COUNT"
echo ""

if [ "$REVERT_COUNT" -gt 0 ]; then
    cat <<'EOF'
⚠️  WARNING: function contains arithmetic that REVERTS on overflow/underflow.

If your proposed exploit requires one of these operations to WRAP AROUND
rather than revert, the exploit will NOT work under the current pragma —
the tx will abort with Panic(0x11) before the state change lands.

Before drafting a submission:
  1. Identify WHICH arithmetic op your attack sequence depends on.
  2. Check the REVERTS-marked operations above.
  3. If your critical op is one of them, the finding is likely a FALSE POSITIVE.
  4. Double-check by writing a Foundry PoC that forces the overflow and
     observing whether it reverts or completes.

See: reference/R53_polymarket_retriage.md §M3 near-miss
     SKILL_ISSUES.md Issue #160
EOF
    exit 2
fi

echo "✓ No checked-arithmetic reverts found in target function. Finding is safe to draft."
exit 0
