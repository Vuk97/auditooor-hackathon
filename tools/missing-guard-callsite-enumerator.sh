#!/usr/bin/env bash
# missing-guard-callsite-enumerator.sh — universal L30 helper.
#
# Purpose: when an existing guard is observable on at least one call site
# (e.g. validateTransferLeavesNotExitedToL1, onlyOwner, nonReentrant,
# whenNotPaused, requireAuth, accrueInterest, _lock), enumerate every other
# call site in the target tree that touches the protected resource but does
# NOT invoke the guard. Output is a CANDIDATE list for human triage per
# L30 step 6.
#
# Usage:
#   missing-guard-callsite-enumerator.sh <repo-root> <guard-name> <resource-pattern> [--language auto|go|sol|rs|ts|py] [--rust-trait-mode]
#
# Example (Spark receiver-side missing-guard pattern):
#   missing-guard-callsite-enumerator.sh \
#     ~/audits/spark/external/spark \
#     validateTransferLeavesNotExitedToL1 \
#     'TransferLeaf|leaf\.Status|claimLeaf'
#
# Example (Solidity missing onlyOwner):
#   missing-guard-callsite-enumerator.sh \
#     ~/audits/foo/external/contracts \
#     onlyOwner \
#     '_setBalance|_mint|_burn|_transfer'
#
# Example (Rust trait-method guard, auto-activates on Trait::method syntax):
#   missing-guard-callsite-enumerator.sh \
#     ~/audits/foo/external/crate \
#     'LeafGuard::validate_not_exited' \
#     'leaf_status|transfer_leaf' \
#     --language rs --rust-trait-mode
#
# --rust-trait-mode (Rust only):
#   Instead of a flat grep for <guard-name>, resolves dispatch through trait
#   impls. Steps:
#     1. Parse TraitName::method from <guard-name> (or just method if no ::)
#     2. Grep for `trait <TraitName>` definitions
#     3. Grep for `impl <TraitName> for <Type>` — collect concrete types
#     4. For each type, find call sites that consume an instance of that type
#        AND match <resource-pattern> but do NOT call the guard method
#   Output rows: <file>:<line>:<resource-callsite>  MISSING-GUARD:<guard-name>
#   Auto-activates when <guard-name> contains "::" and language is rs.
#
# Output:
#   GUARDED:    file:line  -- sites that DO call <guard-name>
#   UNGUARDED:  file:line  -- sites that touch <resource-pattern> but NOT <guard-name>
#                             (these are CANDIDATE filing exhibits per L30)
#
# Per L30: this tool emits candidates only. Human triage decides which
# candidates are real missing-guard exposures vs intentional non-coverage.
# The output is NOT a list of bugs — it is a list of paths to investigate.

set -uo pipefail

if [ $# -lt 3 ]; then
    sed -n '2,50p' "$0" | sed 's/^# //; s/^#//'
    exit 1
fi

REPO_ROOT="$1"
GUARD_NAME="$2"
RESOURCE_PATTERN="$3"
LANGUAGE="${4:-auto}"

if [ ! -d "$REPO_ROOT" ]; then
    echo "[error] repo root not a directory: $REPO_ROOT" >&2
    exit 2
fi

# Parse optional flags from all args (position-independent after arg 3).
RUST_TRAIT_MODE=0
for arg in "$@"; do
    if [ "$arg" = "--rust-trait-mode" ]; then
        RUST_TRAIT_MODE=1
    fi
done

# Auto-detect language from file extensions if not specified.
if [ "$LANGUAGE" = "--language" ] && [ -n "${5:-}" ]; then
    LANGUAGE="$5"
fi

# Strip --rust-trait-mode from LANGUAGE if it accidentally landed there.
if [ "$LANGUAGE" = "--rust-trait-mode" ]; then
    LANGUAGE="auto"
fi

if [ "$LANGUAGE" = "auto" ]; then
    if find "$REPO_ROOT" -maxdepth 4 -name "*.sol" 2>/dev/null | head -1 | grep -q "."; then
        LANGUAGE="sol"
    elif find "$REPO_ROOT" -maxdepth 4 -name "*.go" 2>/dev/null | head -1 | grep -q "."; then
        LANGUAGE="go"
    elif find "$REPO_ROOT" -maxdepth 4 -name "*.rs" 2>/dev/null | head -1 | grep -q "."; then
        LANGUAGE="rs"
    elif find "$REPO_ROOT" -maxdepth 4 -name "*.ts" -o -name "*.tsx" 2>/dev/null | head -1 | grep -q "."; then
        LANGUAGE="ts"
    elif find "$REPO_ROOT" -maxdepth 4 -name "*.py" 2>/dev/null | head -1 | grep -q "."; then
        LANGUAGE="py"
    else
        echo "[warn] could not auto-detect language; falling back to all-text grep" >&2
        LANGUAGE="all"
    fi
fi

# Auto-activate rust-trait-mode when guard-name contains '::' and language is rs.
if [ "$LANGUAGE" = "rs" ] && echo "$GUARD_NAME" | grep -q "::"; then
    RUST_TRAIT_MODE=1
fi

case "$LANGUAGE" in
    sol)  EXT_FILTER='--include=*.sol' ;;
    go)   EXT_FILTER='--include=*.go --exclude=*_test.go' ;;
    rs)   EXT_FILTER='--include=*.rs' ;;
    ts)   EXT_FILTER='--include=*.ts --include=*.tsx' ;;
    py)   EXT_FILTER='--include=*.py --exclude=test_*.py' ;;
    all)  EXT_FILTER='' ;;
    *)    echo "[error] unsupported language: $LANGUAGE" >&2; exit 3 ;;
esac

EXCLUDE_DIRS='--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=target --exclude-dir=dist --exclude-dir=build'

echo "============================================================"
echo "  missing-guard-callsite-enumerator (L30 helper)"
echo "============================================================"
echo "  repo:      $REPO_ROOT"
echo "  guard:     $GUARD_NAME"
echo "  resource:  $RESOURCE_PATTERN"
echo "  language:  $LANGUAGE  (filter: ${EXT_FILTER:-none})"
echo "  rust-trait-mode: $RUST_TRAIT_MODE"
echo "============================================================"
echo ""

# ============================================================
# Rust trait-method enumeration mode (--rust-trait-mode / auto)
# ============================================================
# When active, resolves guard dispatch through trait impls:
#   1. Parse TraitName + method from <guard-name> (Trait::method form)
#   2. Find `trait <TraitName>` definitions (confirms trait exists)
#   3. Find `impl <TraitName> for <Type>` — collect concrete impl types
#   4. For each .rs file: check if it consumes one of those types AND
#      matches <resource-pattern> but does NOT call the guard method
# Falls back to flat-grep if trait name cannot be parsed.
# ============================================================
if [ "$RUST_TRAIT_MODE" = "1" ] && [ "$LANGUAGE" = "rs" ]; then
    # Parse Trait::method or plain method from GUARD_NAME.
    if echo "$GUARD_NAME" | grep -q "::"; then
        TRAIT_NAME=$(echo "$GUARD_NAME" | sed 's/::.*$//')
        GUARD_METHOD=$(echo "$GUARD_NAME" | sed 's/^.*:://')
    else
        TRAIT_NAME=""
        GUARD_METHOD="$GUARD_NAME"
    fi

    echo "  [rust-trait-mode] trait: ${TRAIT_NAME:-<none>}  method: $GUARD_METHOD"
    echo ""

    # Step T1: locate trait definition.
    if [ -n "$TRAIT_NAME" ]; then
        echo "TRAIT DEFINITION sites (trait $TRAIT_NAME):"
        echo "------------------------------------------------------------"
        TRAIT_DEFS=$(grep -rn $EXCLUDE_DIRS --include='*.rs' -E "trait[[:space:]]+${TRAIT_NAME}[[:space:]]*(:|\\{|<)" "$REPO_ROOT" 2>/dev/null | grep -v "^Binary file" | sort -u || true)
        if [ -z "$TRAIT_DEFS" ]; then
            echo "  (none — trait '$TRAIT_NAME' not found; falling back to flat-grep)"
            RUST_TRAIT_MODE=0
        else
            echo "$TRAIT_DEFS" | sed 's/^/  /'
        fi
    fi
    echo ""

    if [ "$RUST_TRAIT_MODE" = "1" ] && [ -n "$TRAIT_NAME" ]; then
        # Step T2: find all `impl <TraitName> for <Type>` — collect impl-target types.
        echo "IMPL sites (impl $TRAIT_NAME for <Type>):"
        echo "------------------------------------------------------------"
        IMPL_LINES=$(grep -rn $EXCLUDE_DIRS --include='*.rs' -E "impl[[:space:]]+(<[^>]+>[[:space:]]+)?${TRAIT_NAME}[[:space:]]*(for|<)" "$REPO_ROOT" 2>/dev/null | grep -v "^Binary file" | sort -u || true)
        if [ -z "$IMPL_LINES" ]; then
            echo "  (none — no impls of '$TRAIT_NAME' found)"
        else
            echo "$IMPL_LINES" | sed 's/^/  /'
        fi
        echo ""

        # Extract concrete type names from impl lines.
        # Pattern: `impl [<T>] TraitName for TypeName` → capture TypeName word before { or <
        IMPL_TYPES=$(echo "$IMPL_LINES" | grep -oE "for[[:space:]]+[A-Za-z_][A-Za-z0-9_]*" | awk '{print $2}' | sort -u || true)

        echo "  [rust-trait-mode] resolved impl types: $(echo "$IMPL_TYPES" | tr '\n' ' ')"
        echo ""

        # Step T3: for each .rs file, check if it consumes one of those types
        # AND matches resource-pattern but does NOT call the guard method.
        echo "TRAIT-DISPATCH CANDIDATE sites (resource match, no guard method call):"
        echo "  (Per L30: per-file granularity; files where impl-type is used + resource touched, guard absent)"
        echo "------------------------------------------------------------"

        CANDIDATE_FILES=""
        ALL_RS_FILES=$(find "$REPO_ROOT" -name "*.rs" -not -path "*/.git/*" -not -path "*/target/*" 2>/dev/null | sort)

        for rs_file in $ALL_RS_FILES; do
            # Does this file touch the resource pattern?
            if ! grep -qE "$RESOURCE_PATTERN" "$rs_file" 2>/dev/null; then
                continue
            fi

            # Does this file call the guard method? If yes → SAFE.
            if grep -qE "\b${GUARD_METHOD}\b" "$rs_file" 2>/dev/null; then
                continue
            fi

            # Does this file reference at least one impl-type or the trait name?
            TYPE_HIT=0
            if [ -n "$IMPL_TYPES" ]; then
                for t in $IMPL_TYPES; do
                    if grep -qE "\b${t}\b" "$rs_file" 2>/dev/null; then
                        TYPE_HIT=1
                        break
                    fi
                done
            fi
            # Also flag if the file references the trait name itself (generic dispatch).
            if grep -qE "\b${TRAIT_NAME}\b" "$rs_file" 2>/dev/null; then
                TYPE_HIT=1
            fi

            if [ "$TYPE_HIT" = "1" ]; then
                CANDIDATE_FILES="${CANDIDATE_FILES}${rs_file}
"
            fi
        done

        CANDIDATE_FILES=$(echo "$CANDIDATE_FILES" | grep -v "^$" | sort -u || true)

        if [ -z "$CANDIDATE_FILES" ]; then
            echo "  (none — every file touching resource also calls the guard method, or no impl-type references found)"
            echo ""
            echo "[verdict] No trait-dispatch missing-guard candidates."
            exit 0
        fi

        echo "$CANDIDATE_FILES" | sed 's/^/  /'
        echo ""

        echo "============================================================"
        echo "  Per-file trait-dispatch unguarded line excerpts:"
        echo "============================================================"
        for f in $CANDIDATE_FILES; do
            echo ""
            echo "  --- $f ---"
            echo "    [resource matches]"
            grep -nE "$RESOURCE_PATTERN" "$f" 2>/dev/null | head -10 | sed 's/^/      /'
            echo "    [guard method absent — $GUARD_METHOD not called in this file]"
        done

        echo ""
        echo "============================================================"
        echo "  Trait-mode output format per call site:"
        echo "    <file>:<line>:<resource-match>  MISSING-GUARD:$GUARD_NAME"
        echo "============================================================"
        for f in $CANDIDATE_FILES; do
            grep -nE "$RESOURCE_PATTERN" "$f" 2>/dev/null | while IFS=: read -r lineno rest; do
                echo "${f}:${lineno}:${rest}  MISSING-GUARD:${GUARD_NAME}"
            done
        done

        echo ""
        echo "============================================================"
        echo "  Triage instructions per L30 step 6:"
        echo "  For each UNGUARDED CANDIDATE file/line, classify as:"
        echo "    (a) REAL missing-guard exposure — attacker-reachable, file as exhibit"
        echo "    (b) INTENTIONAL non-coverage — guard not needed (read code + comments)"
        echo "    (c) DIFFERENT guard covers it — verify the alternate guard"
        echo ""
        echo "  ONLY (a) candidates become exhibits in your filed report."
        echo "  ALL (a) candidates go in ONE report, not N reports (per L30/L31)."
        echo "============================================================"
        exit 0
    fi
fi

# ============================================================
# AST-EXACT call-site enumeration (Glider gap #4, Solidity only)
# ============================================================
# When the language is Solidity AND Slither can compile the tree, enumerate the
# guard's call sites AST-exactly via tools/callsite-selector.py. This is a
# SUPERSET-or-equal of the grep path below: it ALSO catches renamed-import
# aliases, overloads-by-signature, and virtual/override/interface dispatch that
# a name-only grep silently misses. R80 (never-regress): if the selector is
# unavailable or DEGRADES (rc=3 / non-zero), we fall through to the grep path
# UNCHANGED - no crash, no silent miss vs the old behaviour.
#
# The AST block is ADDITIVE: it prints an `AST-EXACT GUARDED call sites` table
# (the complete call-site set the finding's `## Enumerated Call Sites` section
# CONSUMES for pre-submit Check #48) on top of the grep file-level subtraction,
# which still runs verbatim. The `<file>:<line>` AST set is never SMALLER than
# the grep `\b$GUARD_NAME\b` site set for the same guard.
SELECTOR_PY="$(dirname "$0")/callsite-selector.py"
if [ "$LANGUAGE" = "sol" ] && [ -f "$SELECTOR_PY" ]; then
    PYBIN="${AUDITOOOR_SLITHER_PYTHON:-python3}"
    AST_OUT=$("$PYBIN" "$SELECTOR_PY" --target "$GUARD_NAME" --path "$REPO_ROOT" 2>/dev/null)
    AST_RC=$?
    if [ "$AST_RC" -eq 0 ]; then
        echo "AST-EXACT GUARDED call sites (Glider gap #4 - alias/overload/dispatch resolved):"
        echo "  (Slither-resolved; SUPERSET-or-equal of the grep path below. These are the"
        echo "   complete call sites the finding's '## Enumerated Call Sites' section CONSUMES.)"
        echo "------------------------------------------------------------"
        echo "$AST_OUT" | grep -E ':[0-9]+  ' | sed 's/^/  /' || echo "  (no AST call sites resolved)"
        echo ""
    else
        echo "[gap#4] AST call-site selector unavailable/degraded (rc=$AST_RC) - using grep path (R80 fallback)."
        echo ""
    fi
fi

# ============================================================
# Default path: flat grep for all languages (Solidity / Go / Rust / TS / Py)
# ============================================================

# Step 1: find all sites that call the guard. These are SAFE.
echo "GUARDED sites (call $GUARD_NAME):"
echo "------------------------------------------------------------"
GUARDED_FILES=$(grep -rn $EXCLUDE_DIRS $EXT_FILTER -E "\b$GUARD_NAME\b" "$REPO_ROOT" 2>/dev/null | grep -v "^Binary file" | sort -u || true)
if [ -z "$GUARDED_FILES" ]; then
    echo "  (none — guard $GUARD_NAME not found in repo; cannot enumerate)"
    echo ""
    echo "[warn] No callers of '$GUARD_NAME' found. Either:"
    echo "  - the guard name is misspelled or scoped to a different path"
    echo "  - the guard does not yet exist (greenfield missing-guard hunt)"
    echo "  - the guard is a modifier / decorator and the call-site form differs"
    exit 4
fi
echo "$GUARDED_FILES" | sed 's/^/  /'
echo ""

# Step 2: find all sites that touch the protected resource.
echo "RESOURCE-TOUCHING sites (match $RESOURCE_PATTERN):"
echo "------------------------------------------------------------"
RESOURCE_FILES=$(grep -rn $EXCLUDE_DIRS $EXT_FILTER -E "$RESOURCE_PATTERN" "$REPO_ROOT" 2>/dev/null | grep -v "^Binary file" | sort -u || true)
if [ -z "$RESOURCE_FILES" ]; then
    echo "  (none — resource pattern '$RESOURCE_PATTERN' not found)"
    exit 5
fi

# Step 3: subtract. Resource sites NOT in guarded set = candidates.
GUARDED_FILE_LIST=$(echo "$GUARDED_FILES" | awk -F: '{print $1}' | sort -u)
RESOURCE_FILE_LIST=$(echo "$RESOURCE_FILES" | awk -F: '{print $1}' | sort -u)

CANDIDATE_FILES=$(comm -23 <(echo "$RESOURCE_FILE_LIST") <(echo "$GUARDED_FILE_LIST"))

echo ""
echo "UNGUARDED CANDIDATE files (touch resource, no guard call):"
echo "  (Per L30: these are CANDIDATE FILING EXHIBITS pending human triage)"
echo "------------------------------------------------------------"
if [ -z "$CANDIDATE_FILES" ]; then
    echo "  (none — every resource-touching file also calls the guard)"
    echo ""
    echo "[verdict] No missing-guard candidates at file-level granularity."
    echo "          Consider tightening RESOURCE_PATTERN or extending to"
    echo "          per-function granularity manually."
    exit 0
fi
echo "$CANDIDATE_FILES" | sed 's/^/  /'

echo ""
echo "============================================================"
echo "  Per-file unguarded line excerpts:"
echo "============================================================"
for f in $CANDIDATE_FILES; do
    echo ""
    echo "  --- $f ---"
    grep -nE "$RESOURCE_PATTERN" "$f" 2>/dev/null | head -10 | sed 's/^/    /'
done

echo ""
echo "============================================================"
echo "  Triage instructions per L30 step 6:"
echo "  For each UNGUARDED CANDIDATE file/line, classify as:"
echo "    (a) REAL missing-guard exposure — attacker-reachable, file as exhibit"
echo "    (b) INTENTIONAL non-coverage — guard not needed (read code + comments)"
echo "    (c) DIFFERENT guard covers it — verify the alternate guard"
echo ""
echo "  ONLY (a) candidates become exhibits in your filed report."
echo "  ALL (a) candidates go in ONE report, not N reports (per L30/L31)."
echo "============================================================"
