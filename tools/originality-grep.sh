#!/usr/bin/env bash
# originality-grep.sh — grep all audit corpora AND optionally the project source
#
# Usage:
#   ./tools/originality-grep.sh [--src <dir>] [--smart-expand] [--verbose] <keyword> [keyword2 ...]
#
# Patterns are EXTENDED regex (-E). Use `|` for alternation (NOT `\|`).
#
# Searches:
#   /tmp/audit_*.txt                        — target-specific audits
#   /tmp/cantina_*.txt                      — Cantina audit texts
#   /tmp/quantstamp_*.txt                   — Quantstamp audit texts
#   /tmp/hexens-reports/**/*.txt            — Hexens public archive (if cloned)
#   /tmp/zellic-reports/**/*.txt            — Zellic public archive (if cloned)
#   external/glider-query-db/queries/*.py   — Glider query database
#   <src-dir>/**/*.sol (if --src given)     — target project source
#
# Flags:
#   --src <dir>       Also grep <dir> for .sol matches (Issue 5)
#   --smart-expand    Expand the keyword against reference/originality_keywords.md
#                     to catch phrasing drift across audit firms (Issue 20)
#   --verbose         Print the exact grep command each call uses (Issue 21 debug)
#
# Fixes Issues 5, 20, 21 from SKILL_ISSUES.md.
#
# Exit status: 0 if any hits, 1 if clean (novel finding candidate)

set -uo pipefail

SRC_DIR=""
SMART_EXPAND=0
VERBOSE=0

while [ "${1:-}" = "--src" ] || [ "${1:-}" = "--smart-expand" ] || [ "${1:-}" = "--verbose" ]; do
    case "$1" in
        --src)
            SRC_DIR="$2"
            shift 2
            ;;
        --smart-expand)
            SMART_EXPAND=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            shift
            ;;
    esac
done

if [ $# -lt 1 ]; then
    echo "Usage: $0 [--src <dir>] [--smart-expand] [--verbose] <keyword1> [keyword2 ...]"
    echo "Patterns are extended regex (-E). Use | for alternation, NOT \\|."
    echo "Example: $0 'WRAPPER_ROLE|onlyRoles'"
    echo "Example: $0 --src /path/to/project/src 'MyFunction'"
    echo "Example: $0 --smart-expand 'reentrancy'"
    exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
HITS=0

# Smart-expand: consult the keyword library to broaden narrow single-word patterns
# into multi-phrasing alternations that catch how different audit firms write about
# the same bug class.
smart_expand_keyword() {
    local kw="$1"
    local lib="$AUDITOOOR_DIR/reference/originality_keywords.md"
    if [ ! -f "$lib" ]; then
        echo "$kw"
        return
    fi
    # Find a class whose name matches the input (case-insensitive substring) and
    # return its expanded pattern. The library uses `## <class>` headers and a
    # fenced `pattern:` line underneath. If no match, return the input unchanged.
    awk -v kw="$kw" '
        BEGIN { IGNORECASE=1; in_class=0; found_pattern="" }
        /^## / {
            header=substr($0,4)
            in_class = (index(tolower(header), tolower(kw)) > 0) ? 1 : 0
        }
        in_class && /^pattern:/ {
            sub(/^pattern:[ \t]*/, "")
            found_pattern=$0
            exit
        }
        END {
            if (found_pattern != "") print found_pattern
            else print kw
        }
    ' "$lib"
}

for raw_keyword in "$@"; do
    if [ $SMART_EXPAND -eq 1 ]; then
        keyword=$(smart_expand_keyword "$raw_keyword")
        if [ "$keyword" != "$raw_keyword" ]; then
            echo "[smart-expand] '$raw_keyword' → '$keyword'"
        fi
    else
        keyword="$raw_keyword"
    fi

    echo "======================================"
    echo "Keyword: $keyword"
    echo "======================================"

    if [ $VERBOSE -eq 1 ]; then
        echo "[verbose] grep pattern: $keyword"
    fi

    # 1. Project-specific audit PDFs extracted to /tmp
    if ls /tmp/audit_*.txt >/dev/null 2>&1 || ls /tmp/cantina_*.txt >/dev/null 2>&1 || ls /tmp/quantstamp_*.txt >/dev/null 2>&1; then
        echo ""
        echo "[Target-specific prior audits /tmp/audit_*.txt /tmp/cantina_*.txt /tmp/quantstamp_*.txt]"
        for pattern in "/tmp/audit_*.txt" "/tmp/cantina_*.txt" "/tmp/quantstamp_*.txt"; do
            for f in $pattern; do
                if [ -f "$f" ]; then
                    matches=$(grep -inE "$keyword" "$f" 2>/dev/null | head -5)
                    if [ -n "$matches" ]; then
                        echo "  $f:"
                        echo "$matches" | sed 's/^/    /'
                        HITS=$((HITS + 1))
                    fi
                fi
            done
        done
    else
        echo ""
        echo "[No /tmp/*.txt audit text files found — skipping. Extract PDFs with pypdf first.]"
    fi

    # 2. Hexens public archive
    if [ -d /tmp/hexens-reports ]; then
        echo ""
        echo "[Hexens public audit archive /tmp/hexens-reports]"
        matches=$(grep -rlnE "$keyword" /tmp/hexens-reports --include='*.txt' 2>/dev/null | head -10)
        if [ -n "$matches" ]; then
            echo "$matches" | sed 's/^/    /'
            HITS=$((HITS + 1))
        else
            echo "    (no hits)"
        fi
    else
        echo ""
        echo "[/tmp/hexens-reports not found — run ./tools/clone-hexens-reports.sh to enable]"
    fi

    # 2a. Zellic public archive (367+ reports — GTE CLOB, Hyperliquid, Drift, RabbitX, Orderly, Wasabi, etc.)
    if [ -d /tmp/zellic-reports ]; then
        echo ""
        echo "[Zellic public audit archive /tmp/zellic-reports]"
        matches=$(grep -rlnE "$keyword" /tmp/zellic-reports --include='*.txt' 2>/dev/null | head -10)
        if [ -n "$matches" ]; then
            echo "$matches" | sed 's/^/    /'
            HITS=$((HITS + 1))
        else
            echo "    (no hits)"
        fi
    else
        echo ""
        echo "[/tmp/zellic-reports not found — clone via: gh repo clone Zellic/publications /tmp/zellic-reports]"
    fi

    # 2b. Project source (if --src given)
    if [ -n "$SRC_DIR" ]; then
        echo ""
        echo "[Project source $SRC_DIR]"
        if [ -d "$SRC_DIR" ]; then
            src_matches=$(grep -rnE "$keyword" "$SRC_DIR" --include='*.sol' 2>/dev/null | head -10)
            if [ -n "$src_matches" ]; then
                echo "$src_matches" | sed 's/^/    /'
                HITS=$((HITS + 1))
            else
                echo "    (no hits in project source)"
            fi
        else
            echo "    ($SRC_DIR not found)"
        fi
    fi

    # 3. Glider query database
    echo ""
    echo "[Glider query database (external/glider-query-db/queries/)]"
    GLIDER_DIR="$AUDITOOOR_DIR/external/glider-query-db/queries"
    if [ -d "$GLIDER_DIR" ]; then
        # Search filenames
        filename_matches=$(ls "$GLIDER_DIR" 2>/dev/null | grep -iE "$keyword" | head -5)
        if [ -n "$filename_matches" ]; then
            echo "    Matching filenames:"
            echo "$filename_matches" | sed 's/^/      /'
            HITS=$((HITS + 1))
        fi
        # Search file contents
        content_matches=$(grep -rlnE "$keyword" "$GLIDER_DIR" 2>/dev/null | head -5)
        if [ -n "$content_matches" ]; then
            echo "    Matching content:"
            echo "$content_matches" | sed 's/^/      /'
            HITS=$((HITS + 1))
        fi
        if [ -z "$filename_matches" ] && [ -z "$content_matches" ]; then
            echo "    (no hits)"
        fi
    else
        echo "    (glider-query-db submodule not initialized — run 'git submodule update --init --recursive')"
    fi

    echo
done

echo "======================================"
if [ $HITS -eq 0 ]; then
    echo "NO HITS across any corpus. Finding is a candidate for novel submission."
    exit 1
else
    echo "$HITS hit(s) across corpora. Review each before claiming novelty."
    exit 0
fi
