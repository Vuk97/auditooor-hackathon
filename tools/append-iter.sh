#!/usr/bin/env bash
# append-iter.sh — add a new iteration row to a workspace's SESSION_LOG.md
#
# Usage:
#   ./tools/append-iter.sh <workspace-dir> <iter-num> "description" [findings-delta] [pocs-added]
#   ./tools/append-iter.sh <workspace-dir> "description" [findings-delta] [pocs-added]
#       (iter-num auto-derived from the last row — preferred form)
#
# Adds a row to the "Iteration Index" table. The table is located by finding
# the last line matching `^| [0-9]+ |` and inserting after it.
#
# Fixes Issues 7, 22 from SKILL_ISSUES.md:
#   #7  — append-after-last-iter-row via awk
#   #22 — validate that iter-num is numeric; auto-derive from last row if only
#         a description is passed (so the caller cannot accidentally pass a long
#         description in the iter-num slot and corrupt the table)

set -uo pipefail

if [ $# -lt 2 ]; then
    cat <<EOF
Usage: $0 <workspace-dir> <iter-num> "description" [findings] [pocs]
       $0 <workspace-dir> "description" [findings] [pocs]   # iter-num auto-derived

Examples:
    $0 ~/audits/myproject 17 "Found XYZ via sonnet agent" 1
    $0 ~/audits/myproject "Found XYZ via sonnet agent" 1     # auto-num
EOF
    exit 1
fi

WS="$1"
SL="$WS/SESSION_LOG.md"
if [ ! -f "$SL" ]; then
    echo "Error: $SL not found"
    exit 1
fi

# Smart arg dispatch: if $2 looks numeric, treat it as iter-num; otherwise
# auto-derive iter-num from the last row and treat $2 as description.
if [[ "$2" =~ ^[0-9]+$ ]]; then
    N="$2"
    DESC="${3:-}"
    FINDINGS="${4:-0}"
    POCS="${5:-—}"
    if [ -z "$DESC" ]; then
        echo "Error: description required when iter-num is given explicitly"
        exit 1
    fi
else
    # Auto-derive: parse last iter row's number, add 1
    last_num=$(grep -oE '^\| +[0-9]+ +\|' "$SL" | tail -1 | tr -cd '0-9')
    if [ -z "$last_num" ]; then
        echo "Error: no prior iter rows found in $SL; pass iter-num explicitly"
        exit 1
    fi
    N=$((last_num + 1))
    DESC="$2"
    FINDINGS="${3:-0}"
    POCS="${4:-—}"
    echo "[auto] iter-num derived as $N (last was $last_num)"
fi

# Validate findings-delta is numeric (common fat-finger)
if ! [[ "$FINDINGS" =~ ^[0-9]+$ ]]; then
    echo "Error: findings-delta must be an integer, got: $FINDINGS"
    exit 1
fi

# Auto-escape bare pipes in description so they don't break the table shape.
# We replace `|` with the Unicode fullwidth vertical line U+FF5C (｜), which
# is visually ~identical to `|` but is not a markdown table delimiter. This
# avoids the awk -v variable-escape-interpretation footgun that plain `\|`
# would have to survive (awk -v assignment strips unknown backslash escapes).
ORIG_DESC="$DESC"
DESC=$(printf '%s' "$DESC" | sed 's/|/｜/g')
if [ "$DESC" != "$ORIG_DESC" ]; then
    echo "[auto] replaced | characters with fullwidth ｜ (U+FF5C) for table compatibility"
fi

TODAY=$(date +%Y-%m-%d)
NEW_ROW=$(printf "| %s | %s | %s | %s | %s |" "$N" "$TODAY" "$DESC" "$FINDINGS" "$POCS")

# Insert the new row after the last iter row via sed. Using sed+temp instead
# of awk -v to sidestep variable-escape interpretation of the new_row string.
tmpfile=$(mktemp)
awk -v new_row="$NEW_ROW" '
    /^\| +[0-9]+ +\|/ { last_iter_line = NR }
    { lines[NR] = $0 }
    END {
        for (i = 1; i <= NR; i++) {
            print lines[i]
            if (i == last_iter_line) {
                print new_row
            }
        }
    }
' "$SL" > "$tmpfile"

mv "$tmpfile" "$SL"
echo "Appended iter $N to $SL:"
echo "  $NEW_ROW"
