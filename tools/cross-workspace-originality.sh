#!/usr/bin/env bash
# cross-workspace-originality.sh — check whether a candidate finding's text
# appears in ANY existing workspace's submission trackers, PoC markdown, or
# submissions/staging/. Prevents accidental cross-engagement re-submission.
#
# This complements `originality-grep.sh`, which only checks
# /tmp/audit_*.txt corpora (prior third-party audits). This tool checks
# OUR OWN prior submissions across every audit workspace.
#
# Usage:
#   ./tools/cross-workspace-originality.sh [--workspaces <root>] [--strict]
#                                          [--exclude <ws-name>] <keyword> [keyword2 ...]
#
# Searches by default:
#   ~/audits/<ws>/submissions/SUBMISSIONS.md
#   ~/audits/<ws>/submissions/*.md
#   ~/audits/<ws>/submissions/staging/*.md
#   ~/audits/<ws>/pocs/*.md
#   ~/audits/<ws>/findings/*.md  (older layout)
#   ~/audits/<ws>/SUBMISSIONS.md  (legacy root tracker)
#
# Multiple keywords are AND-joined with `.*` (loose-order match), useful for
# "find any submission that mentions both 'oracle' and 'circuit_breaker'".
#
# Flags:
#   --workspaces <root>   Override audit-workspace root (default: $HOME/audits,
#                         or $AUDITS_DIR when exported)
#   --exclude <ws-name>   Skip this workspace (e.g. when querying for the
#                         workspace you're currently in, to avoid self-match)
#   --strict              Exit non-zero if ANY match found (use in CI gate)
#   --json                Emit machine-readable JSON instead of human-readable
#   --verbose             Print each grep command and full matching lines
#
# Exit codes:
#   0  No matches found across any workspace (or --strict not set)
#   1  Match found AND --strict set
#   2  Usage error

set -u

DEFAULT_WS_ROOT="${AUDITS_DIR:-$HOME/audits}"
WS_ROOT="$DEFAULT_WS_ROOT"
EXCLUDE=""
STRICT=0
JSON=0
VERBOSE=0
KEYWORDS=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --workspaces) WS_ROOT="$2"; shift 2 ;;
        --exclude)    EXCLUDE="$2"; shift 2 ;;
        --strict)     STRICT=1; shift ;;
        --json)       JSON=1; shift ;;
        --verbose)    VERBOSE=1; shift ;;
        --help|-h)
            head -50 "$0" | grep '^#' | sed 's|^#||'
            exit 0
            ;;
        --) shift; break ;;
        -*) echo "[err] unknown flag: $1" >&2; exit 2 ;;
        *)  KEYWORDS+=("$1"); shift ;;
    esac
done

# Trailing positional args after `--`
while [ "$#" -gt 0 ]; do
    KEYWORDS+=("$1"); shift
done

if [ "${#KEYWORDS[@]}" -eq 0 ]; then
    echo "[err] no keywords provided" >&2
    echo "usage: $0 [--workspaces <root>] [--exclude <ws>] [--strict] [--json] [--verbose] <kw> [kw2 ...]" >&2
    exit 2
fi

if [ ! -d "$WS_ROOT" ]; then
    echo "[err] workspace root not a directory: $WS_ROOT" >&2
    exit 2
fi

# Build the AND-joined regex
JOINED=""
for kw in "${KEYWORDS[@]}"; do
    if [ -z "$JOINED" ]; then
        JOINED="$kw"
    else
        # Use case-insensitive grep -i; AND combine via positive lookahead emulation:
        # we'll grep-pipe instead since lookaheads need PCRE.
        JOINED="$JOINED|$kw"
    fi
done

# For multi-keyword AND we use `grep -i kw1 | grep -i kw2 | ...`. For 1 keyword
# we fall through to a single pattern.
single_query() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return 1
    fi
    local cmd="grep -inE \"${KEYWORDS[0]}\" \"$file\""
    for ((i=1; i < ${#KEYWORDS[@]}; i++)); do
        cmd="$cmd | grep -iE \"${KEYWORDS[$i]}\""
    done
    if [ "$VERBOSE" -eq 1 ]; then
        echo "[cmd] $cmd" >&2
    fi
    eval "$cmd" 2>/dev/null
}

TOTAL_HITS=0
declare -a HIT_WORKSPACES=()

if [ "$JSON" -eq 1 ]; then
    echo "{"
    echo "  \"keywords\": [$(printf '"%s",' "${KEYWORDS[@]}" | sed 's/,$//')]"
    echo "  ,\"workspaces\": ["
fi

FIRST_WS=1
for ws_dir in "$WS_ROOT"/*/; do
    ws_name="$(basename "$ws_dir")"
    if [ "$ws_name" = "$EXCLUDE" ]; then
        continue
    fi

    # Collect candidate files
    files=()
    for pattern in \
        "$ws_dir/submissions/SUBMISSIONS.md" \
        "$ws_dir/submissions/"*.md \
        "$ws_dir/submissions/staging/"*.md \
        "$ws_dir/pocs/"*.md \
        "$ws_dir/findings/"*.md \
        "$ws_dir/SUBMISSIONS.md"; do
        for f in $pattern; do
            [ -f "$f" ] && files+=("$f")
        done
    done

    if [ "${#files[@]}" -eq 0 ]; then
        continue
    fi

    ws_hit_count=0
    declare -a ws_top_hits=()

    for f in "${files[@]}"; do
        hits=$(single_query "$f" || true)
        if [ -n "$hits" ]; then
            n=$(echo "$hits" | wc -l | tr -d ' ')
            ws_hit_count=$((ws_hit_count + n))
            # Capture first matching line as a sample
            first_hit=$(echo "$hits" | head -1)
            ws_top_hits+=("$f:$first_hit")
        fi
    done

    if [ "$ws_hit_count" -gt 0 ]; then
        TOTAL_HITS=$((TOTAL_HITS + ws_hit_count))
        HIT_WORKSPACES+=("$ws_name")
        if [ "$JSON" -eq 1 ]; then
            [ "$FIRST_WS" -eq 0 ] && echo "    ,"
            FIRST_WS=0
            echo "    {\"workspace\":\"$ws_name\",\"hit_count\":$ws_hit_count,\"sample\":\"$(echo "${ws_top_hits[0]}" | sed 's/"/\\"/g' | head -c 300)\"}"
        else
            echo "[$ws_name] $ws_hit_count hits across ${#files[@]} files"
            for hit in "${ws_top_hits[@]:0:3}"; do
                echo "    $hit" | head -c 200
                echo
            done
        fi
    fi
done

if [ "$JSON" -eq 1 ]; then
    echo "  ]"
    echo "  ,\"total_hits\": $TOTAL_HITS"
    echo "  ,\"workspaces_with_hits\": [$(printf '"%s",' "${HIT_WORKSPACES[@]}" | sed 's/,$//')]"
    echo "  ,\"verdict\": \"$([ "$TOTAL_HITS" -eq 0 ] && echo "NEW" || echo "DUPE")\""
    echo "}"
else
    echo
    echo "=== verdict ==="
    if [ "$TOTAL_HITS" -eq 0 ]; then
        echo "NEW — no matches across any workspace under $WS_ROOT"
    else
        echo "DUPE — $TOTAL_HITS total hits across workspaces: ${HIT_WORKSPACES[*]}"
        echo
        echo "Risk class:"
        if [ "${#HIT_WORKSPACES[@]}" -eq 1 ]; then
            echo "  SAME-WORKSPACE-DUPE: only matches in ${HIT_WORKSPACES[0]}, likely the same engagement"
        else
            echo "  CROSS-WORKSPACE-DUPE: matches in ${#HIT_WORKSPACES[@]} workspaces — review before re-submitting"
        fi
    fi
fi

if [ "$STRICT" -eq 1 ] && [ "$TOTAL_HITS" -gt 0 ]; then
    exit 1
fi
exit 0
