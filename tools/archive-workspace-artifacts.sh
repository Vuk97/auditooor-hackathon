#!/usr/bin/env bash
# archive-workspace-artifacts.sh — preserve prior workspace artifacts before overwrite
#
# Usage: ./tools/archive-workspace-artifacts.sh <workspace-dir>
#
# Archives every known output artifact in <workspace> to
# <name>.<YYYY-MM-DD>.<N>.<ext> before any tool overwrites it. N is a
# run counter: first run today = 1, second = 2, etc.
#
# Call this at the top of any tool that writes to workspace artifacts.
# See SKILL_ISSUES #41 — NEVER DELETE FILES, always archive first.
#
# Artifacts covered:
#   static-analysis-summary.md
#   custom-detectors.log
#   slither.json
#   aderyn-report.md
#   semgrep.json
#
# Behavior:
#   - If an artifact file exists, copy it to an archive path.
#   - If no file exists, silently skip.
#   - Never deletes the source. Only copies.
#   - Archive naming: <stem>.<YYYY-MM-DD>.<N>.<ext>, where N auto-increments
#     if a previous archive from today already exists.
#   - Exits 0 on success, 1 on usage error.

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir>" >&2
    echo "Archives known output artifacts with a dated suffix before they are overwritten." >&2
    exit 1
fi

WS="$1"

if [ ! -d "$WS" ]; then
    echo "[archive] warn: $WS is not a directory — nothing to archive" >&2
    exit 0
fi

TODAY=$(date -u +%Y-%m-%d)

# Known output artifacts produced by run-slither.sh and friends.
ARTIFACTS=(
    "static-analysis-summary.md"
    "custom-detectors.log"
    "slither.json"
    "aderyn-report.md"
    "semgrep.json"
)

archived_count=0
for rel in "${ARTIFACTS[@]}"; do
    src="$WS/$rel"
    if [ ! -f "$src" ]; then
        continue
    fi

    # Split filename into stem + extension.
    stem="${rel%.*}"
    ext="${rel##*.}"
    # If the filename has no extension (e.g. `foo`), ext == stem.
    if [ "$ext" = "$rel" ]; then
        ext=""
        name_base="$stem"
    else
        name_base="$stem"
    fi

    # Find next free run counter for today.
    n=1
    while :; do
        if [ -n "$ext" ]; then
            archive_rel="${name_base}.${TODAY}.${n}.${ext}"
        else
            archive_rel="${name_base}.${TODAY}.${n}"
        fi
        dest="$WS/$archive_rel"
        if [ ! -e "$dest" ]; then
            break
        fi
        n=$((n + 1))
        # Sanity cap to avoid runaway loops (shouldn't happen in practice).
        if [ "$n" -gt 999 ]; then
            echo "[archive] error: too many existing archives for $rel today — aborting" >&2
            exit 2
        fi
    done

    cp -p "$src" "$dest"
    echo "[archive] $rel -> $archive_rel"
    archived_count=$((archived_count + 1))
done

if [ $archived_count -eq 0 ]; then
    echo "[archive] no prior artifacts in $WS — nothing to archive"
fi
exit 0
