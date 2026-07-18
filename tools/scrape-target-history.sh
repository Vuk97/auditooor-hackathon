#!/usr/bin/env bash
# scrape-target-history.sh — pull target's OWN git fix-commit history (Issue #127).
#
# The diff scraper in R32-R37 pulls Solodit-linked commits spanning many
# protocols. The HIGHEST-signal fix-deltas, however, come from the TARGET's
# own recent history — especially post-audit fixes from the target's last
# audit round. This tool walks `git log` of the target repo for security /
# fix commits, extracts each commit's diff, and pipes into mine-diffs-to-patterns.
#
# Usage:
#   ./tools/scrape-target-history.sh <target-repo-path> [--since YYYY-MM-DD] [--limit N]
#
# Output: patterns/fixtures/auto/target-<owner_repo>/<SHA>.{diff,meta.json}
# Then: run mine-diffs-to-patterns.py against that output to extract shapes.

set -u
REPO="${1:-}"
SINCE=""
LIMIT=50
shift 1 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --since) SINCE="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ -z "$REPO" ] || [ ! -d "$REPO/.git" ]; then
  echo "usage: $0 <target-repo-path> [--since YYYY-MM-DD] [--limit N]" >&2
  exit 2
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME=$(basename "$(cd "$REPO" && git config --get remote.origin.url 2>/dev/null | sed -E 's|.*/([^/]+)/([^/]+?)(\.git)?$|\1_\2|' || echo "unknown")")
if [ -z "$REPO_NAME" ] || [ "$REPO_NAME" = "unknown" ]; then
  REPO_NAME=$(basename "$REPO")
fi

OUT_DIR="$AUDITOOOR_DIR/patterns/fixtures/auto/target-$REPO_NAME"
mkdir -p "$OUT_DIR"

echo "[target-history] scanning $REPO → $OUT_DIR"
echo "[target-history] repo name: $REPO_NAME"

# Match security-ish commits. Keep broad — we prefer recall over precision.
PATTERN="(?i)(fix|sec|vuln|audit|CVE|advisory|patch|harden|secure|critical|bounded|validate|overflow|underflow|reentran|race|collision|stale|bypass|miss|wrong|incorrect)"

ARGS="--perl-regexp --grep=$PATTERN --no-merges -n $LIMIT"
[ -n "$SINCE" ] && ARGS="$ARGS --since=$SINCE"

CANDIDATES=$(cd "$REPO" && git log $ARGS --pretty=format:"%H|%ci|%s" 2>/dev/null)

if [ -z "$CANDIDATES" ]; then
  echo "[target-history] no matching commits found"
  exit 0
fi

COUNT=0
while IFS='|' read -r SHA DATE SUBJECT; do
  [ -z "$SHA" ] && continue
  SHORT_SHA="${SHA:0:12}"
  DIFF_OUT="$OUT_DIR/$SHORT_SHA.diff"
  META_OUT="$OUT_DIR/$SHORT_SHA.meta.json"

  if [ -f "$DIFF_OUT" ]; then
    continue
  fi

  (cd "$REPO" && git show --format='' "$SHA" -- '*.sol' > "$DIFF_OUT" 2>/dev/null)
  if [ ! -s "$DIFF_OUT" ]; then
    rm -f "$DIFF_OUT"
    continue
  fi

  # Escape subject for JSON
  ESCAPED=$(echo "$SUBJECT" | sed 's/"/\\"/g; s/\\/\\\\/g')
  cat > "$META_OUT" <<EOF
{
  "sha": "$SHA",
  "short_sha": "$SHORT_SHA",
  "date": "$DATE",
  "subject": "$ESCAPED",
  "repo": "$REPO_NAME",
  "source": "target-history"
}
EOF
  COUNT=$((COUNT + 1))
done <<< "$CANDIDATES"

echo "[target-history] extracted $COUNT commits"
echo "[target-history] next: python3 tools/mine-diffs-to-patterns.py --limit $COUNT  # or feed OUT_DIR explicitly"
