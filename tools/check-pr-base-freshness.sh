#!/usr/bin/env bash
# tools/check-pr-base-freshness.sh — guard against PRs rooted on a stale base.
#
# Real-world catch (PR #139): a PR's branch was rooted at the PR #112 era while
# main had advanced through 7+ merged PRs. `git diff origin/main..HEAD --stat`
# showed 8,379 deletions because the branch had never picked up the post-#112
# work; merging would have silently wiped those lines. The catch was manual.
# This script (and its CI sibling) makes the catch automatic.
#
# Logic:
#   - "commits behind"  = git rev-list --count "$(merge-base)..origin/main"
#   - "deletions"       = sum of column-2 of `git diff --numstat origin/main..HEAD`
#
# Exit codes:
#   0 — fresh (within both thresholds)
#   1 — high deletions only (warning; informational)
#   2 — too many commits behind base (stale; rebase required)
#   3 — both stale base AND high deletions (treat as stale)
#
# Usage:
#   tools/check-pr-base-freshness.sh \
#       [--branch <name>] \
#       [--threshold-commits N] \
#       [--threshold-deletions N] \
#       [--remote <name>] \
#       [--base-branch <name>] \
#       [--no-fetch]
#
# Env-var equivalents (CLI flags win if both are set):
#   BASE_FRESHNESS_THRESHOLD_COMMITS    (default 20)
#   BASE_FRESHNESS_THRESHOLD_DELETIONS  (default 500)
#   BASE_FRESHNESS_REMOTE               (default origin)
#   BASE_FRESHNESS_BASE_BRANCH          (default main)
#   BASE_FRESHNESS_NO_FETCH             (set to 1 to skip `git fetch`)

set -euo pipefail

THRESHOLD_COMMITS="${BASE_FRESHNESS_THRESHOLD_COMMITS:-20}"
THRESHOLD_DELETIONS="${BASE_FRESHNESS_THRESHOLD_DELETIONS:-500}"
REMOTE="${BASE_FRESHNESS_REMOTE:-origin}"
BASE_BRANCH="${BASE_FRESHNESS_BASE_BRANCH:-main}"
NO_FETCH="${BASE_FRESHNESS_NO_FETCH:-0}"
BRANCH=""

while [ $# -gt 0 ]; do
    case "$1" in
        --branch)
            BRANCH="$2"; shift 2 ;;
        --threshold-commits)
            THRESHOLD_COMMITS="$2"; shift 2 ;;
        --threshold-deletions)
            THRESHOLD_DELETIONS="$2"; shift 2 ;;
        --remote)
            REMOTE="$2"; shift 2 ;;
        --base-branch)
            BASE_BRANCH="$2"; shift 2 ;;
        --no-fetch)
            NO_FETCH=1; shift ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0 ;;
        *)
            echo "[check-pr-base-freshness] ERR: unknown arg '$1'" >&2
            exit 64 ;;
    esac
done

if ! git rev-parse --git-dir >/dev/null 2>&1; then
    echo "[check-pr-base-freshness] ERR: not inside a git repo" >&2
    exit 64
fi

if [ "$NO_FETCH" != "1" ]; then
    # Best-effort fetch. Failing fetch is a hard error in CI but tolerated locally
    # via --no-fetch (used by hermetic tests with a pre-built local repo).
    git fetch "$REMOTE" "$BASE_BRANCH" >/dev/null 2>&1 || {
        echo "[check-pr-base-freshness] ERR: 'git fetch $REMOTE $BASE_BRANCH' failed" >&2
        exit 64
    }
fi

REMOTE_REF="${REMOTE}/${BASE_BRANCH}"
if ! git rev-parse --verify "$REMOTE_REF" >/dev/null 2>&1; then
    echo "[check-pr-base-freshness] ERR: ref '$REMOTE_REF' not found" >&2
    exit 64
fi

HEAD_REF="${BRANCH:-HEAD}"
if ! git rev-parse --verify "$HEAD_REF" >/dev/null 2>&1; then
    echo "[check-pr-base-freshness] ERR: ref '$HEAD_REF' not found" >&2
    exit 64
fi

BASE_SHA="$(git merge-base "$REMOTE_REF" "$HEAD_REF")"
COMMITS_BEHIND="$(git rev-list --count "${BASE_SHA}..${REMOTE_REF}")"
# numstat format: <added>\t<deleted>\t<path>. Deleted may be "-" for binary;
# coerce to 0 in that case so awk arithmetic stays safe.
DELETIONS="$(git diff --numstat "${REMOTE_REF}..${HEAD_REF}" \
    | awk '{ d = ($2 == "-" ? 0 : $2); total += d } END { print total + 0 }')"

echo "[check-pr-base-freshness] head=${HEAD_REF} base=${REMOTE_REF}"
echo "[check-pr-base-freshness] merge-base=${BASE_SHA}"
echo "[check-pr-base-freshness] commits-behind=${COMMITS_BEHIND} (threshold ${THRESHOLD_COMMITS})"
echo "[check-pr-base-freshness] deletions=${DELETIONS} (threshold ${THRESHOLD_DELETIONS})"

stale=0
deletions_high=0
if [ "$COMMITS_BEHIND" -gt "$THRESHOLD_COMMITS" ]; then
    stale=1
fi
if [ "$DELETIONS" -gt "$THRESHOLD_DELETIONS" ]; then
    deletions_high=1
fi

if [ "$stale" = "1" ] && [ "$deletions_high" = "1" ]; then
    echo "::error::PR base is ${COMMITS_BEHIND} commits behind ${REMOTE_REF} (threshold ${THRESHOLD_COMMITS}) AND diff shows ${DELETIONS} deletions (threshold ${THRESHOLD_DELETIONS}). Rebase before merge — likely a stale-base artifact." >&2
    exit 3
fi
if [ "$stale" = "1" ]; then
    echo "::error::PR base is ${COMMITS_BEHIND} commits behind ${REMOTE_REF} (threshold ${THRESHOLD_COMMITS}). Rebase before merge." >&2
    exit 2
fi
if [ "$deletions_high" = "1" ]; then
    echo "::warning::PR diff vs ${REMOTE_REF} shows ${DELETIONS} deletions (threshold ${THRESHOLD_DELETIONS}). Verify these are intentional, not stale-base artifacts." >&2
    exit 1
fi

echo "[check-pr-base-freshness] OK: branch is fresh."
exit 0
