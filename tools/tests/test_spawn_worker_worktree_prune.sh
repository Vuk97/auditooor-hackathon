#!/usr/bin/env bash
# <!-- r36-rebuttal: lane L37-SPAWN-WORKER-WORKTREE-PRUNE registered via agent-pathspec-register.py -->
# Guard: spawn-worker.sh GCs STALE per-lane worktrees (disk-leak fix).
#
# Each hunt lane provisions a ~2.4G /tmp/auditooor-lane-* worktree; unpruned they
# fill the disk (observed: 32 dirs -> 100% on 460G -> silent write failures).
# This asserts (1) the prune hook exists + is called, and (2) the selection
# logic removes lane dirs OLDER than the TTL while preserving fresh ones.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPAWN="$SCRIPT_DIR/../spawn-worker.sh"
fail() { echo "FAIL: $1" >&2; exit 1; }

# (1) hook present + invoked
grep -q 'prune_stale_lane_worktrees()' "$SPAWN" || fail "prune function missing"
grep -qE '^prune_stale_lane_worktrees$' "$SPAWN" || fail "prune function not invoked at entry"
grep -q 'AUDITOOOR_LANE_WORKTREE_TTL_HOURS' "$SPAWN" || fail "TTL env knob missing"

# (2) selection logic: stale matched, fresh preserved (replicates the find used)
base="$(mktemp -d)"
trap 'rm -rf "$base"' EXIT
stale="$base/auditooor-lane-STALE-deadbee"
fresh="$base/auditooor-lane-FRESH-cafef00"
unrelated="$base/some-other-tmp-dir"
mkdir -p "$stale" "$fresh" "$unrelated"
# age the stale dir well past a 6h TTL (touch 10h ago)
touch -t "$(date -v-10H +%Y%m%d%H%M 2>/dev/null || date -d '10 hours ago' +%Y%m%d%H%M)" "$stale"

# uses `find -L` to follow the macOS /tmp -> /private/tmp symlink (the real bug)
ttl_h=6; ttl_min=$(( ttl_h * 60 ))
matched="$(find -L "$base" -maxdepth 1 -type d -name 'auditooor-lane-*' -mmin "+${ttl_min}" 2>/dev/null)"

printf '%s\n' "$matched" | grep -q "auditooor-lane-STALE" || fail "stale lane worktree not selected for prune"
printf '%s\n' "$matched" | grep -q "auditooor-lane-FRESH" && fail "FRESH lane worktree wrongly selected for prune"
printf '%s\n' "$matched" | grep -q "some-other-tmp-dir" && fail "non-lane dir wrongly selected (blast radius leak)"

# (3) the prune uses `find -L` (symlink-following) and a TTL=0 disable-guard
grep -q 'find -L "\$base"' "$SPAWN" || fail "prune find must use -L (follow /tmp symlink)"
grep -q '\[\[ "\$ttl_h" -eq 0 \]\] && return 0' "$SPAWN" || fail "TTL=0 disable-guard missing"

echo "PASS: spawn-worker stale-worktree prune logic verified"
