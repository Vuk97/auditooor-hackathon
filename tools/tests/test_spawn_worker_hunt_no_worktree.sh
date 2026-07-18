#!/usr/bin/env bash
# Guard: a READ-ONLY `hunt` lane must NOT auto-provision a per-lane git worktree.
#
# spawn-worker.sh used to auto-default hunt|drill|comp -> USE_WORKTREE=1. But a
# per-fn hunt is read-only (reads source, writes verdict sidecars under .auditooor/),
# so it never needs an isolated checkout. A 58-batch hunt-dispatch provisioned ~53
# full 229k-file worktrees and nearly filled a 460G disk. Fix (2026-06-29): only the
# harness-authoring lanes (drill/comp) auto-isolate; hunt defaults OFF.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPAWN="$SCRIPT_DIR/../spawn-worker.sh"
fail() { echo "FAIL: $1" >&2; exit 1; }

# (1) hunt is NOT in the auto-worktree-on default case.
grep -Eq 'drill\|comp\) USE_WORKTREE=1' "$SPAWN" || fail "drill|comp auto-on default missing"
if grep -Eq 'hunt\|drill\|comp\) USE_WORKTREE=1' "$SPAWN"; then
    fail "hunt still auto-defaults to a worktree (the disk-blowup regression)"
fi

# (2) the collision warning no longer fires for hunt (it is read-only, not authoring).
if grep -Eq '^[[:space:]]*hunt\|drill\|comp\)' "$SPAWN"; then
    fail "collision-warning case still includes hunt (noisy false warning)"
fi

# (3) end-to-end: a hunt lane adds zero worktrees + creates no lane dir.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
before=$(git -C "$REPO_ROOT" worktree list 2>/dev/null | wc -l | tr -d ' ')
probe=$(mktemp /tmp/hunt_probe_XXXX.md); echo "probe" > "$probe"
SPAWN_WORKER_BYPASS_REASON="hunt-no-worktree-test" bash "$SPAWN" \
    --no-prebriefing --lane-type hunt --lane-id probe-hunt-nowt-$$ --severity HIGH \
    --workspace "$REPO_ROOT" --prompt-file "$probe" >/dev/null 2>&1 || true
after=$(git -C "$REPO_ROOT" worktree list 2>/dev/null | wc -l | tr -d ' ')
rm -f "$probe"
[ "$before" = "$after" ] || fail "hunt lane changed worktree count ($before -> $after)"
ls -d /private/tmp/auditooor-lane-probe-hunt-nowt-* /tmp/auditooor-lane-probe-hunt-nowt-* 2>/dev/null \
    && fail "hunt lane created a worktree dir" || true

echo "PASS: hunt lane provisions no worktree (drill/comp still auto-isolate)"
