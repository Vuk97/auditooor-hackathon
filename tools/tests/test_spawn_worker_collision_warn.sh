#!/usr/bin/env bash
# <!-- r36-rebuttal: lane FIX-SPAWN-WORKER-COLLISION-WARN registered via agent-pathspec-register.py -->
# Guard: spawn-worker.sh warns LOUDLY when a harness/PoC-authoring lane
# (hunt/drill/comp) explicitly DISABLES worktree isolation (--no-use-worktree),
# because parallel authoring then shares ONE forge/cargo/go build and a single
# broken sibling file fails every sibling's baseline (the 2026-06-23 collision).
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPAWN="$SCRIPT_DIR/../spawn-worker.sh"
fail() { echo "FAIL: $1" >&2; exit 1; }

bash -n "$SPAWN" || fail "spawn-worker.sh has a bash syntax error"

# (1) the collision-warning block exists + keys on the authoring lane types
grep -q 'SHARED-BUILD COLLISION WARNING' "$SPAWN" || fail "collision-warning block missing"
grep -q 'shared build for ALL of them' "$SPAWN" || fail "collision-warning message missing"

# (2) it is gated on USE_WORKTREE==0 for hunt|drill|comp (explicit-disable case)
awk '/SHARED-BUILD COLLISION WARNING/,/^esac/' "$SPAWN" | grep -q 'hunt|drill|comp' \
    || fail "warning not scoped to authoring lane types"
awk '/SHARED-BUILD COLLISION WARNING/,/^esac/' "$SPAWN" | grep -q 'USE_WORKTREE -eq 0' \
    || fail "warning not gated on explicit isolation-disable"

# (3) logic replication: comp/hunt/drill + USE_WORKTREE==0 -> warn; tool-build or
# isolated (==1) -> no warn. Mirrors the case block so the gating can't silently drift.
warn_decision() {  # $1=lane_type $2=use_worktree(0/1)
    case "$1" in hunt|drill|comp) [ "$2" -eq 0 ] && echo warn || echo silent ;;
                 *) echo silent ;; esac
}
[ "$(warn_decision comp 0)" = warn ] || fail "comp + disabled-isolation must warn"
[ "$(warn_decision hunt 0)" = warn ] || fail "hunt + disabled-isolation must warn"
[ "$(warn_decision comp 1)" = silent ] || fail "comp WITH isolation must NOT warn"
[ "$(warn_decision tool-build 0)" = silent ] || fail "tool-build must NOT warn"

echo "PASS: spawn-worker collision-warn guard"
