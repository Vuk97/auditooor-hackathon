#!/usr/bin/env bash
# audit-run-guard.sh - per-workspace concurrency guard for heavy audit stages.
#
# A recurring loop tick (e.g. every 5 min) must NOT launch a second `make audit`
# while a prior one is still scanning the same workspace - that caused orphaned
# workspace-scan-orchestrator pileups on near-intents (4 Rust repos, 3.3 GB).
# This guard is a portable PID-file lock (macOS has no flock): a fresh run claims
# the lock recording its owning `make` PID; a concurrent run sees the live PID and
# skips. A stale lock whose PID is dead (run finished or was killed) is ignored,
# so a crash never blocks future runs - no cleanup/trap needed.
#
# Usage:  audit-run-guard.sh <workspace> [lock-name]
#   exit 0  -> ACQUIRED (lock now records our owner pid); caller PROCEEDS
#   exit 3  -> BUSY (a live run holds the lock); caller should SKIP gracefully
#   exit 2  -> usage error
#
# Owner PID resolution: AUDITOOOR_RUN_OWNER_PID if set (tests / explicit), else
# the grandparent of this script == the `make` process (recipe-shell's parent),
# which lives for the whole audit; falls back to the parent pid.
set -u

ws="${1:-}"
[ -n "$ws" ] || { echo "usage: audit-run-guard.sh <workspace> [lock-name]" >&2; exit 2; }
name="${2:-audit_run}"

owner="${AUDITOOOR_RUN_OWNER_PID:-}"
if [ -z "$owner" ]; then
  owner="$(ps -o ppid= -p "$PPID" 2>/dev/null | tr -dc '0-9')"
fi
[ -n "$owner" ] || owner="$PPID"

lk="$ws/.auditooor/.$name.lock"
mkdir -p "$ws/.auditooor" 2>/dev/null || true

if [ -f "$lk" ]; then
  lp="$(head -1 "$lk" 2>/dev/null | tr -dc '0-9')"
  if [ -n "$lp" ] && kill -0 "$lp" 2>/dev/null; then
    echo "[audit-run-guard] BUSY: '$name' active (pid $lp) for $ws - skipping this run" >&2
    exit 3
  fi
fi

printf '%s\n' "$owner" > "$lk"
exit 0
