#!/usr/bin/env bash
# skill-state.sh — persist cross-session workspace memory (Issue #104).
#
# Reads/writes <workspace>/.skill_state.yaml — a durable record of:
#   - last scan date + hit count
#   - per-detector verdict history for THIS workspace (from _hits_ledger.yaml)
#   - adversarial-read cursor (which contracts have been deep-read)
#   - rubric-coverage snapshot
#   - pending drill queue (hypotheses surfaced but not yet verified)
#
# `iter-dashboard.sh` reads this on invocation to orient fast when returning
# to a workspace after days/weeks away.
#
# Usage:
#   ./tools/skill-state.sh <workspace> show          # display current state
#   ./tools/skill-state.sh <workspace> init          # create state if absent (idempotent)
#   ./tools/skill-state.sh <workspace> touch-scan    # record a scan ran now
#   ./tools/skill-state.sh <workspace> mark-read <contract>  # cursor +1
#   ./tools/skill-state.sh <workspace> drill-add <hypothesis>
#
# V5-P0-07 / Gap 17 idempotency contract for `init`:
#   * If <ws>/.skill_state.yaml exists AND carries the
#     `auditooor.skill_state.v1` marker line: init is a no-op (rc=0).
#   * If it exists but is unmarked or unreadable: backup to
#     `.skill_state.yaml.bak.<unix-ts>` and write a fresh marked file.
#   * If it does not exist: write a fresh marked file.
#   The backup-rename keeps every previous file as `.bak.<unix-ts>` so a
#   misclassification can always be recovered. `init` NEVER overwrites
#   without a backup.

set -u
WS="${1:-}"
CMD="${2:-show}"
ARG="${3:-}"

if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace> [show|init|touch-scan|mark-read <contract>|drill-add <hyp>|drill-list|drill-done <hyp>]" >&2
  exit 2
fi

STATE="$WS/.skill_state.yaml"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
NOW_UNIX=$(date -u +%s)
# V5-P0-07: machine-readable marker. Bumping this string requires bumping
# the test harness in tools/tests/test_skill_state_idempotent.py.
SKILL_STATE_MARKER="auditooor.skill_state.v1"

init_state() {
  cat > "$STATE" <<EOF
# auditooor workspace state (Issue #104)
# $SKILL_STATE_MARKER
version: 1
created: $NOW
workspace: $(basename "$WS")
last_scan:
  date: null
  hit_count: 0
adversarial_reads: []
pending_drills: []
completed_drills: []
EOF
}

# V5-P0-07 helper: returns 0 iff $STATE exists AND contains the marker.
# `grep -F` so the literal-string match never trips on regex meta in the
# marker if it is bumped in the future.
state_is_marked() {
  [ -f "$STATE" ] && grep -Fq "$SKILL_STATE_MARKER" "$STATE" 2>/dev/null
}

# V5-P0-07 helper: rename existing $STATE to a unique `.bak.<unix-ts>`
# sidecar. Never clobbers an existing backup; appends a counter on the
# vanishingly unlikely same-second collision. Returns the backup path on
# stdout; non-zero exit propagates to the caller (e.g. disk full).
backup_state() {
  local bak="$STATE.bak.$NOW_UNIX"
  local n=0
  while [ -e "$bak" ]; do
    n=$((n + 1))
    bak="$STATE.bak.$NOW_UNIX.$n"
  done
  mv "$STATE" "$bak" || return 1
  printf '%s\n' "$bak"
}

case "$CMD" in
  init)
    # Defensive: refuse to operate when $STATE path is occupied by a
    # non-regular-file (e.g. a directory or symlink to a directory). The
    # original `cat >` would fail with "Is a directory", but a clear
    # error here is easier for the operator to debug.
    if [ -e "$STATE" ] && [ ! -f "$STATE" ]; then
      echo "[skill-state] FATAL: $STATE exists but is not a regular file; refusing to write" >&2
      exit 2
    fi
    if state_is_marked; then
      # Idempotent re-run — leave the curated file untouched.
      echo "[skill-state] already initialized (marker present) → $STATE"
      exit 0
    fi
    if [ -f "$STATE" ]; then
      if ! backup_path=$(backup_state); then
        echo "[skill-state] FATAL: failed to back up unmarked state $STATE" >&2
        exit 1
      fi
      echo "[skill-state] existing unmarked state backed up → $backup_path" >&2
    fi
    init_state
    echo "[skill-state] initialized → $STATE"
    ;;
  show)
    [ -f "$STATE" ] || { echo "[skill-state] no state file; run 'init'"; exit 1; }
    cat "$STATE"
    ;;
  touch-scan)
    [ -f "$STATE" ] || init_state
    # use python+yaml if available, else naive sed
    if command -v python3 >/dev/null; then
      python3 -c "
import yaml, sys
from pathlib import Path
p = Path('$STATE')
d = yaml.safe_load(p.read_text()) or {}
d['last_scan'] = {'date': '$NOW', 'hit_count': d.get('last_scan',{}).get('hit_count', 0)}
p.write_text(yaml.safe_dump(d, sort_keys=False))
"
    fi
    echo "[skill-state] scan touch → $NOW"
    ;;
  mark-read)
    [ -z "$ARG" ] && { echo "need <contract> arg"; exit 1; }
    [ -f "$STATE" ] || init_state
    python3 -c "
import yaml
from pathlib import Path
p = Path('$STATE')
d = yaml.safe_load(p.read_text()) or {}
reads = d.setdefault('adversarial_reads', [])
if '$ARG' not in [r.get('contract') for r in reads if isinstance(r,dict)]:
    reads.append({'contract': '$ARG', 'date': '$NOW'})
p.write_text(yaml.safe_dump(d, sort_keys=False))
"
    echo "[skill-state] marked read → $ARG"
    ;;
  drill-add)
    [ -z "$ARG" ] && { echo "need <hypothesis> arg"; exit 1; }
    [ -f "$STATE" ] || init_state
    python3 -c "
import yaml
from pathlib import Path
p = Path('$STATE')
d = yaml.safe_load(p.read_text()) or {}
drills = d.setdefault('pending_drills', [])
drills.append({'hypothesis': '$ARG', 'added': '$NOW'})
p.write_text(yaml.safe_dump(d, sort_keys=False))
"
    echo "[skill-state] queued drill → $ARG"
    ;;
  drill-list)
    [ -f "$STATE" ] || { echo "[skill-state] no state file"; exit 1; }
    python3 -c "
import yaml
from pathlib import Path
d = yaml.safe_load(Path('$STATE').read_text()) or {}
for i,x in enumerate(d.get('pending_drills', []), 1):
    print(f\"{i}. {x.get('hypothesis')} (added {x.get('added')})\")
"
    ;;
  drill-done)
    [ -z "$ARG" ] && { echo "need <hypothesis-or-index> arg"; exit 1; }
    [ -f "$STATE" ] || { echo "[skill-state] no state file"; exit 1; }
    python3 -c "
import yaml
from pathlib import Path
p = Path('$STATE')
d = yaml.safe_load(p.read_text()) or {}
pending = d.get('pending_drills', [])
done = d.setdefault('completed_drills', [])
arg = '$ARG'
try:
    idx = int(arg) - 1
    if 0 <= idx < len(pending):
        done.append({**pending[idx], 'completed': '$NOW'})
        pending.pop(idx)
except ValueError:
    for i, x in enumerate(pending):
        if x.get('hypothesis') == arg:
            done.append({**pending.pop(i), 'completed': '$NOW'})
            break
d['pending_drills'] = pending
p.write_text(yaml.safe_dump(d, sort_keys=False))
"
    echo "[skill-state] drill done → $ARG"
    ;;
  *)
    echo "unknown command: $CMD" >&2
    exit 1
    ;;
esac
