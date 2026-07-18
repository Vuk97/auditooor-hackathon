#!/usr/bin/env bash
# ============================================================================
# Rule 55 - integration-commit-preserves-sibling-work hard gate.
#
# Refuses a destructive git operation (`git reset --hard`, `git checkout --`,
# `git clean -fd`, `git stash drop`) when it would discard uncommitted
# working-tree changes that belong to a SIBLING lane's declared pathspec.
#
# Companion rule to R36 (parallel-worktree-commit-pathspec-discipline). R36
# polices the SHAPE of the commit (no sweeping `git add -A`); R55 polices the
# DESTRUCTIVE-OP precondition (no `git reset --hard` against sibling work).
#
# Empirical anchor: V3 iter17 Lane SSSSS investigation of iter16 DDDDD's
# "PID 83461 stomp" report. The actual root cause was the iter16
# OOOOO_integration_commit lane running two consecutive `git reset --hard`
# operations that wiped YYYY's iter15 working-tree brief-anchor edits for 7
# bug-class briefs. The reflog showed:
#   HEAD@{1}: reset: moving to HEAD
#   HEAD@{2}: reset: moving to HEAD
# Both ran from the integration-commit lane with sibling-lane (YYYY) edits
# uncommitted in the working tree. See
# `docs/R36_PARALLEL_SESSION_RECOVERY_2026-05-23.md` Section 5.3.
#
# Behaviour:
#   * Invoked as a wrapper script: `git-reset-safe.sh <reset args>` (or any
#     destructive op via WRAPPER_OP env var). It performs the precondition
#     check, then chains to real git if the check passes.
#   * Also installable as a custom pre-commit step (when combined with a
#     post-commit reset pattern); the standalone destructive ops require
#     the wrapper because mainline git lacks pre-reset / pre-checkout hooks.
#   * Reads `.auditooor/agent_pathspec.json` (R36's per-agent pathspec). If
#     `git status -uno --porcelain` shows uncommitted changes outside the
#     CURRENT lane's declared paths, the destructive op is refused.
#   * A `<!-- r55-rebuttal: <reason> -->` marker in env var R55_REBUTTAL
#     (or in `.auditooor/r55_rebuttal.txt`, single line) with a non-empty
#     reason allows operator-driven housekeeping.
#
# Current lane identification:
#   * If env var R55_CURRENT_AGENT_ID is set, use that agent_id from the
#     pathspec to determine "this lane's owned files".
#   * Otherwise, use the UNION of all live agent pathspecs (treats every
#     declared file as in-scope and only refuses on truly-undeclared edits).
#
# Installation:
#   * Wrapper: alias `git-reset` (or alias `git reset`) to this script with
#     WRAPPER_OP=reset. Example: see Section 5.3 of recovery doc.
#   * Pre-commit chain: invoke from a pre-commit hook that wraps a subsequent
#     `git reset --hard` in the same lane script.
#
# Override marker: <!-- r55-rebuttal: <reason up to 200 chars> -->
# ============================================================================

set -u

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "${REPO_ROOT}" ]; then
  # Not in a git repo - nothing to enforce.
  exit 0
fi

WRAPPER_OP="${WRAPPER_OP:-reset}"
PATHSPEC_FILE="${REPO_ROOT}/.auditooor/agent_pathspec.json"
REBUTTAL_FILE="${REPO_ROOT}/.auditooor/r55_rebuttal.txt"
R55_REBUTTAL_ENV="${R55_REBUTTAL:-}"

# Check the rebuttal file first; env-var rebuttal layered on top.
R55_REBUTTAL_FILE_CONTENT=""
if [ -f "${REBUTTAL_FILE}" ]; then
  R55_REBUTTAL_FILE_CONTENT="$(head -c 256 "${REBUTTAL_FILE}" 2>/dev/null || true)"
fi

# Identify only candidate-destructive ops. Other commands skip the gate.
case "${WRAPPER_OP}" in
  reset|checkout|clean|stash-drop)
    : # proceed to precondition check
    ;;
  *)
    # Wrapper invoked for a non-destructive op (e.g. status, log, diff). Pass.
    exit 0
    ;;
esac

# For `git reset` only refuse on --hard / --merge (which modify working tree);
# `git reset --soft` / `git reset --mixed` (default) preserve working tree.
# Look at WRAPPER_ARGS to determine.
WRAPPER_ARGS="${WRAPPER_ARGS:-}"
case "${WRAPPER_OP}" in
  reset)
    case "${WRAPPER_ARGS}" in
      *"--hard"*|*"--merge"*|*"--keep"*)
        : # destructive variant, proceed
        ;;
      *)
        # `git reset` without --hard/--merge/--keep preserves WT. Pass.
        exit 0
        ;;
    esac
    ;;
  checkout)
    # `git checkout -- <paths>` discards WT; `git checkout <branch>` is also
    # destructive if WT has conflicting changes. Treat all `checkout` invocations
    # under this wrapper as candidate-destructive.
    :
    ;;
  clean)
    case "${WRAPPER_ARGS}" in
      *"-f"*|*"-d"*|*"-x"*)
        : # destructive
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  stash-drop)
    : # always destructive
    ;;
esac

# Capture uncommitted working-tree state.
STATUS_RAW="$(git status -uno --porcelain 2>/dev/null)"

PATHSPEC_FILE="${PATHSPEC_FILE}" \
STATUS_RAW="${STATUS_RAW}" \
WRAPPER_OP="${WRAPPER_OP}" \
WRAPPER_ARGS="${WRAPPER_ARGS}" \
R55_REBUTTAL_ENV="${R55_REBUTTAL_ENV}" \
R55_REBUTTAL_FILE_CONTENT="${R55_REBUTTAL_FILE_CONTENT}" \
R55_CURRENT_AGENT_ID="${R55_CURRENT_AGENT_ID:-}" \
python3 - <<'PYEOF'
import json
import os
import re
import sys
from datetime import datetime, timezone

pathspec_file = os.environ["PATHSPEC_FILE"]
status_raw = os.environ.get("STATUS_RAW", "")
wrapper_op = os.environ.get("WRAPPER_OP", "reset")
wrapper_args = os.environ.get("WRAPPER_ARGS", "")
rebuttal_env = os.environ.get("R55_REBUTTAL_ENV", "")
rebuttal_file_content = os.environ.get("R55_REBUTTAL_FILE_CONTENT", "")
current_agent_id = os.environ.get("R55_CURRENT_AGENT_ID", "").strip()


def _parse_status(raw):
    """Parse `git status -uno --porcelain` output to a list of file paths.

    Only tracked files (uno = untracked-not-shown). Rename entries (R) carry
    `old -> new`; we keep the NEW path (post-rename).
    """
    files = []
    for line in raw.splitlines():
        if not line or len(line) < 4:
            continue
        # XY <path>  OR  XY <old> -> <new>
        rest = line[3:]
        if " -> " in rest:
            rest = rest.split(" -> ", 1)[1]
        files.append(rest.strip().strip('"'))
    return sorted(set(f for f in files if f))


def _agents(payload):
    if isinstance(payload, dict) and isinstance(payload.get("agents"), list):
        return [a for a in payload["agents"] if isinstance(a, dict)]
    if isinstance(payload, dict) and "files" in payload:
        return [payload]
    return []


def _parse_ts(value):
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


modified = _parse_status(status_raw)

# Nothing in the working tree -> no destruction possible. Pass.
if not modified:
    print(f"[r55-destructive-op] OK: no uncommitted working-tree changes; "
          f"{wrapper_op} {wrapper_args} is safe")
    sys.exit(0)

# No pathspec declaration -> warn but do not hard-fail (cannot determine
# sibling vs current-lane attribution).
if not os.path.isfile(pathspec_file):
    print(f"[r55-destructive-op] WARNING: {pathspec_file} missing; cannot "
          f"distinguish sibling-lane changes from current-lane changes.")
    print(f"[r55-destructive-op] WARNING: proceeding with {wrapper_op} "
          f"{wrapper_args}, but {len(modified)} uncommitted file(s) WILL be "
          f"discarded:")
    for f in modified[:10]:
        print(f"    - {f}")
    if len(modified) > 10:
        print(f"    ... and {len(modified) - 10} more")
    print("[r55-destructive-op] To enforce: declare lane ownership in "
          ".auditooor/agent_pathspec.json (R36 schema).")
    # Warn-only path: exit 0 so legacy worktrees keep working. To upgrade to
    # hard-fail, set R55_STRICT_NO_PATHSPEC=1.
    if os.environ.get("R55_STRICT_NO_PATHSPEC") == "1":
        sys.exit(1)
    sys.exit(0)

try:
    with open(pathspec_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
except Exception as exc:
    print(f"[r55-destructive-op] WARNING: cannot parse {pathspec_file}: "
          f"{exc}; gate skipped")
    sys.exit(0)

now = datetime.now(timezone.utc)
agents = _agents(data)

# Build per-agent live file sets.
live_agents = {}  # agent_id -> set(files)
for agent in agents:
    files = agent.get("files")
    if not isinstance(files, list):
        continue
    declared = {str(f).strip() for f in files if str(f).strip()}
    if not declared:
        continue
    expires = _parse_ts(agent.get("expires_at"))
    agent_id = str(agent.get("agent_id", "<unnamed>"))
    if expires is not None and expires <= now:
        continue
    live_agents[agent_id] = declared

if not live_agents:
    # No live declarations -> can't attribute. Warn and pass.
    print(f"[r55-destructive-op] WARNING: no live pathspec declarations in "
          f"{pathspec_file}; cannot attribute changes to lane.")
    sys.exit(0)

# Determine the CURRENT lane's owned set, vs SIBLING-lane owned set.
if current_agent_id and current_agent_id in live_agents:
    current_owned = live_agents[current_agent_id]
    sibling_owned = set()
    for aid, files in live_agents.items():
        if aid != current_agent_id:
            sibling_owned |= files
else:
    # No current-agent identification; treat any declared file as "could be
    # current OR sibling". Conservative posture: refuse if ANY uncommitted
    # file matches a live declaration that is not certainly the current
    # lane's. This is the safer default for shared-worktree orchestrators.
    current_owned = set()
    sibling_owned = set()
    for aid, files in live_agents.items():
        sibling_owned |= files

# Files that are uncommitted AND belong to a SIBLING lane's declared set
# (and NOT to the current lane).
at_risk = sorted(
    f for f in modified
    if f in sibling_owned and f not in current_owned
)

# Files uncommitted that match NO declared lane: undeclared work.
# Cautious: these are also at risk if destructive op proceeds, but with
# unknown attribution. Surface but do not refuse for these alone, unless
# R55_STRICT_UNDECLARED=1.
undeclared = sorted(
    f for f in modified
    if f not in sibling_owned and f not in current_owned
)

# Honour rebuttal: env-var FIRST, then file-content. Either accepted if
# non-empty and <= 200 chars (after collapse-whitespace).
def _norm_rebuttal(raw):
    text = " ".join((raw or "").split())
    if not text:
        return None
    if len(text) > 200:
        return None  # oversized; ignored
    return text


rebuttal = _norm_rebuttal(rebuttal_env) or _norm_rebuttal(rebuttal_file_content)
if rebuttal:
    if at_risk or undeclared:
        print(f"[r55-destructive-op] rebuttal accepted: {rebuttal}")
        if at_risk:
            print(f"  proceeding with {wrapper_op} {wrapper_args} despite "
                  f"{len(at_risk)} sibling-owned file(s) at risk:")
            for f in at_risk[:5]:
                print(f"    - {f}")
        sys.exit(0)
    # No conflict; rebuttal is moot but pass.
    sys.exit(0)

if at_risk:
    print(f"[r55-destructive-op] REFUSED: {wrapper_op} {wrapper_args} would "
          f"discard sibling-lane uncommitted work.")
    print(f"  declaration : {pathspec_file}")
    if current_agent_id:
        print(f"  current lane: {current_agent_id}")
    else:
        print(f"  current lane: (not declared via R55_CURRENT_AGENT_ID)")
    print(f"  sibling-owned at-risk file(s) (NOT in current lane's pathspec):")
    for f in at_risk:
        print(f"    + {f}")
    print("")
    print("  Rule 55 - integration-commit-preserves-sibling-work.")
    print("  An integration / cleanup lane must NOT run a destructive git op")
    print("  while sibling lanes have uncommitted edits in their declared paths.")
    print("  Either:")
    print("    * `git stash push -m sibling-lane-rescue -- <files>`, run your")
    print("      destructive op, then `git stash pop` to restore, or")
    print("    * coordinate with the sibling lane to commit their work first, or")
    print("    * for legitimate operator-driven housekeeping, set:")
    print("        export R55_REBUTTAL='<reason up to 200 chars>'")
    print("      or write the reason to .auditooor/r55_rebuttal.txt")
    sys.exit(1)

if undeclared and os.environ.get("R55_STRICT_UNDECLARED") == "1":
    print(f"[r55-destructive-op] REFUSED (strict): {wrapper_op} {wrapper_args} "
          f"would discard {len(undeclared)} undeclared uncommitted file(s):")
    for f in undeclared[:10]:
        print(f"    + {f}")
    print("  Set R55_STRICT_UNDECLARED=0 to downgrade to warning, or add the")
    print("  files to .auditooor/agent_pathspec.json under the responsible lane.")
    sys.exit(1)

if undeclared:
    print(f"[r55-destructive-op] WARNING: {len(undeclared)} undeclared "
          f"uncommitted file(s) will be discarded by {wrapper_op} "
          f"{wrapper_args} (cannot attribute):")
    for f in undeclared[:10]:
        print(f"    - {f}")

print(f"[r55-destructive-op] OK: {wrapper_op} {wrapper_args} does not affect "
      f"any sibling-lane declared file")
sys.exit(0)
PYEOF
exit $?
