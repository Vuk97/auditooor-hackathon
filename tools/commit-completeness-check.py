#!/usr/bin/env python3
"""Commit-completeness gate (caveat B): fail-closed when a lane reports
"complete" but UNDER-committed (registered a pathspec then staged only a
subset) or OVER-committed (staged files outside its registered pathspec).

Motivation
----------
Integration agents have twice this session registered a lane pathspec via
`tools/agent-pathspec-register.py` and then staged only a SUBSET of those
files while reporting the lane "complete". The miss was caught only by a
manual `git show --stat`. The existing R36 hook
(`tools/git-hooks/pre-commit-pathspec-discipline.sh`) is the dual of this
gate: R36 refuses staging files OUTSIDE the lane's pathspec (over-stage /
sibling absorption). It does NOT catch the inverse - a lane that
under-stages and walks away. This tool closes that gap.

What it compares
----------------
For a given lane id (looked up in `.auditooor/agent_pathspec.json`, the
same registry that `agent-pathspec-register.py` writes and the R36/R55
hooks read), three sets:

  * REGISTERED   = the lane's declared `files` from the registry.
  * STAGED       = `git diff --cached --name-only` (the index).
  * UNSTAGED-WT  = `git diff --name-only` (working-tree modifications not
                   yet staged) PLUS untracked files (`git ls-files
                   --others --exclude-standard`).

Two fail-closed conditions:

  UNDER-COMMIT (the caveat-B failure mode):
    A registered-pathspec file that HAS working-tree content to commit
    (it differs from HEAD - i.e. it is modified-unstaged, or untracked,
    or staged) but is NOT in the staged set. In other words: the lane
    declared it owns this file, the file has uncommitted changes, yet the
    lane is about to commit without it. This is the under-commit that was
    reported as "complete".

    A registered file that is byte-identical to HEAD (no pending change)
    is NOT an under-commit - the lane may legitimately have touched only
    some of its declared files. We only flag registered files that have
    REAL pending content left behind unstaged.

  OVER-COMMIT (the R36 dual, surfaced here as a completeness symptom):
    A file that is staged (or has working-tree changes since the
    baseline) but is in NO live lane's registered pathspec - i.e. an
    unregistered change. By default this checks against the union of all
    live lanes (so a multi-lane worktree does not false-fire). Pass
    `--strict-lane` to require every staged file to be in THE NAMED
    lane's pathspec specifically.

    System-wide coordination paths (the registry file itself, its lock,
    and reports/v3_iter_*/phase_state.json) are exempt from the over-commit
    check - they are shared bookkeeping that every lane may stage. This
    mirrors the `_DEFAULT_SYSTEM_PATTERNS` allowlist in the R36 hook.

Both are reported and BOTH set a nonzero rc. The gate is fail-closed: any
mismatch -> rc 1. A clean lane (every registered file with pending content
is staged, no unregistered staged/changed files) -> rc 0.

Baseline
--------
"Files changed since a baseline" defaults to HEAD. Pass `--baseline <ref>`
to compare against a different commit (e.g. the lane's branch-point) for
the over-commit check.

Exit codes
----------
  0  complete: no under-commit and no over-commit.
  1  incomplete: under-commit and/or over-commit detected (fail-closed).
  2  usage / environment error (lane not found, not a git repo, bad args).

Wiring (NOT done here - out of worktree scope)
----------------------------------------------
This tool is intentionally NOT wired into the live `~/.claude` hooks from
this worktree. To wire it into the repo pre-commit hook later, append a
stanza like the following to `tools/git-hooks/pre-commit` (AFTER the R36
chain, so over-stage is caught first), guarded on a lane id being present:

    # ------------------------------------------------------------------
    # Commit-completeness gate (caveat B): refuse a commit that
    # under-commits the current lane's registered pathspec. Only fires
    # when a lane id is exported (R36_CURRENT_AGENT_ID / R55_CURRENT_AGENT_ID).
    # ------------------------------------------------------------------
    CC_LANE="${R36_CURRENT_AGENT_ID:-${R55_CURRENT_AGENT_ID:-}}"
    CC_TOOL="$WS_ROOT/tools/commit-completeness-check.py"
    if [[ -n "$CC_LANE" ]] && [[ -f "$CC_TOOL" ]]; then
        if ! python3 "$CC_TOOL" --lane "$CC_LANE"; then
            echo "[pre-commit] commit-completeness gate REFUSED commit" >&2
            exit 1
        fi
    fi

It can equally run standalone after a lane reports done:

    python3 tools/commit-completeness-check.py --lane lane-X

Output is a human-readable under-/over-commit report on stderr/stdout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_PATHSPEC_REL = ".auditooor/agent_pathspec.json"
DEFAULT_BASELINE = "HEAD"

# System-wide coordination paths that ANY lane may legitimately stage as part
# of normal bookkeeping. These bypass the over-commit (unregistered-change)
# check. Mirrors `_DEFAULT_SYSTEM_PATTERNS` in
# tools/git-hooks/pre-commit-pathspec-discipline.sh so the two gates agree on
# what counts as "shared" (the registry file writes itself on every register,
# so it must not be flagged as an unregistered change).
_SYSTEM_WIDE_PATTERNS = [
    r"^\.auditooor/agent_pathspec\.json$",
    r"^\.auditooor/agent_pathspec\.json\.lock$",
    r"^reports/v3_iter_[^/]+/phase_state\.json$",
    r"^reports/v3_iter_[^/]+/hacker_brain_phase_state\.json$",
]


def _is_system_wide(path: str) -> bool:
    for pat in _SYSTEM_WIDE_PATTERNS:
        try:
            if re.match(pat, path):
                return True
        except re.error:
            continue
    return False


def _parse_ts(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp; return aware UTC datetime or None."""
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


def _git(repo_root: Path, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _git_lines(repo_root: Path, *args: str) -> list[str]:
    rc, out, _ = _git(repo_root, *args)
    if rc != 0:
        return []
    return sorted({ln.strip() for ln in out.splitlines() if ln.strip()})


def _repo_root(start: Path) -> Path | None:
    rc, out, _ = _git(start, "rev-parse", "--show-toplevel")
    if rc != 0:
        return None
    top = out.strip()
    return Path(top) if top else None


def _load_registry(pathspec_file: Path) -> dict[str, Any]:
    if not pathspec_file.exists():
        return {"agents": []}
    try:
        with pathspec_file.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[commit-completeness] ERROR: cannot read/parse "
              f"{pathspec_file}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(data, dict):
        print(f"[commit-completeness] ERROR: {pathspec_file} top-level must "
              f"be a JSON object", file=sys.stderr)
        sys.exit(2)
    return data


def _agents(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise to a list of agent entries (matches R36 hook semantics)."""
    if isinstance(payload, dict) and isinstance(payload.get("agents"), list):
        return [a for a in payload["agents"] if isinstance(a, dict)]
    if isinstance(payload, dict) and "files" in payload:
        return [payload]
    return []


def _declared_files(agent: dict[str, Any]) -> set[str]:
    files = agent.get("files")
    if not isinstance(files, list):
        return set()
    return {str(f).strip() for f in files if str(f).strip()}


def _is_live(agent: dict[str, Any], now: datetime,
             include_expired: bool) -> bool:
    if include_expired:
        return True
    expires = _parse_ts(agent.get("expires_at"))
    # No expiry -> live. Future expiry -> live. Past expiry -> dead.
    return expires is None or expires > now


def _changed_since_baseline(repo_root: Path, baseline: str) -> set[str]:
    """All paths that differ from `baseline`: staged + unstaged tracked
    diffs vs the baseline, plus untracked files."""
    changed: set[str] = set()
    # Tracked changes vs baseline (covers both staged and working-tree).
    changed.update(_git_lines(repo_root, "diff", "--name-only", baseline))
    # Also staged set explicitly (in case baseline == HEAD and a file is
    # staged but its working tree was reverted - diff vs HEAD still shows it).
    changed.update(_git_lines(repo_root, "diff", "--cached", "--name-only"))
    # Untracked, not-ignored.
    changed.update(_git_lines(
        repo_root, "ls-files", "--others", "--exclude-standard"))
    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="commit-completeness-check.py",
        description=(
            "Fail-closed commit-completeness gate: refuse a lane that "
            "under-commits its registered pathspec (caveat B) or stages "
            "unregistered changes (over-commit)."
        ),
    )
    parser.add_argument(
        "--lane", "--agent-id", dest="lane", required=True,
        help="Lane id to check (must match an entry in the pathspec registry).")
    parser.add_argument(
        "--pathspec-file", default=None,
        help=(f"Path to the registry JSON (default: <repo-root>/"
              f"{DEFAULT_PATHSPEC_REL})."))
    parser.add_argument(
        "--repo-root", default=None,
        help="Repo root (default: discover via git rev-parse from cwd).")
    parser.add_argument(
        "--baseline", default=DEFAULT_BASELINE,
        help=(f"Baseline ref for the over-commit 'changed since' check "
              f"(default: {DEFAULT_BASELINE})."))
    parser.add_argument(
        "--strict-lane", action="store_true",
        help=("Over-commit check requires every staged/changed file to be in "
              "THE NAMED lane's pathspec (default: union of all live lanes)."))
    parser.add_argument(
        "--include-expired", action="store_true",
        help=("Treat expired registry entries as live when resolving the lane "
              "and the over-commit owner set (default: live entries only)."))
    parser.add_argument(
        "--no-over-commit", action="store_true",
        help="Skip the over-commit (unregistered-change) check; under-commit only.")
    args = parser.parse_args(argv)

    # Resolve repo root.
    if args.repo_root:
        repo_root = Path(args.repo_root).resolve()
    else:
        discovered = _repo_root(Path.cwd())
        if discovered is None:
            print("[commit-completeness] ERROR: not inside a git repo (and "
                  "--repo-root not given)", file=sys.stderr)
            return 2
        repo_root = discovered

    if not (repo_root / ".git").exists() and not (repo_root / ".git").is_file():
        # Allow worktrees where .git is a file pointer; just sanity-check git works.
        rc, _, _ = _git(repo_root, "rev-parse", "--git-dir")
        if rc != 0:
            print(f"[commit-completeness] ERROR: {repo_root} is not a git "
                  f"work tree", file=sys.stderr)
            return 2

    pathspec_file = (Path(args.pathspec_file) if args.pathspec_file
                     else repo_root / DEFAULT_PATHSPEC_REL)

    registry = _load_registry(pathspec_file)
    agents = _agents(registry)
    now = datetime.now(timezone.utc)

    # Locate the named lane.
    lane_agent = None
    for a in agents:
        if str(a.get("agent_id", "")) == args.lane:
            if _is_live(a, now, args.include_expired):
                lane_agent = a
            else:
                print(f"[commit-completeness] ERROR: lane '{args.lane}' is "
                      f"EXPIRED in {pathspec_file}. Re-register/refresh it, or "
                      f"pass --include-expired to check anyway.",
                      file=sys.stderr)
                return 2
            break
    if lane_agent is None:
        live_ids = sorted(
            str(a.get("agent_id", "<unnamed>")) for a in agents
            if _is_live(a, now, args.include_expired))
        print(f"[commit-completeness] ERROR: lane '{args.lane}' not found in "
              f"{pathspec_file}.", file=sys.stderr)
        if live_ids:
            print(f"  live lanes: {', '.join(live_ids)}", file=sys.stderr)
        else:
            print("  no live lanes registered.", file=sys.stderr)
        return 2

    registered = _declared_files(lane_agent)
    if not registered:
        print(f"[commit-completeness] ERROR: lane '{args.lane}' has an empty "
              f"`files` list in {pathspec_file}", file=sys.stderr)
        return 2

    staged = set(_git_lines(repo_root, "diff", "--cached", "--name-only"))
    unstaged_tracked = set(_git_lines(repo_root, "diff", "--name-only"))
    untracked = set(_git_lines(
        repo_root, "ls-files", "--others", "--exclude-standard"))
    # A registered file has "pending content to commit" if it differs from
    # HEAD in any of these three buckets.
    pending = staged | unstaged_tracked | untracked

    # ---- UNDER-COMMIT: registered files with pending content not staged. ----
    under_commit = sorted(
        f for f in registered
        if f in pending and f not in staged
    )

    # ---- OVER-COMMIT: staged/changed files in NO live lane's pathspec. ----
    over_commit: list[str] = []
    if not args.no_over_commit:
        if args.strict_lane:
            owner_union = set(registered)
        else:
            owner_union = set()
            for a in agents:
                if _is_live(a, now, args.include_expired):
                    owner_union |= _declared_files(a)
        changed = _changed_since_baseline(repo_root, args.baseline)
        # Over-commit candidates are things actually staged OR changed since
        # baseline, that belong to no live lane.
        candidates = staged | changed
        over_commit = sorted(
            f for f in candidates
            if f not in owner_union and not _is_system_wide(f))

    # ---- Report. ----
    failed = bool(under_commit) or bool(over_commit)
    print(f"[commit-completeness] lane={args.lane} registry={pathspec_file}")
    print(f"  registered files : {len(registered)}")
    print(f"  staged files     : {len(staged)}")
    print(f"  pending (wt+idx) : {len(pending)}")

    if under_commit:
        print("")
        print(f"[commit-completeness] UNDER-COMMIT (fail-closed): "
              f"{len(under_commit)} registered file(s) have pending content "
              f"but are NOT staged:")
        for f in under_commit:
            buckets = []
            if f in unstaged_tracked:
                buckets.append("modified-unstaged")
            if f in untracked:
                buckets.append("untracked")
            tag = f" [{', '.join(buckets)}]" if buckets else ""
            print(f"    - {f}{tag}")
        print("  -> The lane registered these files but is about to commit "
              "WITHOUT them.")
        print("     Stage them (git add <file>) or unregister them from the "
              "lane pathspec if intentionally dropped.")

    if over_commit:
        print("")
        scope = ("the named lane" if args.strict_lane
                 else "any live lane")
        print(f"[commit-completeness] OVER-COMMIT (fail-closed): "
              f"{len(over_commit)} staged/changed file(s) are in NO "
              f"{scope}'s registered pathspec:")
        for f in over_commit:
            print(f"    + {f}")
        print("  -> Register them to a lane pathspec, or unstage them.")

    if not failed:
        print("")
        print(f"[commit-completeness] OK: lane '{args.lane}' is complete - "
              f"every registered file with pending content is staged and no "
              f"unregistered change leaked in.")
        return 0

    print("")
    print("[commit-completeness] RESULT: incomplete (fail-closed, rc=1).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
