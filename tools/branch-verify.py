#!/usr/bin/env python3
"""branch-verify.py — pre-commit guard against foot-gun #15 (parallel-agent
shared-``.git`` branch race).

Background: when several source-mining / dispatch agents run against the
same local ``auditooor`` clone, sibling agents' ``git checkout`` invocations
silently bump the worktree's HEAD. Verify-then-stash discipline (per PR
#274) recovers, but the verbal habit fails ~6 times per heavy-parallel
session. This tool replaces the ad-hoc bash snippet in
``docs/SOURCE_MINING_RUNBOOK.md`` with a mechanical check that:

  - matches the active branch against an expected name
  - on match: exits 0 silently
  - on mismatch: prints structured stderr JSON with classification, the
    list of uncommitted-but-not-yet-tracked files (so the operator sees
    what would be carried into a wrong branch), and a recovery suggestion
  - on hard error (no git, not a repo, missing CLI): exits 2 with a
    structured ``not-a-git-repo`` / ``git-unavailable`` classification

The tool deliberately **does not auto-fix**: foot-gun #17 (operator must
inspect contamination before reset/checkout). It only surfaces evidence
and a recovery hint; the operator decides.

Exit codes:
  0  branch matches expected
  1  mismatch (different branch, detached HEAD, or worktree-has-no-branch)
  2  hard error (no git, not in a repo, internal failure)

Usage:
  python3 tools/branch-verify.py --expected-branch <name>
  BRANCH_VERIFY_EXPECTED=<name> python3 tools/branch-verify.py
  python3 tools/branch-verify.py --expected-branch <name> --json-stdout

The ``--json-stdout`` switch (off by default) mirrors the stderr JSON to
stdout for easier capture in CI scripts.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any


# Mismatch classes — exposed via stderr JSON ``classification`` field so a
# caller can route different remediations without parsing free-form text.
CLASS_MATCH = "match"
CLASS_RISKY_LOCATION = "risky-location-not-in-isolated-worktree"
CLASS_BRANCH_MISMATCH = "branch-mismatch"
CLASS_DETACHED_HEAD = "detached-head"
CLASS_NOT_A_GIT_REPO = "not-a-git-repo"
CLASS_GIT_UNAVAILABLE = "git-unavailable"
CLASS_INTERNAL_ERROR = "internal-error"


def _run_git(args: list[str]) -> tuple[int, str, str]:
    """Run ``git`` with the supplied args. Returns (rc, stdout, stderr).
    Inherits the caller's environment (so ``GIT_DIR`` / worktree behaviour
    is preserved). Never raises on non-zero exit.

    Note: stdout is *only* trailing-stripped (``rstrip``) — ``git status
    --short`` emits a leading ``X`` byte that may be a literal space (e.g.
    `` M README.md`` for a worktree-modified file). A blanket ``strip()``
    would silently corrupt the path slice in ``_uncommitted_files``."""
    try:
        proc = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return 127, "", "git not on PATH"
    return proc.returncode, proc.stdout.rstrip("\n"), proc.stderr.strip()


def _emit(payload: dict[str, Any], also_stdout: bool) -> None:
    line = json.dumps(payload, sort_keys=True)
    sys.stderr.write(line + "\n")
    if also_stdout:
        sys.stdout.write(line + "\n")


def _is_canonical_clone() -> bool:
    """Return True iff the current working dir is the canonical clone (NOT
    an isolated worktree).

    A ``git worktree`` has separate ``--git-dir`` (e.g.
    ``/path/.git/worktrees/foo``) but shared ``--git-common-dir``
    (``/path/.git``). The canonical clone has both pointing to the same
    location.

    Why this matters: foot-gun #15 fires when N agents share a single
    ``.git``. The race is materially impossible inside a per-agent
    ``git worktree`` because each worktree carries its own HEAD ref. Agents
    that work directly in the canonical clone and rely on verbal verify-
    then-stash discipline have empirically failed ~11x in a single V5
    session. The runbook now treats the canonical-clone location as
    risky-by-default; this function surfaces it.
    """
    rc1, git_dir, _ = _run_git(["rev-parse", "--git-dir"])
    rc2, git_common_dir, _ = _run_git(["rev-parse", "--git-common-dir"])
    if rc1 != 0 or rc2 != 0:
        return False
    # Resolve both to absolute paths so a shared parent is comparable.
    try:
        gd = os.path.realpath(git_dir)
        gcd = os.path.realpath(git_common_dir)
    except OSError:
        return False
    return gd == gcd


def _uncommitted_files() -> list[str]:
    """Return ``git status --short`` paths (one per line). Empty list if
    the call fails — the tool's job is to not crash on side-show errors."""
    rc, out, _ = _run_git(["status", "--short"])
    if rc != 0 or not out:
        return []
    paths: list[str] = []
    for raw in out.splitlines():
        # ``git status --short`` format: XY <path> or XY <orig> -> <new>.
        # Keep the human-visible suffix; we want the operator to recognise
        # the file, not parse the porcelain.
        if len(raw) > 3:
            paths.append(raw[3:].strip())
    return paths


def _recovery_commands(expected: str, actual: str | None) -> list[str]:
    """Build a non-destructive recovery suggestion. We always prefix with
    ``git stash push`` so uncommitted in-flight work is preserved (per
    foot-gun #17 — the operator inspects before reset)."""
    cmds: list[str] = []
    cmds.append(
        f'git stash push -m "branch-verify autosaved before switching from '
        f'{actual or "<unknown>"} to {expected}"'
    )
    cmds.append(f"git checkout {expected}")
    cmds.append("git stash list   # inspect; pop only if the diff belongs here")
    return cmds


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Pre-commit guard for foot-gun #15: verify the active git "
            "branch matches the expected one before agents commit."
        )
    )
    parser.add_argument(
        "--expected-branch",
        default=os.environ.get("BRANCH_VERIFY_EXPECTED"),
        help=(
            "Expected branch name. If omitted, falls back to the "
            "BRANCH_VERIFY_EXPECTED env var (useful from CI scripts)."
        ),
    )
    parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Mirror the structured stderr JSON to stdout for capture.",
    )
    parser.add_argument(
        "--strict-isolation",
        action="store_true",
        help=(
            "Escalate the risky-location warning (working directly in the "
            "canonical clone instead of a per-agent `git worktree`) from "
            "WARN to a hard FAIL (exit 1). Recommended for unattended "
            "multi-agent runs where foot-gun #15 has high impact."
        ),
    )
    args = parser.parse_args(argv)

    if not args.expected_branch:
        _emit(
            {
                "tool": "branch-verify",
                "classification": CLASS_INTERNAL_ERROR,
                "error": (
                    "no expected branch supplied "
                    "(use --expected-branch or BRANCH_VERIFY_EXPECTED)"
                ),
            },
            args.json_stdout,
        )
        return 2

    if shutil.which("git") is None:
        _emit(
            {
                "tool": "branch-verify",
                "classification": CLASS_GIT_UNAVAILABLE,
                "expected": args.expected_branch,
                "error": "git executable not found on PATH",
            },
            args.json_stdout,
        )
        return 2

    rc, out, err = _run_git(["rev-parse", "--is-inside-work-tree"])
    if rc != 0 or out != "true":
        _emit(
            {
                "tool": "branch-verify",
                "classification": CLASS_NOT_A_GIT_REPO,
                "expected": args.expected_branch,
                "error": err or "not inside a git work tree",
            },
            args.json_stdout,
        )
        return 2

    rc, abbrev, err = _run_git(["rev-parse", "--abbrev-ref", "HEAD"])
    if rc != 0:
        _emit(
            {
                "tool": "branch-verify",
                "classification": CLASS_INTERNAL_ERROR,
                "expected": args.expected_branch,
                "error": err or "rev-parse failed",
            },
            args.json_stdout,
        )
        return 2

    # Detached HEAD: ``git rev-parse --abbrev-ref HEAD`` prints "HEAD".
    if abbrev == "HEAD":
        head_rc, head_sha, _ = _run_git(["rev-parse", "HEAD"])
        head_sha_short = head_sha[:12] if head_rc == 0 else "<unknown>"
        _emit(
            {
                "tool": "branch-verify",
                "classification": CLASS_DETACHED_HEAD,
                "expected": args.expected_branch,
                "actual": None,
                "head_sha": head_sha_short,
                "uncommitted": _uncommitted_files(),
                "suggested_recovery": _recovery_commands(
                    args.expected_branch, None
                ),
                "note": (
                    "HEAD is detached — a sibling agent likely ran "
                    "`git checkout <sha>` in this shared clone. Inspect "
                    "before switching; uncommitted edits would otherwise "
                    "be carried."
                ),
            },
            args.json_stdout,
        )
        return 1

    if abbrev == args.expected_branch:
        # Branch match. Now check whether we're in the canonical clone vs
        # a per-agent isolated worktree (foot-gun #15 hard-rule check).
        if _is_canonical_clone():
            payload = {
                "tool": "branch-verify",
                "classification": CLASS_RISKY_LOCATION,
                "expected": args.expected_branch,
                "actual": abbrev,
                "uncommitted": _uncommitted_files(),
                "note": (
                    "Branch matches but you are working in the CANONICAL "
                    "clone. Foot-gun #15 (sibling agents share `.git` HEAD) "
                    "fired ~11x across the V5 session at this location even "
                    "with branch-verify discipline. Hard rule per "
                    "docs/SOURCE_MINING_RUNBOOK.md: agents must work in a "
                    "per-agent `git worktree`. For new agent work, use "
                    "`python3 tools/agent-worktree-dispatch.py prepare ...` "
                    "so the dirty-coordinator and writable-root preflight "
                    "runs before any worktree is created. Use raw "
                    "`git worktree add` only for manual recovery after "
                    "confirming this coordinator checkout is clean."
                ),
                "suggested_recovery": [
                    (
                        "python3 tools/agent-worktree-dispatch.py prepare "
                        "--parent-pr <parent-pr> --task-slug <task-slug> "
                        f"--base-branch {args.expected_branch}"
                    ),
                    "# Then cd to the printed AGENT_WORKTREE path.",
                    (
                        "# Manual fallback only after `git status --porcelain` is empty: "
                        f"git worktree add /private/tmp/auditooor-<task> {args.expected_branch}"
                    ),
                ],
            }
            _emit(payload, args.json_stdout)
            return 1 if args.strict_isolation else 0
        # Match + isolated worktree: silent success.
        return 0

    _emit(
        {
            "tool": "branch-verify",
            "classification": CLASS_BRANCH_MISMATCH,
            "expected": args.expected_branch,
            "actual": abbrev,
            "uncommitted": _uncommitted_files(),
            "suggested_recovery": _recovery_commands(
                args.expected_branch, abbrev
            ),
            "note": (
                "Active branch does not match the expected one. A sibling "
                "agent's `git checkout` in the same shared clone is the "
                "most common cause (foot-gun #15). Do NOT auto-reset; "
                "inspect uncommitted files first (foot-gun #17)."
            ),
        },
        args.json_stdout,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
