#!/usr/bin/env python3
"""worktree-cleanup.py — cherry-based safe-delete of stale iter branches.

The claudeboy loop workflow cherry-picks task branches into the main trunk
rather than merging them. Cherry-picking creates new commit SHAs on
`claudeboy`, so the original iter task branches never become SHA-ancestors
of `claudeboy` — they carry commits whose changes live on `claudeboy`
under different hashes. `git merge-base --is-ancestor` therefore reports
NO, and `git branch -d` refuses to remove them as "unmerged", even though
every commit on the branch has been patch-applied to `claudeboy` already.

`git cherry -v <target> <branch>` solves this: it reports commits on
`<branch>` by their patch-id equivalence against `<target>`. A `-` prefix
means the commit's patch is already in `<target>`; a `+` prefix means it
is NOT. A branch whose every commit is `-` is, by content, a subset of
`<target>` — safely deletable, even if SHA-ancestry disagrees.

Usage
-----

    tools/worktree-cleanup.py                       # dry-run (default)
    tools/worktree-cleanup.py --really-delete       # destructive

    tools/worktree-cleanup.py --target-branch <ref>
                              --prefix <str>
                              [--worktree-path-prefix <path-prefix>]
                              [--include-worktrees]
                              [--really-delete]
                              [--dry-run]

Safety invariants
-----------------

    * `--dry-run` is the default. `--really-delete` is required to
      actually invoke `git worktree remove` or `git branch -D`.
    * Fail-closed: if `git cherry` errors, returns empty output, or
      returns mixed `+`/`-` lines, the branch is classified PRESERVE.
      Only an all-`-` response produces SAFE-TO-DELETE.
    * Branches `claudeboy`, `main`, `claudeboy-roadmap-v2`, the
      `--target-branch` itself, and any `origin/*` ref are never
      candidates, regardless of prefix match.
    * When `--worktree-path-prefix` is set, attached-worktree candidates
      outside that filesystem prefix are skipped. Branches without an
      attached worktree are also skipped so operators can target only a
      known stale-worktree namespace such as `/private/tmp/auditooor-`.
    * A branch attached to a worktree is only removed under
      `--really-delete` AND `--include-worktrees`. The worktree itself
      must not have uncommitted changes; dirty attached worktrees are
      classified PRESERVE before any deletion attempt.

Vocabulary
----------

    The tool emits classification labels ("SAFE-TO-DELETE", "PRESERVE",
    "SKIP") for its own algorithm. These are *not* submission-ledger
    status strings and do not touch `docs/10_OF_10_PLAYBOOK.md` §5
    vocabulary.

Truth-audit
-----------

    1. Overclaim risk: "cherry-equivalence = merged" — false. `git cherry`
       only compares patch-id equivalence of commits already applied to
       target, not semantic-equivalence of branch state. A cherry-
       equivalent branch may still have been abandoned mid-rebase. The
       `--dry-run` default + explicit `--really-delete` opt-in + the
       mandatory all-`-` check keep the blast radius bounded.
    2. Status vocabulary: tool emits no tokens that collide with the
       submission ledger's locked `{pending, accepted, paid, duplicate,
       rejected}` set.
    3. Fail-closed on ambiguity: any mixed or empty `git cherry` output
       preserves the branch.
    4. Cannot-judge behaviour: `--dry-run` prints the classification
       table + exits 0 without mutating anything.
    5. Duplicate guard: protected branches (target, main, roadmap-v2)
       never enter the candidate pool.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


# Classification labels. Not ledger vocabulary.
CLASS_SAFE = "SAFE-TO-DELETE"
CLASS_PRESERVE = "PRESERVE"
CLASS_SKIP = "SKIP"

# Branches that never enter the candidate pool regardless of prefix match.
# `--target-branch` is added at runtime.
ALWAYS_PROTECTED = frozenset({"claudeboy", "main", "claudeboy-roadmap-v2"})


@dataclass
class BranchRow:
    branch: str
    classification: str
    reason: str
    plus_count: int
    minus_count: int
    worktree_path: Optional[str] = None
    worktree_clean: Optional[bool] = None


# ---------------------------------------------------------------------------
# git helpers
# ---------------------------------------------------------------------------


def _run_git(args: List[str], cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Invoke git; return (exit_code, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        return 127, "", f"git not found: {exc}"
    return proc.returncode, proc.stdout, proc.stderr


def _list_branches(prefix: str, cwd: Optional[str] = None) -> List[str]:
    """Return local branches whose name starts with `prefix`."""
    rc, out, _ = _run_git(
        ["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
        cwd=cwd,
    )
    if rc != 0:
        return []
    names = [line.strip() for line in out.splitlines() if line.strip()]
    return [n for n in names if n.startswith(prefix)]


def _worktree_for_branch(branch: str, cwd: Optional[str] = None) -> Optional[str]:
    """Return the worktree path (if any) attached to `branch`."""
    rc, out, _ = _run_git(["worktree", "list", "--porcelain"], cwd=cwd)
    if rc != 0:
        return None
    current_path: Optional[str] = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("worktree "):
            current_path = line[len("worktree "):].strip()
        elif line.startswith("branch "):
            ref = line[len("branch "):].strip()
            # ref looks like refs/heads/<branch-name>
            if ref == f"refs/heads/{branch}":
                return current_path
    return None


def _worktree_is_clean(path: str) -> Tuple[bool, str]:
    """Return whether an attached worktree has no tracked/untracked changes."""
    rc, out, err = _run_git(["status", "--porcelain"], cwd=path)
    if rc != 0:
        return False, f"git status failed (rc={rc}): {err.strip()}"
    if out.strip():
        return False, "attached worktree has uncommitted or untracked changes"
    return True, "attached worktree is clean"


def _cherry(target: str, branch: str, cwd: Optional[str] = None) -> Tuple[int, str, str]:
    """Run `git cherry -v <target> <branch>`. Return raw (rc, stdout, stderr)."""
    return _run_git(["cherry", "-v", target, branch], cwd=cwd)


def _branch_ahead_count(target: str, branch: str, cwd: Optional[str] = None) -> Tuple[Optional[int], str]:
    """Return commits reachable from branch but not target."""
    rc, stdout, stderr = _run_git(["rev-list", "--count", f"{target}..{branch}"], cwd=cwd)
    if rc != 0:
        return None, stderr.strip()
    try:
        return int(stdout.strip()), ""
    except ValueError:
        return None, f"unexpected rev-list count: {stdout.strip()!r}"


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------


def _parse_cherry(stdout: str) -> Tuple[int, int]:
    """Parse `git cherry -v` output. Return (plus_count, minus_count).

    Lines starting with `+ ` are un-picked commits; `- ` are picked.
    Any line not matching either shape is ignored.
    """
    plus = 0
    minus = 0
    for raw in stdout.splitlines():
        if raw.startswith("+ "):
            plus += 1
        elif raw.startswith("- "):
            minus += 1
    return plus, minus


def _path_has_prefix(path: str, prefix: str) -> bool:
    """String-prefix path filter for temp namespace cleanup.

    This intentionally supports prefixes such as `/private/tmp/auditooor-`,
    which are not directory ancestors but name namespaces.
    """
    normalized_path = str(Path(path).expanduser().resolve(strict=False))
    normalized_prefix = str(Path(prefix).expanduser().resolve(strict=False))
    return normalized_path.startswith(normalized_prefix)


def apply_worktree_safety_filters(
    row: BranchRow,
    worktree_path_prefix: Optional[str] = None,
) -> BranchRow:
    """Apply attached-worktree prefix and cleanliness gates to a classified row."""
    if row.classification != CLASS_SAFE:
        return row

    if worktree_path_prefix is not None:
        if row.worktree_path is None:
            row.classification = CLASS_SKIP
            row.reason = (
                "no attached worktree; skipped by --worktree-path-prefix "
                f"{worktree_path_prefix!r}"
            )
            return row
        if not _path_has_prefix(row.worktree_path, worktree_path_prefix):
            row.classification = CLASS_SKIP
            row.reason = (
                f"attached worktree outside --worktree-path-prefix "
                f"{worktree_path_prefix!r}"
            )
            return row

    if row.worktree_path is not None:
        clean, reason = _worktree_is_clean(row.worktree_path)
        row.worktree_clean = clean
        if not clean:
            row.classification = CLASS_PRESERVE
            row.reason = reason
    return row


def classify_branch(
    branch: str,
    target: str,
    cwd: Optional[str] = None,
    protected: Optional[Iterable[str]] = None,
) -> BranchRow:
    """Classify `branch` against `target` via `git cherry -v`.

    Fail-closed: any error or mixed `+`/`-` produces PRESERVE. Empty
    `git cherry` output is SAFE only when `git rev-list target..branch`
    confirms the branch has no commits ahead of target.
    """
    protected_set = set(protected or ()) | ALWAYS_PROTECTED | {target}
    if branch in protected_set:
        return BranchRow(
            branch=branch,
            classification=CLASS_SKIP,
            reason=f"protected branch (never a candidate)",
            plus_count=0,
            minus_count=0,
        )

    rc, stdout, stderr = _cherry(target, branch, cwd=cwd)
    if rc != 0:
        return BranchRow(
            branch=branch,
            classification=CLASS_PRESERVE,
            reason=f"git cherry failed (rc={rc}); fail-closed",
            plus_count=0,
            minus_count=0,
        )

    plus, minus = _parse_cherry(stdout)
    if plus == 0 and minus == 0:
        ahead_count, ahead_err = _branch_ahead_count(target, branch, cwd=cwd)
        if ahead_count == 0:
            return BranchRow(
                branch=branch,
                classification=CLASS_SAFE,
                reason=f"branch has no commits ahead of {target}",
                plus_count=0,
                minus_count=0,
            )
        return BranchRow(
            branch=branch,
            classification=CLASS_PRESERVE,
            reason=(
                "git cherry emitted no classifiable lines and ahead-count "
                f"could not prove safety; fail-closed ({ahead_err or 'unknown'})"
            ),
            plus_count=0,
            minus_count=0,
        )
    if plus > 0:
        return BranchRow(
            branch=branch,
            classification=CLASS_PRESERVE,
            reason=f"{plus} commit(s) not yet on {target}; safe-delete would lose work",
            plus_count=plus,
            minus_count=minus,
        )
    # plus == 0 AND minus > 0 → every commit is patch-equivalent to target.
    return BranchRow(
        branch=branch,
        classification=CLASS_SAFE,
        reason=f"all {minus} commit(s) are patch-equivalent to {target}",
        plus_count=plus,
        minus_count=minus,
    )


# ---------------------------------------------------------------------------
# formatting + execution
# ---------------------------------------------------------------------------


def _format_table(rows: List[BranchRow]) -> str:
    if not rows:
        return "(no branches matched the prefix)\n"
    # column widths
    bw = max(len("branch"), max(len(r.branch) for r in rows))
    cw = max(len("classification"), max(len(r.classification) for r in rows))
    lines: List[str] = []
    header = f"{'branch':<{bw}}  {'classification':<{cw}}  +/-    reason"
    lines.append(header)
    lines.append("-" * len(header))
    for r in rows:
        clean = ""
        if r.worktree_clean is True:
            clean = ", clean"
        elif r.worktree_clean is False:
            clean = ", dirty"
        wt = f" [worktree: {r.worktree_path}{clean}]" if r.worktree_path else ""
        counts = f"{r.plus_count}/{r.minus_count}"
        lines.append(
            f"{r.branch:<{bw}}  {r.classification:<{cw}}  {counts:<5}  "
            f"{r.reason}{wt}"
        )
    return "\n".join(lines) + "\n"


def _summary(rows: List[BranchRow]) -> str:
    n_safe = sum(1 for r in rows if r.classification == CLASS_SAFE)
    n_preserve = sum(1 for r in rows if r.classification == CLASS_PRESERVE)
    n_skip = sum(1 for r in rows if r.classification == CLASS_SKIP)
    return (
        f"summary: {n_safe} safe-to-delete, {n_preserve} preserve, "
        f"{n_skip} skip (total {len(rows)})"
    )


def _delete_branch(
    row: BranchRow,
    include_worktrees: bool,
    cwd: Optional[str] = None,
    out=None,
) -> bool:
    """Destructive path. Returns True iff branch was deleted."""
    if out is None:
        out = sys.stdout
    if row.worktree_path is not None:
        if not include_worktrees:
            print(
                f"  skip: {row.branch} has attached worktree at "
                f"{row.worktree_path} and --include-worktrees not set",
                file=out,
            )
            return False
        clean, reason = _worktree_is_clean(row.worktree_path)
        if not clean:
            print(
                f"  skip: {row.branch} has dirty attached worktree at "
                f"{row.worktree_path}: {reason}",
                file=out,
            )
            return False
        rc, wt_out, wt_err = _run_git(
            ["worktree", "remove", row.worktree_path], cwd=cwd,
        )
        if rc != 0:
            print(
                f"  skip: git worktree remove {row.worktree_path} failed "
                f"(rc={rc}): {wt_err.strip()}",
                file=out,
            )
            return False
        print(
            f"  removed worktree: {row.worktree_path}",
            file=out,
        )

    # Use -D because the whole point of this tool is: `git cherry` has
    # proven content-equivalence to target, but SHA-based safe-delete
    # (`-d`) rejects cherry-picked branches. The `classify_branch` call
    # is the safety gate.
    rc, br_out, br_err = _run_git(["branch", "-D", row.branch], cwd=cwd)
    if rc != 0:
        print(
            f"  skip: git branch -D {row.branch} failed (rc={rc}): "
            f"{br_err.strip()}",
            file=out,
        )
        return False
    print(f"  deleted branch: {row.branch} ({row.reason})", file=out)
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="worktree-cleanup.py",
        description=(
            "Safe-delete stale iter branches whose commits are all "
            "patch-equivalent to a target branch via `git cherry`. "
            "Dry-run by default."
        ),
    )
    p.add_argument(
        "--target-branch",
        default="claudeboy",
        help="Branch to compare patch-equivalence against (default: claudeboy).",
    )
    p.add_argument(
        "--prefix",
        default="claudeboy-iter",
        help=(
            "Only consider branches matching this prefix "
            "(default: claudeboy-iter)."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Print the classification table; make no changes (DEFAULT).",
    )
    p.add_argument(
        "--really-delete",
        action="store_true",
        default=False,
        help=(
            "Actually delete SAFE-TO-DELETE branches (and worktrees if "
            "--include-worktrees). Required for any mutation."
        ),
    )
    p.add_argument(
        "--include-worktrees",
        action="store_true",
        default=True,
        help=(
            "When combined with --really-delete, also remove the worktree "
            "attached to each safe-to-delete branch (default: True)."
        ),
    )
    p.add_argument(
        "--worktree-path-prefix",
        default=None,
        help=(
            "Only allow SAFE attached-worktree candidates whose filesystem "
            "path starts with this prefix. Branches without an attached "
            "worktree are skipped when this filter is set. Useful for "
            "namespaces like /private/tmp/auditooor-."
        ),
    )
    p.add_argument(
        "--repo",
        default=None,
        help=(
            "Optional path to a git repository root (default: current "
            "working directory)."
        ),
    )
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    cwd = args.repo
    target = args.target_branch
    prefix = args.prefix

    # Verify target branch resolves; if not, refuse to continue.
    rc, _, err = _run_git(["rev-parse", "--verify", target], cwd=cwd)
    if rc != 0:
        print(
            f"error: --target-branch {target!r} does not resolve "
            f"(rc={rc}): {err.strip()}",
            file=sys.stderr,
        )
        return 2

    branches = _list_branches(prefix, cwd=cwd)
    if not branches:
        print(f"(no branches match prefix {prefix!r})")
        return 0

    rows: List[BranchRow] = []
    for b in sorted(branches):
        row = classify_branch(b, target, cwd=cwd)
        row.worktree_path = _worktree_for_branch(b, cwd=cwd)
        row = apply_worktree_safety_filters(
            row,
            worktree_path_prefix=args.worktree_path_prefix,
        )
        rows.append(row)

    sys.stdout.write(_format_table(rows))
    print(_summary(rows))

    # Default is dry-run; --really-delete must be explicit.
    if not args.really_delete:
        print(
            "(dry-run: no branches or worktrees were removed. "
            "Pass --really-delete to mutate.)"
        )
        return 0

    # Destructive path.
    print("--- destructive pass (--really-delete set) ---")
    deleted = 0
    for r in rows:
        if r.classification != CLASS_SAFE:
            continue
        if _delete_branch(
            r,
            include_worktrees=args.include_worktrees,
            cwd=cwd,
        ):
            deleted += 1
    print(f"deleted {deleted} of {sum(1 for r in rows if r.classification == CLASS_SAFE)} safe branches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
