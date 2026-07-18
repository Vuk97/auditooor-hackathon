#!/usr/bin/env python3
"""agent-worktree-dispatch.py — worktree + verified-push automation for
sub-agent dispatches.

PR #129. Codex-revised plan absorbed at ac0c5ead. Composes with the existing
``tools/agent-dispatch-enforced.sh`` gatekeeper — this tool owns
git/worktree orchestration, verified-push, and the ``active_agents`` tracker;
it never touches the prior-audit context-completeness checks the gatekeeper
owns.

Key invariants (Codex emphasis):
- NEVER kill, signal, or replace a running agent. Stall handling is advisory.
- Cleanup gated on ``pushed-verified`` state only.
- Failed worktrees retained for debugging.
- All ``gh``/``git`` calls routed through ``_run`` so tests can stub them.
- Atomic tracker writes via ``os.replace``.

Usage::

    agent-worktree-dispatch.py prepare      --parent-pr 129 --task-slug plan-revise
    agent-worktree-dispatch.py verify-push  --branch pr129-plan-revise-20260425T1430Z
    agent-worktree-dispatch.py status       [--stale-secs 1800]
    agent-worktree-dispatch.py retry        --branch <sub-branch>
    agent-worktree-dispatch.py cleanup      --branch <sub-branch>

Exit codes (production):
    0 success
    2 verified-push SHA mismatch
    3 remote ref missing (push didn't reach origin)
    4 network / ``gh`` failure
    5 retry budget exhausted (operator action required)
    6 tracker file corruption / illegal state transition
    7 worktree clash (path or branch already exists)
    8 bad input (slug rejected, missing parent PR, etc.)
    9 unsafe workspace (dirty checkout or unwritable worktree root)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_WORKTREE_ROOT = Path("/private/tmp/auditooor-agent-worktrees")
DEFAULT_TRACKER = Path.home() / ".config" / "auditooor" / "active_agents.txt"

SLUG_REGEX = re.compile(r"^[a-z0-9-]+$")
SLUG_MAX_LEN = 40

VALID_STATES = (
    "prepared",
    "dispatched",
    "pushed-verified",
    "push-mismatch",
    "cleaned",
    "retry-needed",
)

# Allowed forward transitions. Backwards / sideways jumps are rejected.
ALLOWED_TRANSITIONS = {
    "prepared": {"dispatched", "pushed-verified", "push-mismatch", "retry-needed"},
    "dispatched": {"pushed-verified", "push-mismatch", "retry-needed"},
    "push-mismatch": {"dispatched", "pushed-verified", "retry-needed"},
    "retry-needed": {"dispatched", "pushed-verified", "push-mismatch"},
    "pushed-verified": {"cleaned"},
    "cleaned": set(),  # terminal
}

EXIT_OK = 0
EXIT_PUSH_MISMATCH = 2
EXIT_REMOTE_MISSING = 3
EXIT_NETWORK = 4
EXIT_RETRY_EXHAUSTED = 5
EXIT_TRACKER = 6
EXIT_WORKTREE_CLASH = 7
EXIT_BAD_INPUT = 8
EXIT_UNSAFE_WORKSPACE = 9


# ---------------------------------------------------------------------------
# subprocess shim — single chokepoint so tests can stub ``gh``/``git``.
# ---------------------------------------------------------------------------

# Tests monkeypatch ``_RUNNER`` to inject a fake. Production code never touches
# ``subprocess.run`` directly outside this helper.
_RUNNER: Callable[..., subprocess.CompletedProcess] = subprocess.run


def _run(
    cmd: list[str],
    *,
    cwd: Optional[Path] = None,
    check: bool = False,
    env: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess. All ``gh``/``git`` calls go through here."""
    return _RUNNER(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        capture_output=True,
        text=True,
        check=check,
        env=env,
    )


# ---------------------------------------------------------------------------
# Branch-name + slug validation
# ---------------------------------------------------------------------------


def validate_slug(slug: str) -> None:
    """Raise ``ValueError`` if slug is not lowercase kebab-case (<=40 chars)."""
    if not slug:
        raise ValueError("task slug is empty")
    if len(slug) > SLUG_MAX_LEN:
        raise ValueError(
            f"task slug too long ({len(slug)} > {SLUG_MAX_LEN}): {slug!r}"
        )
    if not SLUG_REGEX.match(slug):
        raise ValueError(
            f"task slug must match {SLUG_REGEX.pattern} (lowercase kebab-case): {slug!r}"
        )


def utc_iso_compact(now: Optional[datetime] = None) -> str:
    """Return ``YYYYMMDDTHHMMZ`` (minute precision UTC)."""
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.strftime("%Y%m%dT%H%MZ")


def make_branch_name(parent_pr: int, slug: str, now: Optional[datetime] = None) -> str:
    """Build the canonical sub-branch name.

    Format: ``pr<parent-pr>-<task-slug>-<YYYYMMDDTHHMMZ>``.
    """
    if not isinstance(parent_pr, int) or parent_pr <= 0:
        raise ValueError(f"parent_pr must be positive int, got {parent_pr!r}")
    validate_slug(slug)
    return f"pr{parent_pr}-{slug}-{utc_iso_compact(now)}"


def make_worktree_path(root: Path, branch: str) -> Path:
    return root / f"wt-{branch}"


# ---------------------------------------------------------------------------
# Tracker: read / write / atomic update
# ---------------------------------------------------------------------------


@dataclass
class TrackerEntry:
    created_iso: str
    branch: str
    worktree: str
    parent_pr: int
    state: str
    retry_count: int = 0

    def serialize(self) -> str:
        return "\t".join(
            [
                self.created_iso,
                self.branch,
                self.worktree,
                str(self.parent_pr),
                self.state,
                str(self.retry_count),
            ]
        )

    @classmethod
    def parse(cls, line: str) -> "TrackerEntry":
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 6:
            raise ValueError(
                f"tracker line must have 6 tab-separated fields, got {len(parts)}: {line!r}"
            )
        try:
            parent_pr = int(parts[3])
            retry_count = int(parts[5])
        except ValueError as e:
            raise ValueError(f"tracker line has non-int field: {line!r}") from e
        if parts[4] not in VALID_STATES:
            raise ValueError(
                f"tracker line has unknown state {parts[4]!r}: {line!r}"
            )
        return cls(
            created_iso=parts[0],
            branch=parts[1],
            worktree=parts[2],
            parent_pr=parent_pr,
            state=parts[4],
            retry_count=retry_count,
        )


def tracker_read(path: Path) -> list[TrackerEntry]:
    if not path.exists():
        return []
    entries: list[TrackerEntry] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                entries.append(TrackerEntry.parse(line))
            except ValueError as e:
                raise ValueError(
                    f"tracker file {path} line {i} corrupt: {e}"
                ) from e
    return entries


def tracker_write(path: Path, entries: list[TrackerEntry]) -> None:
    """Atomic write via tempfile + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(entry.serialize() + "\n")
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def tracker_upsert(path: Path, entry: TrackerEntry) -> None:
    """Insert or replace the row with matching branch."""
    entries = tracker_read(path)
    replaced = False
    out: list[TrackerEntry] = []
    for e in entries:
        if e.branch == entry.branch:
            out.append(entry)
            replaced = True
        else:
            out.append(e)
    if not replaced:
        out.append(entry)
    tracker_write(path, out)


def tracker_find(path: Path, branch: str) -> Optional[TrackerEntry]:
    for e in tracker_read(path):
        if e.branch == branch:
            return e
    return None


def transition_state(current: str, desired: str) -> str:
    """Return ``desired`` if the transition is allowed, else raise."""
    if current == desired:
        # Idempotent; no-op.
        return current
    if current not in ALLOWED_TRANSITIONS:
        raise ValueError(f"unknown current state {current!r}")
    if desired not in VALID_STATES:
        raise ValueError(f"unknown target state {desired!r}")
    if desired not in ALLOWED_TRANSITIONS[current]:
        raise ValueError(
            f"illegal state transition {current!r} → {desired!r}"
        )
    return desired


# ---------------------------------------------------------------------------
# Stall classification (advisory only)
# ---------------------------------------------------------------------------


def classify_stale(
    transcript_path: Optional[Path],
    *,
    now_ts: float,
    launched_ts: float,
    died_at_launch_secs: int = 5 * 60,
    stalled_mid_work_secs: int = 30 * 60,
    died_at_launch_byte_threshold: int = 500,
) -> str:
    """Heuristic classification:

    - tiny transcript (<500 bytes) and launched >5 min ago → ``suspected-died-at-launch``
    - large transcript but mtime stale >30 min → ``suspected-stalled-mid-work``
    - anything else → ``active``
    """
    if transcript_path is None or not transcript_path.exists():
        if now_ts - launched_ts > died_at_launch_secs:
            return "suspected-died-at-launch"
        return "active"

    stat = transcript_path.stat()
    size = stat.st_size
    mtime = stat.st_mtime
    age_since_launch = now_ts - launched_ts
    age_since_mtime = now_ts - mtime

    if size < died_at_launch_byte_threshold and age_since_launch > died_at_launch_secs:
        return "suspected-died-at-launch"
    if age_since_mtime > stalled_mid_work_secs:
        return "suspected-stalled-mid-work"
    return "active"


# ---------------------------------------------------------------------------
# gh / git helpers (route through _run)
# ---------------------------------------------------------------------------


_GIT_REMOTE_RE = re.compile(
    r"""^
    (?:
        https?://(?:[^/@]+@)?github\.com/   # https://github.com/  or https://user@github.com/
      | git@github\.com:                    # git@github.com:
      | ssh://git@github\.com[:/]           # ssh://git@github.com[:/]
    )
    (?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?
    $""",
    re.VERBOSE,
)


def _resolve_origin_owner_repo() -> Optional[str]:
    """Try to resolve ``<owner>/<repo>`` from ``git remote get-url origin``.

    Returns ``None`` if origin is missing or the URL doesn't match a known
    GitHub remote shape — caller falls back to ``gh api`` placeholder syntax.
    """
    cp = _run(["git", "remote", "get-url", "origin"])
    if cp.returncode != 0:
        return None
    url = cp.stdout.strip()
    if not url:
        return None
    m = _GIT_REMOTE_RE.match(url)
    if m is None:
        return None
    return f"{m.group('owner')}/{m.group('repo')}"


def _gh_api_ref_sha(branch: str, repo: Optional[str] = None) -> tuple[int, Optional[str], str]:
    """Return ``(rc, sha_or_None, stderr)``.

    rc == 0  → sha is the remote object SHA
    rc == 22 → 404, ref missing
    rc != 0  → network / gh failure (caller maps to EXIT_NETWORK)

    Endpoint resolution order (Codex 16:15Z fix — never pass ``:owner/:repo``):
      1. explicit ``repo`` argument (e.g. ``Vuk97/auditooor``)
      2. derived from ``git remote get-url origin``
      3. fall back to ``{owner}/{repo}`` curly-brace placeholders, which ``gh
         api`` expands using the current repo context. NOT ``:owner/:repo`` —
         that literal text is not a documented placeholder and will not
         resolve.
    """
    if repo:
        owner_repo = repo
    else:
        owner_repo = _resolve_origin_owner_repo() or "{owner}/{repo}"
    path = f"repos/{owner_repo}/git/refs/heads/{branch}"
    cmd = ["gh", "api", path, "--jq", ".object.sha"]
    cp = _run(cmd)
    if cp.returncode == 0:
        sha = cp.stdout.strip()
        if not sha:
            return 4, None, "empty sha from gh api"
        return 0, sha, cp.stderr
    # gh maps 404 → exit 22 in --jq mode in some versions; otherwise the
    # message contains "Not Found". Detect both.
    err = (cp.stdout + cp.stderr).lower()
    if "not found" in err or cp.returncode == 22:
        return 3, None, cp.stderr
    return 4, None, cp.stderr


def _git_local_head(worktree: Path) -> tuple[int, Optional[str], str]:
    cp = _run(["git", "rev-parse", "HEAD"], cwd=worktree)
    if cp.returncode != 0:
        return cp.returncode, None, cp.stderr
    return 0, cp.stdout.strip(), cp.stderr


def _repo_status_porcelain() -> tuple[int, str, str]:
    cp = _run(["git", "status", "--porcelain"])
    return cp.returncode, cp.stdout, cp.stderr


def _ensure_writable_dir(path: Path) -> tuple[bool, str]:
    """Create `path` if needed and verify the current process can write there."""
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".auditooor-write-test"
        probe.write_text("ok\n", encoding="utf-8")
        probe.unlink()
        return True, ""
    except OSError as exc:
        return False, str(exc)


def prepare_environment_error(worktree_root: Path) -> str | None:
    """Fail closed before dispatching agents from unsafe local state.

    Agent work should start from a clean, writable coordinator checkout. Dirty
    roots and unwritable worktree locations are the exact foot-guns that cause
    permission prompts, branch deletion blockers, and accidental commits from
    the canonical clone.
    """
    rc, stdout, stderr = _repo_status_porcelain()
    if rc != 0:
        return f"cannot verify coordinator checkout cleanliness: {stderr.strip()}"
    if stdout.strip():
        return (
            "coordinator checkout is dirty; use a clean /private/tmp worktree "
            "before preparing agent work"
        )
    ok, reason = _ensure_writable_dir(worktree_root)
    if not ok:
        return f"worktree root is not writable: {worktree_root} ({reason})"
    return None


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


def cmd_prepare(args: argparse.Namespace) -> int:
    try:
        validate_slug(args.task_slug)
    except ValueError as e:
        print(f"[bad-input] {e}", file=sys.stderr)
        return EXIT_BAD_INPUT

    if args.parent_pr <= 0:
        print(f"[bad-input] parent-pr must be positive, got {args.parent_pr}", file=sys.stderr)
        return EXIT_BAD_INPUT

    root = Path(os.environ.get("AUDITOOOR_WORKTREE_DIR", str(DEFAULT_WORKTREE_ROOT)))
    tracker = Path(os.environ.get("AUDITOOOR_AGENTS_FILE", str(DEFAULT_TRACKER)))
    unsafe_reason = prepare_environment_error(root)
    if unsafe_reason:
        print(f"[unsafe-workspace] {unsafe_reason}", file=sys.stderr)
        return EXIT_UNSAFE_WORKSPACE

    branch = make_branch_name(args.parent_pr, args.task_slug)
    wt_path = make_worktree_path(root, branch)

    if wt_path.exists():
        print(f"[worktree-clash] path already exists: {wt_path}", file=sys.stderr)
        return EXIT_WORKTREE_CLASH

    base = args.base_branch or f"refs/remotes/origin/pr{args.parent_pr}-head"
    # Best effort: if base ref doesn't exist, fall back to origin/main.
    cp_check = _run(["git", "rev-parse", "--verify", base])
    if cp_check.returncode != 0:
        # Try to use parent-PR head via gh.
        cp_pr = _run(
            ["gh", "pr", "view", str(args.parent_pr), "--json", "headRefName,headRepositoryOwner,headRepository", "--jq", ".headRefName"]
        )
        if cp_pr.returncode == 0 and cp_pr.stdout.strip():
            base = f"origin/{cp_pr.stdout.strip()}"
        else:
            base = "origin/main"

    # I-04 (PR #158): refresh the parent ref before branching the worktree
    # off it. Without this fetch, parallel agents that started before the
    # latest parent commit landed will silently base off a stale tip and
    # produce a stale-base PR. The fetch maps `origin/<branch>` → the
    # remote ref `<branch>`. Best-effort: failures (offline, sandbox) fall
    # through to `git worktree add`, which then either succeeds against
    # whatever ref is locally available or fails with the existing
    # `[worktree-add-failed]` path. `--no-tags` keeps the operation
    # cheap on big repos. Operators can opt out via `--no-fetch-parent`.
    if base.startswith(("origin/", "refs/remotes/origin/")):
        if base.startswith("refs/remotes/origin/"):
            remote_branch = base[len("refs/remotes/origin/"):]
        else:
            remote_branch = base[len("origin/"):]
        if remote_branch and not getattr(args, "no_fetch_parent", False):
            _run([
                "git", "fetch", "--no-tags", "origin",
                f"{remote_branch}:refs/remotes/origin/{remote_branch}",
            ])

    cp_add = _run(["git", "worktree", "add", str(wt_path), "-b", branch, base])
    if cp_add.returncode != 0:
        msg = (cp_add.stdout + cp_add.stderr).strip()
        if "already exists" in msg.lower() or "already checked out" in msg.lower():
            print(f"[worktree-clash] {msg}", file=sys.stderr)
            return EXIT_WORKTREE_CLASH
        print(f"[worktree-add-failed] {msg}", file=sys.stderr)
        return EXIT_WORKTREE_CLASH

    entry = TrackerEntry(
        created_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        branch=branch,
        worktree=str(wt_path),
        parent_pr=args.parent_pr,
        state="prepared",
        retry_count=0,
    )
    try:
        tracker_upsert(tracker, entry)
    except ValueError as e:
        print(f"[tracker] {e}", file=sys.stderr)
        return EXIT_TRACKER

    # Machine-parseable output.
    print(f"AGENT_BRANCH={branch}")
    print(f"AGENT_WORKTREE={wt_path}")
    print(f"AGENT_PARENT_PR={args.parent_pr}")
    print(f"AGENT_TRACKER={tracker}")
    return EXIT_OK


def cmd_verify_push(args: argparse.Namespace) -> int:
    tracker = Path(os.environ.get("AUDITOOOR_AGENTS_FILE", str(DEFAULT_TRACKER)))
    entry = tracker_find(tracker, args.branch)
    if entry is None:
        print(f"[tracker] no entry for branch {args.branch}", file=sys.stderr)
        return EXIT_TRACKER

    worktree = Path(entry.worktree)
    rc, local_sha, err = _git_local_head(worktree)
    if rc != 0 or not local_sha:
        print(f"[git] failed to read LOCAL HEAD in {worktree}: {err}", file=sys.stderr)
        return EXIT_NETWORK

    repo = args.repo or os.environ.get("AUDITOOOR_GH_REPO")
    rc, remote_sha, err = _gh_api_ref_sha(args.branch, repo=repo)
    if rc == 3:
        print(
            f"[push-missing] remote ref refs/heads/{args.branch} not found on origin "
            f"(local HEAD={local_sha}). Push did not reach origin.",
            file=sys.stderr,
        )
        new_entry = TrackerEntry(
            created_iso=entry.created_iso,
            branch=entry.branch,
            worktree=entry.worktree,
            parent_pr=entry.parent_pr,
            state=transition_state(entry.state, "push-mismatch"),
            retry_count=entry.retry_count,
        )
        tracker_upsert(tracker, new_entry)
        return EXIT_REMOTE_MISSING
    if rc == 4:
        print(f"[gh] network/api failure: {err}", file=sys.stderr)
        return EXIT_NETWORK

    if local_sha != remote_sha:
        print(
            f"[push-mismatch] LOCAL={local_sha} REMOTE={remote_sha}",
            file=sys.stderr,
        )
        new_entry = TrackerEntry(
            created_iso=entry.created_iso,
            branch=entry.branch,
            worktree=entry.worktree,
            parent_pr=entry.parent_pr,
            state=transition_state(entry.state, "push-mismatch"),
            retry_count=entry.retry_count,
        )
        tracker_upsert(tracker, new_entry)
        return EXIT_PUSH_MISMATCH

    if args.parent_pr is not None:
        cp_pr = _run(
            ["gh", "pr", "view", str(args.parent_pr), "--json", "headRefOid", "--jq", ".headRefOid"]
        )
        if cp_pr.returncode == 0:
            pr_sha = cp_pr.stdout.strip()
            if pr_sha and pr_sha != local_sha:
                print(
                    f"[pr-head-mismatch] PR #{args.parent_pr} headRefOid={pr_sha} "
                    f"LOCAL={local_sha}. Sub-branch advanced past PR head — likely OK "
                    f"if sub-branch is not the PR head; surfacing for operator review.",
                    file=sys.stderr,
                )

    new_entry = TrackerEntry(
        created_iso=entry.created_iso,
        branch=entry.branch,
        worktree=entry.worktree,
        parent_pr=entry.parent_pr,
        state=transition_state(entry.state, "pushed-verified"),
        retry_count=entry.retry_count,
    )
    try:
        tracker_upsert(tracker, new_entry)
    except ValueError as e:
        print(f"[tracker] illegal transition: {e}", file=sys.stderr)
        return EXIT_TRACKER

    print(f"VERIFIED MATCH: branch={args.branch} sha={local_sha}")
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    tracker = Path(os.environ.get("AUDITOOOR_AGENTS_FILE", str(DEFAULT_TRACKER)))
    entries = tracker_read(tracker)
    now_ts = time.time()
    print(f"# tracker={tracker} entries={len(entries)}")
    for e in entries:
        # We don't have launched_ts in the tracker; approximate from created_iso.
        try:
            launched_ts = datetime.strptime(
                e.created_iso, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            launched_ts = now_ts
        # Heuristic transcript path: agent transcripts live under the worktree
        # by default. Operator can override with AUDITOOOR_TRANSCRIPT_GLOB but
        # we just check the worktree dir mtime as a coarse signal.
        wt = Path(e.worktree)
        transcript_path = wt if wt.exists() else None
        klass = classify_stale(
            transcript_path,
            now_ts=now_ts,
            launched_ts=launched_ts,
            stalled_mid_work_secs=args.stale_secs,
        )
        print(
            f"{e.branch}\tstate={e.state}\tretry={e.retry_count}\t"
            f"parent_pr={e.parent_pr}\tclass={klass}\tworktree={e.worktree}"
        )
    return EXIT_OK


def cmd_retry(args: argparse.Namespace) -> int:
    tracker = Path(os.environ.get("AUDITOOOR_AGENTS_FILE", str(DEFAULT_TRACKER)))
    entry = tracker_find(tracker, args.branch)
    if entry is None:
        print(f"[tracker] no entry for branch {args.branch}", file=sys.stderr)
        return EXIT_TRACKER
    if entry.retry_count >= 1:
        print(
            f"[retry-exhausted] branch {args.branch} already retried "
            f"{entry.retry_count} times — manual escalation required. "
            f"NOTE: This tool does NOT kill or signal the live agent. "
            f"Operator/Claude must take action.",
            file=sys.stderr,
        )
        return EXIT_RETRY_EXHAUSTED
    new_entry = TrackerEntry(
        created_iso=entry.created_iso,
        branch=entry.branch,
        worktree=entry.worktree,
        parent_pr=entry.parent_pr,
        state=transition_state(entry.state, "retry-needed"),
        retry_count=entry.retry_count + 1,
    )
    try:
        tracker_upsert(tracker, new_entry)
    except ValueError as e:
        print(f"[tracker] illegal transition: {e}", file=sys.stderr)
        return EXIT_TRACKER
    print(f"RETRY_BRANCH={args.branch}")
    print(f"RETRY_WORKTREE={entry.worktree}")
    print(f"RETRY_COUNT={new_entry.retry_count}")
    print("# Operator: re-run Task dispatch with a fresh brief in the same worktree.")
    return EXIT_OK


def cmd_cleanup(args: argparse.Namespace) -> int:
    tracker = Path(os.environ.get("AUDITOOOR_AGENTS_FILE", str(DEFAULT_TRACKER)))
    entry = tracker_find(tracker, args.branch)
    if entry is None:
        print(f"[tracker] no entry for branch {args.branch}", file=sys.stderr)
        return EXIT_TRACKER
    if entry.state != "pushed-verified":
        print(
            f"[cleanup-refused] branch {args.branch} is in state {entry.state!r}; "
            f"only pushed-verified worktrees may be cleaned. Worktree retained "
            f"for debugging: {entry.worktree}",
            file=sys.stderr,
        )
        return EXIT_TRACKER

    cp = _run(["git", "worktree", "remove", entry.worktree])
    if cp.returncode != 0:
        msg = (cp.stdout + cp.stderr).strip()
        print(f"[git] worktree remove failed: {msg}", file=sys.stderr)
        return EXIT_WORKTREE_CLASH

    new_entry = TrackerEntry(
        created_iso=entry.created_iso,
        branch=entry.branch,
        worktree=entry.worktree,
        parent_pr=entry.parent_pr,
        state=transition_state(entry.state, "cleaned"),
        retry_count=entry.retry_count,
    )
    tracker_upsert(tracker, new_entry)
    print(f"CLEANED={args.branch}")
    return EXIT_OK


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-worktree-dispatch",
        description="Worktree + verified-push automation for sub-agent dispatches (PR #129).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp_prep = sub.add_parser("prepare", help="Create worktree + sub-branch.")
    sp_prep.add_argument("--parent-pr", type=int, required=True)
    sp_prep.add_argument("--task-slug", type=str, required=True)
    sp_prep.add_argument("--base-branch", type=str, default=None)
    sp_prep.add_argument(
        "--no-fetch-parent",
        action="store_true",
        help=(
            "Skip the pre-worktree `git fetch origin <parent>` step. "
            "Defaults to fetching to avoid stale-base PRs (PR #158 I-04)."
        ),
    )
    sp_prep.set_defaults(func=cmd_prepare)

    sp_v = sub.add_parser("verify-push", help="Compare LOCAL HEAD to remote.")
    sp_v.add_argument("--branch", type=str, required=True)
    sp_v.add_argument("--parent-pr", type=int, default=None)
    sp_v.add_argument("--repo", type=str, default=None)
    sp_v.set_defaults(func=cmd_verify_push)

    sp_st = sub.add_parser("status", help="Read-only listing + advisory stall classification.")
    sp_st.add_argument("--stale-secs", type=int, default=30 * 60)
    sp_st.set_defaults(func=cmd_status)

    sp_r = sub.add_parser("retry", help="Mark branch retry-needed; max 1 retry.")
    sp_r.add_argument("--branch", type=str, required=True)
    sp_r.set_defaults(func=cmd_retry)

    sp_c = sub.add_parser("cleanup", help="Remove worktree (only if pushed-verified).")
    sp_c.add_argument("--branch", type=str, required=True)
    sp_c.set_defaults(func=cmd_cleanup)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
