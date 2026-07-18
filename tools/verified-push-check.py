#!/usr/bin/env python3
"""verified-push-check.py — single-purpose pre-PR-creation gate.

Background
----------
V5-P0-19 / foot-gun #10: agents have repeatedly opened PRs against a stale
remote SHA because their LOCAL tree has commits the REMOTE has never seen
("I pushed but didn't"). The general ``agent-preflight-check.py`` includes
``verified_push`` as one row among 6, which makes it easy to miss in
glance-over agent output.

This tool is the **mechanical gate**: a single check, a single exit code,
zero noise. Recommend operators wire it directly into their PR-create
workflow:

  python3 tools/verified-push-check.py --branch <branch> && gh pr create ...

Behaviour
---------
- Returns 0 ONLY when LOCAL HEAD == REMOTE HEAD for the named branch.
- Returns 1 on any mismatch, including: branch not yet pushed, force-push
  divergence, partial push (e.g. amended commit not pushed). The output
  paragraph explains why each shape matters.
- Returns 2 on argument / invocation error (no branch, no gh on PATH,
  unparseable origin, no git repo).

Discipline
----------
- Stdlib only.
- Network: a single ``gh api`` call to fetch the remote head SHA.
- Offline-safe via ``--no-network`` (returns 2 — the caller asked for a
  network-y check; we cannot satisfy it offline).
- No side effects (no auto-push, no state writes).

Usage
-----
::

    python3 tools/verified-push-check.py --branch fix-foo
    python3 tools/verified-push-check.py --branch fix-foo --json
    python3 tools/verified-push-check.py            # autodetect branch
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


_REMOTE_URL_RES = (
    re.compile(r"https?://github\.com/(?P<o>[^/]+)/(?P<r>[^/]+?)(?:\.git)?/?$"),
    re.compile(r"git@github\.com:(?P<o>[^/]+)/(?P<r>[^/]+?)(?:\.git)?$"),
    re.compile(r"ssh://git@github\.com[:/](?P<o>[^/]+)/(?P<r>[^/]+?)(?:\.git)?$"),
)


def _git(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.stdout.strip()
    except OSError:
        return ""


def _resolve_owner_repo(repo: Path) -> tuple[str, str] | None:
    url = _git(repo, "remote", "get-url", "origin")
    if not url:
        return None
    for rx in _REMOTE_URL_RES:
        m = rx.match(url.strip())
        if m:
            return m.group("o"), m.group("r")
    return None


def _emit(payload: dict, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    status = payload.get("status", "FAIL")
    print(f"[verified-push-check] {status}")
    for line in payload.get("evidence", []):
        print(f"  {line}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Single-purpose pre-PR gate: verify LOCAL HEAD matches REMOTE "
            "HEAD before opening a pull request (V5-P0-19, foot-gun #10)."
        ),
    )
    p.add_argument("--repo", type=Path, default=Path.cwd(),
                   help="Repository root (default: cwd).")
    p.add_argument("--branch", default=None,
                   help="Branch to verify (default: detect HEAD).")
    p.add_argument("--no-network", action="store_true",
                   help="Reject — the check requires a remote SHA fetch.")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON instead of human output.")
    args = p.parse_args(argv)

    repo = args.repo
    if not (repo / ".git").exists():
        # Worktrees have a .git file (not dir).
        if not (repo / ".git").is_file():
            _emit({
                "status": "FAIL",
                "evidence": [f"{repo} is not a git repo"],
            }, as_json=args.json)
            return 2

    if args.no_network:
        _emit({
            "status": "FAIL",
            "evidence": [
                "--no-network passed; this check cannot be satisfied "
                "without a remote SHA fetch. Drop the flag and try again.",
            ],
        }, as_json=args.json)
        return 2

    if shutil.which("gh") is None:
        _emit({
            "status": "FAIL",
            "evidence": ["`gh` not on PATH; cannot fetch remote SHA"],
        }, as_json=args.json)
        return 2

    branch = args.branch
    if not branch:
        branch = _git(repo, "rev-parse", "--abbrev-ref", "HEAD")
        if not branch or branch == "HEAD":
            _emit({
                "status": "FAIL",
                "evidence": ["detached HEAD; pass --branch to verify"],
            }, as_json=args.json)
            return 2

    or_ = _resolve_owner_repo(repo)
    if not or_:
        _emit({
            "status": "FAIL",
            "evidence": [
                "could not parse owner/repo from `git remote get-url origin`",
            ],
        }, as_json=args.json)
        return 2
    owner, name = or_
    local_sha = _git(repo, "rev-parse", "HEAD")
    if not local_sha:
        _emit({
            "status": "FAIL",
            "evidence": ["could not resolve local HEAD"],
        }, as_json=args.json)
        return 2

    api_path = f"repos/{owner}/{name}/git/refs/heads/{branch}"
    try:
        proc = subprocess.run(
            ["gh", "api", api_path, "--jq", ".object.sha"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        _emit({
            "status": "FAIL",
            "evidence": ["`gh api` timed out after 15s"],
        }, as_json=args.json)
        return 1
    if proc.returncode != 0:
        _emit({
            "status": "FAIL",
            "branch": branch,
            "owner": owner,
            "repo": name,
            "local_sha": local_sha,
            "remote_sha": None,
            "evidence": [
                f"branch `{branch}` not found on {owner}/{name} "
                "(or insufficient gh auth).",
                f"gh api stderr: {proc.stderr.strip()[:200]}",
                "Foot-gun #10 / V5-P0-19: opening a PR before pushing is "
                "the canonical 'I pushed but didn't' silent failure. "
                "The PR will either fail to create or — worse — race a "
                "later push and pin a stale commit, so reviewers see "
                "an SHA the agent never intended.",
                f"suggested fix: git push -u origin {branch}",
            ],
        }, as_json=args.json)
        return 1
    remote_sha = proc.stdout.strip()
    if remote_sha != local_sha:
        _emit({
            "status": "FAIL",
            "branch": branch,
            "owner": owner,
            "repo": name,
            "local_sha": local_sha,
            "remote_sha": remote_sha,
            "evidence": [
                f"LOCAL  = {local_sha}",
                f"REMOTE = {remote_sha}",
                f"branch = {branch} on {owner}/{name}",
                "Foot-gun #10 / V5-P0-19: LOCAL and REMOTE diverge. "
                "Reviewers will see a SHA different from what the agent "
                "is reasoning about; force-pushes after PR open can "
                "invalidate prior approvals; recovery requires a manual "
                "re-review pass.",
                f"suggested fix: git push origin {branch}  "
                "(use --force-with-lease only if you intentionally "
                "rewrote history)",
            ],
        }, as_json=args.json)
        return 1

    _emit({
        "status": "PASS",
        "branch": branch,
        "owner": owner,
        "repo": name,
        "local_sha": local_sha,
        "remote_sha": remote_sha,
        "evidence": [
            f"LOCAL = REMOTE = {local_sha}",
            f"branch = {branch} on {owner}/{name}",
        ],
    }, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
