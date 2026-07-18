#!/usr/bin/env python3
"""
contest-target-fetch.py — Phase 1 of §J GitHub fix-commit mining.

For each contest in reference/contest_registry.jsonl, performs a sparse-checkout
of the target repos at two points:
  - pre_audit/  : state at commit_pin (audit-window end)
  - post_audit/ : current HEAD

Layout under /private/tmp/contest_targets/:
  <contest_id>/
    <repo_basename>/
      pre_audit/    ← sparse-worktree at commit_pin
      post_audit/   ← sparse-worktree at HEAD
    .fetch_meta.json

Skips private repos (403/404 on ls-remote). Surfaces skip count.
Supports --max-parallel 4 + exponential back-off on rate-limit errors.

M14-trap note: repos whose commit_pin == "<TODO_OPERATOR>" are cloned to
HEAD only (pre_audit is skipped and noted in .fetch_meta.json).

Usage:
  python3 tools/contest-target-fetch.py [options]

Options:
  --contest-id <id>     Process only this contest
  --platform <p>        Filter by platform
  --max-contests N      Stop after N contests (useful for smoke-tests)
  --max-parallel N      Concurrency (default 4)
  --dry-run             Print actions without executing git commands
  --output-dir <dir>    Override /private/tmp/contest_targets/
  --fix-mine-status <s> Only process contests with this fix_mine_status
                        (default: pending)
  --all-statuses        Ignore fix_mine_status filter

Exit codes: 0 = all ok or dry-run, 1 = one or more fetch failures.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_REGISTRY_PATH = _REPO_ROOT / "reference" / "contest_registry.jsonl"
_DEFAULT_OUTPUT_DIR = Path("/private/tmp/contest_targets")

_TODO_PLACEHOLDER = "<TODO_OPERATOR>"


# ---------------------------------------------------------------------------
# Registry loader
# ---------------------------------------------------------------------------

def _load_registry() -> list:
    if not _REGISTRY_PATH.exists():
        print(f"[ERROR] registry not found: {_REGISTRY_PATH}", file=sys.stderr)
        sys.exit(2)
    rows = []
    with _REGISTRY_PATH.open() as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"[ERROR] line {lineno}: {exc}", file=sys.stderr)
                sys.exit(1)
    return rows


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _run_git(cmd: list, cwd: Path = None, dry_run: bool = False,
             retries: int = 3) -> tuple:
    """
    Run a git command with exponential back-off on exit code 429-ish errors.
    Returns (returncode, stdout, stderr).
    In dry-run mode prints the command and returns (0, "", "").
    """
    if dry_run:
        display = " ".join(str(c) for c in cmd)
        print(f"  [DRY-RUN] {display}" + (f" (cwd={cwd})" if cwd else ""))
        return (0, "", "")

    delay = 2
    for attempt in range(retries):
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            cwd=str(cwd) if cwd else None
        )
        stderr_lower = result.stderr.lower()
        # Rate-limit signals from GitHub
        if result.returncode != 0 and (
            "rate limit" in stderr_lower or
            "429" in result.stderr or
            "too many requests" in stderr_lower
        ):
            if attempt < retries - 1:
                print(f"  [RATE-LIMIT] backing off {delay}s (attempt {attempt+1}/{retries})")
                time.sleep(delay)
                delay = min(delay * 2, 60)
                continue
        return (result.returncode, result.stdout, result.stderr)
    return (result.returncode, result.stdout, result.stderr)


def _is_private_repo(url: str, dry_run: bool = False) -> bool:
    """
    Use git ls-remote to probe accessibility.
    Returns True if the repo appears private/inaccessible.
    """
    if dry_run:
        return False
    rc, _, stderr = _run_git(
        ["git", "ls-remote", "--heads", url, "HEAD"],
        dry_run=False, retries=1
    )
    if rc != 0:
        # 128 = command failed (private, 404, DNS, …)
        return True
    return False


def _resolve_head_sha(url: str, dry_run: bool = False) -> str:
    """Return the HEAD SHA of the remote repo, or empty string on failure."""
    if dry_run:
        return "HEAD"
    rc, stdout, _ = _run_git(
        ["git", "ls-remote", url, "HEAD"],
        dry_run=False, retries=2
    )
    if rc != 0 or not stdout.strip():
        return ""
    return stdout.strip().split()[0]


# ---------------------------------------------------------------------------
# Per-repo fetch
# ---------------------------------------------------------------------------

def _fetch_repo(contest_id: str, repo: dict, output_dir: Path,
                dry_run: bool = False) -> dict:
    """
    Sparse-clone one repo for a contest. Returns a result dict.
    repo = {url, commit_pin, notes}
    """
    url = repo.get("url", "")
    commit_pin = repo.get("commit_pin", _TODO_PLACEHOLDER)
    basename = Path(url.rstrip("/").rstrip(".git")).name
    if not basename:
        basename = "repo"

    target_root = output_dir / contest_id / basename
    result = {
        "url": url,
        "basename": basename,
        "commit_pin": commit_pin,
        "commit_pin_is_placeholder": (commit_pin == _TODO_PLACEHOLDER),
        "pre_audit_ok": False,
        "post_audit_ok": False,
        "skipped": False,
        "skip_reason": None,
        "head_sha": None,
        "error": None,
    }

    print(f"  [{contest_id}] {basename}: probing {url} ...")

    # --- Privacy probe ---
    if _is_private_repo(url, dry_run=dry_run):
        result["skipped"] = True
        result["skip_reason"] = "private or inaccessible"
        print(f"  [{contest_id}] {basename}: SKIPPED (private/inaccessible)")
        return result

    head_sha = _resolve_head_sha(url, dry_run=dry_run)
    result["head_sha"] = head_sha

    # --- Sparse clone (filter=blob:none, no-checkout) ---
    bare_dir = target_root / ".git_bare"
    if dry_run or not (bare_dir / "HEAD").exists():
        rc, _, stderr = _run_git([
            "git", "clone",
            "--filter=blob:none",
            "--no-checkout",
            "--bare",
            url, str(bare_dir),
        ], dry_run=dry_run)
        if rc != 0 and not dry_run:
            result["error"] = f"clone failed: {stderr[:200]}"
            print(f"  [{contest_id}] {basename}: clone FAILED: {stderr[:120]}")
            return result
    else:
        # Update existing bare clone
        _run_git(["git", "fetch", "--prune"], cwd=bare_dir, dry_run=dry_run)

    # --- post_audit worktree (HEAD) ---
    post_dir = target_root / "post_audit"
    if not dry_run:
        post_dir.mkdir(parents=True, exist_ok=True)
    post_sha = head_sha or "HEAD"
    rc, _, stderr = _run_git([
        "git", "--git-dir", str(bare_dir),
        "worktree", "add",
        "--detach",
        str(post_dir),
        post_sha,
    ], dry_run=dry_run)
    if rc == 0 or dry_run:
        result["post_audit_ok"] = True
    elif "already exists" in stderr.lower():
        result["post_audit_ok"] = True  # already set up
    else:
        result["error"] = (result.get("error") or "") + f"; post_audit worktree failed: {stderr[:200]}"
        print(f"  [{contest_id}] {basename}: post_audit worktree WARN: {stderr[:80]}")

    # --- pre_audit worktree (commit_pin) ---
    if commit_pin == _TODO_PLACEHOLDER:
        result["pre_audit_ok"] = False
        result["skip_reason"] = (result.get("skip_reason") or "") + \
            " commit_pin is <TODO_OPERATOR>; pre_audit skipped"
        print(f"  [{contest_id}] {basename}: pre_audit SKIPPED "
              "(commit_pin is placeholder)")
    else:
        pre_dir = target_root / "pre_audit"
        if not dry_run:
            pre_dir.mkdir(parents=True, exist_ok=True)
        rc, _, stderr = _run_git([
            "git", "--git-dir", str(bare_dir),
            "worktree", "add",
            "--detach",
            str(pre_dir),
            commit_pin,
        ], dry_run=dry_run)
        if rc == 0 or dry_run:
            result["pre_audit_ok"] = True
        elif "already exists" in stderr.lower():
            result["pre_audit_ok"] = True
        else:
            result["error"] = (result.get("error") or "") + \
                f"; pre_audit worktree failed: {stderr[:200]}"
            print(f"  [{contest_id}] {basename}: pre_audit worktree WARN: {stderr[:80]}")

    print(f"  [{contest_id}] {basename}: "
          f"pre={result['pre_audit_ok']} post={result['post_audit_ok']}")
    return result


# ---------------------------------------------------------------------------
# Per-contest fetch
# ---------------------------------------------------------------------------

def _fetch_contest(contest: dict, output_dir: Path, dry_run: bool) -> dict:
    contest_id = contest["contest_id"]
    repos = contest.get("target_repos", [])
    contest_dir = output_dir / contest_id
    if not dry_run:
        contest_dir.mkdir(parents=True, exist_ok=True)

    repo_results = []
    for repo in repos:
        r = _fetch_repo(contest_id, repo, output_dir, dry_run=dry_run)
        repo_results.append(r)

    skipped = [r for r in repo_results if r.get("skipped")]
    failed = [r for r in repo_results
              if not r.get("skipped") and r.get("error")]
    ok = [r for r in repo_results
          if not r.get("skipped") and not r.get("error")]

    meta = {
        "contest_id": contest_id,
        "platform": contest.get("platform"),
        "protocol": contest.get("protocol"),
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dry_run": dry_run,
        "repos": repo_results,
        "summary": {
            "total": len(repos),
            "ok": len(ok),
            "skipped": len(skipped),
            "failed": len(failed),
        }
    }

    meta_path = contest_dir / ".fetch_meta.json"
    if not dry_run:
        with meta_path.open("w") as fh:
            json.dump(meta, fh, indent=2)
    else:
        print(f"  [DRY-RUN] would write {meta_path}")

    return meta


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sparse-clone contest target repos for fix-commit mining")
    parser.add_argument("--contest-id", help="Process only this contest_id")
    parser.add_argument("--platform", help="Filter by platform")
    parser.add_argument("--max-contests", type=int, default=0,
                        help="Stop after N contests (0 = no limit)")
    parser.add_argument("--max-parallel", type=int, default=4,
                        help="Concurrent fetch workers (default 4)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without cloning")
    parser.add_argument("--output-dir", type=Path,
                        default=_DEFAULT_OUTPUT_DIR)
    parser.add_argument("--fix-mine-status", default="pending",
                        help="Only process contests with this fix_mine_status "
                             "(default: pending)")
    parser.add_argument("--all-statuses", action="store_true",
                        help="Ignore fix_mine_status filter")

    args = parser.parse_args()

    rows = _load_registry()

    # Apply filters
    candidates = rows
    if args.contest_id:
        candidates = [r for r in candidates if r["contest_id"] == args.contest_id]
    if args.platform:
        candidates = [r for r in candidates if r.get("platform") == args.platform]
    if not args.all_statuses:
        candidates = [r for r in candidates
                      if r.get("fix_mine_status") == args.fix_mine_status]

    if args.max_contests > 0:
        candidates = candidates[:args.max_contests]

    if not candidates:
        print("[INFO] no contests match the given filters")
        return 0

    print(f"[INFO] will process {len(candidates)} contest(s) "
          f"with max_parallel={args.max_parallel}"
          + (" [DRY-RUN]" if args.dry_run else ""))

    if not args.dry_run:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    all_metas = []
    failed_ids = []

    with ThreadPoolExecutor(max_workers=args.max_parallel) as pool:
        futures = {
            pool.submit(_fetch_contest, c, args.output_dir, args.dry_run): c
            for c in candidates
        }
        for fut in as_completed(futures):
            contest = futures[fut]
            try:
                meta = fut.result()
                all_metas.append(meta)
                s = meta["summary"]
                status_str = (
                    f"ok={s['ok']} skipped={s['skipped']} failed={s['failed']}"
                )
                print(f"[DONE] {meta['contest_id']}: {status_str}")
                if s["failed"] > 0:
                    failed_ids.append(meta["contest_id"])
            except Exception as exc:
                cid = contest["contest_id"]
                print(f"[ERROR] {cid}: unhandled exception: {exc}", file=sys.stderr)
                failed_ids.append(cid)

    # Summary
    total_repos = sum(m["summary"]["total"] for m in all_metas)
    total_ok = sum(m["summary"]["ok"] for m in all_metas)
    total_skipped = sum(m["summary"]["skipped"] for m in all_metas)
    total_failed = sum(m["summary"]["failed"] for m in all_metas)

    print("\n=== Fetch Summary ===")
    print(f"  Contests processed : {len(all_metas)}")
    print(f"  Repos total        : {total_repos}")
    print(f"  Repos ok           : {total_ok}")
    print(f"  Repos skipped      : {total_skipped} (private / placeholder pin)")
    print(f"  Repos failed       : {total_failed}")
    if failed_ids:
        print(f"  Failed contest IDs : {failed_ids}")

    return 1 if failed_ids else 0


if __name__ == "__main__":
    sys.exit(main())
