#!/usr/bin/env python3
"""git-mining-diff-backfill.py - fetch the real DIFF for every shaped commit in
the git-commits-mining reports so hackerman-etl-from-git-mining can classify from
code, not the commit subject.

WHY (2026-06-19): the mining JSONs store only sha/date/subject/url - no diff. So
the ETL's classify_text() saw only the subject and dumped ~75% of records into
generic "security-shaped-commit / security-fix-regression" with boilerplate
mechanics (and ingested pure noise like "Fix units in comments" as a theft vuln).
The diff is the real signal. This tool fetches each commit's diff via plain `git`
(gh api is unauthenticated/flaky here) using a per-repo partial clone (blob:none),
writes it into the row as `diff`, and saves an enriched report. Re-running the ETL
then yields real bug classes (access-control / reentrancy / upgrade-storage / ...).

Idempotent + cached: each upstream_repo is partial-cloned once into the cache dir;
rows that already carry a diff are skipped unless --force. Private/unreachable
repos are skipped with a logged reason (no diff invented).

Usage:
  python3 tools/git-mining-diff-backfill.py --repo MakerDAO/dss        # one repo (validate-cheap)
  python3 tools/git-mining-diff-backfill.py --all                      # every report
  python3 tools/git-mining-diff-backfill.py --all --dry-run            # plan only
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDITS = Path.home() / "audits"
CACHE = Path(os.environ.get("AUDITOOOR_GIT_MINING_CACHE", "/tmp/auditooor-git-mining-cache"))
MAX_DIFF_CHARS = 16000  # bound per commit (classify_text reads first 12k)


def discover_reports() -> list[Path]:
    out: list[Path] = []
    out += [Path(p) for p in glob.glob(str(ROOT / "reports" / "git_commits_mining_*.json"))]
    out += [Path(p) for p in glob.glob(str(AUDITS / "**" / "git_commits_mining_*.json"), recursive=True)]
    return sorted(set(out))


def repo_url(upstream_repo: str) -> str:
    r = upstream_repo.strip().rstrip("/")
    if r.startswith("http"):
        return r if r.endswith(".git") else r + ".git"
    return f"https://github.com/{r}.git"


def _run(cmd: list[str], timeout: int = 180) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:  # noqa: BLE001
        return 1, str(exc)


def ensure_clone(upstream_repo: str) -> Path | None:
    """Partial bare clone (blob:none) of upstream_repo, cached. None if unreachable."""
    slug = upstream_repo.strip().strip("/").replace("/", "__")
    dest = CACHE / f"{slug}.git"
    if dest.is_dir():
        return dest
    CACHE.mkdir(parents=True, exist_ok=True)
    rc, out = _run(["git", "clone", "--bare", "--filter=blob:none", "-q",
                    repo_url(upstream_repo), str(dest)], timeout=600)
    if rc != 0:
        sys.stderr.write(f"[diff-backfill] SKIP clone failed {upstream_repo}: {out.strip()[:160]}\n")
        return None
    return dest


def fetch_diff(clone: Path, sha: str) -> str | None:
    if not sha:
        return None
    # git show fetches the needed blobs on demand (promisor partial clone).
    rc, out = _run(["git", "-C", str(clone), "show", "--no-color", "--format=%s%n%b",
                    sha], timeout=180)
    if rc != 0 or not out.strip():
        # blob may not be fetchable by sha alone if unreachable from any ref
        return None
    return out[:MAX_DIFF_CHARS]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", help="only this upstream_repo (e.g. MakerDAO/dss)")
    ap.add_argument("--all", action="store_true", help="every report")
    ap.add_argument("--force", action="store_true", help="re-fetch rows that already have a diff")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=0, help="cap commits processed (0=all)")
    args = ap.parse_args()
    if not (args.repo or args.all):
        ap.error("pass --repo <owner/repo> or --all")

    reports = discover_reports()
    stats = {"reports": 0, "commits_seen": 0, "diffs_fetched": 0, "skipped_have_diff": 0,
             "skipped_no_diff": 0, "repos_unreachable": []}
    clones: dict[str, Path | None] = {}
    budget = args.limit or 10**9

    for rpath in reports:
        try:
            doc = json.loads(rpath.read_text(encoding="utf-8"))
        except Exception:
            continue
        upstream = str(doc.get("upstream_repo") or doc.get("repo") or "").strip()
        if not upstream:
            continue
        if args.repo and upstream != args.repo:
            continue
        idx = doc.get("shaped_commits_index") or []
        if not idx:
            continue
        stats["reports"] += 1
        changed = False
        for row in idx:
            if budget <= 0:
                break
            stats["commits_seen"] += 1
            if row.get("diff") and not args.force:
                stats["skipped_have_diff"] += 1
                continue
            if args.dry_run:
                continue
            if upstream not in clones:
                clones[upstream] = ensure_clone(upstream)
                if clones[upstream] is None:
                    stats["repos_unreachable"].append(upstream)
            clone = clones[upstream]
            if clone is None:
                stats["skipped_no_diff"] += 1
                continue
            diff = fetch_diff(clone, str(row.get("sha") or ""))
            if diff:
                row["diff"] = diff
                stats["diffs_fetched"] += 1
                changed = True
                budget -= 1
            else:
                stats["skipped_no_diff"] += 1
        if changed and not args.dry_run:
            rpath.write_text(json.dumps(doc, indent=2), encoding="utf-8")

    stats["repos_unreachable"] = sorted(set(stats["repos_unreachable"]))
    print(json.dumps({"schema": "auditooor.git_mining_diff_backfill.v1", **stats}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
