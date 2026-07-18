#!/usr/bin/env python3
"""mine-all-targets.py - deep commit-mining campaign driver across EVERY target we
have: the contest_registry "popular DeFi" worklist + every audited workspace's
upstream repo + a re-mine of already-mined repos at full depth.

Runs tools/git-commits-mining.py per repo (bidirectional, deep window, far-back
since, security-fix filter), one report per repo under reports/. Idempotent: skips
a repo that already has a *_deep.json report unless --force. Sequential with a
per-repo timeout so one giant repo (cosmos-sdk, nearcore, balancer-monorepo)
cannot stall the batch. The emitted reports feed tools/git-mining-diff-backfill.py
then the LLM diff-classification.

Usage:
  python3 tools/mine-all-targets.py --plan            # print the deduped target list, mine nothing
  python3 tools/mine-all-targets.py --run [--limit N] [--since 2019-01-01]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDITS = Path.home() / "audits"
REPORTS = ROOT / "reports"
ENGINE = ROOT / "tools" / "git-commits-mining.py"
REGISTRY = ROOT / "reference" / "contest_registry.jsonl"

# Always-include extras (operator-named). nuva: bounty reopening - mine deep.
EXTRA = ["ProvLabs/nuva-evm-contracts", "ProvLabs/vault"]


def _slug(repo: str) -> str:
    return repo.strip().strip("/").replace("/", "__")


def registry_repos() -> list[str]:
    out: list[str] = []
    if not REGISTRY.is_file():
        return out
    for line in REGISTRY.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except Exception:
            continue
        for t in r.get("target_repos") or []:
            url = t.get("url") if isinstance(t, dict) else t
            if not url:
                continue
            slug = str(url).split("github.com")[-1].lstrip(":/").replace(".git", "")
            if slug:
                out.append(slug)
    return out


def workspace_repos() -> list[str]:
    out: list[str] = []
    if not AUDITS.is_dir():
        return out
    for ws in sorted(AUDITS.iterdir()):
        for d in (ws / "src", ws):
            try:
                p = subprocess.run(["git", "-C", str(d), "remote", "get-url", "origin"],
                                   capture_output=True, text=True, timeout=5)
            except Exception:
                continue
            u = (p.stdout or "").strip()
            if u and "github.com" in u:
                slug = u.split("github.com")[-1].lstrip(":/").replace(".git", "")
                if slug and not slug.startswith("/"):
                    out.append(slug)
                break
    return out


def already_mined() -> set[str]:
    seen: set[str] = set()
    import glob
    for f in glob.glob(str(REPORTS / "git_commits_mining_*.json")) + \
            glob.glob(str(AUDITS / "**" / "git_commits_mining_*.json"), recursive=True):
        try:
            seen.add((json.load(open(f)).get("upstream_repo") or "").strip().lower())
        except Exception:
            pass
    return seen


def build_targets() -> list[str]:
    raw = registry_repos() + workspace_repos() + EXTRA + sorted(already_mined())
    seen: set[str] = set()
    out: list[str] = []
    for r in raw:
        r = r.strip()
        key = r.lower()
        if not r or "/" not in r or r.startswith("/") or key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


CACHE = Path(os.environ.get("AUDITOOOR_GIT_MINING_CACHE", "/tmp/auditooor-git-mining-cache"))


def ensure_clone(repo: str, timeout: int = 600) -> Path | None:
    """Bare partial clone (full commit history, lazy blobs) - shared with the
    diff-backfill cache so the same checkout serves `git log` mining AND `git show`
    diffs. `gh` is unauthenticated here, so the engine needs --local-repo."""
    dest = CACHE / f"{_slug(repo)}.git"
    if dest.is_dir():
        return dest
    CACHE.mkdir(parents=True, exist_ok=True)
    url = f"https://github.com/{repo}.git"
    try:
        p = subprocess.run(["git", "clone", "--bare", "--filter=blob:none", "-q", url, str(dest)],
                           capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return None
    return dest if p.returncode == 0 and dest.is_dir() else None


def mine_one(repo: str, since: str, window: int, limit: int, timeout: int) -> tuple[str, str]:
    out_path = REPORTS / f"git_commits_mining_{_slug(repo)}_deep.json"
    clone = ensure_clone(repo, timeout=timeout)
    if clone is None:
        return "fail", "clone failed (private/unreachable)"
    cmd = ["python3", str(ENGINE),
           "--workspace", "corpus-deep-mine",
           "--upstream", repo,
           "--mode", "bidirectional",
           "--window", str(window),
           "--since", since,
           "--limit", str(limit),
           "--local-repo", str(clone),
           "--output", str(out_path)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if p.returncode == 0 and out_path.is_file():
            try:
                n = len(json.load(open(out_path)).get("shaped_commits_index") or [])
            except Exception:
                n = -1
            return "ok", f"{n} shaped commits"
        return "fail", (p.stderr or p.stdout or "")[-160:].strip()
    except subprocess.TimeoutExpired:
        return "timeout", f">{timeout}s"
    except Exception as exc:  # noqa: BLE001
        return "error", str(exc)[:160]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--plan", action="store_true", help="print deduped targets, mine nothing")
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--since", default="2019-01-01")
    ap.add_argument("--window", type=int, default=4000)
    ap.add_argument("--limit", type=int, default=300, help="cap shaped commits per repo")
    ap.add_argument("--timeout", type=int, default=900, help="per-repo wall-clock cap (s)")
    ap.add_argument("--force", action="store_true", help="re-mine repos that already have a _deep.json")
    ap.add_argument("--only", help="substring filter on repo slug")
    args = ap.parse_args()
    targets = build_targets()
    if args.only:
        targets = [t for t in targets if args.only.lower() in t.lower()]
    if args.plan or not args.run:
        print(json.dumps({"target_count": len(targets), "targets": targets}, indent=2))
        return 0
    REPORTS.mkdir(parents=True, exist_ok=True)
    done = 0
    for i, repo in enumerate(targets, 1):
        out_path = REPORTS / f"git_commits_mining_{_slug(repo)}_deep.json"
        if out_path.is_file() and not args.force:
            print(f"[{i}/{len(targets)}] SKIP (have report) {repo}", flush=True)
            continue
        status, note = mine_one(repo, args.since, args.window, args.limit, args.timeout)
        if status == "ok":
            done += 1
        print(f"[{i}/{len(targets)}] {status.upper():7s} {repo}  ({note})", flush=True)
    print(f"[mine-all-targets] done: {done}/{len(targets)} mined this run", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
