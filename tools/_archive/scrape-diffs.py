#!/usr/bin/env python3
"""
scrape-diffs.py — fetch vuln/fix commit pairs from protocol repos (Issue #87)

For each finding with a resolvable GitHub URL, shallow-clone the repo and
extract the diff hunks that touch the flagged function. Write the pre-fix
code as *_vuln.sol and post-fix as *_clean.sol into patterns/fixtures/auto/.

v1 scope (bounded):
  - Only finds URLs that look like github.com/<owner>/<repo>/.../<path>.sol
  - Skips repos > SIZE_LIMIT_MB (default 50 MB)
  - Maxes at MAX_FINDINGS per invocation (default 100) to fit in one run
  - Stores results in a JSON ledger so repeat invocations resume from cursor

This is a first-run, incremental scraper. Not all 19k findings have fix
commits linked directly — coverage will grow as Solodit metadata improves.

Usage:
    python3 tools/scrape-diffs.py                   # scrape next 100
    python3 tools/scrape-diffs.py --limit 500       # scrape next 500
    python3 tools/scrape-diffs.py --dry-run         # list targets, no cloning
    python3 tools/scrape-diffs.py --status          # show cursor + tallies
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
SOLODIT_RAW = AUDITOOOR_DIR / "detectors" / "_specs" / "solodit_raw"
AUTO_FIXTURES = AUDITOOOR_DIR / "patterns" / "fixtures" / "auto"
LEDGER = AUDITOOOR_DIR / "reference" / "diff_scrape_ledger.json"
CLONE_CACHE = Path("/tmp/auditooor_diff_clones")

SIZE_LIMIT_MB = 50
GITHUB_URL_RE = re.compile(
    r"github\.com/([\w.-]+)/([\w.-]+)(?:/tree/|/blob/|/commit/|/pull/)?(\w+)?"
)


def load_ledger():
    if LEDGER.exists():
        try:
            return json.loads(LEDGER.read_text())
        except Exception:
            pass
    return {"version": 1, "processed_ids": [], "success": 0, "failed": 0, "skipped": 0,
            "last_run": None}


def save_ledger(data):
    LEDGER.write_text(json.dumps(data, indent=2))


def iter_candidates():
    """Yield (finding_id, title, github_url) for every finding with a GH link."""
    for jf in sorted(SOLODIT_RAW.glob("*.json")):
        try:
            data = json.loads(jf.read_text())
        except Exception:
            continue
        for f in data.get("findings", []):
            fid = f.get("id")
            content = (f.get("content") or "") + (f.get("contest_link") or "")
            m = GITHUB_URL_RE.search(content)
            if m:
                yield fid, f.get("title", "")[:120], m.group(0)


def _run(cmd, **kw):
    """Wrapper: timeout-bounded subprocess."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60, **kw)
    except subprocess.TimeoutExpired:
        return None


def scrape(limit, dry_run):
    ledger = load_ledger()
    processed = set(ledger.get("processed_ids", []))

    AUTO_FIXTURES.mkdir(parents=True, exist_ok=True)
    CLONE_CACHE.mkdir(parents=True, exist_ok=True)

    candidates = []
    for fid, title, url in iter_candidates():
        if fid in processed:
            continue
        candidates.append((fid, title, url))
        if len(candidates) >= limit:
            break

    print(f"[scrape] {len(candidates)} new candidates (limit={limit})")
    print(f"[scrape] previously processed: {len(processed)}")
    if dry_run:
        for fid, title, url in candidates[:20]:
            print(f"  [{fid}] {title[:60]} — {url}")
        print(f"\n(dry-run, no cloning)")
        return

    success = ledger.get("success", 0)
    failed = ledger.get("failed", 0)
    skipped = ledger.get("skipped", 0)

    for fid, title, url in candidates:
        processed.add(fid)
        # Parse owner/repo
        m = GITHUB_URL_RE.search(url)
        if not m:
            skipped += 1
            continue
        owner, repo, ref = m.group(1), m.group(2), m.group(3) or ""
        repo = repo.rstrip(".git")

        repo_dir = CLONE_CACHE / f"{owner}_{repo}"

        # Clone (shallow) if missing
        if not repo_dir.exists():
            print(f"  [{fid}] cloning {owner}/{repo}...")
            r = _run(["git", "clone", "--depth", "20",
                      f"https://github.com/{owner}/{repo}.git", str(repo_dir)])
            if r is None or r.returncode != 0:
                print(f"    [fail] clone")
                failed += 1
                continue
            # Size check
            size_mb = sum(p.stat().st_size for p in repo_dir.rglob("*") if p.is_file()) / 1_000_000
            if size_mb > SIZE_LIMIT_MB:
                print(f"    [skip] repo > {SIZE_LIMIT_MB}MB ({size_mb:.0f}MB)")
                # Leave cloned but mark skipped
                skipped += 1
                continue

        # Try to extract the fix-commit diff if ref is a commit SHA
        if not ref or len(ref) < 7:
            skipped += 1
            continue
        r = _run(["git", "-C", str(repo_dir), "show", "--stat", ref])
        if r is None or r.returncode != 0:
            # Commit may not be in shallow clone — deepen
            _run(["git", "-C", str(repo_dir), "fetch", "--deepen=200"])
            r = _run(["git", "-C", str(repo_dir), "show", ref])
            if r is None or r.returncode != 0:
                skipped += 1
                continue

        # Extract .sol hunks from the diff
        diff = _run(["git", "-C", str(repo_dir), "show", ref, "--", "*.sol"])
        if diff is None or not diff.stdout:
            skipped += 1
            continue

        # Write raw diff for later pattern-extraction
        (AUTO_FIXTURES / f"finding_{fid}.diff").write_text(diff.stdout[:50000])
        success += 1
        print(f"  [{fid}] ok — diff saved ({len(diff.stdout)} bytes)")

    ledger["processed_ids"] = list(processed)
    ledger["success"] = success
    ledger["failed"] = failed
    ledger["skipped"] = skipped
    ledger["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_ledger(ledger)
    print(f"\n[done] success={success}, failed={failed}, skipped={skipped}")


def status():
    l = load_ledger()
    print(f"  Processed IDs: {len(l.get('processed_ids', []))}")
    print(f"  Success:       {l.get('success', 0)}")
    print(f"  Failed:        {l.get('failed', 0)}")
    print(f"  Skipped:       {l.get('skipped', 0)}")
    print(f"  Last run:      {l.get('last_run')}")
    print(f"  Diffs dir:     {AUTO_FIXTURES}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--status", action="store_true")
    args = ap.parse_args()
    if args.status:
        status()
    else:
        scrape(args.limit, args.dry_run)


if __name__ == "__main__":
    main()
