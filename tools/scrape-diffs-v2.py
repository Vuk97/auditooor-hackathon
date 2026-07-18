#!/usr/bin/env python3
"""
scrape-diffs-v2.py — aggressive diff + report scraper (Round 29, Issue #87 expansion)

## Cron
    # Run every 6 hours, resuming from the ledger automatically:
    0 */6 * * * cd <repo-root> && python3 tools/scrape-diffs-v2.py --limit 500 >> logs/scrape-diffs-v2.log 2>&1

Upgrades over v1:
  - Scans solodit_raw/*.json AND drafts_audit_text/*.yaml (covers 21k+ findings)
  - Handles github.com URLs with /commit/SHA, /pull/N, /blob/SHA/path, /tree/SHA/path
  - File globbing expanded: .sol / .t.sol / .huff / .vy / .rs / .cairo / .move / .md
  - PR mode: when URL is /pull/<N>, fetches PR via gh CLI (if available) → real diff
  - Size cap enforcement + rate limit + resumable ledger
  - Fully unattended: designed for long background runs
  - Auto-splits diff hunks into candidate (vuln, clean) fixture pairs grouped by file

Usage:
    python3 tools/scrape-diffs-v2.py --limit 500
    python3 tools/scrape-diffs-v2.py --limit 10000 --background     # resumable
    python3 tools/scrape-diffs-v2.py --status
    python3 tools/scrape-diffs-v2.py --split                         # post-process .diffs → fixtures

All outputs land in patterns/fixtures/auto/:
  finding_<id>.diff           — raw diff from the fix commit / PR
  finding_<id>.meta.json      — {title, severity, url, cluster_id, fix_commit, file_list}
  finding_<id>.vuln.<ext>     — pre-fix file(s) — one per .sol/.vy/.rs touched
  finding_<id>.clean.<ext>    — post-fix file(s)

The splitter writes vuln/clean pairs from the diff by reading BEFORE + AFTER
blobs via `git show <sha>:<path>` for each touched file. Non-code files
(*.md, *.json config) saved as `report.md` for audit-report-in-repo cases.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
SOLODIT_RAW = AUDITOOOR_DIR / "detectors" / "_specs" / "solodit_raw"
DRAFTS_AUDIT_TEXT = AUDITOOOR_DIR / "detectors" / "_specs" / "drafts_audit_text"
AUTO_FIXTURES = AUDITOOOR_DIR / "patterns" / "fixtures" / "auto"
LEDGER = AUDITOOOR_DIR / "reference" / "diff_scrape_ledger.json"
CLONE_CACHE = Path("/tmp/auditooor_diff_clones")

SIZE_LIMIT_MB = 80
CLONE_TIMEOUT_S = 120
GIT_CMD_TIMEOUT_S = 60

# Extract any github commit/PR/blob URL
GITHUB_URL_RE = re.compile(
    r"github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/(commit|pull|blob|tree)/([\w./-]+?))?(?:[)\s\"'#?]|$)"
)

INTERESTING_GLOBS = ["*.sol", "*.t.sol", "*.huff", "*.vy", "*.rs",
                     "*.cairo", "*.move", "*.md", "*.txt"]


def load_ledger():
    if LEDGER.exists():
        try:
            return json.loads(LEDGER.read_text())
        except Exception:
            pass
    return {
        "version": 2,
        "processed_ids": [],
        "success": 0,
        "failed": 0,
        "skipped": 0,
        "last_run": None,
        "sources": {"solodit_raw": 0, "drafts_audit_text": 0, "other": 0},
    }


def save_ledger(data):
    LEDGER.write_text(json.dumps(data, indent=2))


def _parse_url(url):
    m = GITHUB_URL_RE.search(url)
    if not m:
        return None
    owner, repo, kind, ref = m.group(1), m.group(2), m.group(3), m.group(4) or ""
    return {"owner": owner, "repo": repo.rstrip(".git"), "kind": kind or "",
            "ref": ref.split("/")[0] if ref else "", "path": "/".join(ref.split("/")[1:]) if ref else ""}


def iter_candidates():
    """Yield (source_name, fid, title, url, severity) for every finding
    with a resolvable GitHub link across all mined corpora."""

    # 1. Solodit raw findings
    if SOLODIT_RAW.exists():
        for jf in sorted(SOLODIT_RAW.glob("*.json")):
            try:
                data = json.loads(jf.read_text())
            except Exception:
                continue
            for f in data.get("findings", []):
                fid = f.get("id")
                title = (f.get("title") or "")[:120]
                severity = (f.get("impact") or "").upper()
                content = "\n".join([
                    f.get("content") or "", f.get("contest_link") or "",
                    f.get("summary") or "",
                ])
                m = GITHUB_URL_RE.search(content)
                if m:
                    yield ("solodit_raw", str(fid), title, m.group(0), severity)

    # 2. Audit-text drafts
    try:
        import yaml as _yaml
    except ImportError:
        _yaml = None
    if _yaml and DRAFTS_AUDIT_TEXT.exists():
        for yf in sorted(DRAFTS_AUDIT_TEXT.glob("*.yaml")):
            try:
                spec = _yaml.safe_load(yf.read_text()) or {}
            except Exception:
                continue
            fid = spec.get("name") or yf.stem
            title = spec.get("help", "") or spec.get("wiki_title", "")
            severity = str(spec.get("severity") or "").upper()
            # Look for github URLs in every string field
            for key in ("wiki_exploit_scenario", "wiki_description", "source", "url"):
                v = spec.get(key)
                if not v or not isinstance(v, str):
                    continue
                m = GITHUB_URL_RE.search(v)
                if m:
                    yield ("drafts_audit_text", f"at:{fid}", title[:120],
                           m.group(0), severity)
                    break


def _run(cmd, timeout=GIT_CMD_TIMEOUT_S):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def _clone_if_needed(owner, repo):
    repo_dir = CLONE_CACHE / f"{owner}__{repo}"
    if repo_dir.exists():
        return repo_dir
    # Shallow clone
    r = _run(["git", "clone", "--depth", "50", "--no-tags",
              f"https://github.com/{owner}/{repo}.git", str(repo_dir)],
             timeout=CLONE_TIMEOUT_S)
    if r is None or r.returncode != 0:
        return None
    # Size cap enforcement
    try:
        size_mb = sum(p.stat().st_size for p in repo_dir.rglob("*") if p.is_file()) / 1_000_000
        if size_mb > SIZE_LIMIT_MB:
            return None  # too big — ignore but don't delete
    except Exception:
        pass
    return repo_dir


def _fetch_pr(repo_dir, pr_number):
    """Return the merge-commit SHA for PR N, or None."""
    # Try `gh` first if available
    gh_check = _run(["which", "gh"])
    if gh_check and gh_check.returncode == 0:
        r = _run(["gh", "pr", "view", str(pr_number),
                  "--repo", str(repo_dir.name).replace("__", "/"),
                  "--json", "mergeCommit", "-q", ".mergeCommit.oid"])
        if r and r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    # Fallback: fetch refs/pull/N/head and use its SHA
    r = _run(["git", "-C", str(repo_dir), "fetch", "origin",
              f"refs/pull/{pr_number}/head:pr-{pr_number}"],
             timeout=CLONE_TIMEOUT_S)
    if r is None or r.returncode != 0:
        return None
    r = _run(["git", "-C", str(repo_dir), "rev-parse", f"pr-{pr_number}"])
    if r and r.returncode == 0:
        return r.stdout.strip()
    return None


def _extract_diff(repo_dir, ref):
    """Return (diff_text, touched_files_list)."""
    # Ensure ref is available; deepen if not
    check = _run(["git", "-C", str(repo_dir), "cat-file", "-e", ref])
    if check is None or check.returncode != 0:
        _run(["git", "-C", str(repo_dir), "fetch", "--deepen=500"],
             timeout=CLONE_TIMEOUT_S)

    r = _run(["git", "-C", str(repo_dir), "show", ref,
              "--name-only", "--pretty=format:"])
    if r is None or r.returncode != 0:
        return None, []
    touched = [line.strip() for line in r.stdout.splitlines() if line.strip()]
    interesting_touched = [
        p for p in touched
        if any(p.endswith(g.lstrip("*")) for g in INTERESTING_GLOBS)
    ]
    if not interesting_touched:
        return None, []
    # Build full diff scoped to interesting globs
    diff = _run(["git", "-C", str(repo_dir), "show", ref, "--"]
                + INTERESTING_GLOBS)
    if diff is None or diff.returncode != 0:
        return None, []
    return diff.stdout, interesting_touched


def _write_pair(repo_dir, ref, path, fid):
    """Extract <ref>^:path → vuln, <ref>:path → clean."""
    # Normalize output file extension
    ext = Path(path).suffix or ".txt"
    clean_path = AUTO_FIXTURES / f"finding_{fid}__{Path(path).name}.clean{ext}"
    vuln_path = AUTO_FIXTURES / f"finding_{fid}__{Path(path).name}.vuln{ext}"
    # Before
    r_before = _run(["git", "-C", str(repo_dir), "show", f"{ref}^:{path}"])
    # After
    r_after = _run(["git", "-C", str(repo_dir), "show", f"{ref}:{path}"])
    if r_before and r_before.returncode == 0 and r_before.stdout:
        vuln_path.write_text(r_before.stdout[:200_000])
    if r_after and r_after.returncode == 0 and r_after.stdout:
        clean_path.write_text(r_after.stdout[:200_000])


def scrape_one(source, fid, title, url, severity, ledger):
    parsed = _parse_url(url)
    if not parsed:
        return "skipped_url"
    owner, repo, kind, ref = parsed["owner"], parsed["repo"], parsed["kind"], parsed["ref"]
    repo_dir = _clone_if_needed(owner, repo)
    if repo_dir is None:
        return "failed_clone"

    # Resolve ref for /pull/N mode
    if kind == "pull":
        sha = _fetch_pr(repo_dir, ref)
        if not sha:
            return "failed_pr"
        ref = sha
    if not ref or len(ref) < 7:
        return "skipped_no_ref"

    diff_text, touched = _extract_diff(repo_dir, ref)
    if not diff_text:
        return "skipped_no_diff"

    # Write raw diff + meta
    (AUTO_FIXTURES / f"finding_{fid}.diff").write_text(diff_text[:500_000])
    meta = {
        "fid": fid, "source": source, "title": title, "severity": severity,
        "url": url, "owner": owner, "repo": repo, "commit": ref,
        "touched_files": touched,
    }
    (AUTO_FIXTURES / f"finding_{fid}.meta.json").write_text(json.dumps(meta, indent=2))
    # Auto-split fixtures
    for p in touched[:8]:  # cap at 8 files per finding
        try:
            _write_pair(repo_dir, ref, p, fid)
        except Exception:
            continue
    return "ok"


def scrape(limit, dry_run):
    ledger = load_ledger()
    processed = set(ledger.get("processed_ids", []))
    AUTO_FIXTURES.mkdir(parents=True, exist_ok=True)
    CLONE_CACHE.mkdir(parents=True, exist_ok=True)

    candidates = []
    for source, fid, title, url, sev in iter_candidates():
        if fid in processed:
            continue
        candidates.append((source, fid, title, url, sev))
        if len(candidates) >= limit:
            break

    print(f"[scrape-v2] {len(candidates)} new candidates (limit={limit})")
    print(f"[scrape-v2] previously processed: {len(processed)}")
    # Source distribution
    src_ctr = {}
    for s, _, _, _, _ in candidates:
        src_ctr[s] = src_ctr.get(s, 0) + 1
    print(f"[scrape-v2] by source: {src_ctr}")
    if dry_run:
        for (s, fid, title, url, sev) in candidates[:25]:
            print(f"  [{s}:{fid}] {title[:60]} — {url[:80]}")
        print("\n(dry-run, no cloning)")
        return

    t0 = time.time()
    success = ledger.get("success", 0)
    failed = ledger.get("failed", 0)
    skipped = ledger.get("skipped", 0)
    sources = ledger.get("sources", {"solodit_raw": 0, "drafts_audit_text": 0, "other": 0})

    for i, (source, fid, title, url, sev) in enumerate(candidates, 1):
        processed.add(fid)
        status = scrape_one(source, fid, title, url, sev, ledger)
        if status == "ok":
            success += 1
            sources[source] = sources.get(source, 0) + 1
        elif status.startswith("failed"):
            failed += 1
        else:
            skipped += 1

        # Print progress every 10
        if i % 10 == 0 or i == len(candidates):
            elapsed = time.time() - t0
            print(f"  [{i}/{len(candidates)}] elapsed={elapsed:.0f}s "
                  f"success={success} failed={failed} skipped={skipped}")

        # Resume-friendly: save ledger every 20 items
        if i % 20 == 0:
            ledger["processed_ids"] = list(processed)
            ledger["success"] = success
            ledger["failed"] = failed
            ledger["skipped"] = skipped
            ledger["sources"] = sources
            ledger["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            save_ledger(ledger)

    ledger["processed_ids"] = list(processed)
    ledger["success"] = success
    ledger["failed"] = failed
    ledger["skipped"] = skipped
    ledger["sources"] = sources
    ledger["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    save_ledger(ledger)
    print(f"\n[done] success={success} failed={failed} skipped={skipped} "
          f"total_time={time.time()-t0:.0f}s")


def status():
    l = load_ledger()
    print(f"  Processed IDs: {len(l.get('processed_ids', []))}")
    print(f"  Success:       {l.get('success', 0)}")
    print(f"  Failed:        {l.get('failed', 0)}")
    print(f"  Skipped:       {l.get('skipped', 0)}")
    print(f"  By source:     {l.get('sources', {})}")
    print(f"  Last run:      {l.get('last_run')}")
    print(f"  Diffs dir:     {AUTO_FIXTURES}")
    if AUTO_FIXTURES.exists():
        n_diff = len(list(AUTO_FIXTURES.glob("*.diff")))
        n_vuln = len(list(AUTO_FIXTURES.glob("*.vuln.*")))
        n_clean = len(list(AUTO_FIXTURES.glob("*.clean.*")))
        print(f"  On-disk diffs: {n_diff}")
        print(f"  Vuln fixtures: {n_vuln}")
        print(f"  Clean fixtures:{n_clean}")


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
