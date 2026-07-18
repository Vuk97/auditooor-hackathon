#!/usr/bin/env python3
"""submission-target-rubric-fetch.py — T-07.

Fetch + cache active SEVERITY rubric per submission platform. Surface a
staleness flag if the rubric was last fetched more than 24h before
submission.

Cached rubric directory: `cache/submission_rubrics/`
Each rubric is `<platform>_<key>.json` with shape:
  {
    "platform": "immunefi" | "cantina" | "sherlock" | "c4" | "hackerone" | "spearbit" | "cyfrin",
    "key": "general" | "<program-slug>",
    "fetched_at": "ISO8601",
    "source_url": "<url>",
    "rubric_text": "<verbatim severity rubric>",
    "categorical_severities": ["Critical", "High", "Medium", "Low", "Info"],
    "score_basis": "categorical|numeric|hybrid",
    "notes": "..."
  }

Usage:
  # Fetch all default rubrics (uses well-known public severity URLs)
  python3 tools/submission-target-rubric-fetch.py --fetch-all

  # Fetch one platform
  python3 tools/submission-target-rubric-fetch.py --platform immunefi --key general

  # Check staleness without fetching
  python3 tools/submission-target-rubric-fetch.py --check-staleness \\
    --platform immunefi --key general

  # Bulk staleness report (all cached)
  python3 tools/submission-target-rubric-fetch.py --staleness-report

This tool DOES NOT auto-fetch on submission — it surfaces staleness so
operators decide whether to refresh. Many platforms have rate-limited or
gated severity docs and an automated fetcher could trigger ToS issues.

Exit codes:
  0  success / staleness check passed
  1  staleness threshold exceeded (>24h)
  2  invalid args / fetch failed
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CACHE_DIR = REPO / "cache" / "submission_rubrics"
STALE_HOURS = 24

# Default well-known sources. Adjust as platforms publish updates.
# These are documentation pages, not API endpoints. Tool fetches HTML/MD.
DEFAULT_SOURCES = {
    ("immunefi", "general"): {
        "url": "https://immunefi.com/severity-classification-system/",
        "score_basis": "categorical",
        "categorical_severities": ["Critical", "High", "Medium", "Low", "Insight"],
        "notes": "Immunefi vulnerability severity v2.3 — main reference for crypto bug bounties.",
    },
    ("cantina", "general"): {
        "url": "https://docs.cantina.xyz/cantina-docs/",
        "score_basis": "categorical",
        "categorical_severities": ["Critical", "High", "Medium", "Low", "Informational"],
        "notes": "Cantina contest severity. Per-contest rubric may further constrain — fetch per-contest separately.",
    },
    ("sherlock", "general"): {
        "url": "https://docs.sherlock.xyz/audits/judging/judging",
        "score_basis": "categorical",
        "categorical_severities": ["High", "Medium", "Low"],
        "notes": "Sherlock judging matrix — High/Medium/Low only; no Critical or Info distinction.",
    },
    ("c4", "general"): {
        "url": "https://docs.code4rena.com/awarding/judging-criteria/severity-categorization",
        "score_basis": "numeric",
        "categorical_severities": ["3 (High Risk)", "2 (Medium Risk)", "1 (Low Risk)", "QA / Gas"],
        "notes": "Code4rena severity tiers — 1/2/3 numeric mapping.",
    },
    ("hackerone", "general"): {
        "url": "https://docs.hackerone.com/en/articles/8369891-severity",
        "score_basis": "hybrid",
        "categorical_severities": ["Critical", "High", "Medium", "Low", "None"],
        "notes": "HackerOne severity uses CVSS 3.1 score basis but maps to categorical labels.",
    },
    ("spearbit", "general"): {
        "url": "https://github.com/spearbit/portfolio",
        "score_basis": "categorical",
        "categorical_severities": ["Critical", "High", "Medium", "Low", "Gas optimization", "Informational"],
        "notes": "Spearbit reports use categorical labels; per-engagement severity boundary negotiated with team.",
    },
    ("cyfrin", "general"): {
        "url": "https://github.com/cyfrin/audit-reports",
        "score_basis": "categorical",
        "categorical_severities": ["High", "Medium", "Low", "Informational", "Gas"],
        "notes": "Cyfrin reports use categorical labels matching their audit checklist.",
    },
}


def cache_path(platform: str, key: str) -> Path:
    return CACHE_DIR / f"{platform}_{key}.json"


def fetch_url(url: str, timeout_sec: int = 30) -> tuple[bool, str]:
    """Returns (ok, text-or-error)."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "auditooor-rubric-fetch/1.0"})
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            return True, resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        return False, f"fetch_error: {e}"
    except Exception as e:
        return False, f"unexpected_error: {e}"


def fetch_one(platform: str, key: str, dry_run: bool = False) -> dict:
    src = DEFAULT_SOURCES.get((platform, key))
    if not src:
        return {"ok": False, "reason": f"no default source for ({platform}, {key})"}
    if dry_run:
        return {"ok": True, "dry_run": True, "url": src["url"]}
    ok, content = fetch_url(src["url"])
    if not ok:
        return {"ok": False, "reason": content, "url": src["url"]}
    rubric = {
        "platform": platform,
        "key": key,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_url": src["url"],
        "rubric_text": content[:200_000],  # cap at 200KB
        "categorical_severities": src["categorical_severities"],
        "score_basis": src["score_basis"],
        "notes": src["notes"],
    }
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path(platform, key).write_text(json.dumps(rubric, indent=2))
    return {"ok": True, "platform": platform, "key": key, "cached_at": rubric["fetched_at"], "url": src["url"]}


def check_staleness(platform: str, key: str) -> dict:
    cp = cache_path(platform, key)
    if not cp.exists():
        return {"platform": platform, "key": key, "exists": False, "stale": True, "stale_reason": "not cached"}
    try:
        rubric = json.loads(cp.read_text())
        fetched_at = datetime.datetime.fromisoformat(rubric["fetched_at"])
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=datetime.timezone.utc)
    except Exception as e:
        return {"platform": platform, "key": key, "exists": True, "stale": True, "stale_reason": f"parse error: {e}"}
    now = datetime.datetime.now(datetime.timezone.utc)
    age_hours = (now - fetched_at).total_seconds() / 3600.0
    return {
        "platform": platform,
        "key": key,
        "exists": True,
        "fetched_at": rubric["fetched_at"],
        "age_hours": round(age_hours, 2),
        "stale": age_hours > STALE_HOURS,
        "stale_reason": f"older than {STALE_HOURS}h" if age_hours > STALE_HOURS else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch-all", action="store_true")
    ap.add_argument("--platform")
    ap.add_argument("--key", default="general")
    ap.add_argument("--check-staleness", action="store_true")
    ap.add_argument("--staleness-report", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if args.fetch_all:
        results = []
        for (plat, key) in DEFAULT_SOURCES:
            r = fetch_one(plat, key, dry_run=args.dry_run)
            results.append(r)
            print(f"  [{plat}/{key}] {'OK' if r.get('ok') else 'FAIL'} {r.get('url') or r.get('reason')}")
        ok_count = sum(1 for r in results if r.get("ok"))
        print(f"\n[fetch-all] {ok_count}/{len(results)} ok")
        return 0 if ok_count > 0 else 2

    if args.staleness_report:
        any_stale = False
        for cp in sorted(CACHE_DIR.glob("*.json")):
            stem = cp.stem
            try:
                plat, key = stem.split("_", 1)
            except ValueError:
                continue
            r = check_staleness(plat, key)
            stale_marker = "STALE" if r.get("stale") else "fresh"
            age = r.get("age_hours", "?")
            print(f"  [{stale_marker}] {plat}/{key} age={age}h")
            if r.get("stale"):
                any_stale = True
        if not any(CACHE_DIR.glob("*.json")):
            print("[staleness-report] no rubrics cached. Run --fetch-all first.")
            return 2
        return 1 if any_stale else 0

    if args.check_staleness:
        if not args.platform:
            print("--check-staleness requires --platform", file=sys.stderr)
            return 2
        r = check_staleness(args.platform, args.key)
        print(json.dumps(r, indent=2))
        return 1 if r.get("stale") else 0

    if args.platform:
        r = fetch_one(args.platform, args.key, dry_run=args.dry_run)
        print(json.dumps(r, indent=2))
        return 0 if r.get("ok") else 2

    print("No action specified. Use --fetch-all / --platform <p> / --staleness-report / --check-staleness", file=sys.stderr)
    ap.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
