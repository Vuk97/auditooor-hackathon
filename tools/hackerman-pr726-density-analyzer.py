#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - commit-density analyzer.

Reads the git log of branch ``wave-1-hackerman-capability-lift`` since
2026-05-08 and aggregates commit cadence, author distribution, lane
velocity, and hour-of-day landing distribution. Output is chart-ready
JSON and a human report.

Why
~~~

PR #726 ("wave-1 hackerman capability lift") accumulates dozens of
sibling tool / doc / Makefile commits per day across multiple parallel
agent lanes. The orchestrator needs a single command that surfaces:

- Are commits clustering on specific days? (cadence histogram)
- Which authors / agent identities are contributing? (author distribution)
- Which lanes (W1.x / W2.x / hackerman-<slug> / docs(...)) carry the
  most velocity? (top-5 lanes)
- When during the day do commits land? (hour-of-day histogram)

Outputs
~~~~~~~

- Commits per day (sorted asc by date)
- Per-author counts (sorted desc by count, tie-break asc by author)
- Top-5 lanes by commit count (lane = best-effort regex on subject)
- Hour-of-day distribution (00..23 buckets)
- JSON envelope ``auditooor.hackerman_pr726_density_analyzer.v1`` on
  ``--json`` (stable key ordering, deterministic).

CLI examples
~~~~~~~~~~~~

  # Human report (default)
  python3 tools/hackerman-pr726-density-analyzer.py

  # Machine envelope
  python3 tools/hackerman-pr726-density-analyzer.py --json

  # Override branch / since / repo dir (used by tests)
  python3 tools/hackerman-pr726-density-analyzer.py \
      --repo /tmp/fake --branch refs/heads/foo --since 2026-05-08

  # Read pre-captured git log from a file (used by tests)
  python3 tools/hackerman-pr726-density-analyzer.py --log-file /tmp/log.txt
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "auditooor.hackerman_pr726_density_analyzer.v1"

DEFAULT_BRANCH = "origin/wave-1-hackerman-capability-lift"
DEFAULT_SINCE = "2026-05-08"

TOP_LANES = 5
TOP_AUTHORS = 20


# Lane extraction patterns (ordered: first match wins). Each pattern returns
# a stable canonical lane id. Generic fallback lane is "<other>".
LANE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Wave designators e.g. "W2.1", "Wave-2", "wave-1"
    ("wave-{0}", re.compile(r"\b[Ww]ave[- ]?(\d+(?:\.\d+)?)\b")),
    ("W{0}", re.compile(r"\bW(\d+(?:\.\d+)?)\b")),
    # Conventional commits scope, e.g. "docs(wave-2):"
    ("scope-{0}", re.compile(r"^[a-z]+\(([^)]+)\)\s*:")),
    # Hackerman tool slug, e.g. "hackerman-contest-contributor-stats"
    # Greedy match captures the entire hyphen-joined slug so
    # `hackerman-foo-bar` does not truncate to `hackerman-foo`.
    ("hackerman-{0}", re.compile(r"\bhackerman-([a-z0-9][a-z0-9-]*[a-z0-9])\b")),
    # PR-only commits ("PR #726 wave-1: foo")
    ("pr-{0}", re.compile(r"\bPR\s+#(\d+)\b")),
]


# ---------------------------------------------------------------------------
# Git log retrieval.
# ---------------------------------------------------------------------------


def read_git_log(
    repo: Path,
    branch: str,
    since: str,
    *,
    runner: Any = None,
) -> str:
    """Run ``git log`` and return the raw multi-line string output.

    ``runner`` is dependency-injection seam for tests; defaults to
    ``subprocess.run``. Must return an object with ``.stdout`` (str) and
    ``.returncode`` (int) attributes.
    """
    cmd = [
        "git",
        "-C",
        str(repo),
        "log",
        branch,
        f"--since={since}",
        "--pretty=format:%H|%an|%ae|%ad|%s",
        "--date=iso",
    ]
    if runner is None:
        result = subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    else:
        result = runner(cmd)
    if getattr(result, "returncode", 0) != 0:
        sys.stderr.write(
            f"hackerman-pr726-density-analyzer: git log failed "
            f"(rc={getattr(result, 'returncode', '?')}): "
            f"{getattr(result, 'stderr', '')!r}\n"
        )
    return getattr(result, "stdout", "") or ""


# ---------------------------------------------------------------------------
# Parsing.
# ---------------------------------------------------------------------------


def parse_log(raw: str) -> list[dict[str, Any]]:
    """Parse pipe-delimited git log lines into structured records.

    Returns a list of dicts with keys: sha, author_name, author_email,
    iso_date, subject, day (YYYY-MM-DD), hour (int 0-23), lane.

    Lines that do not match the expected 5-field shape are silently
    skipped (defensive against `|`-containing subjects -- we use rsplit
    pattern to recover where possible).
    """
    out: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        # split into exactly 5 fields, allowing pipes inside the subject.
        parts = line.split("|", 4)
        if len(parts) != 5:
            continue
        sha, an, ae, ad, subject = parts
        sha = sha.strip()
        if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
            continue
        day, hour = _split_iso_date(ad)
        out.append(
            {
                "sha": sha,
                "author_name": an.strip(),
                "author_email": ae.strip(),
                "iso_date": ad.strip(),
                "subject": subject,
                "day": day,
                "hour": hour,
                "lane": detect_lane(subject),
            }
        )
    return out


def _split_iso_date(iso: str) -> tuple[str, int]:
    """Return (YYYY-MM-DD, hour_int 0-23) from an iso-ish git date.

    Falls back to ("", -1) when parsing fails.
    """
    iso = iso.strip()
    # git --date=iso emits "2026-05-16 07:12:29 +0200"
    m = re.match(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}):", iso)
    if not m:
        return "", -1
    try:
        hour = int(m.group(2))
    except ValueError:
        hour = -1
    if hour < 0 or hour > 23:
        hour = -1
    return m.group(1), hour


def detect_lane(subject: str) -> str:
    """Classify a commit subject into a canonical lane id.

    Tries each LANE_PATTERNS regex in order; first match wins. Falls
    back to ``<other>`` when no pattern fires.
    """
    s = subject.strip()
    for template, pat in LANE_PATTERNS:
        m = pat.search(s)
        if not m:
            continue
        group = m.group(1).strip().lower()
        if not group:
            continue
        return template.format(group)
    return "<other>"


# ---------------------------------------------------------------------------
# Aggregation.
# ---------------------------------------------------------------------------


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate parsed records into chart-ready buckets."""
    per_day: Counter[str] = Counter()
    per_author: Counter[str] = Counter()
    per_lane: Counter[str] = Counter()
    per_hour: Counter[int] = Counter()
    for rec in records:
        if rec["day"]:
            per_day[rec["day"]] += 1
        if rec["author_name"]:
            per_author[rec["author_name"]] += 1
        per_lane[rec["lane"]] += 1
        if rec["hour"] >= 0:
            per_hour[rec["hour"]] += 1

    days_sorted = sorted(per_day.items())
    top_days = sorted(
        per_day.items(), key=lambda kv: (-kv[1], kv[0])
    )
    authors_sorted = sorted(
        per_author.items(), key=lambda kv: (-kv[1], kv[0])
    )[:TOP_AUTHORS]
    lanes_sorted = sorted(
        per_lane.items(), key=lambda kv: (-kv[1], kv[0])
    )[:TOP_LANES]
    hours_full = [(h, per_hour.get(h, 0)) for h in range(24)]

    return {
        "total_commits": len(records),
        "distinct_days": len(per_day),
        "distinct_authors": len(per_author),
        "distinct_lanes": len(per_lane),
        "commits_per_day": [
            {"day": d, "count": c} for d, c in days_sorted
        ],
        "top_days": [
            {"day": d, "count": c} for d, c in top_days[:10]
        ],
        "top_authors": [
            {"author": a, "count": c} for a, c in authors_sorted
        ],
        "top_lanes": [
            {"lane": lane, "count": c} for lane, c in lanes_sorted
        ],
        "hour_of_day": [
            {"hour": h, "count": c} for h, c in hours_full
        ],
    }


# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------


def _bar(count: int, max_count: int, width: int = 40) -> str:
    if max_count <= 0:
        return ""
    n = max(1, int(round(count * width / max_count))) if count > 0 else 0
    return "#" * n


def render_report(agg: dict[str, Any], *, generated_at: str | None = None) -> str:
    if generated_at is None:
        generated_at = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    lines: list[str] = []
    lines.append("# PR #726 commit-density analyzer")
    lines.append("")
    lines.append(f"_Generated at {generated_at}_")
    lines.append("")
    lines.append(f"- total_commits: {agg['total_commits']}")
    lines.append(f"- distinct_days: {agg['distinct_days']}")
    lines.append(f"- distinct_authors: {agg['distinct_authors']}")
    lines.append(f"- distinct_lanes: {agg['distinct_lanes']}")
    lines.append("")

    # Commits-per-day histogram
    lines.append("## Commits per day")
    lines.append("")
    if agg["commits_per_day"]:
        max_day = max(item["count"] for item in agg["commits_per_day"])
        for item in agg["commits_per_day"]:
            lines.append(
                f"  {item['day']}  {item['count']:>4}  "
                f"{_bar(item['count'], max_day)}"
            )
    else:
        lines.append("  (no commits)")
    lines.append("")

    # Top days
    lines.append("## Top days by commit count")
    lines.append("")
    if agg["top_days"]:
        for i, item in enumerate(agg["top_days"], 1):
            lines.append(
                f"  {i:>2}. {item['day']}  {item['count']:>4} commits"
            )
    else:
        lines.append("  (no commits)")
    lines.append("")

    # Author distribution
    lines.append("## Author distribution (top {0})".format(TOP_AUTHORS))
    lines.append("")
    if agg["top_authors"]:
        max_auth = max(item["count"] for item in agg["top_authors"])
        for item in agg["top_authors"]:
            lines.append(
                f"  {item['author']:<40} {item['count']:>4}  "
                f"{_bar(item['count'], max_auth, width=20)}"
            )
    else:
        lines.append("  (no commits)")
    lines.append("")

    # Lane velocity
    lines.append("## Lane velocity (top {0})".format(TOP_LANES))
    lines.append("")
    if agg["top_lanes"]:
        max_lane = max(item["count"] for item in agg["top_lanes"])
        for item in agg["top_lanes"]:
            lines.append(
                f"  {item['lane']:<32} {item['count']:>4}  "
                f"{_bar(item['count'], max_lane, width=20)}"
            )
    else:
        lines.append("  (no commits)")
    lines.append("")

    # Hour-of-day
    lines.append("## Hour-of-day distribution (UTC offset preserved per commit)")
    lines.append("")
    if agg["hour_of_day"]:
        max_h = max((item["count"] for item in agg["hour_of_day"]), default=0)
        for item in agg["hour_of_day"]:
            lines.append(
                f"  {item['hour']:02d}:00  {item['count']:>4}  "
                f"{_bar(item['count'], max_h)}"
            )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Envelope.
# ---------------------------------------------------------------------------


def build_envelope(
    agg: dict[str, Any],
    *,
    branch: str,
    since: str,
    generated_at: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "branch": branch,
        "since": since,
        "stats": {
            "total_commits": agg["total_commits"],
            "distinct_days": agg["distinct_days"],
            "distinct_authors": agg["distinct_authors"],
            "distinct_lanes": agg["distinct_lanes"],
        },
        "commits_per_day": agg["commits_per_day"],
        "top_days": agg["top_days"],
        "top_authors": agg["top_authors"],
        "top_lanes": agg["top_lanes"],
        "hour_of_day": agg["hour_of_day"],
    }


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Commit-density analyzer for PR #726.",
    )
    p.add_argument(
        "--repo",
        default=str(REPO_ROOT),
        help="repo root for git log (default: %(default)s)",
    )
    p.add_argument(
        "--branch",
        default=DEFAULT_BRANCH,
        help="branch / ref to read (default: %(default)s)",
    )
    p.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        help="--since cutoff for git log (default: %(default)s)",
    )
    p.add_argument(
        "--log-file",
        default=None,
        help="read pre-captured git log from this file instead of "
        "invoking git (used by tests).",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit JSON envelope instead of human report.",
    )
    p.add_argument(
        "--out-json",
        default=None,
        help="optional path to write the JSON envelope to. Implies --json.",
    )
    p.add_argument(
        "--out-report",
        default=None,
        help="optional path to write the human report markdown to.",
    )
    p.add_argument(
        "--generated-at",
        default=None,
        help="override generated_at timestamp (for deterministic tests).",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if args.log_file:
        try:
            raw = Path(args.log_file).read_text(encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"failed to read --log-file: {exc}\n")
            return 2
    else:
        raw = read_git_log(Path(args.repo), args.branch, args.since)

    records = parse_log(raw)
    agg = aggregate(records)
    generated_at = args.generated_at or datetime.datetime.now(
        datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.out_report:
        Path(args.out_report).write_text(
            render_report(agg, generated_at=generated_at),
            encoding="utf-8",
        )

    if args.json or args.out_json:
        envelope = build_envelope(
            agg,
            branch=args.branch,
            since=args.since,
            generated_at=generated_at,
        )
        text = json.dumps(envelope, indent=2, sort_keys=True)
        if args.out_json:
            Path(args.out_json).write_text(text, encoding="utf-8")
        if args.json:
            sys.stdout.write(text)
            sys.stdout.write("\n")
        return 0

    sys.stdout.write(render_report(agg, generated_at=generated_at))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
