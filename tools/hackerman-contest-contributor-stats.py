#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - contest contributor stats.

Sibling of ``tools/hackerman-severity-stats.py``,
``tools/hackerman-language-stats.py``, and ``tools/hackerman-domain-stats.py``.
Walks ``audit/corpus_tags/tags/contest_platform_findings/**/record.{json,yaml}``
and aggregates per-contributor (warden / submitter handle) finding counts so
the hunt loop can calibrate against the highest-yield wardens.

Why
~~~

Wave-1 shipped 3,006 contest-platform findings (Code4rena 2,615 +
Sherlock 391). Each finding is attributable to a single submitter handle,
either explicitly via a ``Reported by handle <name>`` clause in
``required_preconditions`` (Code4rena) or implicitly via the
``<title>. <Warden Name> (high|medium|low) #`` shape embedded in
``attacker_action_sequence`` (Sherlock). The two patterns together cover
100% of contest_platform_findings on the live corpus (verified 2026-05-16).

Outputs
~~~~~~~

- Top-50 contributors by total finding count (sorted desc, tie-break asc by handle)
- Top-50 contributors by severity-weighted score (high=3, medium=1, low=0.3,
  critical=5, info=0.1)
- Cross-platform contributors (active on BOTH code4rena AND sherlock)
- Per-platform totals + distinct-contributor counts
- JSON envelope ``auditooor.hackerman_contest_contributor_stats.v1`` on
  ``--json`` (stable key ordering, deterministic)

CLI examples
~~~~~~~~~~~~

  # Human-readable report (default)
  python3 tools/hackerman-contest-contributor-stats.py

  # Machine envelope
  python3 tools/hackerman-contest-contributor-stats.py --json

  # Override tags dir (used by tests)
  python3 tools/hackerman-contest-contributor-stats.py --tags-dir /tmp/tags
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover - optional pyyaml
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = (
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "contest_platform_findings"
)
SCHEMA = "auditooor.hackerman_contest_contributor_stats.v1"

TOP_N = 50

# Severity -> weight (canonical map). Anything missing / non-canonical
# falls back to 0.0 so the score is well-defined.
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 5.0,
    "high": 3.0,
    "medium": 1.0,
    "low": 0.3,
    "info": 0.1,
    "informational": 0.1,
}

PLATFORM_CODE4RENA = "code4rena"
PLATFORM_SHERLOCK = "sherlock"
PLATFORM_UNKNOWN = "<unknown>"

# Code4rena: explicit "Reported by handle <name>" in required_preconditions.
HANDLE_PRECONDITION_RE = re.compile(r"^\s*Reported by handle\s+(.+?)\s*$")
# Sherlock: "<title>. <Warden Name> <severity> # <title> ..." inside attacker_action_sequence.
SHERLOCK_HANDLE_RE = re.compile(
    r"\.\s+([A-Za-z0-9_][\w \-]*?)\s+(high|medium|low|info|informational|critical)\s+#\s",
    re.IGNORECASE,
)

UNKNOWN_HANDLE = "<unknown-handle>"


# ---------------------------------------------------------------------------
# Record loaders.
# ---------------------------------------------------------------------------


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load. Falls back to a minimal key:value parser when
    PyYAML is unavailable. We only need top-level scalars + a few list
    fields (``required_preconditions``)."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    current_list_key: str | None = None
    list_acc: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("- "):
            if current_list_key:
                list_acc.append(line[2:].strip().strip("'\""))
            continue
        # Non-list line; flush any pending list.
        if current_list_key:
            out[current_list_key] = list_acc
            current_list_key = None
            list_acc = []
        if ":" in line and not line.startswith(" "):
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip().strip("'\"")
            if not v:
                # Empty value -> list header
                current_list_key = k
                list_acc = []
            else:
                out[k] = v
    if current_list_key:
        out[current_list_key] = list_acc
    return out


def _load_record(path: Path) -> dict[str, Any]:
    """Load a single record file. Returns {} on any I/O / parse error."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}
    return _yaml_load(text)


# ---------------------------------------------------------------------------
# Platform + handle extraction.
# ---------------------------------------------------------------------------


def extract_platform(record: dict[str, Any]) -> str:
    """Resolve the contest platform from ``attack_class`` first, then
    ``source_audit_ref`` prefix (``code4rena:`` / ``sherlock:``)."""
    ac = str(record.get("attack_class") or "").strip().lower()
    if ac.endswith("-code4rena") or "code4rena" in ac:
        return PLATFORM_CODE4RENA
    if ac.endswith("-sherlock") or "sherlock" in ac:
        return PLATFORM_SHERLOCK
    ref = str(record.get("source_audit_ref") or "").strip().lower()
    if ref.startswith("code4rena:"):
        return PLATFORM_CODE4RENA
    if ref.startswith("sherlock:"):
        return PLATFORM_SHERLOCK
    return PLATFORM_UNKNOWN


def extract_handle(record: dict[str, Any], platform: str) -> str:
    """Extract submitter handle from a record. Falls back to
    ``UNKNOWN_HANDLE`` when no canonical signal is present.

    Code4rena: matches ``Reported by handle <name>`` in required_preconditions.
    Sherlock: matches ``<title>. <Warden Name> <severity> #`` in
    ``attacker_action_sequence``.

    Both extractors strip surrounding whitespace and inline ``[source=...]``
    annotations.
    """
    # Prefer the explicit precondition channel first (works for any platform
    # that uses the same convention).
    preconditions = record.get("required_preconditions")
    if isinstance(preconditions, list):
        for pre in preconditions:
            text = str(pre or "")
            # Strip any inline annotation like ``[source=...]`` so the match
            # against the trailing tag does not bleed into the handle.
            text_clean = re.sub(r"\s*\[source=.+?\]\s*", "", text).strip()
            m = HANDLE_PRECONDITION_RE.match(text_clean)
            if m:
                handle = m.group(1).strip()
                if handle:
                    return handle

    # Sherlock fallback: parse the AAS prefix.
    if platform == PLATFORM_SHERLOCK:
        aas = str(record.get("attacker_action_sequence") or "")
        m = SHERLOCK_HANDLE_RE.search(aas)
        if m:
            handle = m.group(1).strip()
            if handle:
                return handle

    return UNKNOWN_HANDLE


def extract_severity(record: dict[str, Any]) -> str:
    """Lowercased canonical severity, or ``<unknown>`` if missing."""
    sev = str(record.get("severity_at_finding") or "").strip().lower()
    if not sev:
        return "<unknown>"
    if sev == "informational":
        return "info"
    return sev


def severity_weight(severity: str) -> float:
    return SEVERITY_WEIGHTS.get(severity, 0.0)


# ---------------------------------------------------------------------------
# Walker / aggregator.
# ---------------------------------------------------------------------------


def _iter_records(tags_dir: Path) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Walk the contest_platform_findings tree. YAML preferred over JSON
    when both exist (sibling-precedence rule)."""
    seen_dirs: set[Path] = set()
    for p in sorted(tags_dir.rglob("record.yaml")):
        seen_dirs.add(p.parent)
        rec = _load_record(p)
        if rec:
            yield p, rec
    for p in sorted(tags_dir.rglob("record.json")):
        if p.parent in seen_dirs:
            continue
        rec = _load_record(p)
        if rec:
            yield p, rec


def build_stats(tags_dir: Path) -> dict[str, Any]:
    """Aggregate contributor stats over the contest_platform_findings tree.

    Output payload (stable key ordering):

      schema: <SCHEMA>
      tags_dir: <abs path>
      total_records: int
      per_platform: { code4rena: {records, distinct_contributors}, ... }
      contributors: { <handle>: { total, per_platform, per_severity, score } }
      top_by_count: [ {handle, total, score, platforms}, ... ] (TOP_N)
      top_by_score: [ {handle, total, score, platforms}, ... ] (TOP_N)
      cross_platform: [ {handle, total, score, platforms}, ... ]
                       contributors active on >=2 platforms (sorted by total desc)
      severity_weights: { <severity>: <weight> }
    """
    per_platform_records: Counter[str] = Counter()
    per_platform_contribs: defaultdict[str, set[str]] = defaultdict(set)

    contribs: dict[str, dict[str, Any]] = {}
    total = 0
    unknown_handles = 0

    for _, rec in _iter_records(tags_dir):
        platform = extract_platform(rec)
        handle = extract_handle(rec, platform)
        severity = extract_severity(rec)

        if handle == UNKNOWN_HANDLE:
            unknown_handles += 1

        total += 1
        per_platform_records[platform] += 1
        per_platform_contribs[platform].add(handle)

        entry = contribs.setdefault(
            handle,
            {
                "total": 0,
                "per_platform": Counter(),
                "per_severity": Counter(),
                "score": 0.0,
            },
        )
        entry["total"] += 1
        entry["per_platform"][platform] += 1
        entry["per_severity"][severity] += 1
        entry["score"] += severity_weight(severity)

    # Materialize contributor list (sorted by handle for determinism).
    contributor_rows: dict[str, dict[str, Any]] = {}
    for handle in sorted(contribs.keys()):
        entry = contribs[handle]
        contributor_rows[handle] = {
            "total": int(entry["total"]),
            "per_platform": {
                k: int(entry["per_platform"][k])
                for k in sorted(entry["per_platform"].keys())
            },
            "per_severity": {
                k: int(entry["per_severity"][k])
                for k in sorted(entry["per_severity"].keys())
            },
            "score": round(float(entry["score"]), 4),
            "platforms": sorted(entry["per_platform"].keys()),
        }

    def _row(handle: str) -> dict[str, Any]:
        e = contributor_rows[handle]
        return {
            "handle": handle,
            "total": e["total"],
            "score": e["score"],
            "platforms": e["platforms"],
        }

    # Top-N by raw finding count (desc by total, tie-break asc by handle).
    by_count = sorted(
        contributor_rows.keys(),
        key=lambda h: (-contributor_rows[h]["total"], h),
    )[:TOP_N]
    # Top-N by severity-weighted score (desc by score, tie-break asc by handle).
    by_score = sorted(
        contributor_rows.keys(),
        key=lambda h: (-contributor_rows[h]["score"], h),
    )[:TOP_N]
    # Cross-platform contributors: active on >=2 platforms.
    cross = sorted(
        [h for h, e in contributor_rows.items() if len(e["platforms"]) >= 2],
        key=lambda h: (-contributor_rows[h]["total"], h),
    )

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total,
        "unknown_handle_records": unknown_handles,
        "per_platform": {
            platform: {
                "records": int(per_platform_records[platform]),
                "distinct_contributors": len(per_platform_contribs[platform]),
            }
            for platform in sorted(per_platform_records.keys())
        },
        "contributors_total": len(contributor_rows),
        "contributors": contributor_rows,
        "top_by_count": [_row(h) for h in by_count],
        "top_by_score": [_row(h) for h in by_score],
        "cross_platform": [_row(h) for h in cross],
        "severity_weights": dict(sorted(SEVERITY_WEIGHTS.items())),
    }


# ---------------------------------------------------------------------------
# Rendering.
# ---------------------------------------------------------------------------


def _generated_at(override: str | None = None) -> str:
    if override:
        return override
    env = os.environ.get("AUDITOOOR_CONTRIBUTOR_STATS_GENERATED_AT")
    if env:
        return env
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def render_report(stats: dict[str, Any], *, generated_at: str) -> str:
    """Human-readable markdown report (deterministic, 200-400 lines)."""
    lines: list[str] = []
    lines.append(
        "# Hackerman contest-platform contributor stats (PR #726, Wave-1)"
    )
    lines.append("")
    lines.append(f"- schema: `{stats['schema']}`")
    lines.append(f"- generated_at: {generated_at}")
    lines.append(f"- tags_dir: `{stats['tags_dir']}`")
    lines.append(f"- total_records: {stats['total_records']}")
    lines.append(
        f"- contributors_total: {stats['contributors_total']}"
    )
    lines.append(
        f"- unknown_handle_records: {stats['unknown_handle_records']}"
    )
    lines.append("")
    lines.append("## Per-platform totals")
    lines.append("")
    lines.append("| platform | records | distinct_contributors |")
    lines.append("|----------|--------:|----------------------:|")
    for platform in sorted(stats["per_platform"].keys()):
        row = stats["per_platform"][platform]
        lines.append(
            f"| {platform} | {row['records']} | {row['distinct_contributors']} |"
        )
    lines.append("")
    lines.append("## Severity weights (score = sum(weight * count))")
    lines.append("")
    lines.append("| severity | weight |")
    lines.append("|----------|-------:|")
    for sev in sorted(stats["severity_weights"].keys()):
        lines.append(f"| {sev} | {stats['severity_weights'][sev]} |")
    lines.append("")
    lines.append(f"## Top-{TOP_N} contributors by finding count")
    lines.append("")
    lines.append("| rank | handle | total | score | platforms |")
    lines.append("|----:|--------|------:|------:|-----------|")
    for i, row in enumerate(stats["top_by_count"], start=1):
        platforms = ",".join(row["platforms"]) or "<none>"
        lines.append(
            f"| {i} | {row['handle']} | {row['total']} | {row['score']} | {platforms} |"
        )
    lines.append("")
    lines.append(f"## Top-{TOP_N} contributors by severity-weighted score")
    lines.append("")
    lines.append("| rank | handle | score | total | platforms |")
    lines.append("|----:|--------|------:|------:|-----------|")
    for i, row in enumerate(stats["top_by_score"], start=1):
        platforms = ",".join(row["platforms"]) or "<none>"
        lines.append(
            f"| {i} | {row['handle']} | {row['score']} | {row['total']} | {platforms} |"
        )
    lines.append("")
    cross = stats["cross_platform"]
    lines.append(
        f"## Cross-platform contributors (active on both Code4rena AND Sherlock): {len(cross)}"
    )
    lines.append("")
    if cross:
        lines.append("| rank | handle | total | score | platforms |")
        lines.append("|----:|--------|------:|------:|-----------|")
        for i, row in enumerate(cross, start=1):
            platforms = ",".join(row["platforms"]) or "<none>"
            lines.append(
                f"| {i} | {row['handle']} | {row['total']} | {row['score']} | {platforms} |"
            )
    else:
        lines.append("- (no contributors active on both platforms)")
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "- Records walked: `audit/corpus_tags/tags/contest_platform_findings/**/record.{yaml,json}` (YAML preferred when both exist)."
    )
    lines.append(
        "- Code4rena handles: parsed from `Reported by handle <name>` line in `required_preconditions`."
    )
    lines.append(
        "- Sherlock handles: parsed from `<title>. <Warden Name> <severity> #` prefix in `attacker_action_sequence` (case-insensitive)."
    )
    lines.append(
        "- Severity-weighted score = `sum(severity_weight * count)` per contributor (critical=5, high=3, medium=1, low=0.3, info=0.1)."
    )
    lines.append(
        "- Cross-platform = contributors with `>=2` distinct entries in `per_platform`."
    )
    lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="hackerman-contest-contributor-stats"
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of contest_platform_findings records.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the JSON envelope instead of the human-readable report.",
    )
    parser.add_argument(
        "--generated-at",
        type=str,
        default=None,
        help="Override the generated_at timestamp (also via env AUDITOOOR_CONTRIBUTOR_STATS_GENERATED_AT).",
    )
    args = parser.parse_args(argv)

    tags_dir = args.tags_dir.resolve()
    if not tags_dir.is_dir():
        sys.stderr.write(
            f"[hackerman-contest-contributor-stats] tags_dir not found: {tags_dir}\n"
        )
        return 2

    stats = build_stats(tags_dir)
    generated_at = _generated_at(args.generated_at)
    if args.json:
        payload = {
            "schema": SCHEMA,
            "generated_at": generated_at,
            "stats": stats,
        }
        sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    else:
        report = render_report(stats, generated_at=generated_at)
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
