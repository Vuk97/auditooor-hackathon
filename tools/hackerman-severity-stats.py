#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - severity distribution stats.

Sibling of ``tools/hackerman-language-stats.py`` /
``tools/hackerman-domain-stats.py`` /
``tools/hackerman-attack-class-distribution.py``. Those tools cover the
per-target-language, per-protocol-domain, and per-attack-class views of
the corpus; this tool gives the orthogonal **per-severity** view: how
many records fall under each severity tier (critical / high / medium /
low / info / etc.), plus the severity x record_tier and severity x
subtree breakdowns so we can see whether high-severity findings cluster
in a particular corpus tier or subtree.

Why
~~~

Wave-1 hackerman discoverability wants to answer "where does our
high-severity finding mass live, and where are the gaps?" before we
spend Wave-2/3 cycles writing new detectors. A subtree that is 90%
``low`` severity is a different attention surface than one that is
60% ``critical``.

Inputs
~~~~~~

- ``audit/corpus_tags/tags/**/record.{yaml,json}`` (subtree records,
  YAML wins over JSON when both exist - matches sibling-tool
  precedence).
- ``audit/corpus_tags/tags/*.yaml`` (flat tags at the tags-dir root,
  bucketed by filename prefix exactly the way the sibling stats tools
  bucket them: ``_flat_solodit_spec`` / ``_flat_dsl_pattern`` /
  ``_flat_prior_audit`` / ``_flat_corpus_mined`` / ``_flat_seed`` /
  ``_flat_other``).

Outputs
~~~~~~~

- Human report (default): summary counts + severity table + top-3 per
  severity x record_tier + top-3 per severity x subtree.
- JSON envelope ``auditooor.hackerman_severity_stats.v1`` on ``--json``
  (stable key ordering, deterministic).
- Optional ``--out-json`` writes the same envelope to disk.

CLI examples
~~~~~~~~~~~~

  # human table over the real corpus
  python3 tools/hackerman-severity-stats.py

  # machine-readable envelope
  python3 tools/hackerman-severity-stats.py --json

  # synthetic tags dir (used by unit tests)
  python3 tools/hackerman-severity-stats.py --tags-dir /tmp/tags
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

try:  # pragma: no cover
    import yaml  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    yaml = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_JSON = (
    REPO_ROOT
    / "audit"
    / "corpus_tags"
    / "derived"
    / "severity_stats.json"
)
SCHEMA = "auditooor.hackerman_severity_stats.v1"

MISSING_SEVERITY = "<unknown>"
MISSING_TIER = "<missing-tier>"

# Canonical severity slugs, in canonical ranked order. Anything outside
# this set surfaces verbatim (lower-cased / stripped) so corpus rot is
# visible rather than silently collapsed.
CANONICAL_SEVERITIES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

# Flat-tag filename prefixes -> synthetic subtree bucket. Same as the
# sibling stats tools so a record's bucket is consistent across reports.
FLAT_PREFIX_BUCKETS: tuple[tuple[str, str], ...] = (
    ("solodit-spec:", "_flat_solodit_spec"),
    ("dsl_pattern_", "_flat_dsl_pattern"),
    ("prior-audit-", "_flat_prior_audit"),
    ("corpus-mined-", "_flat_corpus_mined"),
    ("seed_", "_flat_seed"),
)


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load with a minimal fallback parser when PyYAML
    is unavailable.  The fallback handles the top-level scalar fields we
    read (``severity_at_finding`` / ``record_tier``)."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith(" "):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if v == "":
                continue
            out[k] = v.strip("\"'")
    return out


def _load_record(path: Path) -> dict[str, Any]:
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


def _normalize_severity(raw: Any) -> str:
    """Return a stable severity slug.

    - missing / non-string / empty -> ``MISSING_SEVERITY``
    - whitespace stripped, lowered
    - common aliases collapsed (``crit`` -> ``critical``,
      ``med`` -> ``medium``, ``informational`` -> ``info``,
      ``none`` / ``n/a`` -> ``info``, ``gas`` -> ``info``).
    """
    if not isinstance(raw, str):
        return MISSING_SEVERITY
    v = raw.strip().lower()
    if not v:
        return MISSING_SEVERITY
    aliases = {
        "crit": "critical",
        "criticals": "critical",
        "hi": "high",
        "highs": "high",
        "med": "medium",
        "meds": "medium",
        "moderate": "medium",
        "lows": "low",
        "informational": "info",
        "information": "info",
        "note": "info",
        "notes": "info",
        "gas": "info",
        "none": "info",
        "n/a": "info",
        "na": "info",
    }
    return aliases.get(v, v)


def _normalize_tier(raw: Any) -> str:
    if not isinstance(raw, str):
        return MISSING_TIER
    v = raw.strip()
    return v or MISSING_TIER


def _subtree_for_subdir_record(path: Path, tags_dir: Path) -> str:
    try:
        rel = path.relative_to(tags_dir)
    except ValueError:
        return "_unknown"
    parts = rel.parts
    if len(parts) < 2:
        return "_unknown"
    return parts[0]


def _subtree_for_flat_record(path: Path) -> str:
    name = path.name
    for prefix, bucket in FLAT_PREFIX_BUCKETS:
        if name.startswith(prefix):
            return bucket
    return "_flat_other"


def _walk_records(tags_dir: Path) -> Iterable[tuple[Path, dict[str, Any], str]]:
    """Yield ``(path, record, subtree)`` tuples.  YAML wins over JSON when
    both ``record.yaml`` and ``record.json`` live in the same dir."""
    seen_dirs: set[Path] = set()
    for path in sorted(tags_dir.rglob("record.yaml")):
        seen_dirs.add(path.parent)
        rec = _load_record(path)
        if rec:
            yield path, rec, _subtree_for_subdir_record(path, tags_dir)
    for path in sorted(tags_dir.rglob("record.json")):
        if path.parent in seen_dirs:
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, _subtree_for_subdir_record(path, tags_dir)
    # Harmonized with corpus-stats walker: rglob covers nested flat *.yaml
    # records (e.g. immunefi/, zk_miners/, mev_flashloan/, l2_zkrollup/,
    # _QUARANTINE_FABRICATED_CVE/) so panel-aggregate totals match the
    # canonical baseline (36,492). Skip ``record.yaml`` to avoid double-
    # counting structured records already yielded above. See
    # docs/HACKERMAN_BASELINE_RECONCILIATION_2026-05-16.md.
    for path in sorted(tags_dir.rglob("*.yaml")):
        if path.name == "record.yaml":
            continue
        if not path.is_file():
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, _subtree_for_flat_record(path)


def _severity_sort_key(severity: str) -> tuple[int, str]:
    """Order canonical severities by their declared rank
    (critical -> info), then everything else alphabetical after."""
    try:
        idx = CANONICAL_SEVERITIES.index(severity)
    except ValueError:
        return (len(CANONICAL_SEVERITIES) + 1, severity)
    return (idx, severity)


def build_stats(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and build severity distribution stats.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``severities``: list[str] sorted by canonical rank, then by name
    - ``severity_totals``: dict[severity, int]
    - ``severity_by_tier``: dict[severity, dict[tier, int]]
    - ``severity_by_subtree``: dict[severity, dict[subtree, int]]
    - ``tier_totals``: dict[tier, int]
    - ``subtree_totals``: dict[subtree, int]
    """
    severity_totals: dict[str, int] = defaultdict(int)
    tier_totals: dict[str, int] = defaultdict(int)
    subtree_totals: dict[str, int] = defaultdict(int)
    severity_by_tier: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    severity_by_subtree: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    total_records = 0

    for _path, record, subtree in _walk_records(tags_dir):
        sev = _normalize_severity(record.get("severity_at_finding"))
        tier = _normalize_tier(record.get("record_tier"))
        severity_totals[sev] += 1
        tier_totals[tier] += 1
        subtree_totals[subtree] += 1
        severity_by_tier[sev][tier] += 1
        severity_by_subtree[sev][subtree] += 1
        total_records += 1

    severities_sorted = sorted(
        severity_totals.keys(),
        key=_severity_sort_key,
    )

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "severities": severities_sorted,
        "severity_totals": dict(sorted(severity_totals.items())),
        "severity_by_tier": {
            s: {t: int(n) for t, n in sorted(severity_by_tier[s].items())}
            for s in severities_sorted
        },
        "severity_by_subtree": {
            s: {b: int(n) for b, n in sorted(severity_by_subtree[s].items())}
            for s in severities_sorted
        },
        "tier_totals": dict(sorted(tier_totals.items())),
        "subtree_totals": dict(sorted(subtree_totals.items())),
    }


def top_n_for_severity(
    stats: dict[str, Any], axis: str, severity: str, n: int = 3
) -> list[dict[str, Any]]:
    """Return the top-N (tier or subtree) cells for ``severity`` sorted
    by count desc, name asc."""
    if axis == "tier":
        cells = stats["severity_by_tier"].get(severity, {})
        key = "tier"
    elif axis == "subtree":
        cells = stats["severity_by_subtree"].get(severity, {})
        key = "subtree"
    else:
        raise ValueError(f"unknown axis: {axis!r}")
    ranked = sorted(cells.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{key: k, "count": int(v)} for k, v in ranked[:n]]


def render_table(stats: dict[str, Any]) -> str:
    """Render the severity overview as a fenced ASCII table."""
    headers = ["severity", "total", "pct"]
    rows: list[list[str]] = []
    total = stats["total_records"] or 1
    for sev in stats["severities"]:
        cnt = int(stats["severity_totals"].get(sev, 0))
        pct = (cnt / total) * 100.0
        rows.append([sev, str(cnt), f"{pct:.2f}"])
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    def fmt(cells: list[str]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    sep = "-+-".join("-" * w for w in widths)
    out = [fmt(headers), sep]
    out.extend(fmt(r) for r in rows)
    return "\n".join(out)


def render_human(stats: dict[str, Any]) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out: list[str] = []
    out.append(f"# Hackerman severity distribution stats ({today})")
    out.append("")
    out.append(f"- tags_dir: {stats['tags_dir']}")
    out.append(f"- total_records: {stats['total_records']}")
    out.append(f"- distinct_severities: {len(stats['severities'])}")
    out.append(f"- distinct_tiers: {len(stats['tier_totals'])}")
    out.append(f"- distinct_subtrees: {len(stats['subtree_totals'])}")
    out.append("")
    out.append("## Severity overview (rows = severity, canonical rank order)")
    out.append("")
    out.append("```")
    out.append(render_table(stats))
    out.append("```")
    out.append("")
    out.append("## Top-3 record_tiers per severity")
    out.append("")
    for sev in stats["severities"]:
        top = top_n_for_severity(stats, "tier", sev)
        chunks = [f"{r['tier']} ({r['count']})" for r in top]
        out.append(f"- `{sev}`: {', '.join(chunks) if chunks else '(empty)'}")
    out.append("")
    out.append("## Top-3 subtrees per severity")
    out.append("")
    for sev in stats["severities"]:
        top = top_n_for_severity(stats, "subtree", sev)
        chunks = [f"{r['subtree']} ({r['count']})" for r in top]
        out.append(f"- `{sev}`: {', '.join(chunks) if chunks else '(empty)'}")
    out.append("")
    return "\n".join(out)


def render_json(stats: dict[str, Any]) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": stats["tags_dir"],
        "total_records": stats["total_records"],
        "severities": stats["severities"],
        "severity_totals": stats["severity_totals"],
        "severity_by_tier": stats["severity_by_tier"],
        "severity_by_subtree": stats["severity_by_subtree"],
        "tier_totals": stats["tier_totals"],
        "subtree_totals": stats["subtree_totals"],
        "top_tiers_per_severity": {
            sev: top_n_for_severity(stats, "tier", sev)
            for sev in stats["severities"]
        },
        "top_subtrees_per_severity": {
            sev: top_n_for_severity(stats, "subtree", sev)
            for sev in stats["severities"]
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit per-severity distribution stats from "
            "audit/corpus_tags/tags/."
        )
    )
    p.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="root of the corpus tags tree",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="emit JSON envelope to stdout",
    )
    p.add_argument(
        "--out-json",
        type=Path,
        default=None,
        help=(
            "also write the JSON envelope to this path "
            f"(default: {DEFAULT_OUT_JSON})"
        ),
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    tags_dir = args.tags_dir
    if not tags_dir.exists():
        print(f"tags-dir does not exist: {tags_dir}", file=sys.stderr)
        return 2
    stats = build_stats(tags_dir)
    if args.json:
        sys.stdout.write(render_json(stats))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(stats))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(stats) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
