#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - year distribution stats.

Sibling of ``tools/hackerman-target-repo-stats.py`` /
``tools/hackerman-language-stats.py`` / ``tools/hackerman-domain-stats.py``
/ ``tools/hackerman-severity-stats.py``. Those tools cover the
per-target_repo, per-target-language, per-protocol-domain, and
per-severity views of the corpus; this tool gives the orthogonal
**per-year** view: when (in calendar-year terms) the hackerman
records' incidents / fixes happened, plus the per-tier
(tier-1 / tier-2 / tier-3 verification-tier) and per-subtree
breakdowns so a worker can see whether a year's record mass is
dominated by realtime-API-verified findings (tier-1),
public-archive-verified (tier-2), or synthetic taxonomy-anchored
(tier-3).

Why
~~~

Wave-1 hackerman discoverability needs to answer "across calendar
years, when did the bug-class evidence in our corpus actually
happen?" - critical for (a) detecting corpus-age skew (heavy 2023
mass means our priors are 2023-shaped), (b) routing time-correlated
hunts (e.g. "did the 2024-Q2 EIP-X rollout introduce a new bug
class?"), and (c) calibrating audit-pin selection in commit-mining
lanes ("if the audit-pin is 2024 but the bug-class mass is 2021,
the team may have already fixed it"). Until now we had per-repo /
language / domain / severity density but no per-year density.

Year extraction precedence
~~~~~~~~~~~~~~~~~~~~~~~~~~

The hackerman record schema does NOT enforce a single canonical
year field. We mine the year from (in precedence order):

1. Top-level ``year`` scalar (e.g. ``year: 2024``).
2. ``incident_date`` scalar (any of ``YYYY``, ``YYYY-MM``,
   ``YYYY-MM-DD``, ``YYYY-MM-DDTHH:MM:SS...``).
3. ``disclosure_date`` scalar (same shapes).
4. ``required_preconditions`` list entries containing a
   ``Published-at YYYY-...`` substring (GHSA preconditions).
5. ``source_audit_ref`` URL scanned with regex ``(20\\d{2})`` -
   first hit wins. Picks up Code4rena / Sherlock / Cantina /
   github URLs that embed the contest year.
6. Whole-record raw_text regex fallback ``(20\\d{2})`` for the
   PyYAML-unavailable fallback parser path.

Years outside the plausible range (2000..2099 - the regex
constrains to 20xx) bucket under ``<missing-year>``.

Outputs
~~~~~~~

- Human report (default): summary counts + year table (chronological)
  + per-year tier-1/2/3 breakdown + top-N subtree-by-year cells.
- JSON envelope ``auditooor.hackerman_year_stats.v1`` on ``--json``
  (stable key ordering, deterministic).
- Optional ``--out-json`` writes the same envelope to disk.

CLI examples
~~~~~~~~~~~~

  # human chronological view over the real corpus
  python3 tools/hackerman-year-stats.py

  # machine-readable envelope
  python3 tools/hackerman-year-stats.py --json

  # synthetic tags dir (used by unit tests)
  python3 tools/hackerman-year-stats.py --tags-dir /tmp/tags
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
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
    / "year_stats.json"
)
SCHEMA = "auditooor.hackerman_year_stats.v1"

MISSING_YEAR = "<missing-year>"
MISSING_TIER = "<missing-tier>"

# Canonical verification-tier heads, in canonical ranked order. Anything
# outside this set surfaces verbatim so corpus rot is visible rather
# than silently collapsed.
CANONICAL_TIERS: tuple[str, ...] = ("tier-1", "tier-2", "tier-3")

_VERIFICATION_TIER_TAG_RE = re.compile(
    r"verification_tier[:=]\s*(tier-[123])(?:-[a-z0-9-]+)?",
    re.IGNORECASE,
)

# Year regex: 20xx, four digits, word-boundary on the left side so we
# don't match the middle of longer numerics like "version 12025".
_YEAR_RE = re.compile(r"(?<![0-9])(20\d{2})(?![0-9])")

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
    is unavailable. The fallback handles the top-level scalar fields we
    read (``year``, ``incident_date``, ``disclosure_date``,
    ``source_audit_ref``) plus a flattened scan for ``Published-at`` /
    ``verification_tier`` substrings anywhere in the file body."""
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
    # Surface a synthetic ``_raw_text`` field so the year/tier extractors
    # have something to scan when the structured shape_tags /
    # required_preconditions lists aren't available via the fallback
    # parser. Sibling stats tools accept this convention.
    out.setdefault("_raw_text", text)
    return out


def _load_record(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    if path.suffix == ".json":
        try:
            data = json.loads(text)
            if isinstance(data, dict):
                return data
            return {}
        except json.JSONDecodeError:
            return {}
    return _yaml_load(text)


def _first_year_in(text: str) -> str | None:
    """Return the first ``20xx`` substring in *text*, or None."""
    if not isinstance(text, str):
        return None
    m = _YEAR_RE.search(text)
    if not m:
        return None
    return m.group(1)


def _normalize_year(raw: Any) -> str | None:
    """Coerce *raw* to a four-digit ``20xx`` string, or None if no
    plausible year can be extracted."""
    if raw is None:
        return None
    if isinstance(raw, int):
        if 2000 <= raw <= 2099:
            return str(raw)
        return None
    if isinstance(raw, str):
        return _first_year_in(raw)
    # datetime.date / datetime.datetime - PyYAML can produce these.
    if isinstance(raw, (datetime.date, datetime.datetime)):
        y = raw.year
        if 2000 <= y <= 2099:
            return str(y)
        return None
    return None


def _extract_year(record: dict[str, Any]) -> str:
    """Best-effort year extraction. Order of precedence as documented
    in the module docstring."""
    # 1. top-level year
    y = _normalize_year(record.get("year"))
    if y is not None:
        return y
    # 2. incident_date
    y = _normalize_year(record.get("incident_date"))
    if y is not None:
        return y
    # 3. disclosure_date
    y = _normalize_year(record.get("disclosure_date"))
    if y is not None:
        return y
    # 4. required_preconditions list - scan for "Published-at YYYY..."
    preconds = record.get("required_preconditions")
    if isinstance(preconds, list):
        for entry in preconds:
            if not isinstance(entry, str):
                continue
            if "published-at" in entry.lower() or "published at" in entry.lower():
                y = _first_year_in(entry)
                if y is not None:
                    return y
        # Fallback within preconditions: any 20xx hit, first-wins
        for entry in preconds:
            if isinstance(entry, str):
                y = _first_year_in(entry)
                if y is not None:
                    return y
    # 5. source_audit_ref URL
    y = _normalize_year(record.get("source_audit_ref"))
    if y is not None:
        return y
    # 6. raw_text fallback (PyYAML-unavailable path)
    raw_text = record.get("_raw_text")
    if isinstance(raw_text, str):
        y = _first_year_in(raw_text)
        if y is not None:
            return y
    return MISSING_YEAR


def _normalize_tier(raw: str) -> str:
    """Map a raw verification_tier shape_tag value to its canonical
    tier-N head. Returns ``MISSING_TIER`` when no canonical head can be
    extracted."""
    m = _VERIFICATION_TIER_TAG_RE.search(raw)
    if not m:
        return MISSING_TIER
    head = m.group(1).lower()
    if head in CANONICAL_TIERS:
        return head
    return MISSING_TIER


def _extract_tier(record: dict[str, Any]) -> str:
    """Best-effort verification_tier extraction. Order of precedence:
    1. ``function_shape.shape_tags`` list elements.
    2. ``required_preconditions`` list elements.
    3. Raw-text fallback scan."""
    fs = record.get("function_shape")
    if isinstance(fs, dict):
        shape_tags = fs.get("shape_tags")
        if isinstance(shape_tags, list):
            for tag in shape_tags:
                if isinstance(tag, str):
                    norm = _normalize_tier(tag)
                    if norm != MISSING_TIER:
                        return norm
    preconds = record.get("required_preconditions")
    if isinstance(preconds, list):
        for tag in preconds:
            if isinstance(tag, str):
                norm = _normalize_tier(tag)
                if norm != MISSING_TIER:
                    return norm
    raw_text = record.get("_raw_text")
    if isinstance(raw_text, str):
        return _normalize_tier(raw_text)
    return MISSING_TIER


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
    """Yield ``(path, record, subtree)`` tuples. YAML wins over JSON
    when both ``record.yaml`` and ``record.json`` live in the same
    dir."""
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


def _tier_sort_key(tier: str) -> tuple[int, str]:
    try:
        idx = CANONICAL_TIERS.index(tier)
    except ValueError:
        return (len(CANONICAL_TIERS) + 1, tier)
    return (idx, tier)


def _year_sort_key(year: str) -> tuple[int, str]:
    """Sort canonical 20xx years chronologically; bucket
    ``<missing-year>`` (and any other non-canonical sentinel) after
    all canonical years."""
    if _YEAR_RE.fullmatch(year):
        return (0, year)
    return (1, year)


def build_stats(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and build year distribution stats.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``years``: list[str] sorted chronologically (missing bucket last)
    - ``year_totals``: dict[year, int]
    - ``year_by_tier``: dict[year, dict[tier, int]]
    - ``year_by_subtree``: dict[year, dict[subtree, int]]
    - ``tier_totals``: dict[tier, int] (sorted canonical first)
    - ``subtree_totals``: dict[subtree, int]
    """
    year_totals: dict[str, int] = defaultdict(int)
    tier_totals: dict[str, int] = defaultdict(int)
    subtree_totals: dict[str, int] = defaultdict(int)
    year_by_tier: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    year_by_subtree: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    total_records = 0

    for _path, record, subtree in _walk_records(tags_dir):
        year = _extract_year(record)
        tier = _extract_tier(record)
        year_totals[year] += 1
        tier_totals[tier] += 1
        subtree_totals[subtree] += 1
        year_by_tier[year][tier] += 1
        year_by_subtree[year][subtree] += 1
        total_records += 1

    years_sorted = sorted(year_totals.keys(), key=_year_sort_key)

    tier_totals_sorted = dict(
        sorted(tier_totals.items(), key=lambda kv: _tier_sort_key(kv[0]))
    )

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "years": years_sorted,
        "year_totals": dict(sorted(year_totals.items(), key=lambda kv: _year_sort_key(kv[0]))),
        "year_by_tier": {
            y: {t: int(n) for t, n in sorted(
                year_by_tier[y].items(), key=lambda kv: _tier_sort_key(kv[0])
            )}
            for y in years_sorted
        },
        "year_by_subtree": {
            y: {s: int(n) for s, n in sorted(year_by_subtree[y].items())}
            for y in years_sorted
        },
        "tier_totals": tier_totals_sorted,
        "subtree_totals": dict(sorted(subtree_totals.items())),
    }


def top_years(stats: dict[str, Any], top_n: int) -> list[dict[str, Any]]:
    """Return the top-N years by record count (ranked, deterministic).
    Each entry carries the tier-1/2/3 breakdown so the consumer can
    decide on confidence."""
    out: list[dict[str, Any]] = []
    ranked = sorted(
        stats["years"],
        key=lambda y: (-int(stats["year_totals"].get(y, 0)), _year_sort_key(y)),
    )
    for y in ranked[:top_n]:
        tier_cells = stats["year_by_tier"].get(y, {})
        out.append(
            {
                "year": y,
                "count": int(stats["year_totals"].get(y, 0)),
                "tier_1": int(tier_cells.get("tier-1", 0)),
                "tier_2": int(tier_cells.get("tier-2", 0)),
                "tier_3": int(tier_cells.get("tier-3", 0)),
                "tier_missing": int(tier_cells.get(MISSING_TIER, 0)),
            }
        )
    return out


def render_table_rows(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    def fmt_row(cells: list[str]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    sep = "-+-".join("-" * w for w in widths)
    return "\n".join([fmt_row(headers), sep, *[fmt_row(r) for r in rows]])


def render_human(stats: dict[str, Any], top_n: int = 20) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out: list[str] = []
    out.append(f"# Hackerman year distribution ({today})")
    out.append("")
    out.append(f"- tags_dir: {stats['tags_dir']}")
    out.append(f"- total_records: {stats['total_records']}")
    out.append(f"- distinct_years: {len(stats['years'])}")
    out.append(f"- distinct_tiers: {len(stats['tier_totals'])}")
    out.append(f"- distinct_subtrees: {len(stats['subtree_totals'])}")
    out.append("")
    out.append("## Tier totals (canonical rank order)")
    out.append("")
    out.append("```")
    rows: list[list[str]] = []
    total = stats["total_records"] or 1
    for tier, cnt in stats["tier_totals"].items():
        pct = (int(cnt) / total) * 100.0
        rows.append([tier, str(int(cnt)), f"{pct:.2f}%"])
    if not rows:
        rows.append(["(none)", "0", "0.00%"])
    out.append(render_table_rows(rows, headers=["tier", "count", "share"]))
    out.append("```")
    out.append("")
    out.append("## Years (chronological)")
    out.append("")
    out.append("```")
    rows = []
    for y in stats["years"]:
        cnt = int(stats["year_totals"].get(y, 0))
        pct = (cnt / total) * 100.0
        tier_cells = stats["year_by_tier"].get(y, {})
        t1 = int(tier_cells.get("tier-1", 0))
        t2 = int(tier_cells.get("tier-2", 0))
        t3 = int(tier_cells.get("tier-3", 0))
        tm = int(tier_cells.get(MISSING_TIER, 0))
        rows.append(
            [
                y,
                str(cnt),
                f"{pct:.2f}%",
                str(t1) if t1 else ".",
                str(t2) if t2 else ".",
                str(t3) if t3 else ".",
                str(tm) if tm else ".",
            ]
        )
    if not rows:
        rows.append(["(none)", "0", "0.00%", ".", ".", ".", "."])
    out.append(
        render_table_rows(
            rows,
            headers=[
                "year",
                "count",
                "share",
                "tier-1",
                "tier-2",
                "tier-3",
                "missing",
            ],
        )
    )
    out.append("```")
    out.append("")
    out.append(f"## Top-{top_n} years by record count")
    out.append("")
    out.append("```")
    rows = []
    for entry in top_years(stats, top_n):
        cnt = entry["count"]
        pct = (cnt / total) * 100.0
        rows.append(
            [
                entry["year"],
                str(cnt),
                f"{pct:.2f}%",
                str(entry["tier_1"]) if entry["tier_1"] else ".",
                str(entry["tier_2"]) if entry["tier_2"] else ".",
                str(entry["tier_3"]) if entry["tier_3"] else ".",
            ]
        )
    if not rows:
        rows.append(["(none)", "0", "0.00%", ".", ".", "."])
    out.append(
        render_table_rows(
            rows,
            headers=["year", "count", "share", "tier-1", "tier-2", "tier-3"],
        )
    )
    out.append("```")
    out.append("")
    return "\n".join(out)


def render_json(stats: dict[str, Any], top_n: int = 20) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": stats["tags_dir"],
        "total_records": stats["total_records"],
        "years": stats["years"],
        "year_totals": stats["year_totals"],
        "year_by_tier": stats["year_by_tier"],
        "year_by_subtree": stats["year_by_subtree"],
        "tier_totals": stats["tier_totals"],
        "subtree_totals": stats["subtree_totals"],
        "top_years": top_years(stats, top_n),
        "top_n": top_n,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit year distribution stats from "
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
        "--top-n",
        type=int,
        default=20,
        help="top-N years in the top_years panel (default: 20)",
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
        sys.stdout.write(render_json(stats, args.top_n))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(stats, args.top_n))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(stats, args.top_n) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
