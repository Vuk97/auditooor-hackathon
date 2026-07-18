#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - language distribution stats.

Sibling of ``tools/hackerman-attack-class-distribution.py``. That tool gives
the per-subtree x per-attack-class view of the corpus; this tool gives the
orthogonal **per-target-language** view: how many records each language
contributes, the language x tier breakdown (so we can see whether non-
solidity languages are concentrated in low-confidence tiers), and the
language x subtree breakdown (so we can see which subtrees are language-
diverse vs language-monocultures).

Why
~~~

Wave-1 hackerman discoverability wants to answer "how language-diverse is
the corpus right now, and where are the gaps?" before we spend Wave-2/3
cycles writing new detectors. Languages we expect to see (non-exhaustive):
solidity, vyper, cairo, move, rust, go, circom, ts/js, python. Anything
else surfaces as ``<unknown>`` so corpus rot is visible (not silently
dropped).

Inputs
~~~~~~

- ``audit/corpus_tags/tags/**/record.{yaml,json}`` (subtree records, YAML
  preferred over JSON when both exist - matches the sibling tools'
  precedence).
- ``audit/corpus_tags/tags/*.yaml`` (flat tags at the tags-dir root,
  bucketed by filename prefix exactly the way the distribution tool
  buckets them: ``_flat_solodit_spec`` / ``_flat_dsl_pattern`` /
  ``_flat_prior_audit`` / ``_flat_corpus_mined`` / ``_flat_seed`` /
  ``_flat_other``).

Outputs
~~~~~~~

- Human report (default): summary counts + language table + top-3 per
  language x tier + top-3 per language x subtree.
- JSON envelope ``auditooor.hackerman_language_stats.v1`` on ``--json``
  (stable key ordering, deterministic).
- Optional ``--out-json`` writes the same envelope to disk.

CLI examples
~~~~~~~~~~~~

  # human table over the real corpus
  python3 tools/hackerman-language-stats.py

  # machine-readable envelope
  python3 tools/hackerman-language-stats.py --json

  # synthetic tags dir (used by unit tests)
  python3 tools/hackerman-language-stats.py --tags-dir /tmp/tags
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
    / "language_stats.json"
)
SCHEMA = "auditooor.hackerman_language_stats.v1"

MISSING_LANG = "<unknown>"
MISSING_TIER = "<missing-tier>"

# Flat-tag filename prefixes -> synthetic subtree bucket. Same as the
# distribution tool so a record's bucket is consistent across reports.
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
    read (``target_language`` / ``record_tier``)."""
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


def _normalize_language(raw: Any) -> str:
    """Return a stable language slug.

    - missing / non-string / empty -> ``MISSING_LANG``
    - whitespace stripped, lowered
    - common aliases collapsed (``solidity-yul`` -> ``solidity``,
      ``typescript`` -> ``ts``, ``javascript`` -> ``js``).
    """
    if not isinstance(raw, str):
        return MISSING_LANG
    v = raw.strip().lower()
    if not v:
        return MISSING_LANG
    aliases = {
        "sol": "solidity",
        "solidity-yul": "solidity",
        "yul": "solidity",
        "huff": "huff",
        "typescript": "ts",
        "javascript": "js",
        "tsx": "ts",
        "py": "python",
        "golang": "go",
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


def build_stats(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and build language distribution stats.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``languages``: list[str] sorted by total desc, then name asc
    - ``language_totals``: dict[lang, int]
    - ``language_by_tier``: dict[lang, dict[tier, int]] (only non-zero)
    - ``language_by_subtree``: dict[lang, dict[subtree, int]]
    - ``tier_totals``: dict[tier, int]
    - ``subtree_totals``: dict[subtree, int]
    """
    language_totals: dict[str, int] = defaultdict(int)
    tier_totals: dict[str, int] = defaultdict(int)
    subtree_totals: dict[str, int] = defaultdict(int)
    language_by_tier: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    language_by_subtree: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    total_records = 0

    for _path, record, subtree in _walk_records(tags_dir):
        lang = _normalize_language(record.get("target_language"))
        tier = _normalize_tier(record.get("record_tier"))
        language_totals[lang] += 1
        tier_totals[tier] += 1
        subtree_totals[subtree] += 1
        language_by_tier[lang][tier] += 1
        language_by_subtree[lang][subtree] += 1
        total_records += 1

    languages_sorted = sorted(
        language_totals.keys(),
        key=lambda l: (-language_totals[l], l),
    )

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "languages": languages_sorted,
        "language_totals": dict(sorted(language_totals.items())),
        "language_by_tier": {
            l: {t: int(n) for t, n in sorted(language_by_tier[l].items())}
            for l in languages_sorted
        },
        "language_by_subtree": {
            l: {s: int(n) for s, n in sorted(language_by_subtree[l].items())}
            for l in languages_sorted
        },
        "tier_totals": dict(sorted(tier_totals.items())),
        "subtree_totals": dict(sorted(subtree_totals.items())),
    }


def top_n_for_language(
    stats: dict[str, Any], axis: str, language: str, n: int = 3
) -> list[dict[str, Any]]:
    """Return the top-N (tier or subtree) cells for ``language`` sorted
    by count desc, name asc."""
    if axis == "tier":
        cells = stats["language_by_tier"].get(language, {})
        key = "tier"
    elif axis == "subtree":
        cells = stats["language_by_subtree"].get(language, {})
        key = "subtree"
    else:
        raise ValueError(f"unknown axis: {axis!r}")
    ranked = sorted(cells.items(), key=lambda kv: (-kv[1], kv[0]))
    return [{key: k, "count": int(v)} for k, v in ranked[:n]]


def render_table(stats: dict[str, Any]) -> str:
    """Render the language overview as a fenced ASCII table."""
    headers = ["language", "total", "pct"]
    rows: list[list[str]] = []
    total = stats["total_records"] or 1
    for lang in stats["languages"]:
        cnt = int(stats["language_totals"].get(lang, 0))
        pct = (cnt / total) * 100.0
        rows.append([lang, str(cnt), f"{pct:.2f}"])
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
    out.append(f"# Hackerman language distribution stats ({today})")
    out.append("")
    out.append(f"- tags_dir: {stats['tags_dir']}")
    out.append(f"- total_records: {stats['total_records']}")
    out.append(f"- distinct_languages: {len(stats['languages'])}")
    out.append(f"- distinct_tiers: {len(stats['tier_totals'])}")
    out.append(f"- distinct_subtrees: {len(stats['subtree_totals'])}")
    out.append("")
    out.append("## Language overview (rows = language)")
    out.append("")
    out.append("```")
    out.append(render_table(stats))
    out.append("```")
    out.append("")
    out.append("## Top-3 tiers per language")
    out.append("")
    for lang in stats["languages"]:
        top = top_n_for_language(stats, "tier", lang)
        chunks = [f"{r['tier']} ({r['count']})" for r in top]
        out.append(f"- `{lang}`: {', '.join(chunks) if chunks else '(empty)'}")
    out.append("")
    out.append("## Top-3 subtrees per language")
    out.append("")
    for lang in stats["languages"]:
        top = top_n_for_language(stats, "subtree", lang)
        chunks = [f"{r['subtree']} ({r['count']})" for r in top]
        out.append(f"- `{lang}`: {', '.join(chunks) if chunks else '(empty)'}")
    out.append("")
    return "\n".join(out)


def render_json(stats: dict[str, Any]) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": stats["tags_dir"],
        "total_records": stats["total_records"],
        "languages": stats["languages"],
        "language_totals": stats["language_totals"],
        "language_by_tier": stats["language_by_tier"],
        "language_by_subtree": stats["language_by_subtree"],
        "tier_totals": stats["tier_totals"],
        "subtree_totals": stats["subtree_totals"],
        "top_tiers_per_language": {
            lang: top_n_for_language(stats, "tier", lang)
            for lang in stats["languages"]
        },
        "top_subtrees_per_language": {
            lang: top_n_for_language(stats, "subtree", lang)
            for lang in stats["languages"]
        },
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit per-target-language distribution stats from "
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
