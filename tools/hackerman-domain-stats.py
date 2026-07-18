#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - target_domain distribution.

Sibling of ``tools/hackerman-attack-class-distribution.py`` and
``tools/hackerman-attack-class-inventory.py``.  The two attack-class tools
expose where bug *patterns* live.  This tool exposes where *protocol
domains* live (vault / dex / lending / oracle / bridge / governance /
staking / etc.) - the orthogonal axis a worker needs when picking a lane.

Why
~~~

Wave-1 hackerman discoverability needs to answer "for protocol domain X
(e.g. vault, dex, lending), how many hackerman records do we have, broken
out by tier and by subtree?".  Until now we had attack-class density but
no domain density, so a worker dispatching for "vault audit" could not
tell whether the corpus actually backed the lane.  This tool emits both
the human roll-up and a machine envelope keyed by
``auditooor.hackerman_domain_stats.v1`` so the MCP layer can resolve the
question without a second walk.

Inputs
~~~~~~

- ``audit/corpus_tags/tags/**/record.{yaml,json}`` (subtree records, YAML
  preferred over JSON when both exist - matches the sibling tools)
- ``audit/corpus_tags/tags/*.yaml`` (flat tags at the tags-dir root,
  bucketed by filename prefix - matches
  ``hackerman-attack-class-distribution.py``)

Records without a ``target_domain`` field are bucketed under
``<missing-target-domain>`` so corpus rot is visible rather than silent.

Outputs
~~~~~~~

- JSON envelope ``auditooor.hackerman_domain_stats.v1`` on ``--json``
  (stable key ordering, deterministic).
- Human table otherwise (markdown-style fenced ASCII).
- Three roll-ups: by domain, by domain x tier, by domain x subtree.

CLI examples
~~~~~~~~~~~~

  # human roll-up
  python3 tools/hackerman-domain-stats.py

  # machine envelope to stdout
  python3 tools/hackerman-domain-stats.py --json

  # alternate tags dir (used by the unit tests)
  python3 tools/hackerman-domain-stats.py --tags-dir /tmp/tags
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
    / "domain_stats.json"
)
SCHEMA = "auditooor.hackerman_domain_stats.v1"

MISSING_DOMAIN = "<missing-target-domain>"
MISSING_TIER = "<missing-record-tier>"
TOP_DOMAINS_HUMAN = 25

# Flat-tag filename prefixes -> synthetic subtree bucket. Mirrors the
# convention used by hackerman-attack-class-distribution.py.
FLAT_PREFIX_BUCKETS: tuple[tuple[str, str], ...] = (
    ("solodit-spec:", "_flat_solodit_spec"),
    ("dsl_pattern_", "_flat_dsl_pattern"),
    ("prior-audit-", "_flat_prior_audit"),
    ("corpus-mined-", "_flat_corpus_mined"),
    ("seed_", "_flat_seed"),
)


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load with a minimal fallback parser when PyYAML
    is unavailable.  The fallback handles only the top-level scalar fields
    we read (``target_domain`` and ``record_tier``)."""
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


def _record_domain(record: dict[str, Any]) -> str:
    v = record.get("target_domain")
    if isinstance(v, str) and v.strip():
        return v.strip()
    return MISSING_DOMAIN


def _record_tier(record: dict[str, Any]) -> str:
    v = record.get("record_tier")
    if isinstance(v, str) and v.strip():
        return v.strip()
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
    """Yield ``(path, record, subtree)`` tuples for every loadable record
    under ``tags_dir``.  Walks subdir ``record.{yaml,json}`` first (YAML
    preferred) then flat ``*.yaml`` files at the tags-dir root."""
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
    """Walk the tags dir and aggregate target_domain distributions.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``domains``: list[str] sorted by (-total, name)
    - ``domain_totals``: dict[domain, int]
    - ``domain_by_tier``: dict[domain, dict[tier, int]]
    - ``domain_by_subtree``: dict[domain, dict[subtree, int]]
    - ``tier_totals``: dict[tier, int]
    - ``subtree_totals``: dict[subtree, int]
    """
    domain_totals: dict[str, int] = defaultdict(int)
    domain_by_tier: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    domain_by_subtree: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    tier_totals: dict[str, int] = defaultdict(int)
    subtree_totals: dict[str, int] = defaultdict(int)
    total_records = 0

    for _path, record, subtree in _walk_records(tags_dir):
        domain = _record_domain(record)
        tier = _record_tier(record)
        domain_totals[domain] += 1
        domain_by_tier[domain][tier] += 1
        domain_by_subtree[domain][subtree] += 1
        tier_totals[tier] += 1
        subtree_totals[subtree] += 1
        total_records += 1

    domains_sorted = sorted(
        domain_totals.keys(),
        key=lambda d: (-domain_totals[d], d),
    )

    # Materialize sparse maps with stable key ordering.
    sparse_by_tier = {
        d: {t: int(n) for t, n in sorted(domain_by_tier[d].items())}
        for d in domains_sorted
    }
    sparse_by_subtree = {
        d: {s: int(n) for s, n in sorted(domain_by_subtree[d].items())}
        for d in domains_sorted
    }

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "domains": domains_sorted,
        "domain_totals": dict(sorted(domain_totals.items())),
        "domain_by_tier": sparse_by_tier,
        "domain_by_subtree": sparse_by_subtree,
        "tier_totals": dict(sorted(tier_totals.items())),
        "subtree_totals": dict(sorted(subtree_totals.items())),
    }


def top_domains(stats: dict[str, Any], top_n: int) -> list[dict[str, Any]]:
    """Return top-N domains by record count (ranked, deterministic)."""
    out: list[dict[str, Any]] = []
    for d in stats["domains"][:top_n]:
        out.append(
            {
                "target_domain": d,
                "count": int(stats["domain_totals"].get(d, 0)),
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


def render_human(stats: dict[str, Any]) -> str:
    out: list[str] = []
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out.append(f"# Hackerman target_domain distribution ({today})")
    out.append("")
    out.append(f"- tags_dir: {stats['tags_dir']}")
    out.append(f"- total_records: {stats['total_records']}")
    out.append(f"- distinct_domains: {len(stats['domains'])}")
    out.append(f"- distinct_tiers: {len(stats['tier_totals'])}")
    out.append(f"- distinct_subtrees: {len(stats['subtree_totals'])}")
    out.append("")
    out.append("## Domains by record count")
    out.append("")
    out.append("```")
    rows: list[list[str]] = []
    for d in stats["domains"][:TOP_DOMAINS_HUMAN]:
        total = int(stats["domain_totals"].get(d, 0))
        pct = (
            (total / stats["total_records"] * 100.0)
            if stats["total_records"]
            else 0.0
        )
        rows.append([d, str(total), f"{pct:.2f}%"])
    if not rows:
        rows.append(["(none)", "0", "0.00%"])
    out.append(
        render_table_rows(rows, headers=["target_domain", "count", "share"])
    )
    out.append("```")
    if len(stats["domains"]) > TOP_DOMAINS_HUMAN:
        out.append("")
        out.append(
            f"_({len(stats['domains']) - TOP_DOMAINS_HUMAN} more domains; "
            "see --json for full set)_"
        )
    out.append("")
    out.append("## Domain x record_tier")
    out.append("")
    tiers_sorted = sorted(stats["tier_totals"].keys())
    headers = ["target_domain"] + tiers_sorted + ["total"]
    rows = []
    for d in stats["domains"][:TOP_DOMAINS_HUMAN]:
        cells = stats["domain_by_tier"].get(d, {})
        row = [d]
        for t in tiers_sorted:
            n = int(cells.get(t, 0))
            row.append(str(n) if n > 0 else ".")
        row.append(str(int(stats["domain_totals"].get(d, 0))))
        rows.append(row)
    out.append("```")
    if rows:
        out.append(render_table_rows(rows, headers=headers))
    else:
        out.append("(empty)")
    out.append("```")
    out.append("")
    out.append("## Domain x subtree (top-3 subtrees per domain)")
    out.append("")
    for d in stats["domains"][:TOP_DOMAINS_HUMAN]:
        cells = stats["domain_by_subtree"].get(d, {})
        ranked = sorted(cells.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
        if not ranked:
            out.append(f"- `{d}`: (none)")
            continue
        chunks = [f"{s} ({n})" for s, n in ranked]
        out.append(f"- `{d}`: {', '.join(chunks)}")
    out.append("")
    return "\n".join(out)


def render_json(stats: dict[str, Any], top_n: int = TOP_DOMAINS_HUMAN) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": stats["tags_dir"],
        "total_records": stats["total_records"],
        "domains": stats["domains"],
        "domain_totals": stats["domain_totals"],
        "domain_by_tier": stats["domain_by_tier"],
        "domain_by_subtree": stats["domain_by_subtree"],
        "tier_totals": stats["tier_totals"],
        "subtree_totals": stats["subtree_totals"],
        "top_domains": top_domains(stats, top_n),
        "top_n": top_n,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit target_domain distribution from audit/corpus_tags/tags/."
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
        default=TOP_DOMAINS_HUMAN,
        help="top-N domains in the top_domains panel (default: 25)",
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
        sys.stdout.write(render_human(stats))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(stats, args.top_n) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
