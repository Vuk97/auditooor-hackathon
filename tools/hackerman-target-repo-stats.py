#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - target_repo distribution stats.

Sibling of ``tools/hackerman-language-stats.py`` /
``tools/hackerman-domain-stats.py`` / ``tools/hackerman-severity-stats.py``.
Those tools cover the per-target-language, per-protocol-domain, and
per-severity views of the corpus; this tool gives the orthogonal
**per-target_repo** view: which upstream repositories have the densest
hackerman record mass, plus the per-tier (tier-1 / tier-2 / tier-3
verification-tier) breakdown so a worker can see whether a repo's
record mass is dominated by realtime-API-verified findings (tier-1),
public-archive-verified (tier-2), or synthetic taxonomy-anchored
(tier-3).

Why
~~~

Wave-1 hackerman discoverability needs to answer "for upstream repo X
(e.g. liquity/dev, aave-protocol/v3, cosmos/cosmos-sdk), how many
hackerman records do we have, and what verification-tier confidence
does that mass carry?" Until now we had per-language, per-domain,
per-severity density but no per-repo density, so a worker dispatching
into a sibling-engagement lane could not tell whether the corpus
actually backed the lane's specific repo target. Top-50 is the human
panel default; the JSON envelope carries the full distribution.

Inputs
~~~~~~

- ``audit/corpus_tags/tags/**/record.{yaml,json}`` (subtree records,
  YAML wins over JSON when both exist - matches sibling-tool precedence).
- ``audit/corpus_tags/tags/*.yaml`` (flat tags at the tags-dir root,
  bucketed by filename prefix exactly the way the sibling stats tools
  bucket them: ``_flat_solodit_spec`` / ``_flat_dsl_pattern`` /
  ``_flat_prior_audit`` / ``_flat_corpus_mined`` / ``_flat_seed`` /
  ``_flat_other``).

Tier-1/2/3 extraction
~~~~~~~~~~~~~~~~~~~~~

The verification_tier identity is stored as a structured shape_tag
``verification_tier:tier-N-<suffix>`` inside ``function_shape.shape_tags``
(e.g. ``verification_tier:tier-1-verified-realtime-api``,
``verification_tier:tier-2-verified-public-archive``,
``verification_tier:tier-3-synthetic-taxonomy-anchored``). This tool
normalises any such tag to its canonical ``tier-1`` / ``tier-2`` /
``tier-3`` head so the breakdown is comparable across subtype suffixes.
Records with no parseable verification_tier shape_tag bucket under
``<missing-tier>``.

Outputs
~~~~~~~

- Human report (default): summary counts + top-50 repos table + per-repo
  tier-1/2/3 breakdown.
- JSON envelope ``auditooor.hackerman_target_repo_stats.v1`` on ``--json``
  (stable key ordering, deterministic).
- Optional ``--out-json`` writes the same envelope to disk.

CLI examples
~~~~~~~~~~~~

  # human top-50 over the real corpus
  python3 tools/hackerman-target-repo-stats.py

  # machine-readable envelope
  python3 tools/hackerman-target-repo-stats.py --json

  # synthetic tags dir (used by unit tests)
  python3 tools/hackerman-target-repo-stats.py --tags-dir /tmp/tags

  # different top-N for the human panel
  python3 tools/hackerman-target-repo-stats.py --top-n 25
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
    / "target_repo_stats.json"
)
SCHEMA = "auditooor.hackerman_target_repo_stats.v1"

MISSING_REPO = "<missing-target-repo>"
MISSING_TIER = "<missing-tier>"
TOP_REPOS_HUMAN = 50

# Canonical verification-tier heads, in canonical ranked order. Anything
# outside this set surfaces verbatim so corpus rot is visible rather
# than silently collapsed.
CANONICAL_TIERS: tuple[str, ...] = ("tier-1", "tier-2", "tier-3")

_VERIFICATION_TIER_TAG_RE = re.compile(
    r"verification_tier[:=]\s*(tier-[123])(?:-[a-z0-9-]+)?",
    re.IGNORECASE,
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
    is unavailable.  The fallback handles the top-level scalar fields
    we read (``target_repo``) plus a flattened scan for the
    ``verification_tier:tier-N`` shape_tag substring anywhere in the
    file body."""
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
    # Surface a synthetic ``_raw_text`` field so the tier extractor has
    # something to scan when the structured shape_tags list isn't
    # available via the fallback parser. Sibling stats tools accept this
    # convention.
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


def _normalize_repo(raw: Any) -> str:
    if not isinstance(raw, str):
        return MISSING_REPO
    v = raw.strip()
    if not v:
        return MISSING_REPO
    # Collapse trailing slashes / whitespace; do NOT lowercase repo names
    # (case-sensitive on GitHub for org names; leave verbatim so a worker
    # can copy/paste).
    return v.rstrip("/")


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
    """Best-effort verification_tier extraction.

    Order of precedence:
      1. ``function_shape.shape_tags`` list elements matching
         ``verification_tier:tier-N``.
      2. ``required_preconditions`` list elements matching the same
         pattern (some records store the canonical tag there too).
      3. Raw-text fallback scan (kicks in when the fallback YAML parser
         couldn't reach into the nested list).
    """
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


def build_stats(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and build target_repo distribution stats.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``repos``: list[str] sorted by (-total, name)
    - ``repo_totals``: dict[repo, int]
    - ``repo_by_tier``: dict[repo, dict[tier, int]]
    - ``repo_by_subtree``: dict[repo, dict[subtree, int]]
    - ``tier_totals``: dict[tier, int] (sorted canonical first)
    - ``subtree_totals``: dict[subtree, int]
    """
    repo_totals: dict[str, int] = defaultdict(int)
    tier_totals: dict[str, int] = defaultdict(int)
    subtree_totals: dict[str, int] = defaultdict(int)
    repo_by_tier: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    repo_by_subtree: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    total_records = 0

    for _path, record, subtree in _walk_records(tags_dir):
        repo = _normalize_repo(record.get("target_repo"))
        tier = _extract_tier(record)
        repo_totals[repo] += 1
        tier_totals[tier] += 1
        subtree_totals[subtree] += 1
        repo_by_tier[repo][tier] += 1
        repo_by_subtree[repo][subtree] += 1
        total_records += 1

    repos_sorted = sorted(
        repo_totals.keys(),
        key=lambda r: (-repo_totals[r], r),
    )

    # Tier totals sorted with canonical tier-1/2/3 first, then anything
    # outside the canonical set alphabetical (typically just
    # ``<missing-tier>``).
    tier_totals_sorted = dict(
        sorted(tier_totals.items(), key=lambda kv: _tier_sort_key(kv[0]))
    )

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "repos": repos_sorted,
        "repo_totals": dict(sorted(repo_totals.items())),
        "repo_by_tier": {
            r: {t: int(n) for t, n in sorted(
                repo_by_tier[r].items(), key=lambda kv: _tier_sort_key(kv[0])
            )}
            for r in repos_sorted
        },
        "repo_by_subtree": {
            r: {s: int(n) for s, n in sorted(repo_by_subtree[r].items())}
            for r in repos_sorted
        },
        "tier_totals": tier_totals_sorted,
        "subtree_totals": dict(sorted(subtree_totals.items())),
    }


def top_repos(stats: dict[str, Any], top_n: int) -> list[dict[str, Any]]:
    """Return the top-N repos by record count (ranked, deterministic).
    Each entry carries the tier-1/2/3 breakdown so the consumer can
    decide on confidence."""
    out: list[dict[str, Any]] = []
    for r in stats["repos"][:top_n]:
        tier_cells = stats["repo_by_tier"].get(r, {})
        out.append(
            {
                "target_repo": r,
                "count": int(stats["repo_totals"].get(r, 0)),
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


def render_human(stats: dict[str, Any], top_n: int = TOP_REPOS_HUMAN) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out: list[str] = []
    out.append(f"# Hackerman target_repo distribution ({today})")
    out.append("")
    out.append(f"- tags_dir: {stats['tags_dir']}")
    out.append(f"- total_records: {stats['total_records']}")
    out.append(f"- distinct_repos: {len(stats['repos'])}")
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
    out.append(f"## Top-{top_n} target_repos by record count")
    out.append("")
    out.append("```")
    rows = []
    for r in stats["repos"][:top_n]:
        cnt = int(stats["repo_totals"].get(r, 0))
        pct = (cnt / total) * 100.0
        tier_cells = stats["repo_by_tier"].get(r, {})
        t1 = int(tier_cells.get("tier-1", 0))
        t2 = int(tier_cells.get("tier-2", 0))
        t3 = int(tier_cells.get("tier-3", 0))
        tm = int(tier_cells.get(MISSING_TIER, 0))
        rows.append(
            [
                r,
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
                "target_repo",
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
    if len(stats["repos"]) > top_n:
        out.append("")
        out.append(
            f"_({len(stats['repos']) - top_n} more repos; "
            "see --json for full set)_"
        )
    out.append("")
    return "\n".join(out)


def render_json(stats: dict[str, Any], top_n: int = TOP_REPOS_HUMAN) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": stats["tags_dir"],
        "total_records": stats["total_records"],
        "repos": stats["repos"],
        "repo_totals": stats["repo_totals"],
        "repo_by_tier": stats["repo_by_tier"],
        "repo_by_subtree": stats["repo_by_subtree"],
        "tier_totals": stats["tier_totals"],
        "subtree_totals": stats["subtree_totals"],
        "top_repos": top_repos(stats, top_n),
        "top_n": top_n,
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit target_repo distribution stats from "
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
        default=TOP_REPOS_HUMAN,
        help="top-N repos in the top_repos panel (default: 50)",
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
