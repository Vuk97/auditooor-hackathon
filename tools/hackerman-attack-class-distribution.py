#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - per-subtree x per-class matrix.

Sibling of ``tools/hackerman-attack-class-inventory.py``. The inventory tool
aggregates *per attack-class* (rows = class, cols = aggregate). This tool
emits the orthogonal view: a **per-subtree x per-attack-class matrix** that
makes class concentration / orphan patterns immediately visible across the
corpus subtrees.

Why
~~~

Wave-1 hackerman discoverability needs to answer "which corpus subtrees does
a given attack class show up in, at what density, and which classes only
ever appear in a single subtree?". The inventory tool gives a class-centric
view; the matrix tool gives the subtree-centric view. Both are emitted into
``audit/corpus_tags/derived/`` so the MCP layer can resolve either question
without a second walk.

Inputs
~~~~~~

- ``audit/corpus_tags/tags/**/record.{yaml,json}`` (subtree records, YAML
  preferred over JSON when both exist - matches the inventory tool's
  precedence)
- ``audit/corpus_tags/tags/*.yaml`` (flat tags at the tags-dir root, bucketed
  by filename prefix: ``solodit-spec`` / ``dsl_pattern`` / ``prior-audit`` /
  ``corpus-mined`` / ``seed`` / ``_flat``).  This is the only divergence
  from the inventory tool, which deliberately skips flat tags.

Modes
~~~~~

- ``dense`` (default): top-20 attack classes by global record count. Stable
  output for the daily report; the table fits in one screen.
- ``full``: every distinct attack_class.

Outputs
~~~~~~~

- JSON envelope ``auditooor.hackerman_attack_class_distribution.v1`` on
  ``--json`` (stable key ordering, deterministic).
- Human table otherwise (markdown-style fenced ASCII).
- Side panels: top-3 classes per subtree, orphan classes (single-subtree),
  concentrated classes (>=80% records in one subtree).

CLI examples
~~~~~~~~~~~~

  # dense human table
  python3 tools/hackerman-attack-class-distribution.py

  # full machine-readable
  python3 tools/hackerman-attack-class-distribution.py --mode full --json

  # alternate tags dir (used by the unit tests)
  python3 tools/hackerman-attack-class-distribution.py --tags-dir /tmp/tags
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
    / "attack_class_distribution.json"
)
SCHEMA = "auditooor.hackerman_attack_class_distribution.v1"

DENSE_TOP_N = 20
TOP_PER_SUBTREE = 3
CONCENTRATION_THRESHOLD_PCT = 80.0
MISSING_AC = "<missing-attack-class>"

# Placeholder / unclassified attack-class labels. These are the
# unrouted-record sentinels the solodit backfill leaves behind when the
# fallback classifier finds no confident, specific canonical class (see
# tools/hackerman-backfill-solodit-class.py:70-72, UNKNOWN_VALUES). The
# ~43k solodit-backfill records carrying ``unknown-attack`` are real
# provenance but carry zero attack-class signal, so they are segregated
# from the real-signal distribution panels (dense/full columns, orphan,
# concentrated) while their raw counts are preserved in class_totals.
PLACEHOLDER_ATTACK_CLASSES = frozenset(
    {"unknown-attack", "unknown-class", "unknown"}
)


def _is_placeholder_class(ac: str) -> bool:
    """True for the missing-class sentinel and any unrouted placeholder
    label that carries no real attack-class signal."""
    return ac == MISSING_AC or ac in PLACEHOLDER_ATTACK_CLASSES

# Flat-tag filename prefixes -> synthetic subtree bucket. Anything not
# matching falls into ``_flat_other`` so it still shows up in the matrix.
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
    we read (``attack_class`` and ``attack_classes_to_try`` list)."""
    if yaml is not None:
        try:
            data = yaml.safe_load(text)
            return data if isinstance(data, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    out: dict[str, Any] = {}
    in_list_key: str | None = None
    list_acc: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if in_list_key and (line.startswith("- ") or line.startswith("  - ")):
            v = line.split("- ", 1)[1].strip().strip("\"'")
            if v:
                list_acc.append(v)
            continue
        if in_list_key:
            out[in_list_key] = list(list_acc)
            in_list_key = None
            list_acc = []
        if line.startswith(" "):
            continue
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip()
            v = v.strip()
            if v == "":
                # Could be the start of a list; defer.
                in_list_key = k
                list_acc = []
            else:
                out[k] = v.strip("\"'")
    if in_list_key:
        out[in_list_key] = list(list_acc)
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


def _record_attack_classes(record: dict[str, Any]) -> list[str]:
    """Return all attack_class values for one record.

    - subdir tags use a single ``attack_class`` string
    - flat dsl_pattern tags use ``attack_classes_to_try`` (list of strings)

    Returns ``[MISSING_AC]`` when neither is present so the record still
    contributes one cell in the matrix (we want orphan/concentration
    signal on missing-class corpus rot, not silent drops).
    """
    out: list[str] = []
    ac = record.get("attack_class")
    if isinstance(ac, str) and ac.strip():
        out.append(ac.strip())
    elif isinstance(ac, list):
        for v in ac:
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
    actt = record.get("attack_classes_to_try")
    if isinstance(actt, list):
        for v in actt:
            if isinstance(v, str) and v.strip():
                out.append(v.strip())
    if not out:
        out.append(MISSING_AC)
    # Deduplicate while preserving stable order.
    seen: set[str] = set()
    deduped: list[str] = []
    for v in out:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped


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


def build_distribution(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and build the per-subtree x per-class matrix.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``subtrees``: list[str] sorted
    - ``classes``: list[str] sorted by global total desc, then name asc
    - ``matrix``: dict[subtree, dict[class, int]] (only non-zero cells)
    - ``class_totals``: dict[class, int]
    - ``subtree_totals``: dict[subtree, int]
    """
    matrix: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    class_totals: dict[str, int] = defaultdict(int)
    subtree_totals: dict[str, int] = defaultdict(int)
    total_records = 0

    for _path, record, subtree in _walk_records(tags_dir):
        classes = _record_attack_classes(record)
        for ac in classes:
            matrix[subtree][ac] += 1
            class_totals[ac] += 1
        # Each record contributes one to its subtree total even if it
        # surfaces multiple attack_class values (so subtree_totals is a
        # record count, NOT a cell sum).
        subtree_totals[subtree] += 1
        total_records += 1

    classes_sorted = sorted(
        class_totals.keys(),
        key=lambda c: (-class_totals[c], c),
    )
    subtrees_sorted = sorted(matrix.keys())

    # Materialize the matrix with explicit zeros only for classes/subtrees
    # we want to show; the on-disk JSON keeps the sparse form to stay small.
    sparse_matrix = {
        s: {c: int(n) for c, n in sorted(matrix[s].items())}
        for s in subtrees_sorted
    }

    # Segregated placeholder panel: provenance-preserving accounting of the
    # unrouted/unclassified records that are excluded from the real-signal
    # distribution panels. class_totals (above) still counts every record,
    # so raw-total consumers are unaffected; this block only NAMES which
    # classes were segregated and how many records they account for.
    placeholder_classes = sorted(
        c for c in class_totals if _is_placeholder_class(c)
    )
    placeholder_total = sum(class_totals[c] for c in placeholder_classes)
    segregated_placeholders = {
        "classes": placeholder_classes,
        "total_records": int(placeholder_total),
        "note": (
            "placeholder/unclassified solodit-backfill records; excluded "
            "from real-signal distribution panels"
        ),
    }

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "subtrees": subtrees_sorted,
        "classes": classes_sorted,
        "matrix": sparse_matrix,
        "class_totals": dict(sorted(class_totals.items())),
        "subtree_totals": dict(sorted(subtree_totals.items())),
        "segregated_placeholders": segregated_placeholders,
    }


def top_classes_per_subtree(
    dist: dict[str, Any], top_n: int = TOP_PER_SUBTREE
) -> dict[str, list[dict[str, Any]]]:
    """Return the top-N attack classes per subtree by cell count."""
    out: dict[str, list[dict[str, Any]]] = {}
    matrix = dist["matrix"]
    for subtree in dist["subtrees"]:
        cells = matrix.get(subtree, {})
        ranked = sorted(
            cells.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )
        out[subtree] = [
            {"attack_class": c, "count": int(n)}
            for c, n in ranked[:top_n]
        ]
    return out


def orphan_classes(dist: dict[str, Any]) -> list[dict[str, Any]]:
    """Attack classes whose records all live in exactly one subtree.

    Skips ``<missing-attack-class>`` (it's a sentinel, not a real class).
    """
    matrix = dist["matrix"]
    counts_by_class: dict[str, dict[str, int]] = defaultdict(dict)
    for subtree, cells in matrix.items():
        for ac, n in cells.items():
            counts_by_class[ac][subtree] = int(n)
    out: list[dict[str, Any]] = []
    for ac in dist["classes"]:
        if _is_placeholder_class(ac):
            continue
        by = counts_by_class.get(ac, {})
        non_zero = {s: n for s, n in by.items() if n > 0}
        if len(non_zero) == 1:
            (only_subtree,) = non_zero.keys()
            (only_count,) = non_zero.values()
            out.append(
                {
                    "attack_class": ac,
                    "total_records": int(only_count),
                    "only_subtree": only_subtree,
                }
            )
    # Largest orphans first.
    out.sort(key=lambda r: (-r["total_records"], r["attack_class"]))
    return out


def concentrated_classes(
    dist: dict[str, Any], threshold_pct: float = CONCENTRATION_THRESHOLD_PCT
) -> list[dict[str, Any]]:
    """Attack classes with >=``threshold_pct`` of records in a single subtree,
    AND present in >=2 subtrees (single-subtree classes are orphans, not
    concentrated; we want classes that diffuse-but-clump)."""
    matrix = dist["matrix"]
    counts_by_class: dict[str, dict[str, int]] = defaultdict(dict)
    for subtree, cells in matrix.items():
        for ac, n in cells.items():
            counts_by_class[ac][subtree] = int(n)
    out: list[dict[str, Any]] = []
    for ac in dist["classes"]:
        if _is_placeholder_class(ac):
            continue
        by = counts_by_class.get(ac, {})
        if len(by) < 2:
            continue
        total = sum(by.values())
        if total <= 0:
            continue
        top_subtree, top_count = max(by.items(), key=lambda kv: (kv[1], -ord(kv[0][0]) if kv[0] else 0))
        # Re-do the max with a deterministic tie-break: count desc, name asc.
        top_subtree, top_count = sorted(
            by.items(),
            key=lambda kv: (-kv[1], kv[0]),
        )[0]
        pct = (top_count / total) * 100.0
        if pct >= threshold_pct:
            out.append(
                {
                    "attack_class": ac,
                    "total_records": int(total),
                    "top_subtree": top_subtree,
                    "top_subtree_count": int(top_count),
                    "top_subtree_pct": round(pct, 2),
                }
            )
    out.sort(key=lambda r: (-r["total_records"], r["attack_class"]))
    return out


def select_columns(dist: dict[str, Any], mode: str) -> list[str]:
    # Segregate placeholder/unclassified classes out of the presentation
    # columns BEFORE the dense top-N slice, so dense shows the top REAL
    # classes rather than the ~43k-record ``unknown-attack`` placeholder.
    real_classes = [
        c for c in dist["classes"] if not _is_placeholder_class(c)
    ]
    if mode == "full":
        return real_classes
    if mode == "dense":
        return real_classes[:DENSE_TOP_N]
    raise ValueError(f"unknown mode: {mode!r}")


def render_table(
    dist: dict[str, Any],
    columns: list[str],
    *,
    max_col_width: int = 28,
) -> str:
    """Render the matrix as a fenced ASCII table.  Long class names are
    truncated to ``max_col_width`` chars (with a trailing ``...``)."""

    def trunc(s: str) -> str:
        if len(s) <= max_col_width:
            return s
        return s[: max_col_width - 3] + "..."

    matrix = dist["matrix"]
    headers = ["subtree", "total"] + [trunc(c) for c in columns]
    rows: list[list[str]] = []
    for subtree in dist["subtrees"]:
        cells = matrix.get(subtree, {})
        row = [subtree, str(int(dist["subtree_totals"].get(subtree, 0)))]
        for c in columns:
            n = int(cells.get(c, 0))
            row.append(str(n) if n > 0 else ".")
        rows.append(row)

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    def fmt_row(cells: list[str]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    sep = "-+-".join("-" * w for w in widths)
    out_lines = [fmt_row(headers), sep]
    for row in rows:
        out_lines.append(fmt_row(row))
    return "\n".join(out_lines)


def render_human(dist: dict[str, Any], mode: str) -> str:
    columns = select_columns(dist, mode)
    out: list[str] = []
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out.append(
        f"# Hackerman attack-class distribution matrix ({today}, mode={mode})"
    )
    out.append("")
    out.append(f"- tags_dir: {dist['tags_dir']}")
    out.append(f"- total_records: {dist['total_records']}")
    out.append(f"- subtrees: {len(dist['subtrees'])}")
    out.append(f"- distinct_classes: {len(dist['classes'])}")
    out.append(f"- columns_shown: {len(columns)}")
    out.append("")
    out.append("## Matrix (rows = subtree, cols = attack_class)")
    out.append("")
    out.append("```")
    out.append(render_table(dist, columns))
    out.append("```")
    out.append("")
    out.append("## Top-3 attack classes per subtree")
    out.append("")
    tps = top_classes_per_subtree(dist)
    for subtree in dist["subtrees"]:
        row = tps.get(subtree, [])
        if not row:
            out.append(f"- `{subtree}`: (empty)")
            continue
        chunks = [f"{r['attack_class']} ({r['count']})" for r in row]
        out.append(f"- `{subtree}`: {', '.join(chunks)}")
    out.append("")
    orphans = orphan_classes(dist)
    out.append(f"## Orphan classes (single-subtree, {len(orphans)} total)")
    out.append("")
    for row in orphans[:15]:
        out.append(
            f"- `{row['attack_class']}` -> only in `{row['only_subtree']}` "
            f"({row['total_records']} records)"
        )
    if len(orphans) > 15:
        out.append(f"- ... ({len(orphans) - 15} more)")
    out.append("")
    conc = concentrated_classes(dist)
    out.append(
        f"## Concentrated classes (>={int(CONCENTRATION_THRESHOLD_PCT)}% in "
        f"one subtree, {len(conc)} total)"
    )
    out.append("")
    for row in conc[:15]:
        out.append(
            f"- `{row['attack_class']}` -> {row['top_subtree_pct']}% in "
            f"`{row['top_subtree']}` "
            f"({row['top_subtree_count']}/{row['total_records']})"
        )
    if len(conc) > 15:
        out.append(f"- ... ({len(conc) - 15} more)")
    out.append("")
    return "\n".join(out)


def render_json(dist: dict[str, Any], mode: str) -> str:
    columns = select_columns(dist, mode)
    payload = {
        "schema": SCHEMA,
        "mode": mode,
        "tags_dir": dist["tags_dir"],
        "total_records": dist["total_records"],
        "subtrees": dist["subtrees"],
        "columns_shown": columns,
        "classes": dist["classes"],
        "matrix": dist["matrix"],
        "class_totals": dist["class_totals"],
        "subtree_totals": dist["subtree_totals"],
        "top_classes_per_subtree": top_classes_per_subtree(dist),
        "orphan_classes": orphan_classes(dist),
        "concentrated_classes": concentrated_classes(dist),
        "concentration_threshold_pct": CONCENTRATION_THRESHOLD_PCT,
        "segregated_placeholders": dist.get(
            "segregated_placeholders",
            {"classes": [], "total_records": 0, "note": ""},
        ),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit per-subtree x per-attack-class matrix from "
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
        "--mode",
        choices=("dense", "full"),
        default="dense",
        help="dense=top-20 classes, full=every class",
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
    dist = build_distribution(tags_dir)
    if args.json:
        sys.stdout.write(render_json(dist, args.mode))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(dist, args.mode))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(dist, args.mode) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
