#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - per-attack-class severity matrix.

Sibling of ``tools/hackerman-attack-class-distribution.py`` (per-subtree x
per-attack-class) and ``tools/hackerman-severity-stats.py`` (per-severity
totals). This tool emits the orthogonal **per-attack-class severity
histogram** matrix: for each ``attack_class`` in the corpus, count records
falling into each canonical severity tier (critical / high / medium / low /
info / etc.), compute the severity-mode (most common tier) and the
tier-1+2-only severity-mode (using only ``critical`` + ``high`` rows as the
denominator) as a cross-validation knob.

Why
~~~

Rule-14 upside-asymmetric filing decisions require an empirical prior: a
hunter facing a "what severity should I file this re-entrancy at?"
question can now look up the corpus-wide severity-distribution for the
``reentrancy`` attack_class (or any other class) before drafting a
filing. The severity-mode answers "what is the modal severity for this
class". The tier-1+2-only mode answers "among critical/high filings,
which is the dominant tier" - a cross-validation knob because it
ignores low/info noise that can swamp the modal count for classes that
are mostly cosmetic-with-occasional-CRITICAL outliers.

Inputs
~~~~~~

- ``audit/corpus_tags/tags/**/record.{yaml,json}`` (subtree records, YAML
  preferred over JSON when both exist - matches sibling-tool precedence)
- ``audit/corpus_tags/tags/*.yaml`` (flat tags at the tags-dir root,
  bucketed by filename prefix into ``_flat_*`` synthetic subtrees - same
  convention as the distribution / severity-stats tools)

Outputs
~~~~~~~

- JSON envelope ``auditooor.hackerman_attack_class_severity_matrix.v1`` on
  ``--json`` (stable key ordering, deterministic).
- Human report (default): summary + per-class severity table + top-N
  classes whose severity-mode is ``critical``.
- Optional ``--out-json`` writes the same envelope to disk.

CLI examples
~~~~~~~~~~~~

  # human report over the real corpus
  python3 tools/hackerman-attack-class-severity-matrix.py

  # machine-readable envelope
  python3 tools/hackerman-attack-class-severity-matrix.py --json

  # synthetic tags dir (used by unit tests)
  python3 tools/hackerman-attack-class-severity-matrix.py --tags-dir /tmp/tags
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
    / "attack_class_severity_matrix.json"
)
SCHEMA = "auditooor.hackerman_attack_class_severity_matrix.v1"

MISSING_AC = "<missing-attack-class>"
MISSING_SEVERITY = "<unknown>"

# Canonical severity slugs, in canonical ranked order. Sibling-tool aligned.
CANONICAL_SEVERITIES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)

# tier-1+2 = critical + high (only these severities are counted for the
# tier-1+2 cross-validation severity-mode).
TIER_1_2_SEVERITIES: tuple[str, ...] = ("critical", "high")

# Flat-tag filename prefixes -> synthetic subtree bucket (parity with siblings).
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
    read (``attack_class`` / ``severity_at_finding``) and the
    ``attack_classes_to_try`` list form."""
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


def _normalize_severity(raw: Any) -> str:
    """Stable severity slug. Matches ``hackerman-severity-stats.py``
    behaviour byte-for-byte: aliases collapse to canonical
    critical/high/medium/low/info; missing / non-string -> sentinel."""
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


def _record_attack_classes(record: dict[str, Any]) -> list[str]:
    """Return all attack_class values for one record.

    - subdir tags use a single ``attack_class`` string
    - flat dsl_pattern tags use ``attack_classes_to_try`` (list of strings)

    Returns ``[MISSING_AC]`` when neither is present so the record still
    contributes one cell (visible corpus rot, not silent drop)."""
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
    """Yield ``(path, record, subtree)`` tuples. YAML wins over JSON when
    both files live in the same dir (parity with sibling tools)."""
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
    for path in sorted(tags_dir.glob("*.yaml")):
        if not path.is_file():
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec, _subtree_for_flat_record(path)


def _severity_sort_key(severity: str) -> tuple[int, str]:
    try:
        idx = CANONICAL_SEVERITIES.index(severity)
    except ValueError:
        return (len(CANONICAL_SEVERITIES) + 1, severity)
    return (idx, severity)


def _compute_mode(
    histogram: dict[str, int],
    *,
    restrict_to: tuple[str, ...] | None = None,
) -> str | None:
    """Return the severity with the largest count in ``histogram``.

    Tie-break: canonical rank wins (critical > high > medium > low > info >
    non-canonical alpha). When ``restrict_to`` is set, only those severities
    are considered; returns ``None`` if no restricted severity has count>0.
    """
    if restrict_to is not None:
        candidates = {
            s: n for s, n in histogram.items() if s in restrict_to and n > 0
        }
    else:
        candidates = {s: n for s, n in histogram.items() if n > 0}
    if not candidates:
        return None
    # Sort by (-count, canonical_rank, name) -> stable, deterministic.
    ranked = sorted(
        candidates.items(),
        key=lambda kv: (-kv[1], _severity_sort_key(kv[0])),
    )
    return ranked[0][0]


def build_matrix(tags_dir: Path) -> dict[str, Any]:
    """Walk the tags dir and build the per-attack-class severity matrix.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``total_classes``: int
    - ``classes``: list[str] sorted by total record count desc, then name asc
    - ``severities``: list[str] sorted by canonical rank then name
    - ``severity_histogram_by_class``: dict[class, dict[severity, int]]
    - ``class_totals``: dict[class, int]
    - ``severity_mode_by_class``: dict[class, severity-or-null]
    - ``tier_1_2_severity_mode_by_class``: dict[class, severity-or-null]
    """
    severity_histogram_by_class: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    class_totals: dict[str, int] = defaultdict(int)
    severity_totals: dict[str, int] = defaultdict(int)
    total_records = 0

    for _path, record, _subtree in _walk_records(tags_dir):
        classes = _record_attack_classes(record)
        sev = _normalize_severity(record.get("severity_at_finding"))
        for ac in classes:
            severity_histogram_by_class[ac][sev] += 1
            class_totals[ac] += 1
        severity_totals[sev] += 1
        total_records += 1

    classes_sorted = sorted(
        class_totals.keys(),
        key=lambda c: (-class_totals[c], c),
    )
    severities_sorted = sorted(
        severity_totals.keys(),
        key=_severity_sort_key,
    )

    severity_mode_by_class: dict[str, str | None] = {}
    tier_1_2_severity_mode_by_class: dict[str, str | None] = {}
    for ac in classes_sorted:
        hist = severity_histogram_by_class[ac]
        severity_mode_by_class[ac] = _compute_mode(hist)
        tier_1_2_severity_mode_by_class[ac] = _compute_mode(
            hist, restrict_to=TIER_1_2_SEVERITIES
        )

    # Materialize the histogram densely with explicit zeros, sorted by
    # canonical rank, so downstream consumers don't have to guess.
    dense_histogram = {
        ac: {
            s: int(severity_histogram_by_class[ac].get(s, 0))
            for s in severities_sorted
        }
        for ac in classes_sorted
    }

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "total_records": total_records,
        "total_classes": len(classes_sorted),
        "classes": classes_sorted,
        "severities": severities_sorted,
        "severity_histogram_by_class": dense_histogram,
        "class_totals": dict(sorted(class_totals.items())),
        "severity_totals": dict(sorted(severity_totals.items())),
        "severity_mode_by_class": severity_mode_by_class,
        "tier_1_2_severity_mode_by_class": tier_1_2_severity_mode_by_class,
    }


def classes_by_mode(
    matrix: dict[str, Any], target_severity: str, *, tier_1_2_only: bool = False
) -> list[dict[str, Any]]:
    """Return classes whose (tier-1+2 or full) severity_mode == target,
    sorted by class total desc then name asc.

    Each entry: ``{"attack_class", "total_records", "histogram"}``."""
    key = (
        "tier_1_2_severity_mode_by_class"
        if tier_1_2_only
        else "severity_mode_by_class"
    )
    modes: dict[str, str | None] = matrix[key]
    out: list[dict[str, Any]] = []
    for ac in matrix["classes"]:
        if modes.get(ac) == target_severity:
            out.append(
                {
                    "attack_class": ac,
                    "total_records": int(matrix["class_totals"].get(ac, 0)),
                    "histogram": dict(
                        matrix["severity_histogram_by_class"].get(ac, {})
                    ),
                }
            )
    return out


def render_table(matrix: dict[str, Any], *, top_n: int = 25) -> str:
    """Render the top-N classes (by total) x severity columns as a fenced
    ASCII table."""
    severities = matrix["severities"]
    headers = ["attack_class", "total"] + list(severities) + ["mode", "tier12_mode"]
    rows: list[list[str]] = []
    for ac in matrix["classes"][:top_n]:
        hist = matrix["severity_histogram_by_class"].get(ac, {})
        row = [ac, str(int(matrix["class_totals"].get(ac, 0)))]
        for s in severities:
            n = int(hist.get(s, 0))
            row.append(str(n) if n > 0 else ".")
        row.append(matrix["severity_mode_by_class"].get(ac) or "-")
        row.append(
            matrix["tier_1_2_severity_mode_by_class"].get(ac) or "-"
        )
        rows.append(row)

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


def render_human(matrix: dict[str, Any], *, top_n: int = 25) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out: list[str] = []
    out.append(
        f"# Hackerman attack-class severity matrix ({today}, top_n={top_n})"
    )
    out.append("")
    out.append(f"- tags_dir: {matrix['tags_dir']}")
    out.append(f"- total_records: {matrix['total_records']}")
    out.append(f"- total_classes: {matrix['total_classes']}")
    out.append(f"- distinct_severities: {len(matrix['severities'])}")
    out.append("")
    out.append("## Top-N classes by total records (severity histogram)")
    out.append("")
    out.append("```")
    out.append(render_table(matrix, top_n=top_n))
    out.append("```")
    out.append("")
    crit_mode = classes_by_mode(matrix, "critical")
    out.append(
        f"## Classes whose severity_mode == critical ({len(crit_mode)} total)"
    )
    out.append("")
    for row in crit_mode[:15]:
        out.append(
            f"- `{row['attack_class']}` -> {row['total_records']} records"
        )
    if len(crit_mode) > 15:
        out.append(f"- ... ({len(crit_mode) - 15} more)")
    out.append("")
    crit_t12 = classes_by_mode(matrix, "critical", tier_1_2_only=True)
    out.append(
        "## Classes whose tier-1+2-only severity_mode == critical "
        f"({len(crit_t12)} total)"
    )
    out.append("")
    for row in crit_t12[:15]:
        out.append(
            f"- `{row['attack_class']}` -> {row['total_records']} records"
        )
    if len(crit_t12) > 15:
        out.append(f"- ... ({len(crit_t12) - 15} more)")
    out.append("")
    return "\n".join(out)


def render_json(matrix: dict[str, Any]) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": matrix["tags_dir"],
        "total_records": matrix["total_records"],
        "total_classes": matrix["total_classes"],
        "classes": matrix["classes"],
        "severities": matrix["severities"],
        "severity_histogram_by_class": matrix["severity_histogram_by_class"],
        "class_totals": matrix["class_totals"],
        "severity_totals": matrix["severity_totals"],
        "severity_mode_by_class": matrix["severity_mode_by_class"],
        "tier_1_2_severity_mode_by_class": matrix[
            "tier_1_2_severity_mode_by_class"
        ],
        "classes_mode_critical": classes_by_mode(matrix, "critical"),
        "classes_tier12_mode_critical": classes_by_mode(
            matrix, "critical", tier_1_2_only=True
        ),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Emit per-attack-class severity histogram matrix from "
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
        default=25,
        help="number of top classes to render in the human ASCII table",
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
    matrix = build_matrix(tags_dir)
    if args.json:
        sys.stdout.write(render_json(matrix))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(matrix, top_n=args.top_n))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(matrix) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
