#!/usr/bin/env python3
"""Wave-1 hackerman capability lift (PR #726) - per-firm x per-project
coverage matrix for the ``audit_firm_public_reports`` corpus.

Sibling of ``tools/hackerman-audit-firm-pdf-preview-extractor.py``. The
preview extractor surfaced ethena / euler / looksrare as top
cross-firm-coverage projects on a sampled scan; this tool computes the
full project x firm coverage matrix so we can classify projects by how
many firms have audited them:

- 3+ firms = high-confidence anchor (cross-validation lattice).
- 2 firms  = medium-confidence anchor.
- 1 firm   = lower-confidence (potential audit-firm-bias / single-source).

Why
~~~

Wave-1 hackerman discoverability needs a cheap way to weight
audit-firm-sourced patterns: a finding extracted from a project audited
by 3+ independent firms is much higher signal than a finding extracted
from a single-firm engagement. The matrix is also the right input for
Wave-2/3 detector promotion decisions and for prior-audit alignment
checks against the active engagement queue.

Inputs
~~~~~~

- ``audit/corpus_tags/tags/audit_firm_public_reports/**/record.{yaml,json}``
  - YAML wins over JSON when both exist (matches sibling-tool
    precedence).
  - Records outside ``audit_firm_public_reports/`` are ignored - this
    tool is intentionally scoped to that subtree only.

Project name extraction
~~~~~~~~~~~~~~~~~~~~~~~

For each record we extract the project name in this priority order:

1. ``attacker_action_sequence`` -> regex ``covering project '([^']+)'``
   (this is the canonical author-of-record field for these stubs).
2. ``required_preconditions`` -> any entry starting with ``Inferred
   project name `` -> trailing token.
3. Fallback: parse the slug between firm prefix and trailing hash in
   ``record_id`` (``audit-firm:<firm>:<slug>:<hash>``), strip common
   firm prefixes (``chainsecurity_``, ``trailofbits_``, etc.), and
   title-case.

The extracted project name is then normalised:

- whitespace stripped, collapsed to single spaces
- leading date tokens (e.g. ``2025-06-10 ``, ``06 10 ``) stripped
- common report-type suffixes stripped (``Security Review``, ``Audit
  Report``, ``Audit``, ``Review``)
- lower-cased for the matrix key; the canonical display form is the
  first-seen casing.

Outputs
~~~~~~~

- Human report (default): summary counts + matrix preview + top-30
  projects by total firm-coverage + 3+-firm anchor list + 1-firm-only
  list.
- JSON envelope ``auditooor.hackerman_audit_firm_coverage_matrix.v1``
  on ``--json`` (stable key ordering, deterministic).
- Optional ``--out-json`` writes the same envelope to disk.

CLI examples
~~~~~~~~~~~~

  # human report over the real corpus
  python3 tools/hackerman-audit-firm-coverage-matrix.py

  # machine-readable envelope
  python3 tools/hackerman-audit-firm-coverage-matrix.py --json

  # synthetic tags dir (used by unit tests)
  python3 tools/hackerman-audit-firm-coverage-matrix.py \
      --tags-dir /tmp/tags
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
    / "audit_firm_coverage_matrix.json"
)
SCHEMA = "auditooor.hackerman_audit_firm_coverage_matrix.v1"

SUBTREE = "audit_firm_public_reports"

MISSING_PROJECT = "<unknown-project>"
MISSING_FIRM = "<unknown-firm>"

# Regex pulling the project name out of the canonical
# ``attacker_action_sequence`` stub written by the audit-firm corpus
# ETL.  Example anchor (one of 1681): "Report published in 2025-10
# covering project 'Kyber Hook Uniswap Foundation'. PDF/markdown
# content not parsed at this stage; ...".
_PROJECT_FROM_ACTION = re.compile(r"covering project '([^']+)'")
_PROJECT_FROM_PRECOND = re.compile(r"Inferred project name\s+(.+)$")

# Common firm-name prefixes we strip from the slug fallback (lower-case
# comparison).  Order matters: longer prefixes first.
_FIRM_PREFIXES: tuple[str, ...] = (
    "chainsecurity_",
    "trailofbits_",
    "openzeppelin_",
    "spearbit_",
    "sherlock_",
    "zellic_",
    "pashov_",
    "cyfrin_",
)

# Common report-type suffixes we strip from the project name.  Compared
# case-insensitively against the trailing token of the extracted name.
_REPORT_SUFFIXES: tuple[str, ...] = (
    "Security Review",
    "Audit Report",
    "Final Audit Report",
    "Audit",
    "Review",
    "Report",
)

# Leading date-token prefixes we strip from project names.  These match
# the ``YYYY-MM-DD `` / ``YYYY ``/ ``MM DD `` / leading ``MM `` patterns
# the corpus stubs leak into the action sentence (e.g.
# ``06 10 bunni .1``, ``.06.27 Lyra``, ``04 balancer balancerv2``).
_LEADING_DATE_RE = re.compile(
    r"^(\.?\d{2,4}[-./]\d{1,2}([-./]\d{1,2})?|\d{2}\s+\d{2}|\d{2})\s+"
)

# Slug-tail tokens we drop from the trailing edge of an extracted name
# (Trail of Bits + Spearbit love ``securityreview`` / ``finalreport``).
_TRAILING_TAIL_TOKENS: tuple[str, ...] = (
    "securityreview",
    "security review",
    "finalreport",
    "final report",
)


def _yaml_load(text: str) -> dict[str, Any]:
    """Best-effort YAML load with a minimal fallback parser when PyYAML
    is unavailable."""
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


def _normalize_project_name(raw: str) -> str:
    """Apply project-name normalisation rules described in the module
    docstring.  Returns the display form (first-seen casing after
    cleanup); callers lower-case for matrix keying."""
    s = (raw or "").strip()
    if not s:
        return ""
    # Collapse internal whitespace.
    s = re.sub(r"\s+", " ", s)
    # Strip up to 2 successive leading date tokens (handles
    # ``06 10 bunni .1`` -> ``bunni .1``).
    for _ in range(2):
        new = _LEADING_DATE_RE.sub("", s).strip()
        if new == s:
            break
        s = new
    # Strip trailing tail tokens (case-insensitive).
    low = s.lower()
    for tail in _TRAILING_TAIL_TOKENS:
        if low.endswith(" " + tail):
            s = s[: -(len(tail) + 1)].rstrip()
            low = s.lower()
            break
    # Strip report-type suffixes, case-insensitive.  Greedy on longest
    # match first.
    for suf in _REPORT_SUFFIXES:
        if s.lower().endswith(" " + suf.lower()):
            s = s[: -len(suf)].rstrip(" -")
            break
    # Drop trailing punctuation noise.
    s = s.rstrip(" .,-_")
    return s


def _project_from_slug(record_id: str) -> str:
    """Fallback project extractor parsing ``audit-firm:<firm>:<slug>:<hash>``."""
    parts = record_id.split(":")
    if len(parts) < 4:
        return ""
    slug = parts[2]
    low = slug.lower()
    for pref in _FIRM_PREFIXES:
        if low.startswith(pref):
            slug = slug[len(pref):]
            break
    # Slugs frequently embed dates / dashes; normalise to spaces and
    # title-case the result so it merges with names extracted from
    # action sentences.
    slug = slug.replace("_", " ").replace("-", " ")
    slug = re.sub(r"\s+", " ", slug).strip()
    if not slug:
        return ""
    # Title-case for display; we lower-case for the matrix key.
    return slug.title()


def extract_project_name(record: dict[str, Any]) -> str:
    """Return the display-form project name for a record.

    Empty string when nothing usable is found (the caller maps this to
    ``MISSING_PROJECT``)."""
    action = record.get("attacker_action_sequence")
    if isinstance(action, str):
        m = _PROJECT_FROM_ACTION.search(action)
        if m:
            name = _normalize_project_name(m.group(1))
            if name:
                return name
    pre = record.get("required_preconditions")
    if isinstance(pre, list):
        for entry in pre:
            if not isinstance(entry, str):
                continue
            m = _PROJECT_FROM_PRECOND.search(entry.strip())
            if m:
                name = _normalize_project_name(m.group(1))
                if name:
                    return name
    rid = record.get("record_id")
    if isinstance(rid, str):
        name = _normalize_project_name(_project_from_slug(rid))
        if name:
            return name
    return ""


def extract_firm(record: dict[str, Any], path: Path, tags_dir: Path) -> str:
    """Return the firm slug for a record.

    Priority: ``record_id`` parse -> path-relative subdir parse."""
    rid = record.get("record_id")
    if isinstance(rid, str):
        parts = rid.split(":")
        if len(parts) >= 3 and parts[0] == "audit-firm":
            firm = parts[1].strip()
            if firm:
                return firm
    try:
        rel = path.relative_to(tags_dir / SUBTREE)
    except ValueError:
        return MISSING_FIRM
    parts2 = rel.parts
    if not parts2:
        return MISSING_FIRM
    # Record dirs are named ``<firm>__<slug>-<hash>``.  Extract the
    # leading firm slug.
    leaf = parts2[0]
    firm, _, _ = leaf.partition("__")
    return firm.strip() or MISSING_FIRM


def _walk_subtree_records(
    tags_dir: Path,
) -> Iterable[tuple[Path, dict[str, Any]]]:
    """Yield ``(path, record)`` tuples from the
    ``audit_firm_public_reports`` subtree only.

    YAML wins over JSON when both live in the same dir."""
    root = tags_dir / SUBTREE
    if not root.exists():
        return
    seen_dirs: set[Path] = set()
    for path in sorted(root.rglob("record.yaml")):
        seen_dirs.add(path.parent)
        rec = _load_record(path)
        if rec:
            yield path, rec
    for path in sorted(root.rglob("record.json")):
        if path.parent in seen_dirs:
            continue
        rec = _load_record(path)
        if rec:
            yield path, rec


def build_matrix(tags_dir: Path) -> dict[str, Any]:
    """Walk the subtree and build the project x firm coverage matrix.

    Returns a dict with:

    - ``schema``: schema id
    - ``tags_dir``: abs tags dir path
    - ``total_records``: int
    - ``total_projects``: int
    - ``total_firms``: int
    - ``firms``: sorted list[str]
    - ``projects``: sorted list[str] (display-form, by total desc, name asc)
    - ``matrix``: dict[project_display, dict[firm, count]]
    - ``project_totals``: dict[project_display, int]
    - ``firm_totals``: dict[firm, int]
    - ``project_firm_counts``: dict[project_display, int] (distinct firms)
    - ``coverage_buckets``: dict[bucket, list[project_display]] where
      bucket in ``"3plus_firm"`` / ``"2_firm"`` / ``"1_firm"``.
    """
    # Project key (lower-case display) -> display form (first seen).
    display: dict[str, str] = {}
    # matrix[project_key][firm] = count
    matrix: dict[str, dict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    firm_totals: dict[str, int] = defaultdict(int)
    project_totals: dict[str, int] = defaultdict(int)
    total_records = 0

    for path, rec in _walk_subtree_records(tags_dir):
        disp = extract_project_name(rec) or MISSING_PROJECT
        key = disp.lower()
        if key not in display:
            display[key] = disp
        firm = extract_firm(rec, path, tags_dir)
        matrix[key][firm] += 1
        firm_totals[firm] += 1
        project_totals[key] += 1
        total_records += 1

    # Distinct firms per project.
    project_firm_counts: dict[str, int] = {
        k: len(matrix[k]) for k in matrix
    }

    # Build coverage buckets by distinct-firm count.
    buckets: dict[str, list[str]] = {
        "3plus_firm": [],
        "2_firm": [],
        "1_firm": [],
    }
    for k, n in project_firm_counts.items():
        d = display[k]
        if n >= 3:
            buckets["3plus_firm"].append(d)
        elif n == 2:
            buckets["2_firm"].append(d)
        elif n == 1:
            buckets["1_firm"].append(d)
    for v in buckets.values():
        v.sort(key=lambda s: s.lower())

    firms_sorted = sorted(firm_totals.keys())
    # Sort projects by total records desc, then display name asc.  Use
    # display form in outputs.
    projects_sorted_display = [
        display[k]
        for k in sorted(
            project_totals.keys(),
            key=lambda kk: (-project_totals[kk], kk),
        )
    ]

    # Re-key matrix / project_totals / project_firm_counts by display
    # form so consumers don't need to lower-case lookups.
    matrix_display = {
        display[k]: {f: int(n) for f, n in sorted(v.items())}
        for k, v in matrix.items()
    }
    project_totals_display = {
        display[k]: int(n) for k, n in project_totals.items()
    }
    project_firm_counts_display = {
        display[k]: int(n) for k, n in project_firm_counts.items()
    }

    return {
        "schema": SCHEMA,
        "tags_dir": str(tags_dir),
        "subtree": SUBTREE,
        "total_records": total_records,
        "total_projects": len(project_totals),
        "total_firms": len(firm_totals),
        "firms": firms_sorted,
        "projects": projects_sorted_display,
        "matrix": dict(sorted(matrix_display.items())),
        "project_totals": dict(sorted(project_totals_display.items())),
        "firm_totals": dict(sorted(firm_totals.items())),
        "project_firm_counts": dict(
            sorted(project_firm_counts_display.items())
        ),
        "coverage_buckets": buckets,
    }


def top_n_projects(
    stats: dict[str, Any], n: int = 30
) -> list[dict[str, Any]]:
    """Top-N projects ranked by distinct-firm coverage (desc), then by
    total record count (desc), then by name (asc)."""
    rows: list[tuple[str, int, int]] = []
    for proj, total in stats["project_totals"].items():
        firms = stats["project_firm_counts"].get(proj, 0)
        rows.append((proj, int(firms), int(total)))
    rows.sort(key=lambda r: (-r[1], -r[2], r[0].lower()))
    out: list[dict[str, Any]] = []
    for proj, firms, total in rows[:n]:
        firm_breakdown = dict(stats["matrix"].get(proj, {}))
        out.append(
            {
                "project": proj,
                "distinct_firms": firms,
                "total_records": total,
                "firms": sorted(firm_breakdown.keys()),
            }
        )
    return out


def render_top_table(stats: dict[str, Any], n: int = 30) -> str:
    rows = top_n_projects(stats, n=n)
    headers = ["#", "project", "firms", "records", "firm_set"]
    out_rows: list[list[str]] = []
    for i, row in enumerate(rows, start=1):
        out_rows.append(
            [
                str(i),
                row["project"][:64],
                str(row["distinct_firms"]),
                str(row["total_records"]),
                ", ".join(row["firms"]),
            ]
        )
    widths = [len(h) for h in headers]
    for row in out_rows:
        for i, cell in enumerate(row):
            if len(cell) > widths[i]:
                widths[i] = len(cell)

    def fmt(cells: list[str]) -> str:
        return " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells))

    sep = "-+-".join("-" * w for w in widths)
    lines = [fmt(headers), sep]
    lines.extend(fmt(r) for r in out_rows)
    return "\n".join(lines)


def render_human(stats: dict[str, Any], top_n: int = 30) -> str:
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    out: list[str] = []
    out.append(
        f"# Hackerman audit-firm coverage matrix ({today})"
    )
    out.append("")
    out.append(f"- tags_dir: {stats['tags_dir']}")
    out.append(f"- subtree: {stats['subtree']}")
    out.append(f"- total_records: {stats['total_records']}")
    out.append(f"- total_projects: {stats['total_projects']}")
    out.append(f"- total_firms: {stats['total_firms']}")
    b3 = len(stats["coverage_buckets"]["3plus_firm"])
    b2 = len(stats["coverage_buckets"]["2_firm"])
    b1 = len(stats["coverage_buckets"]["1_firm"])
    out.append(f"- 3plus_firm_projects: {b3}")
    out.append(f"- 2_firm_projects: {b2}")
    out.append(f"- 1_firm_projects: {b1}")
    out.append("")
    out.append(
        "## Per-firm totals (records per firm under "
        "audit_firm_public_reports)"
    )
    out.append("")
    for firm, n in sorted(
        stats["firm_totals"].items(),
        key=lambda kv: (-kv[1], kv[0]),
    ):
        out.append(f"- `{firm}`: {n}")
    out.append("")
    out.append(
        f"## Top-{top_n} projects by distinct-firm coverage"
    )
    out.append("")
    out.append("```")
    out.append(render_top_table(stats, n=top_n))
    out.append("```")
    out.append("")
    out.append(
        "## 3+-firm projects (high-confidence cross-validation anchors)"
    )
    out.append("")
    if not stats["coverage_buckets"]["3plus_firm"]:
        out.append("- (none)")
    else:
        for proj in stats["coverage_buckets"]["3plus_firm"]:
            firms = sorted(stats["matrix"].get(proj, {}).keys())
            out.append(
                f"- `{proj}` ({len(firms)} firms): "
                + ", ".join(firms)
            )
    out.append("")
    out.append(
        "## 1-firm-only projects "
        "(lower-confidence; potential audit-firm-bias)"
    )
    out.append("")
    one = stats["coverage_buckets"]["1_firm"]
    if not one:
        out.append("- (none)")
    else:
        out.append(
            f"_{len(one)} projects covered by exactly 1 firm. "
            "Cross-validation requires a sibling-firm scan; "
            "patterns extracted here are weighted lower in "
            "Wave-2/3 detector promotion._"
        )
        out.append("")
        # Compress: just list, one per line, no firm column needed.
        for proj in one:
            firms = list(stats["matrix"].get(proj, {}).keys())
            firm = firms[0] if firms else "?"
            out.append(f"- `{proj}` ({firm})")
    out.append("")
    return "\n".join(out)


def render_json(stats: dict[str, Any], top_n: int = 30) -> str:
    payload = {
        "schema": SCHEMA,
        "tags_dir": stats["tags_dir"],
        "subtree": stats["subtree"],
        "total_records": stats["total_records"],
        "total_projects": stats["total_projects"],
        "total_firms": stats["total_firms"],
        "firms": stats["firms"],
        "firm_totals": stats["firm_totals"],
        "project_totals": stats["project_totals"],
        "project_firm_counts": stats["project_firm_counts"],
        "matrix": stats["matrix"],
        "coverage_buckets": stats["coverage_buckets"],
        "top_projects": top_n_projects(stats, n=top_n),
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Build the per-firm x per-project coverage matrix from "
            "audit/corpus_tags/tags/audit_firm_public_reports/."
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
        default=30,
        help="N for the top-N-projects table (default 30)",
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
    stats = build_matrix(tags_dir)
    if args.json:
        sys.stdout.write(render_json(stats, top_n=args.top_n))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_human(stats, top_n=args.top_n))
        sys.stdout.write("\n")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(
            render_json(stats, top_n=args.top_n) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
