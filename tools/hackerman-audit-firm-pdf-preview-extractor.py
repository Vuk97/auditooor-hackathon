#!/usr/bin/env python3
"""hackerman-audit-firm-pdf-preview-extractor (PREVIEW ONLY).

Walk the Hackerman audit-firm-public-reports corpus subtree under
``audit/corpus_tags/tags/audit_firm_public_reports/<slug>/record.{json,yaml}``
and emit a *preview* JSONL of structured metadata extracted from each
listing-only record. The metadata fields surfaced per record:

  - ``slug``: directory name on disk
  - ``firm``: inferred from the path slug (e.g. ``chainsecurity-audits``,
    ``cyfrin-audit-reports``, ``spearbit-portfolio``)
  - ``project_name``: inferred from filename (preferring the
    ``Inferred project name`` value already present in the record's
    ``required_preconditions`` list, with a filename fallback)
  - ``date``: ``YYYY-MM-DD`` if a full date prefix is in the filename;
    otherwise ``YYYY`` if the record stores a ``year`` field;
    otherwise ``unknown``
  - ``year``: integer year (or ``null``)
  - ``pdf_url``: raw GitHub URL pulled from the
    ``required_preconditions`` entry that begins with ``Reference public
    audit report at``
  - ``file_ext``: ``pdf`` / ``md`` / ``txt`` / ``unknown`` from the URL
  - ``record_path``: relative path of the source record file

This is Wave-1.5 PREVIEW only. The tool does **NOT** fetch any PDF
bytes, does **NOT** parse PDF binary content, and does **NOT** modify
``Makefile``, ``tools/audit-deep-runner.py``, or anything that wires
into ``make audit``. The downstream heavyweight PDF deep-mining lane
will consume the JSONL artifact as input.

Output artifacts:

  - ``.auditooor/audit_firm_pdf_preview.jsonl`` (gitignored)
  - ``docs/HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md`` (committed)

The markdown surfaces:

  - Top firms by record count (descending).
  - Top projects by repeat-audit-coverage (same inferred project name
    appearing across >=2 distinct firms; cross-firm coverage signals
    high-value targets).
  - Year-distribution histogram.
  - Records-with-unknown-date count (data-quality signal).

Usage:

    # Preview run (writes JSONL + markdown)
    python3 tools/hackerman-audit-firm-pdf-preview-extractor.py

    # Dry-run (computes preview, prints summary, writes nothing)
    python3 tools/hackerman-audit-firm-pdf-preview-extractor.py --dry-run

    # Limit how many top firms / projects appear in the markdown
    python3 tools/hackerman-audit-firm-pdf-preview-extractor.py \
        --top-firms 20 --top-projects 30

Exit codes:

    0 - preview generated (or dry-run completed)
    2 - corpus tree missing / unreadable / no records found
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "auditooor.hackerman_audit_firm_pdf_preview_extractor.v1"

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = (
    REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags" / "audit_firm_public_reports"
)
DEFAULT_OUTPUT_JSONL = (
    REPO_ROOT_GUESS / ".auditooor" / "audit_firm_pdf_preview.jsonl"
)
DEFAULT_DOCS_PATH = (
    REPO_ROOT_GUESS / "docs" / "HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md"
)

# Full date prefix: 2023-03-07-<rest>
RE_FULL_DATE_PREFIX = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[-_]")
# Year-month prefix: 2022-10-<rest>
RE_YEARMONTH_PREFIX = re.compile(r"^(\d{4})-(\d{2})(?:[-_]|$)")
# Year-only prefix: 2017
RE_YEAR_PREFIX = re.compile(r"^(\d{4})(?:[-_]|$)")

RE_REFERENCE_LINE = re.compile(
    r"^Reference public audit report at\s+(\S+)\s*$"
)
RE_INFERRED_PROJECT = re.compile(
    r"^Inferred project name\s+(.+?)\s*$"
)
RE_SOURCE_PATH = re.compile(
    r"^Source path\s+(.+?)\s*$"
)


# ---------------------------------------------------------------------------
# Minimal YAML loader (avoids hard PyYAML dep; corpus YAML is shape-restricted)
# ---------------------------------------------------------------------------
def _yaml_load(text: str) -> Dict[str, Any]:
    """Parse the restricted subset of YAML used by Hackerman corpus records.

    Supports:
      * top-level ``key: value`` scalars (string / int / float / bool / null)
      * top-level ``key:`` followed by a block list of ``- item`` lines
      * one level of nested mapping via two-space indent (used by
        ``function_shape:``)

    Not a generic YAML parser; intentionally narrow.
    """
    out: Dict[str, Any] = {}
    lines = text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        if not raw.startswith(" "):
            if ":" not in raw:
                i += 1
                continue
            key, _, rest = raw.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                # block list OR nested mapping coming up
                block_items: List[Any] = []
                nested: Dict[str, Any] = {}
                j = i + 1
                while j < n:
                    nxt = lines[j]
                    if not nxt.strip():
                        j += 1
                        continue
                    if not nxt.startswith(" "):
                        break
                    s = nxt.lstrip()
                    if s.startswith("- "):
                        item_val = s[2:].strip()
                        block_items.append(_coerce_scalar(item_val))
                    elif ":" in s:
                        nkey, _, nrest = s.partition(":")
                        nkey = nkey.strip()
                        nrest = nrest.strip()
                        if nrest == "":
                            # second-level block list (e.g. shape_tags)
                            sub_items: List[Any] = []
                            k = j + 1
                            while k < n:
                                nxt2 = lines[k]
                                if not nxt2.strip():
                                    k += 1
                                    continue
                                if not nxt2.startswith("    "):
                                    break
                                s2 = nxt2.lstrip()
                                if s2.startswith("- "):
                                    sub_items.append(_coerce_scalar(s2[2:].strip()))
                                else:
                                    break
                                k += 1
                            nested[nkey] = sub_items
                            j = k
                            continue
                        else:
                            nested[nkey] = _coerce_scalar(nrest)
                    j += 1
                if block_items and not nested:
                    out[key] = block_items
                elif nested and not block_items:
                    out[key] = nested
                else:
                    out[key] = block_items or nested
                i = j
                continue
            else:
                out[key] = _coerce_scalar(rest)
                i += 1
                continue
        i += 1
    return out


def _coerce_scalar(raw: str) -> Any:
    """Coerce YAML scalar to python type (string / int / float / bool / None)."""
    if raw == "" or raw.lower() == "null" or raw == "~":
        return None
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    # strip wrapping quotes
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    try:
        if "." in raw:
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


# ---------------------------------------------------------------------------
# Record loading
# ---------------------------------------------------------------------------
def _load_record(record_dir: Path) -> Optional[Dict[str, Any]]:
    """Load a record bundle. YAML preferred over JSON when both present."""
    yaml_path = record_dir / "record.yaml"
    json_path = record_dir / "record.json"
    if yaml_path.is_file():
        try:
            return _yaml_load(yaml_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    if json_path.is_file():
        try:
            return json.loads(json_path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


# ---------------------------------------------------------------------------
# Field extraction
# ---------------------------------------------------------------------------
def _extract_firm(slug: str) -> str:
    """Slug format: ``<firm>__<rest>``; firm is the prefix before ``__``."""
    if "__" in slug:
        return slug.split("__", 1)[0]
    return slug


def _extract_pdf_url(preconds: List[Any]) -> Optional[str]:
    for line in preconds or []:
        if not isinstance(line, str):
            continue
        m = RE_REFERENCE_LINE.match(line)
        if m:
            return m.group(1)
    return None


def _extract_source_path(preconds: List[Any]) -> Optional[str]:
    for line in preconds or []:
        if not isinstance(line, str):
            continue
        m = RE_SOURCE_PATH.match(line)
        if m:
            return m.group(1)
    return None


def _extract_inferred_project(preconds: List[Any]) -> Optional[str]:
    for line in preconds or []:
        if not isinstance(line, str):
            continue
        m = RE_INFERRED_PROJECT.match(line)
        if m:
            return m.group(1)
    return None


def _file_ext_from_url(url: Optional[str]) -> str:
    if not url:
        return "unknown"
    tail = url.rsplit(".", 1)
    if len(tail) != 2:
        return "unknown"
    ext = tail[1].lower()
    if "/" in ext or "?" in ext:
        return "unknown"
    if ext in ("pdf", "md", "txt", "html"):
        return ext
    return "unknown"


def _extract_date(filename_stem: str, year_field: Optional[int]) -> Tuple[str, Optional[int]]:
    """Return (date_string, year_int).

    Preference order:
      1. Full ``YYYY-MM-DD`` prefix in filename.
      2. ``YYYY-MM`` prefix in filename -> ``YYYY-MM-01`` (synthetic
         day, but date_string keeps original ``YYYY-MM`` form).
      3. ``YYYY`` prefix in filename.
      4. ``year`` field on the record.
      5. ``"unknown"`` / None.
    """
    m_full = RE_FULL_DATE_PREFIX.match(filename_stem)
    if m_full:
        y, mo, d = m_full.group(1), m_full.group(2), m_full.group(3)
        return f"{y}-{mo}-{d}", int(y)
    m_ym = RE_YEARMONTH_PREFIX.match(filename_stem)
    if m_ym:
        y, mo = m_ym.group(1), m_ym.group(2)
        return f"{y}-{mo}", int(y)
    m_y = RE_YEAR_PREFIX.match(filename_stem)
    if m_y:
        return m_y.group(1), int(m_y.group(1))
    if isinstance(year_field, int) and year_field > 1900:
        return str(year_field), year_field
    return "unknown", None


def _project_from_filename(source_path: Optional[str]) -> Optional[str]:
    """Derive a fallback project label from the report filename.

    Strips leading ``reports/`` / directory prefix, the file extension,
    and any ``YYYY-MM-DD-`` / ``YYYY-MM-`` / ``YYYY-`` date prefix.
    """
    if not source_path:
        return None
    base = source_path.rsplit("/", 1)[-1]
    if "." in base:
        base = base.rsplit(".", 1)[0]
    base = RE_FULL_DATE_PREFIX.sub("", base)
    base = RE_YEARMONTH_PREFIX.sub("", base)
    base = RE_YEAR_PREFIX.sub("", base)
    base = base.strip(" -_")
    return base or None


def _normalize_project_for_coverage(name: Optional[str]) -> Optional[str]:
    """Normalize a project label for cross-firm coverage matching.

    Lowercase, strip punctuation -> spaces, collapse whitespace. Returns
    ``None`` for empty / one-character / pure-digit / clearly-noisy
    inputs (the corpus has 'unknown' / single-digit project labels for
    OpenZeppelin-style date-only filenames).
    """
    if not name:
        return None
    s = name.lower()
    s = re.sub(r"[^a-z0-9]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        return None
    if s.isdigit():
        return None
    if len(s) < 3:
        return None
    if s in ("unknown", "report", "audit", "final", "draft"):
        return None
    return s


# ---------------------------------------------------------------------------
# Main extraction
# ---------------------------------------------------------------------------
def extract_preview(tags_dir: Path) -> List[Dict[str, Any]]:
    """Walk the tags dir and return a list of preview records."""
    if not tags_dir.is_dir():
        return []
    out: List[Dict[str, Any]] = []
    for child in sorted(tags_dir.iterdir()):
        if not child.is_dir():
            continue
        rec = _load_record(child)
        if not rec:
            continue
        slug = child.name
        firm = _extract_firm(slug)
        preconds = rec.get("required_preconditions") or []
        if not isinstance(preconds, list):
            preconds = []
        pdf_url = _extract_pdf_url(preconds)
        source_path = _extract_source_path(preconds)
        inferred_project = _extract_inferred_project(preconds)
        filename_stem = ""
        if source_path:
            base = source_path.rsplit("/", 1)[-1]
            if "." in base:
                filename_stem = base.rsplit(".", 1)[0]
            else:
                filename_stem = base
        year_field = rec.get("year")
        try:
            year_field = int(year_field) if year_field is not None else None
        except (TypeError, ValueError):
            year_field = None
        date_str, year_int = _extract_date(filename_stem, year_field)
        project_name = inferred_project or _project_from_filename(source_path) or "unknown"
        ext = _file_ext_from_url(pdf_url)
        try:
            rel_record_path = str(
                (child / "record.json").relative_to(REPO_ROOT_GUESS)
            )
        except ValueError:
            rel_record_path = str(child / "record.json")
        out.append(
            {
                "schema": SCHEMA,
                "slug": slug,
                "firm": firm,
                "project_name": project_name,
                "project_name_normalized": _normalize_project_for_coverage(project_name),
                "date": date_str,
                "year": year_int,
                "pdf_url": pdf_url,
                "file_ext": ext,
                "source_path": source_path,
                "record_path": rel_record_path,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Aggregations
# ---------------------------------------------------------------------------
def firm_counts(records: List[Dict[str, Any]]) -> List[Tuple[str, int]]:
    c: Counter = Counter()
    for r in records:
        c[r["firm"]] += 1
    return c.most_common()


def year_distribution(records: List[Dict[str, Any]]) -> List[Tuple[Any, int]]:
    c: Counter = Counter()
    for r in records:
        y = r.get("year")
        c[y if y is not None else "unknown"] += 1
    items = list(c.items())
    items.sort(key=lambda kv: (isinstance(kv[0], str), kv[0]))
    return items


def cross_firm_projects(records: List[Dict[str, Any]]) -> List[Tuple[str, int, List[str]]]:
    """Project labels appearing under >=2 distinct firms.

    Returns ``[(normalized_name, firm_count, [firms_sorted])]`` sorted
    by firm_count desc then alphabetical.
    """
    by_proj: Dict[str, set] = defaultdict(set)
    for r in records:
        norm = r.get("project_name_normalized")
        if not norm:
            continue
        by_proj[norm].add(r["firm"])
    multi = [
        (proj, len(firms), sorted(firms))
        for proj, firms in by_proj.items()
        if len(firms) >= 2
    ]
    multi.sort(key=lambda t: (-t[1], t[0]))
    return multi


def unknown_date_count(records: List[Dict[str, Any]]) -> int:
    return sum(1 for r in records if r.get("date") == "unknown")


# ---------------------------------------------------------------------------
# Output rendering
# ---------------------------------------------------------------------------
def render_markdown(
    records: List[Dict[str, Any]],
    top_firms: int,
    top_projects: int,
    generated_at_iso: str,
    jsonl_relpath: str,
) -> str:
    firms = firm_counts(records)
    years = year_distribution(records)
    cross = cross_firm_projects(records)
    unknown_dates = unknown_date_count(records)
    total = len(records)

    lines: List[str] = []
    lines.append("# Hackerman Audit-Firm PDF Preview (operator-review only)")
    lines.append("")
    lines.append("- Generated by: `tools/hackerman-audit-firm-pdf-preview-extractor.py`")
    lines.append(f"- Generated at: {generated_at_iso}")
    lines.append(f"- Schema: `{SCHEMA}`")
    lines.append(f"- JSONL preview artifact: `{jsonl_relpath}` (gitignored)")
    lines.append("- Operator hard rule: metadata-only; PDF binary content NOT fetched or parsed.")
    lines.append("")
    lines.append("> STATUS: PREVIEW. This artifact does NOT feed `make audit` or")
    lines.append("> `tools/audit-deep-runner.py`. Heavyweight PDF deep-mining is")
    lines.append("> queued as a separate downstream lane.")
    lines.append("")
    lines.append("## Scan stats")
    lines.append("")
    lines.append(f"- Records scanned: **{total}**")
    lines.append(f"- Distinct firms: **{len(firms)}**")
    lines.append(f"- Records with unknown date: **{unknown_dates}**")
    lines.append(
        f"- Cross-firm-coverage projects (>=2 firms): **{len(cross)}**"
    )
    lines.append("")

    lines.append(f"## Top {min(top_firms, len(firms))} firms by record count")
    lines.append("")
    lines.append("| Rank | Firm | Records |")
    lines.append("|------|------|---------|")
    for i, (firm, n) in enumerate(firms[:top_firms], 1):
        lines.append(f"| {i} | `{firm}` | {n} |")
    lines.append("")

    lines.append(f"## Top {min(top_projects, len(cross))} projects by cross-firm coverage")
    lines.append("")
    lines.append("Projects audited by >=2 distinct firms in this corpus. High cross-firm")
    lines.append("coverage is a high-value signal for downstream deep-mining priority.")
    lines.append("")
    lines.append("| Rank | Project (normalized) | Firm count | Firms |")
    lines.append("|------|----------------------|------------|-------|")
    if cross:
        for i, (proj, n_firms, firms_list) in enumerate(cross[:top_projects], 1):
            firms_str = ", ".join(f"`{f}`" for f in firms_list)
            lines.append(f"| {i} | `{proj}` | {n_firms} | {firms_str} |")
    else:
        lines.append("| _none_ | _no cross-firm coverage detected_ | 0 | _-_ |")
    lines.append("")

    lines.append("## Year distribution")
    lines.append("")
    lines.append("| Year | Records |")
    lines.append("|------|---------|")
    for y, n in years:
        lines.append(f"| {y} | {n} |")
    lines.append("")

    lines.append("## Downstream consumption notes")
    lines.append("")
    lines.append("- The JSONL artifact is one line per record, schema-tagged.")
    lines.append("- The downstream PDF deep-mining lane will fetch and parse the")
    lines.append("  `pdf_url` field; this preview tool intentionally does NOT do that.")
    lines.append("- Records with `date == \"unknown\"` are filename-only and may need")
    lines.append("  manual year backfill once the PDF body is parsed.")
    lines.append("")
    return "\n".join(lines)


def write_outputs(
    records: List[Dict[str, Any]],
    jsonl_path: Path,
    docs_path: Path,
    top_firms: int,
    top_projects: int,
) -> None:
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        jsonl_relpath = str(jsonl_path.relative_to(REPO_ROOT_GUESS))
    except ValueError:
        jsonl_relpath = str(jsonl_path)
    docs_path.parent.mkdir(parents=True, exist_ok=True)
    docs_path.write_text(
        render_markdown(records, top_firms, top_projects, generated_at, jsonl_relpath),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Hackerman audit-firm-public-reports PDF metadata PREVIEW extractor. "
            "Walks listing-only records and emits per-record metadata; does NOT "
            "fetch or parse PDF binary content."
        ),
    )
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="audit_firm_public_reports tags dir (default: repo audit/corpus_tags/tags/audit_firm_public_reports)",
    )
    parser.add_argument(
        "--output-jsonl",
        type=Path,
        default=DEFAULT_OUTPUT_JSONL,
        help="output JSONL path (default: .auditooor/audit_firm_pdf_preview.jsonl, gitignored)",
    )
    parser.add_argument(
        "--docs-path",
        type=Path,
        default=DEFAULT_DOCS_PATH,
        help="output markdown path (default: docs/HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md)",
    )
    parser.add_argument("--top-firms", type=int, default=10)
    parser.add_argument("--top-projects", type=int, default=25)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compute the preview and print stats; do not write any output files",
    )
    args = parser.parse_args(argv)

    if not args.tags_dir.is_dir():
        print(
            f"[error] tags dir not found: {args.tags_dir}",
            file=sys.stderr,
        )
        return 2

    records = extract_preview(args.tags_dir)
    if not records:
        print(
            f"[error] no records found under {args.tags_dir}",
            file=sys.stderr,
        )
        return 2

    firms = firm_counts(records)
    cross = cross_firm_projects(records)
    print(f"[preview] records={len(records)} firms={len(firms)} cross_firm_projects={len(cross)}")
    if args.dry_run:
        return 0

    write_outputs(records, args.output_jsonl, args.docs_path, args.top_firms, args.top_projects)
    print(f"[preview] wrote JSONL: {args.output_jsonl}")
    print(f"[preview] wrote docs:  {args.docs_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
