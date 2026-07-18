#!/usr/bin/env python3
"""Ingest 0xPARC zk-bug-tracker into auditooor farming artifacts.

The 0xPARC zk-bug-tracker is hosted at https://github.com/0xPARC/zk-bug-tracker
and licensed CC-BY-SA 4.0. This tool parses the README.md (or a local clone)
and emits a ZkBugRecord index compatible with the auditooor.zkbugs_index.v2 schema.

Attribution: records sourced from 0xPARC/zk-bug-tracker carry a provenance field
and the output JSON carries a NOTICE block, both required by CC-BY-SA 4.0.

Usage:
    # From the upstream README directly (default):
    python3 tools/zkbugs-0xparc-ingest.py --out audit/zkbugs/0xparc_index.json

    # From a local clone:
    python3 tools/zkbugs-0xparc-ingest.py \\
        --repo-path /path/to/zk-bug-tracker \\
        --out audit/zkbugs/0xparc_index.json

    # Merge with existing zksecurity index:
    python3 tools/zkbugs-0xparc-ingest.py \\
        --merge-with audit/zkbugs/zkbugs_index.json \\
        --out audit/zkbugs/zkbugs_index_unified.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.zkbugs_index.v2"
DEFAULT_README_URL = "https://raw.githubusercontent.com/0xPARC/zk-bug-tracker/main/README.md"
DEFAULT_OUT = Path(__file__).resolve().parents[1] / "audit" / "zkbugs" / "0xparc_index.json"
PROVENANCE = {
    "source": "0xparc/zk-bug-tracker",
    "license": "CC-BY-SA-4.0",
    "attribution_required": True,
}
NOTICE = (
    "Records sourced from https://github.com/0xPARC/zk-bug-tracker under CC-BY-SA-4.0. "
    "Attribution required."
)

# Anchor slug -> DSL heuristic: if the slug contains any of these substrings,
# classify the bug with the corresponding DSL label.
_DSL_SLUG_HINTS: list[tuple[str, str]] = [
    ("circom", "Circom"),
    ("halo2", "Halo2"),
    ("cairo", "Cairo"),
    ("plonk", "Plonk"),
    ("noir", "Noir"),
    ("rust", "Rust"),
    ("bulletproof", "Bulletproofs"),
]

# Keyword -> DSL for content-based classification
_DSL_CONTENT_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bcircom\b", re.IGNORECASE), "Circom"),
    (re.compile(r"\bhalo2\b", re.IGNORECASE), "Halo2"),
    (re.compile(r"\bcairo\b", re.IGNORECASE), "Cairo"),
    (re.compile(r"\bnoir\b", re.IGNORECASE), "Noir"),
    (re.compile(r"\bplonk\b", re.IGNORECASE), "Plonk"),
    (re.compile(r"\bgroth16\b", re.IGNORECASE), "Groth16"),
    (re.compile(r"\bsnark\b", re.IGNORECASE), "ZK-SNARK"),
    (re.compile(r"\bstark\b", re.IGNORECASE), "ZK-STARK"),
]

# Regex to extract GitHub links
_GITHUB_LINK_RE = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)"
    r"/(?:commit|pull|compare|issues)/([A-Za-z0-9._/#-]+)"
)
_MARKDOWN_LINK_RE = re.compile(r"\[([^\]]+)\]\((https?://[^\)]+)\)")

# Section anchor regex: ## <a name="slug">N. Title text</a>
_SECTION_ANCHOR_RE = re.compile(
    r'^##\s+<a\s+name="([^"]+)">(?:\d+\.\s+)?(.+?)</a>',
    re.IGNORECASE,
)

# Bugs-in-the-wild boundary markers
_BUGS_WILD_ANCHOR = "bugs-in-the-wild-header"
_COMMON_VULN_ANCHOR = "common-vulnerabilities-header"

# Related Vulnerabilities line
_RELATED_VULN_RE = re.compile(r"Related Vulnerabilities:\s*(.+)", re.IGNORECASE)

# Identified By line
_IDENTIFIED_BY_RE = re.compile(r"Identified By:\s*(.+)", re.IGNORECASE)

# Severity line (common-vulnerabilities section)
_SEVERITY_RE = re.compile(r"\*{0,2}Severity\*{0,2}[:\s]+([^\n]+)", re.IGNORECASE)

# Markdown table row: | cell | cell | ...
_TABLE_ROW_RE = re.compile(r"^\s*\|(.+)\|\s*$")

# Separator row: | --- | :---: | ...
_TABLE_SEP_RE = re.compile(r"^\s*\|[\s|:-]+\|\s*$")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ZkBugRecord:
    """Schema-v2 compatible record. Fields that 0xPARC summaries don't carry are empty."""

    title: str
    bug_id: str
    rel_path: str
    dsl: str
    vulnerability: str
    project: str
    commit: str
    fix_commit: str
    reproduced: bool
    location_path: str
    location_function: str
    source_links: list[str]
    source_ids: list[str]
    short_vulnerability: str
    short_exploit: str
    proposed_mitigation: str
    template_name: str
    signal_names: list[str]
    component_names: list[str]
    library_handle: str
    # Provenance: required by CC-BY-SA 4.0
    provenance: dict[str, Any]
    # Optional cross-reference from merge de-duplication
    cross_ref: str = ""


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:80] or "zkbug"


def _bug_id(framework_slug: str, title: str) -> str:
    h = hashlib.sha256(title.encode()).hexdigest()[:8]
    return f"0xparc-{_slug(framework_slug)}-{h}"


def _classify_dsl(slug: str, body: str) -> str:
    """Heuristic DSL classification from section anchor slug + body text."""
    slug_lower = slug.lower()
    for hint, label in _DSL_SLUG_HINTS:
        if hint in slug_lower:
            return label
    for pattern, label in _DSL_CONTENT_HINTS:
        if pattern.search(body):
            return label
    return "ZK (general)"


def _extract_links(body: str) -> list[str]:
    """Return all markdown-linked URLs in section body."""
    return list(dict.fromkeys(url for _, url in _MARKDOWN_LINK_RE.findall(body)))


def _extract_commit(links: list[str]) -> str:
    """Extract the first 40-char commit SHA from GitHub links, if present."""
    for link in links:
        m = re.search(r"/commit/([0-9a-f]{40})", link)
        if m:
            return m.group(1)
    return ""


def _extract_fix_commit(body: str) -> str:
    """Extract commit SHA from lines that mention 'fix' near a GitHub commit URL."""
    fix_link_re = re.compile(
        r"[Ff]ix[^\n]*https://github\.com/[^\s]+/commit/([0-9a-f]{7,40})"
    )
    m = fix_link_re.search(body)
    if m:
        return m.group(1)
    # Fallback: look for 'Commit of the Fix' link
    cof_re = re.compile(
        r"Commit of the Fix[^\n]*https://github\.com/[^\s]+/commit/([0-9a-f]{7,40})",
        re.IGNORECASE,
    )
    m = cof_re.search(body)
    if m:
        return m.group(1)
    return ""


def _extract_project(links: list[str], body: str) -> str:
    """Return first GitHub repo URL (org/repo) mentioned in the section."""
    for link in links:
        m = re.match(r"(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", link)
        if m:
            return m.group(1)
    return ""


def _extract_vulnerability(body: str) -> str:
    """Extract primary vulnerability type from 'Related Vulnerabilities' line."""
    m = _RELATED_VULN_RE.search(body)
    if not m:
        return ""
    raw = m.group(1)
    # Take the first listed vulnerability (before any comma)
    first = re.split(r",\s*\d+\.", raw)[0]
    # Strip leading "1. " numbering
    first = re.sub(r"^\d+\.\s*", "", first).strip()
    return first


def _extract_summary_paragraph(body: str) -> str:
    """Extract the first substantive paragraph after **Summary** as short_vulnerability."""
    # Find **Summary** block
    summary_start = re.search(r"\*{1,2}Summary\*{1,2}", body)
    if not summary_start:
        # Use first non-empty, non-header line
        for line in body.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("**"):
                return line[:400]
        return ""
    after = body[summary_start.end():]
    # Collect lines until the next bold header or empty-blank-blank
    paragraphs: list[str] = []
    blank_count = 0
    for line in after.split("\n"):
        stripped = line.strip()
        if not stripped:
            blank_count += 1
            if blank_count >= 2 and paragraphs:
                break
            continue
        if stripped.startswith("**") and stripped.endswith("**") and len(stripped) < 60:
            # Section header like **Background**
            if paragraphs:
                break
            continue
        blank_count = 0
        paragraphs.append(stripped)
    text = " ".join(paragraphs)
    # Strip "Related Vulnerabilities:" and "Identified By:" prefix lines
    text = _RELATED_VULN_RE.sub("", text)
    text = _IDENTIFIED_BY_RE.sub("", text)
    return text.strip()[:400]


def _library_handle(project_url: str, title: str) -> str:
    """Derive a short library handle from the project URL or title."""
    if project_url:
        parts = project_url.rstrip("/").split("/")
        if len(parts) >= 2:
            return parts[-1]
    # Fall back to first word of title
    words = re.split(r"[\s:]+", title)
    return words[0] if words else ""


# ---------------------------------------------------------------------------
# Markdown table parsing (for future-format support)
# ---------------------------------------------------------------------------

def _parse_markdown_tables(section_body: str) -> list[dict[str, str]]:
    """Parse any markdown tables in section_body.

    Returns a list of dicts keyed by column header.  Heuristic column
    normalization maps common header variants to canonical keys:
    'Bug' / 'Bug Title' / 'Title' -> 'title'
    'Project' -> 'project'
    'Type' / 'Bug Type' / 'Vulnerability' -> 'vulnerability'
    'Severity' -> 'severity'
    'Source' / 'Link' -> 'link'
    'Description' -> 'description'
    """
    _COL_MAP: dict[str, str] = {
        "bug": "title",
        "bug title": "title",
        "title": "title",
        "project": "project",
        "type": "vulnerability",
        "bug type": "vulnerability",
        "vulnerability": "vulnerability",
        "severity": "severity",
        "source": "link",
        "link": "link",
        "description": "description",
    }

    rows: list[dict[str, str]] = []
    lines = section_body.split("\n")
    headers: list[str] = []
    in_table = False

    for line in lines:
        m = _TABLE_ROW_RE.match(line)
        if not m:
            if in_table:
                in_table = False
                headers = []
            continue

        cells = [c.strip() for c in m.group(1).split("|")]

        if _TABLE_SEP_RE.match(line):
            continue

        if not headers:
            # This is a header row
            headers = [_COL_MAP.get(c.lower(), c.lower()) for c in cells]
            in_table = True
            continue

        if in_table and len(cells) >= len(headers):
            row = {headers[i]: cells[i] for i in range(len(headers))}
            rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Section-based parsing (primary format for 0xPARC README)
# ---------------------------------------------------------------------------

def _parse_bug_sections(content: str) -> Iterator[tuple[str, str, str]]:
    """Yield (anchor_slug, title, body) for each bug-in-the-wild section.

    Stops at the Common Vulnerabilities header so we don't ingest the
    taxonomy descriptions as individual bug records.
    """
    lines = content.split("\n")

    # Find the line indices that bound the bugs-in-the-wild section
    bw_start: int | None = None
    cv_start: int | None = None
    for i, line in enumerate(lines):
        if _BUGS_WILD_ANCHOR in line:
            bw_start = i
        if _COMMON_VULN_ANCHOR in line:
            cv_start = i

    scope_start = bw_start if bw_start is not None else 0
    scope_end = cv_start if cv_start is not None else len(lines)

    # Within scope, yield each ## <a name="..."> section
    current_slug: str | None = None
    current_title: str | None = None
    current_lines: list[str] = []

    for i, line in enumerate(lines):
        if i < scope_start:
            continue
        if i >= scope_end:
            break

        m = _SECTION_ANCHOR_RE.match(line)
        if m:
            if current_slug and current_title is not None:
                yield current_slug, current_title, "\n".join(current_lines)
            current_slug = m.group(1)
            current_title = m.group(2).strip()
            current_lines = []
        elif current_slug is not None:
            current_lines.append(line)

    if current_slug and current_title is not None and current_lines:
        yield current_slug, current_title, "\n".join(current_lines)


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

def _make_record(slug: str, title: str, body: str) -> ZkBugRecord:
    dsl = _classify_dsl(slug, body)
    links = _extract_links(body)
    project = _extract_project(links, body)
    commit = _extract_commit(links)
    fix_commit = _extract_fix_commit(body)
    vulnerability = _extract_vulnerability(body)
    short_vuln = _extract_summary_paragraph(body)
    library = _library_handle(project, title)

    return ZkBugRecord(
        title=title,
        bug_id=_bug_id(slug, title),
        rel_path="",
        dsl=dsl,
        vulnerability=vulnerability or "ZK vulnerability",
        project=project,
        commit=commit,
        fix_commit=fix_commit,
        reproduced=False,
        location_path=links[0] if links else "",
        location_function="",
        source_links=links,
        source_ids=[],
        short_vulnerability=short_vuln,
        short_exploit="",
        proposed_mitigation="",
        template_name="",
        signal_names=[],
        component_names=[],
        library_handle=library,
        provenance=PROVENANCE,
    )


def parse_readme(content: str) -> list[ZkBugRecord]:
    """Parse README content (section-based format) into ZkBugRecord list.

    Also handles any embedded markdown tables inside sections for forward
    compatibility if the 0xPARC format evolves.
    """
    records: list[ZkBugRecord] = []

    for slug, title, body in _parse_bug_sections(content):
        # Primary: create one record per section
        rec = _make_record(slug, title, body)
        records.append(rec)

        # Secondary: if there are sub-tables in the body, parse them too.
        # These would add additional rows beyond the section header record.
        # Currently the 0xPARC format does not use sub-tables in bug sections
        # so this loop is effectively a no-op, but is wired in for future-proofing.
        table_rows = _parse_markdown_tables(body)
        for row in table_rows:
            sub_title = row.get("title") or row.get("description") or ""
            if not sub_title or sub_title.lower() == title.lower():
                continue
            sub_link = row.get("link") or ""
            sub_links = [sub_link] if sub_link else []
            sub_project = _extract_project(sub_links, sub_title) or project  # noqa: F821
            sub_rec = ZkBugRecord(
                title=sub_title,
                bug_id=_bug_id(slug, sub_title),
                rel_path="",
                dsl=_classify_dsl(slug, sub_title),
                vulnerability=row.get("vulnerability") or rec.vulnerability,
                project=sub_project,
                commit="",
                fix_commit="",
                reproduced=False,
                location_path=sub_link,
                location_function="",
                source_links=sub_links,
                source_ids=[],
                short_vulnerability=row.get("description", "")[:400],
                short_exploit="",
                proposed_mitigation="",
                template_name="",
                signal_names=[],
                component_names=[],
                library_handle=_library_handle(sub_project, sub_title),
                provenance=PROVENANCE,
            )
            records.append(sub_rec)

    return records


# ---------------------------------------------------------------------------
# Summarize
# ---------------------------------------------------------------------------

def summarize(records: list[ZkBugRecord]) -> dict[str, Any]:
    by_dsl: dict[str, int] = {}
    by_vulnerability: dict[str, int] = {}
    for rec in records:
        k = rec.dsl or "unknown"
        by_dsl[k] = by_dsl.get(k, 0) + 1
        v = rec.vulnerability or "unknown"
        by_vulnerability[v] = by_vulnerability.get(v, 0) + 1
    return {
        "total": len(records),
        "by_dsl": dict(sorted(by_dsl.items())),
        "by_vulnerability": dict(
            sorted(by_vulnerability.items(), key=lambda item: (-item[1], item[0]))
        ),
    }


# ---------------------------------------------------------------------------
# Merge / de-duplication
# ---------------------------------------------------------------------------

def _dedup_key(title: str, project: str) -> str:
    """Normalised key for de-duplication: lowercased (title[:60], repo-name)."""
    repo = project.rstrip("/").split("/")[-1].lower() if project else ""
    return f"{title.lower()[:60]}__{repo}"


def merge_indices(
    primary_path: Path,
    new_records: list[ZkBugRecord],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Merge new_records into the existing index at primary_path.

    De-duplication: prefer the existing (primary) record when
    (project, title) lower-cased substring matches. Record the 0xPARC
    link as cross_ref on the surviving primary record.

    Returns (merged_records_as_dicts, list_of_source_labels).
    """
    primary_data = json.loads(primary_path.read_text(encoding="utf-8"))
    primary_records: list[dict[str, Any]] = primary_data.get("records", [])
    primary_sources = primary_data.get("source", "unknown")
    if isinstance(primary_sources, str):
        primary_sources = [primary_sources]

    # Build dedup index from primary
    seen: dict[str, int] = {}  # dedup_key -> index in primary_records
    for i, rec in enumerate(primary_records):
        dk = _dedup_key(
            rec.get("title", ""),
            rec.get("project", ""),
        )
        seen[dk] = i

    merged = list(primary_records)
    for rec in new_records:
        dk = _dedup_key(rec.title, rec.project)
        if dk in seen:
            # Collision: annotate existing record with 0xPARC cross-ref
            idx = seen[dk]
            existing = dict(merged[idx])
            existing_refs: list[str] = existing.get("cross_refs_0xparc", [])
            for link in rec.source_links:
                if link not in existing_refs:
                    existing_refs.append(link)
            existing["cross_refs_0xparc"] = existing_refs
            merged[idx] = existing
        else:
            merged.append(asdict(rec))
            seen[dk] = len(merged) - 1

    sources = list(
        dict.fromkeys(primary_sources + [PROVENANCE["source"]])
    )
    return merged, sources


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------

def _read_readme(*, readme_url: str, repo_path: Path | None) -> str:
    if repo_path is not None:
        candidates = [
            repo_path / "README.md",
            repo_path / "readme.md",
        ]
        for p in candidates:
            if p.is_file():
                return p.read_text(encoding="utf-8")
        raise FileNotFoundError(
            f"README.md not found under {repo_path}. "
            "Expected one of: README.md, readme.md"
        )
    # Fetch from URL
    with urllib.request.urlopen(readme_url) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def build_output(
    records: list[ZkBugRecord],
    *,
    source: str | list[str] = PROVENANCE["source"],
) -> dict[str, Any]:
    return {
        "NOTICE": NOTICE,
        "schema": SCHEMA,
        "source": source,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summarize(records),
        "records": [asdict(r) for r in records],
    }


def build_merged_output(
    merged_records: list[dict[str, Any]],
    *,
    sources: list[str],
) -> dict[str, Any]:
    # Reconstruct summary from raw dicts
    by_dsl: dict[str, int] = {}
    by_vulnerability: dict[str, int] = {}
    for rec in merged_records:
        k = rec.get("dsl") or "unknown"
        by_dsl[k] = by_dsl.get(k, 0) + 1
        v = rec.get("vulnerability") or "unknown"
        by_vulnerability[v] = by_vulnerability.get(v, 0) + 1
    summary = {
        "total": len(merged_records),
        "by_dsl": dict(sorted(by_dsl.items())),
        "by_vulnerability": dict(
            sorted(by_vulnerability.items(), key=lambda item: (-item[1], item[0]))
        ),
    }
    return {
        "NOTICE": NOTICE,
        "schema": SCHEMA,
        "source": sources,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "records": merged_records,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--readme-url",
        default=DEFAULT_README_URL,
        help="Raw GitHub URL for the 0xPARC README (default: %(default)s)",
    )
    parser.add_argument(
        "--repo-path",
        type=Path,
        default=None,
        help="Local path to a clone of 0xPARC/zk-bug-tracker (overrides --readme-url)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output JSON file path (default: %(default)s)",
    )
    parser.add_argument(
        "--merge-with",
        type=Path,
        default=None,
        metavar="EXISTING_INDEX",
        help=(
            "If provided, merge 0xPARC records with the existing index at this path. "
            "De-duplicates by (project, title) lower-cased substring match; "
            "prefers existing records but annotates them with 0xPARC cross-refs."
        ),
    )
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="Print a JSON summary to stdout after writing the output file",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)

    try:
        content = _read_readme(readme_url=args.readme_url, repo_path=args.repo_path)
    except Exception as exc:
        print(f"ERROR: could not read source: {exc}", file=sys.stderr)
        return 1

    records = parse_readme(content)

    out_path: Path = args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.merge_with is not None:
        if not args.merge_with.is_file():
            print(f"ERROR: --merge-with path not found: {args.merge_with}", file=sys.stderr)
            return 1
        merged_records, sources = merge_indices(args.merge_with, records)
        payload = build_merged_output(merged_records, sources=sources)
    else:
        payload = build_output(records)

    out_path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")

    if args.print_summary:
        print(json.dumps({"summary": payload["summary"]}, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
