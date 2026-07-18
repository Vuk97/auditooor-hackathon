"""PDF -> structured text helper (W2.4 Phase 1, Trail-of-Bits-first).

Low-level PDF parser used by the W2.4 deep-mine ETL drivers. Phase 1 ships
the ``pypdf`` backend; the spec calls for ``pdfplumber`` long-term but
``pypdf`` is dependency-light, pure-Python, and sufficient for the
Trail-of-Bits NIST-style layouts we target first. The public surface keeps
the spec's ``StructuredPage`` dataclass so a ``pdfplumber`` backend can be
swapped in later without rewriting callers.

Real-source-only (M14-trap discipline):

* No network IO from this module - the driver caches PDFs to disk and
  hands paths to ``extract_structured_pages``.
* Empty / unparseable / encrypted PDFs return ``[]`` with the diagnostic
  surfaced via the ``diagnostics`` field on the returned envelope.
* No silent fallbacks: any backend-level exception is caught and reported
  via ``ExtractionResult.diagnostics``; the caller decides whether to
  reject or retry.
"""
from __future__ import annotations

import dataclasses
import re
import unicodedata
from pathlib import Path
from typing import List, Optional, Sequence


__all__ = [
    "TextBlock",
    "HeadingBlock",
    "TableBlock",
    "StructuredPage",
    "ExtractionResult",
    "extract_structured_pages",
    "PARSER_VERSION",
    "SBSecurityFinding",
    "extract_sb_security_findings",
    "ZellicFinding",
    "extract_zellic_findings",
    "SpearbitFinding",
    "extract_spearbit_findings",
    "OpenZeppelinFinding",
    "extract_openzeppelin_findings",
]


PARSER_VERSION = "auditooor.pdf_finding_extractor.v1"


@dataclasses.dataclass
class TextBlock:
    text: str
    page_index: int
    order: int


@dataclasses.dataclass
class HeadingBlock:
    text: str
    page_index: int
    order: int
    # Best-effort heading-level (1=highest). Inferred from regex shape in
    # the pypdf backend; the future pdfplumber backend will derive this
    # from font-size histograms.
    level: int = 2


@dataclasses.dataclass
class TableBlock:
    rows: List[List[str]]
    page_index: int
    order: int


@dataclasses.dataclass
class StructuredPage:
    page_index: int
    text_blocks: List[TextBlock] = dataclasses.field(default_factory=list)
    tables: List[TableBlock] = dataclasses.field(default_factory=list)
    headings: List[HeadingBlock] = dataclasses.field(default_factory=list)
    raw_text: str = ""
    page_width: float = 0.0
    page_height: float = 0.0

    def all_text(self) -> str:
        return self.raw_text


@dataclasses.dataclass
class ExtractionResult:
    pages: List[StructuredPage]
    diagnostics: List[str] = dataclasses.field(default_factory=list)
    page_count: int = 0
    backend: str = "pypdf"


# Heuristic regexes. Trail of Bits headings look like ``1. Title here``,
# ``12. Title here`` etc. We also match bracketed-ID conventions used by
# Cyfrin / Pashov / OpenZeppelin so a later parser variant can re-use the
# same lines.
_HEADING_PATTERNS = [
    re.compile(r"^\s*(\d+)\.\s+([A-Z][^\n]{2,160})$"),
    re.compile(r"^\s*\[(C|H|M|L|I|G|N)-?\d{1,3}\]\s+([^\n]{2,160})$"),
    re.compile(r"^\s*Issue\s+#?\d+:\s+([^\n]{2,160})$"),
    re.compile(r"^\s*Finding\s+#?\d+:\s+([^\n]{2,160})$"),
]


def _looks_like_heading(line: str) -> bool:
    for pat in _HEADING_PATTERNS:
        if pat.match(line):
            return True
    return False


def _split_into_blocks(raw_text: str, page_index: int) -> tuple[list[TextBlock], list[HeadingBlock]]:
    text_blocks: list[TextBlock] = []
    headings: list[HeadingBlock] = []
    order = 0

    # Split on blank lines into paragraph blocks; treat single-line
    # paragraphs matching heading regex as headings.
    paragraphs = re.split(r"\n\s*\n", raw_text)
    for para in paragraphs:
        stripped = para.strip()
        if not stripped:
            continue
        # If the paragraph is exactly one line and matches a heading
        # regex, classify as heading.
        single_line = stripped if "\n" not in stripped else None
        if single_line is not None and _looks_like_heading(single_line):
            headings.append(
                HeadingBlock(
                    text=single_line,
                    page_index=page_index,
                    order=order,
                    level=2,
                )
            )
        else:
            text_blocks.append(
                TextBlock(
                    text=stripped,
                    page_index=page_index,
                    order=order,
                )
            )
        order += 1
    return text_blocks, headings


def _extract_via_pypdf(pdf_path: Path) -> ExtractionResult:
    try:
        import pypdf  # type: ignore
    except Exception as exc:  # pragma: no cover - import-time failure
        return ExtractionResult(
            pages=[],
            diagnostics=[f"pypdf-import-failed:{exc!r}"],
            page_count=0,
            backend="pypdf",
        )

    try:
        reader = pypdf.PdfReader(str(pdf_path))
    except Exception as exc:
        return ExtractionResult(
            pages=[],
            diagnostics=[f"pypdf-open-failed:{exc!r}"],
            page_count=0,
            backend="pypdf",
        )

    if reader.is_encrypted:
        # Try the empty-password unlock (some PDFs ship encrypted with no
        # password as a publishing quirk).
        try:
            reader.decrypt("")
        except Exception:
            return ExtractionResult(
                pages=[],
                diagnostics=["parse-failed-encrypted"],
                page_count=len(reader.pages),
                backend="pypdf",
            )

    pages: list[StructuredPage] = []
    diagnostics: list[str] = []
    page_count = len(reader.pages)

    for idx, page in enumerate(reader.pages):
        try:
            raw_text = page.extract_text() or ""
        except Exception as exc:
            diagnostics.append(f"page-{idx}-extract-failed:{exc!r}")
            raw_text = ""

        if "(cid:" in raw_text:
            diagnostics.append(f"page-{idx}-cid-encoding-warning")

        text_blocks, headings = _split_into_blocks(raw_text, idx)
        try:
            mediabox = page.mediabox
            width = float(mediabox.width)
            height = float(mediabox.height)
        except Exception:
            width = 0.0
            height = 0.0

        pages.append(
            StructuredPage(
                page_index=idx,
                text_blocks=text_blocks,
                tables=[],
                headings=headings,
                raw_text=raw_text,
                page_width=width,
                page_height=height,
            )
        )

    if pages and not any(p.raw_text.strip() for p in pages):
        diagnostics.append("ocr-required-empty-text-layer")

    return ExtractionResult(
        pages=pages,
        diagnostics=diagnostics,
        page_count=page_count,
        backend="pypdf",
    )


def extract_structured_pages(pdf_path: str | Path) -> ExtractionResult:
    """Parse a PDF on disk into a list of ``StructuredPage`` objects.

    Parameters
    ----------
    pdf_path:
        Path on disk to the cached PDF blob. The caller is responsible
        for fetching / caching; this function never touches the network.

    Returns
    -------
    ExtractionResult
        ``pages`` is empty when the PDF could not be parsed; consult
        ``diagnostics`` for the reason. The empty-pages-with-diagnostic
        return is the contract - callers must not raise on empty result.
    """
    pdf_path = Path(pdf_path)
    if not pdf_path.is_file():
        return ExtractionResult(
            pages=[],
            diagnostics=[f"pdf-not-found:{pdf_path}"],
            page_count=0,
            backend="pypdf",
        )

    return _extract_via_pypdf(pdf_path)


# ---------------------------------------------------------------------------
# Trail-of-Bits-specific finding extractor.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ToBFinding:
    """One Trail-of-Bits-style finding extracted from a PDF."""

    finding_index: int                  # 1-based as it appears in the PDF
    title: str
    severity: str                       # normalised lowercase (critical/high/medium/low/informational/undetermined)
    severity_verbatim: str
    difficulty: str = ""
    finding_type: str = ""
    summary: str = ""
    description: str = ""
    recommendation: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    code_snippet_pre_fix: str = ""
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


_TOB_TITLE_RE = re.compile(r"^\s*(\d{1,3})\.\s+([A-Z][^\n]{2,200})\s*$", re.MULTILINE)
_TOB_SEVERITY_RE = re.compile(r"Severity\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|Undetermined)", re.IGNORECASE)
_TOB_DIFFICULTY_RE = re.compile(r"Difficulty\s*[:\|]\s*(Low|Medium|High|Undetermined|N/?A)", re.IGNORECASE)
_TOB_TYPE_RE = re.compile(r"Type\s*[:\|]\s*([A-Za-z][A-Za-z \-/]{2,60})")
_TOB_RECOMMENDATION_HEADERS = ("Recommendation", "Recommendations", "Short Term", "Long Term")
_TOB_DESCRIPTION_HEADERS = ("Description", "Summary")
_TOB_LINES_CITED_RE = re.compile(r"([A-Za-z0-9_./\-]+\.(?:sol|rs|go|move|cairo|vy|py))(?::|#)L?(\d+)(?:[-L]+(\d+))?")
_SEVERITY_NORMALISE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "undetermined": "undetermined",
}


def _slugify_title(title: str, max_len: int = 40) -> str:
    s = title.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    if len(s) > max_len:
        s = s[:max_len].rstrip("-")
    return s or "untitled"


def _collect_full_text(result: ExtractionResult) -> tuple[str, list[tuple[int, int]]]:
    """Return ``(full_text, page_offsets)`` where ``page_offsets`` is a list
    of ``(start_char, end_char)`` per page index, used by the section
    boundary walk to map an absolute char offset back to a page index.
    """
    parts: list[str] = []
    page_offsets: list[tuple[int, int]] = []
    cursor = 0
    for page in result.pages:
        # Always include trailing newline so page boundaries map cleanly.
        body = page.raw_text or ""
        parts.append(body)
        new_cursor = cursor + len(body) + 1  # +1 for the join newline
        page_offsets.append((cursor, new_cursor))
        cursor = new_cursor
    return "\n".join(parts), page_offsets


def _page_for_offset(offset: int, page_offsets: list[tuple[int, int]]) -> int:
    for idx, (start, end) in enumerate(page_offsets):
        if start <= offset < end:
            return idx
    return max(0, len(page_offsets) - 1)


def _section_after_header(text: str, header_options: tuple[str, ...], stop_headers: tuple[str, ...]) -> str:
    """Extract the paragraph block that appears after a header line.

    Returns "" if no header found. Walks forward until a stop-header or
    blank line followed by what looks like a new section marker.
    """
    lines = text.splitlines()
    start_idx: Optional[int] = None
    for i, line in enumerate(lines):
        stripped = line.strip().rstrip(":")
        if stripped in header_options:
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    for line in lines[start_idx:]:
        stripped = line.strip().rstrip(":")
        if stripped in stop_headers:
            break
        # Stop when we hit the next numbered finding heading.
        if _TOB_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _extract_lines_cited(blob: str) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, int, int]] = set()
    for m in _TOB_LINES_CITED_RE.finditer(blob):
        file_path = m.group(1)
        start = int(m.group(2))
        end_raw = m.group(3)
        end = int(end_raw) if end_raw else start
        if start < 1 or end < start:
            continue
        key = (file_path, start, end)
        if key in seen:
            continue
        seen.add(key)
        out.append({"file": file_path, "line_start": start, "line_end": end})
    return out


def extract_trailofbits_findings(result: ExtractionResult) -> List[ToBFinding]:
    """Trail-of-Bits NIST-style finding extractor.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.1.

    The parser is intentionally robust to ``pypdf``'s sometimes-noisy text
    extraction: empty severities, missing recommendations, and findings
    cut off at the end of the PDF are emitted with ``parser_warnings``
    populated rather than dropped silently.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)

    # Find every candidate finding heading. Capture the absolute char
    # offset so we can carve the body.
    matches = list(_TOB_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[ToBFinding] = []
    for i, m in enumerate(matches):
        finding_index = int(m.group(1))
        title = m.group(2).strip()
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        sev_match = _TOB_SEVERITY_RE.search(body)
        severity_verbatim = sev_match.group(1) if sev_match else ""
        severity = _SEVERITY_NORMALISE.get(severity_verbatim.lower(), "undetermined") if severity_verbatim else "undetermined"

        diff_match = _TOB_DIFFICULTY_RE.search(body)
        difficulty = diff_match.group(1) if diff_match else ""

        type_match = _TOB_TYPE_RE.search(body)
        finding_type = type_match.group(1).strip() if type_match else ""

        description = _section_after_header(body, _TOB_DESCRIPTION_HEADERS, _TOB_RECOMMENDATION_HEADERS)
        recommendation = _section_after_header(body, _TOB_RECOMMENDATION_HEADERS, ("References", "Exploit Scenario"))
        summary = description.split("\n\n", 1)[0] if description else body.strip().split("\n\n", 1)[0]

        lines_cited = _extract_lines_cited(body)

        # Confidence scoring (spec §6.4 condensed for ToB Phase 1).
        confidence = 1.0
        warnings: list[str] = []
        if not severity_verbatim:
            confidence -= 0.3
            warnings.append("missing-severity-field")
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            ToBFinding(
                finding_index=finding_index,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                difficulty=difficulty,
                finding_type=finding_type,
                summary=summary[:2000],
                description=description[:6000],
                recommendation=recommendation[:4000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


def slugify_title(title: str, max_len: int = 40) -> str:
    """Public helper used by the driver to build finding_id slugs."""
    return _slugify_title(title, max_len=max_len)


# ---------------------------------------------------------------------------
# Sherlock-specific finding extractor.
# ---------------------------------------------------------------------------
#
# Sherlock audit reports (sherlock-protocol/sherlock-reports, 260 PDFs)
# follow a contest-result layout with per-finding sections shaped as::
#
#   ## H-1: Title here
#   ## M-2: Another title
#   ## C-3: A critical
#   ## L-4: A low
#
#   Source: <link or repo path>
#   Severity: High
#   Summary: <paragraph>
#   Recommendation: <paragraph>
#   Resolution: <often present, "Fixed" / "Acknowledged" / commit ref>
#
# The first capital letter in the heading ID encodes the severity tier
# (C/H/M/L/I) so we use it as the authoritative source even when the
# `Severity:` body field is missing. This mirrors how Sherlock's HTML
# templating renders the contest pages.
#
# Spec ref: PR-Wave2-B / ``tools/hackerman-etl-from-audit-firm-pdf-sherlock.py``.


@dataclasses.dataclass
class SherlockFinding:
    """One Sherlock-style finding extracted from a PDF."""

    finding_index: int                  # numeric portion of e.g. H-1
    finding_letter: str                 # letter prefix (C/H/M/L/I)
    title: str
    severity: str                       # normalised lowercase
    severity_verbatim: str
    source: str = ""
    summary: str = ""
    description: str = ""
    recommendation: str = ""
    resolution: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


# ``## H-1: Title`` heading. Accept H/M/C/L/I followed by ``-<num>`` plus a
# colon and the title. Allow optional leading ``#`` characters (Sherlock
# renders the level via ``##`` but some PDF extractors lose the markdown
# prefix; we still recognise the bare ``H-1:`` line).
_SHERLOCK_TITLE_RE = re.compile(
    r"^\s*#*\s*([CHMLI])-?(\d{1,3})\s*[:\.]\s+([^\n]{2,300})\s*$",
    re.MULTILINE,
)
_SHERLOCK_SEVERITY_RE = re.compile(
    r"Severity\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info)",
    re.IGNORECASE,
)
_SHERLOCK_SOURCE_RE = re.compile(r"Source\s*[:\|]\s*([^\n]{2,400})", re.IGNORECASE)
_SHERLOCK_SUMMARY_HEADERS = ("Summary", "Description", "Issue")
_SHERLOCK_RECOMMENDATION_HEADERS = ("Recommendation", "Recommendations", "Mitigation", "Fix")
_SHERLOCK_RESOLUTION_HEADERS = ("Resolution", "Status", "Fix Status", "Response")
_SHERLOCK_LETTER_TO_SEVERITY = {
    "C": "critical",
    "H": "high",
    "M": "medium",
    "L": "low",
    "I": "informational",
}


def _section_after_header_any(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """Header walker tolerant of inline values (``Header: value on same line``).

    Sherlock PDFs frequently render labels as ``Summary: <text>`` on a
    single line rather than ``Summary\\n<text>``. Support both shapes and
    stop at any other recognised header or a new finding heading.
    """
    lines = text.splitlines()
    inline_match_re = re.compile(
        r"^\s*(" + "|".join(re.escape(h) for h in header_options) + r")\s*[:\|]\s*(.*)$",
        re.IGNORECASE,
    )
    stop_match_re = re.compile(
        r"^\s*(" + "|".join(re.escape(h) for h in stop_headers) + r")\s*[:\|]?",
        re.IGNORECASE,
    )

    start_idx: Optional[int] = None
    prefix_text = ""
    for i, line in enumerate(lines):
        m = inline_match_re.match(line)
        if m:
            prefix_text = m.group(2).strip()
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    if prefix_text:
        out.append(prefix_text)
    for line in lines[start_idx:]:
        if stop_match_re.match(line):
            break
        if _SHERLOCK_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def extract_sherlock_findings(result: ExtractionResult) -> List[SherlockFinding]:
    """Sherlock contest-report finding extractor.

    The parser is robust to two common ``pypdf`` artefacts:

    * Missing ``Severity:`` body field. The first letter of the heading
      ID (``C/H/M/L/I``) is treated as the authoritative severity tier;
      ``Severity:`` body acts as a verbatim copy when present and as a
      tie-breaker when the heading was mis-OCRed.
    * Inline header-value rendering (``Summary: text`` on one line),
      which the ToB walker does not handle.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)
    matches = list(_SHERLOCK_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[SherlockFinding] = []
    for i, m in enumerate(matches):
        letter = m.group(1).upper()
        finding_index = int(m.group(2))
        title = m.group(3).strip()
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        sev_match = _SHERLOCK_SEVERITY_RE.search(body)
        severity_verbatim = sev_match.group(1) if sev_match else ""
        severity_from_letter = _SHERLOCK_LETTER_TO_SEVERITY.get(letter, "undetermined")
        if severity_verbatim:
            severity = _SEVERITY_NORMALISE.get(severity_verbatim.lower(), severity_from_letter)
        else:
            severity = severity_from_letter

        src_match = _SHERLOCK_SOURCE_RE.search(body)
        source = src_match.group(1).strip() if src_match else ""

        summary = _section_after_header_any(
            body,
            _SHERLOCK_SUMMARY_HEADERS,
            _SHERLOCK_RECOMMENDATION_HEADERS + _SHERLOCK_RESOLUTION_HEADERS,
        )
        recommendation = _section_after_header_any(
            body,
            _SHERLOCK_RECOMMENDATION_HEADERS,
            _SHERLOCK_RESOLUTION_HEADERS + ("References",),
        )
        resolution = _section_after_header_any(
            body,
            _SHERLOCK_RESOLUTION_HEADERS,
            ("References",),
        )
        description = summary

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        warnings: list[str] = []
        if not severity_verbatim:
            warnings.append("severity-from-letter-only")
            confidence -= 0.1
        if not summary:
            confidence -= 0.2
            warnings.append("missing-summary")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not source:
            confidence -= 0.05
            warnings.append("missing-source")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            SherlockFinding(
                finding_index=finding_index,
                finding_letter=letter,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                source=source[:600],
                summary=summary[:2000],
                description=description[:6000],
                recommendation=recommendation[:4000],
                resolution=resolution[:2000],
                lines_cited=lines_cited,
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Pashov-specific finding extractor.
# ---------------------------------------------------------------------------
#
# Pashov audit reports (`pashov-audits`, 286 PDFs) ship in two template
# generations:
#
# 1. Modern (2024+) template uses bracketed severity-coded finding IDs
#    like ``[H-1] Title``, ``[M-2] Title``, ``[L-3] Title``,
#    ``[C-1] Title``, ``[I-1] Title`` (Critical/High/Medium/Low/Info).
#    Severity is embedded in the heading prefix; the body usually has
#    Description, Recommendation, and optionally Proof of Concept
#    (~40 % of findings carry a PoC subsection).
# 2. Older (pre-2024) template drops the bracketed prefix entirely;
#    findings are introduced by ``N. Title`` numeric headings and the
#    severity is carried in a body ``Severity:`` label.
#
# Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.6.


@dataclasses.dataclass
class PashovFinding:
    """One Pashov-style finding extracted from a PDF."""

    finding_index: int                  # numeric portion of e.g. H-1
    title: str
    severity: str                       # normalised lowercase
    severity_verbatim: str
    severity_code: str = ""             # bracket-prefix letter (C/H/M/L/I); "" for fallback
    finding_type: str = ""
    summary: str = ""
    description: str = ""
    recommendation: str = ""
    proof_of_concept: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    code_snippet_pre_fix: str = ""
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


# ``[H-1] Title here`` (one space after bracket per Pashov convention).
_PASHOV_TITLE_RE = re.compile(
    r"^\s*\[(C|H|M|L|I)-(\d{1,3})\]\s+([^\n]{2,200})\s*$",
    re.MULTILINE,
)

# Fallback heading for pre-2024 Pashov PDFs that lack the bracketed
# prefix. Same shape as Trail of Bits but used only when the canonical
# bracketed pass yields zero candidates.
_PASHOV_FALLBACK_TITLE_RE = re.compile(
    r"^\s*(\d{1,3})\.\s+([A-Z][^\n]{2,200})\s*$",
    re.MULTILINE,
)

_PASHOV_SEVERITY_RE = re.compile(
    r"Severity\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|Undetermined)",
    re.IGNORECASE,
)

_PASHOV_CODE_TO_SEVERITY = {
    "C": ("critical", "Critical"),
    "H": ("high", "High"),
    "M": ("medium", "Medium"),
    "L": ("low", "Low"),
    "I": ("informational", "Informational"),
}

_PASHOV_DESCRIPTION_HEADERS = ("Description", "Summary", "Impact")
_PASHOV_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Recommended Mitigation",
    "Mitigation",
)
_PASHOV_POC_HEADERS = ("Proof of Concept", "PoC", "Proof-of-Concept")
_PASHOV_STATUS_WORDS = (
    "Fixed",
    "Resolved",
    "Acknowledged",
    "Unresolved",
    "Mitigated",
    "Wontfix",
    "Won't Fix",
)
_PASHOV_TITLE_META_WORDS = (
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
    "Info",
    "Status",
    "Severity",
) + _PASHOV_STATUS_WORDS
_PASHOV_SECTION_SIGNAL_RE = re.compile(
    r"\b(Description|Summary|Impact|Recommendation|Recommendations|Recommended Mitigation|Mitigation|Proof of Concept|PoC|Proof-of-Concept)\b",
    re.IGNORECASE,
)
_PASHOV_LIGATURES = {
    "ﬁ": "fi",
    "ﬂ": "fl",
    "ﬀ": "ff",
    "ﬃ": "ffi",
    "ﬄ": "ffl",
}


def _pashov_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """Pashov variant of ``_section_after_header``.

    Stops on either of Pashov's two heading conventions (bracketed or
    numeric-fallback) so multi-finding PDFs carve cleanly even when the
    body mixes templates inside a single review.
    """
    lines = text.splitlines()
    start_idx: Optional[int] = None
    for i, line in enumerate(lines):
        stripped = line.strip().rstrip(":")
        if stripped in header_options:
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    for line in lines[start_idx:]:
        stripped = line.strip().rstrip(":")
        if stripped in stop_headers:
            break
        if _PASHOV_TITLE_RE.match(line):
            break
        if _PASHOV_FALLBACK_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _normalize_pdf_text(value: str) -> tuple[str, list[str]]:
    warnings: list[str] = []
    out = value
    for src, dst in _PASHOV_LIGATURES.items():
        if src in out:
            out = out.replace(src, dst)
            warnings.append("pashov-ligature-normalized")
    normalised = unicodedata.normalize("NFKC", out)
    if normalised != out:
        out = normalised
        warnings.append("pashov-unicode-normalized")
    out = re.sub(r"\s+", " ", out).strip()
    return out, sorted(set(warnings))


def _clean_pashov_title(raw_title: str, *, severity_code: str = "") -> tuple[str, list[str]]:
    title, warnings = _normalize_pdf_text(raw_title)
    original = title
    if severity_code:
        title = re.sub(
            rf"^\s*(?:\[{severity_code}-\d{{1,3}}\]|{severity_code}-\d{{1,3}})\s*[:\-]?\s*",
            "",
            title,
            flags=re.IGNORECASE,
        )
    title = re.sub(
        r"^\s*(?:Critical|High|Medium|Low|Informational|Info)\s*[:\-]\s*",
        "",
        title,
        flags=re.IGNORECASE,
    )
    title = re.sub(
        r"\s+(?:Severity\s*[:\-]\s*)?(?:Critical|High|Medium|Low|Informational|Info)\s*(?:Status\s*[:\-]\s*)?(?:Fixed|Resolved|Acknowledged|Unresolved|Mitigated|Wontfix|Won't\s+Fix)?\s*$",
        "",
        title,
        flags=re.IGNORECASE,
    )
    title = re.sub(
        r"\s+(?:Status\s*[:\-]\s*)?(?:Fixed|Resolved|Acknowledged|Unresolved|Mitigated|Wontfix|Won't\s+Fix)\s*$",
        "",
        title,
        flags=re.IGNORECASE,
    )
    title = re.sub(
        r"(Critical|High|Medium|Low|Informational|Info)(Fixed|Resolved|Acknowledged|Unresolved|Mitigated|Wontfix)$",
        "",
        title,
    ).strip()
    if title != original:
        warnings.append("pashov-title-cleaned")
    return (title or original or "Untitled finding"), sorted(set(warnings))


# R36 citation: pathspec for LANE-195-PDF-EXTRACTOR-COMPACT registered via
# tools/agent-pathspec-register.py at 2026-05-26T20:51Z; file
# tools/lib/pdf_finding_extractor.py declared, TTL 7200s. Stored in
# .auditooor/agent_pathspec.json.


def _pashov_body_has_evidence(body: str) -> bool:
    return bool(_PASHOV_SECTION_SIGNAL_RE.search(body) or _extract_lines_cited(body))


def _pashov_anchor_score(body: str, title: str) -> tuple[int, int, int]:
    lines = _extract_lines_cited(body)
    score = 0
    if _PASHOV_SECTION_SIGNAL_RE.search(body):
        score += 10
    if lines:
        score += 5
    if len(body.strip()) > 300:
        score += 2
    title_tokens = len(re.findall(r"[A-Za-z0-9]+", title))
    return score, len(body.strip()), title_tokens


# ---------------------------------------------------------------------------
# Compact-layout TOC / summary-table anchor detection.
# ---------------------------------------------------------------------------
#
# A Pashov PDF often contains the bracketed ``[X-N] Title`` heading three
# times: once in the table of contents (titled with a trailing page
# number), once in the summary-table on the findings index page (titled
# with a trailing severity + status), and once at the real body of the
# finding (clean title). The real anchor is the only one whose adjacent
# text is the finding's prose; the others bleed into about/disclaimer/
# methodology sections and contaminate the parsed description.
#
# These regexes recognise the TOC and summary-table title shapes so the
# extractor can filter them out before dedup. Both patterns require the
# match to land at the END of the title; a clean title is preserved.
#
# R36 citation: see header note above; tools/agent-pathspec-register.py
# registers tools/lib/pdf_finding_extractor.py for LANE-195-PDF-EXTRACTOR-COMPACT.

_PASHOV_TOC_TRAILER_RE = re.compile(
    r"\s+\d{1,3}\s*$",
)
# Glued or spaced ``Low Acknowledged`` / ``MediumFixed`` / ... trailer.
_PASHOV_SUMMARY_TRAILER_RE = re.compile(
    r"(?:Critical|High|Medium|Low|Informational|Info)\s*"
    r"(?:Acknowledged|Fixed|Resolved|Unresolved|Mitigated|Wontfix|Won't\s*Fix)"
    r"\s*$",
    re.IGNORECASE,
)


def _pashov_anchor_role(raw_title: str) -> str:
    """Classify a Pashov heading anchor by title shape.

    Returns one of:

    * ``"toc"`` - title carries a trailing page-number digit run.
    * ``"summary"`` - title carries a trailing severity + status word
      pair (the summary-of-findings table layout).
    * ``"body"`` - clean title with no trailer; assumed to be the actual
      finding body anchor.
    """
    title = raw_title.strip()
    if _PASHOV_SUMMARY_TRAILER_RE.search(title):
        return "summary"
    if _PASHOV_TOC_TRAILER_RE.search(title):
        return "toc"
    return "body"


def _pashov_filter_compact_layout_anchors(
    anchor_matches: List["re.Match[str]"],
    anchor_codes: List[str],
    anchor_indices: List[str],
    anchor_titles: List[str],
) -> tuple[
    List["re.Match[str]"],
    List[str],
    List[str],
    List[str],
    bool,
]:
    """Drop TOC / summary-table anchors when a sibling body anchor exists.

    Returns the (possibly shrunk) lists plus a ``filtered`` flag. The
    filter is conservative: for each ``(code, index)`` group, only drop
    TOC or summary anchors when at least one body-role anchor exists in
    the same group. Groups whose ONLY anchors are TOC/summary are kept
    intact so the legacy score-based dedup still produces a candidate.

    This is the compact-layout safety net surfaced by the DefiApp
    2026-05-23 PDF: TOC / summary-table headings produce noise anchors
    whose bodies absorb interior pages (about, disclaimer, methodology)
    and outscore the real body anchors. See ``_pashov_anchor_role``.
    """
    if not anchor_matches:
        return anchor_matches, anchor_codes, anchor_indices, anchor_titles, False

    roles = [_pashov_anchor_role(t) for t in anchor_titles]
    # Group indices by (code, finding_index). When a body-role anchor is
    # present in a group, drop the toc / summary peers.
    by_group: dict[tuple[str, str], list[int]] = {}
    for i in range(len(anchor_matches)):
        key = (anchor_codes[i], anchor_indices[i])
        by_group.setdefault(key, []).append(i)

    drop: set[int] = set()
    for indices in by_group.values():
        roles_in_group = {roles[i] for i in indices}
        if "body" not in roles_in_group:
            continue
        for i in indices:
            if roles[i] in ("toc", "summary"):
                drop.add(i)

    if not drop:
        return anchor_matches, anchor_codes, anchor_indices, anchor_titles, False

    keep = [i for i in range(len(anchor_matches)) if i not in drop]
    return (
        [anchor_matches[i] for i in keep],
        [anchor_codes[i] for i in keep],
        [anchor_indices[i] for i in keep],
        [anchor_titles[i] for i in keep],
        True,
    )


def _pashov_body_fallback_description(body: str) -> str:
    """Cleaned body text used as description when no header is present.

    The compact Pashov layout (3 findings per page, one paragraph per
    finding) does NOT carry a ``Description:`` header before the body
    prose. ``_pashov_section_after_header`` returns ``""`` in that case
    and the caller would emit an empty-description finding. This helper
    builds a fallback description from the raw body slice with page-
    footer noise stripped.

    Returns the empty string when the trimmed body has fewer than 50
    characters of substantive content; the caller treats empty as
    "still low-quality" so we never fabricate a description.
    """
    if not body:
        return ""
    lines = body.splitlines()
    cleaned: List[str] = []
    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            cleaned.append("")
            continue
        # Drop running page-header / page-footer lines that Pashov PDFs
        # repeat on each page (``Pashov Audit Group <Project> Security
        # Review`` and ``<n> / <m>``).
        if stripped.startswith("Pashov Audit Group "):
            continue
        if re.fullmatch(r"\d{1,3}\s*/\s*\d{1,3}", stripped):
            continue
        # Drop standalone ``Low findings`` / ``Medium findings`` etc.
        # section subheadings that sit between the actual body anchor
        # and the next anchor.
        if re.fullmatch(
            r"(?:Critical|High|Medium|Low|Informational|Info)\s+findings",
            stripped,
            re.IGNORECASE,
        ):
            continue
        cleaned.append(stripped)
    joined = "\n".join(cleaned).strip()
    if len(re.sub(r"\s+", " ", joined)) < 50:
        return ""
    return joined


def _pashov_parse_body(
    body: str,
    *,
    severity_code: str,
) -> tuple[str, str, str, str, str, str, list[str]]:
    """Return ``(severity, severity_verbatim, description, recommendation,
    poc, summary, warnings)`` for a Pashov finding body slice.

    ``severity_code`` is the bracketed-prefix letter when present; empty
    string means the fallback path and severity must come from a body
    ``Severity:`` label.
    """
    warnings: list[str] = []

    if severity_code:
        severity, severity_verbatim = _PASHOV_CODE_TO_SEVERITY[severity_code]
    else:
        sev_match = _PASHOV_SEVERITY_RE.search(body)
        if sev_match:
            severity_verbatim = sev_match.group(1)
            severity = _SEVERITY_NORMALISE.get(
                severity_verbatim.lower(), "undetermined"
            )
        else:
            severity = "undetermined"
            severity_verbatim = ""
            warnings.append("missing-severity-field")

    # R36 citation: pathspec for LANE-195-PDF-EXTRACTOR-COMPACT registered
    # via tools/agent-pathspec-register.py (see agent_pathspec.json).
    description = _pashov_section_after_header(
        body,
        _PASHOV_DESCRIPTION_HEADERS,
        _PASHOV_RECOMMENDATION_HEADERS + _PASHOV_POC_HEADERS,
    )
    recommendation = _pashov_section_after_header(
        body,
        _PASHOV_RECOMMENDATION_HEADERS,
        ("References",),
    )
    poc = _pashov_section_after_header(
        body,
        _PASHOV_POC_HEADERS,
        _PASHOV_RECOMMENDATION_HEADERS,
    )

    # Compact-layout fallback (Task #195): the DefiApp 2026-05-23 PDF
    # and similar compact 3-findings-per-page Pashov layouts carry the
    # finding prose DIRECTLY after the bracketed title with no
    # ``Description:`` header. ``_pashov_section_after_header`` returns
    # empty in that case. Treat the cleaned body as the description so
    # the parser confidence stays above the 0.65 ETL threshold.
    if not description:
        fallback = _pashov_body_fallback_description(body)
        if fallback:
            description = fallback
            warnings.append("pashov-compact-layout-description-fallback")

    # Spec §5.6(c): include the PoC text in ``summary``, NOT in
    # ``recommendation``. ``summary`` becomes the first paragraph of the
    # ``description ++ poc`` blob.
    if poc and description:
        summary_seed = f"{description}\n\n{poc}".strip()
    elif poc:
        summary_seed = poc
    elif description:
        summary_seed = description
    else:
        summary_seed = body.strip().split("\n\n", 1)[0]
    summary = summary_seed.split("\n\n", 1)[0] if summary_seed else ""

    return severity, severity_verbatim, description, recommendation, poc, summary, warnings


def extract_pashov_findings(result: ExtractionResult) -> List[PashovFinding]:
    """Pashov bracketed-severity-prefix finding extractor.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.6.

    Strategy:

    1. Scan for headings matching the canonical ``[X-N] Title`` form.
       Each match is one finding; severity comes from the prefix
       letter (C/H/M/L/I) per ``_PASHOV_CODE_TO_SEVERITY``.
    2. If the bracketed pass yields zero candidates, fall back to a
       numeric-prefix scan (``N. Title``) used by older Pashov PDFs
       that predate the bracketed template. In that path the severity
       comes from a body ``Severity:`` label.

    Returns an empty list when no findings are detectable; callers
    must not raise on the empty result.
    """
    if not result.pages:
        return []

    # R36 citation: pathspec for LANE-195-PDF-EXTRACTOR-COMPACT registered
    # via tools/agent-pathspec-register.py (see agent_pathspec.json).
    full_text, page_offsets = _collect_full_text(result)

    bracket_matches = list(_PASHOV_TITLE_RE.finditer(full_text))
    used_fallback = False
    if bracket_matches:
        anchor_matches = bracket_matches
        anchor_codes = [m.group(1) for m in bracket_matches]
        anchor_indices = [m.group(2) for m in bracket_matches]
        anchor_titles = [m.group(3).strip() for m in bracket_matches]
    else:
        fallback_matches = list(_PASHOV_FALLBACK_TITLE_RE.finditer(full_text))
        if not fallback_matches:
            return []
        used_fallback = True
        anchor_matches = fallback_matches
        anchor_codes = ["" for _ in fallback_matches]
        anchor_indices = [m.group(1) for m in fallback_matches]
        anchor_titles = [m.group(2).strip() for m in fallback_matches]

    # Compact-layout pass (Task #195): drop TOC / summary-table noise
    # anchors whose body slices absorb interior pages and outscore the
    # real finding body anchors. The filter is conservative: TOC /
    # summary anchors are only dropped when a sibling body anchor
    # exists in the same ``(code, finding_index)`` group.
    compact_layout_filtered = False
    if not used_fallback:
        (
            anchor_matches,
            anchor_codes,
            anchor_indices,
            anchor_titles,
            compact_layout_filtered,
        ) = _pashov_filter_compact_layout_anchors(
            anchor_matches,
            anchor_codes,
            anchor_indices,
            anchor_titles,
        )

    candidates: dict[tuple[str, int], dict[str, object]] = {}
    duplicate_keys: set[tuple[str, int]] = set()
    for i, m in enumerate(anchor_matches):
        section_start = m.end()
        section_end = (
            anchor_matches[i + 1].start()
            if i + 1 < len(anchor_matches)
            else len(full_text)
        )
        body = full_text[section_start:section_end]
        code = anchor_codes[i]
        try:
            finding_index = int(anchor_indices[i])
        except ValueError:
            finding_index = i + 1
        title, title_warnings = _clean_pashov_title(
            anchor_titles[i],
            severity_code=code,
        )
        key = (code or "fallback", finding_index)
        score = _pashov_anchor_score(body, title)
        candidate = {
            "match": m,
            "section_end": section_end,
            "body": body,
            "code": code,
            "finding_index": finding_index,
            "title": title,
            "title_warnings": title_warnings,
            "score": score,
        }
        existing = candidates.get(key)
        if existing is None:
            candidates[key] = candidate
            continue
        duplicate_keys.add(key)
        if score > existing["score"]:
            candidates[key] = candidate

    findings: list[PashovFinding] = []
    for key, candidate in sorted(
        candidates.items(),
        key=lambda item: (item[0][0], item[0][1], item[1]["match"].start()),  # type: ignore[index,union-attr]
    ):
        m = candidate["match"]  # type: ignore[assignment]
        section_end = int(candidate["section_end"])
        body = str(candidate["body"])
        code = str(candidate["code"])
        finding_index = int(candidate["finding_index"])
        title = str(candidate["title"])
        title_warnings = list(candidate["title_warnings"])  # type: ignore[arg-type]

        (
            severity,
            severity_verbatim,
            description,
            recommendation,
            poc,
            summary,
            warnings,
        ) = _pashov_parse_body(body, severity_code=code)

        # R36 citation: pathspec via tools/agent-pathspec-register.py.
        warnings.extend(title_warnings)
        if key in duplicate_keys:
            warnings.append("pashov-duplicate-heading-suppressed")
        if used_fallback:
            warnings.append("pashov-fallback-numeric-heading")
        if compact_layout_filtered:
            warnings.append("pashov-compact-layout-anchor-filtered")

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        if used_fallback:
            confidence -= 0.1
        if not severity_verbatim and not code:
            confidence -= 0.3
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            PashovFinding(
                finding_index=finding_index,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                severity_code=code,
                finding_type="",
                summary=summary[:2000],
                description=description[:6000],
                recommendation=recommendation[:4000],
                proof_of_concept=poc[:4000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# SB Security-specific finding extractor.
# ---------------------------------------------------------------------------
#
# Native SBSecurity PDFs use section-numbered findings grouped under
# severity sections:
#
#   5.1.Critical severity
#   5.1.1.OmniNFT::mint does not estimate fees for multiple tokens
#   Severity: Critical Risk
#   Context: OmniNFT.sol#L83
#   Description: ...
#   Recommendation: ...
#   Resolution: Fixed
#
# A small number of SB-authored/co-branded reports follow a nearby Cyfrin
# layout. The extractor keeps the anchor generic enough to parse those when
# the text layer still exposes numbered finding headings, but the intended
# first slice is the native SBSecurity report template.


@dataclasses.dataclass
class SBSecurityFinding:
    """One SB Security-style finding extracted from a PDF."""

    finding_index: int                  # 1-based per report order
    finding_id: str                     # e.g. 5.1.1
    title: str
    severity: str                       # normalised lowercase
    severity_verbatim: str
    summary: str = ""
    description: str = ""
    recommendation: str = ""
    proof_of_concept: str = ""
    impact: str = ""
    resolution_status: str = ""
    resolution_note: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    code_snippet_pre_fix: str = ""
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


_SB_TITLE_RE = re.compile(
    r"^\s*(\d{1,2})\.(\d{1,2})\.(\d{1,3})\.?\s*([A-Za-z0-9_][^\n]{2,240})\s*$",
    re.MULTILINE,
)
_SB_BRACKET_TITLE_RE = re.compile(
    r"^\s*\[(C|H|M|L|I)-(\d{1,3})\]\s+([^\n]{2,300})\s*$",
    re.MULTILINE,
)
_SB_SEVERITY_RE = re.compile(
    r"Severity\s*:\s*(Critical|High|Medium|Low|Informational|Info)\s*(?:Risk|severity)?",
    re.IGNORECASE,
)
_SB_SEVERITY_SECTION_RE = re.compile(
    r"^\s*\d{1,2}\.\d{1,2}\.?\s*(Critical|High|Medium|Low|Informational|Info|Low/Info)\s*(?:severity|Risk)?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_SB_DESCRIPTION_HEADERS = ("Description", "Summary")
_SB_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Recommended Mitigation",
    "Mitigation",
)
_SB_POC_HEADERS = ("Proof of Concept", "PoC", "Proof-of-Concept")
_SB_IMPACT_HEADERS = ("Impact",)
_SB_RESOLUTION_HEADERS = ("Resolution",)
_SB_STOP_HEADERS = (
    "Description",
    "Summary",
    "Recommendation",
    "Recommendations",
    "Recommended Mitigation",
    "Mitigation",
    "Proof of Concept",
    "PoC",
    "Proof-of-Concept",
    "Impact",
    "Resolution",
    "Link",
)
_SB_BRACKET_CODE_TO_SEVERITY = {
    "C": ("critical", "Critical"),
    "H": ("high", "High"),
    "M": ("medium", "Medium"),
    "L": ("low", "Low"),
    "I": ("informational", "Informational"),
}


def _clean_sb_title(raw_title: str) -> tuple[str, list[str]]:
    title, warnings = _normalize_pdf_text(raw_title)
    original = title
    title = re.sub(r"\.{2,}\s*\d+\s*$", "", title).strip()
    title = re.sub(
        r"\s+(?:Fixed|Resolved|Acknowledged|Unresolved|Mitigated)\s*$",
        "",
        title,
        flags=re.IGNORECASE,
    )
    if title != original:
        warnings.append("sb-security-title-cleaned")
    return (title or original or "Untitled finding"), sorted(set(warnings))


def _sb_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """Extract a section whose header may be ``Header`` or ``Header: text``."""
    header_alt = "|".join(re.escape(h) for h in header_options)
    header_re = re.compile(rf"^\s*(?:{header_alt})\s*:?\s*(.*)$", re.IGNORECASE)
    stop_set = {h.lower() for h in stop_headers}

    lines = text.splitlines()
    start_idx: Optional[int] = None
    first_inline = ""
    for i, line in enumerate(lines):
        m = header_re.match(line)
        if m:
            start_idx = i + 1
            first_inline = m.group(1).strip()
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    if first_inline:
        out.append(first_inline)
    for line in lines[start_idx:]:
        stripped = line.strip()
        stripped_header = stripped.rstrip(":").lower()
        if stripped_header in stop_set:
            break
        if any(stripped.lower().startswith(h.lower() + ":") for h in stop_headers):
            break
        if _SB_TITLE_RE.match(line):
            break
        if _SB_SEVERITY_SECTION_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _sb_severity_from_context(full_text: str, start_offset: int) -> tuple[str, str, list[str]]:
    warnings: list[str] = []
    prior = full_text[:start_offset]
    matches = list(_SB_SEVERITY_SECTION_RE.finditer(prior))
    if not matches:
        warnings.append("missing-severity-section")
        return "undetermined", "", warnings
    verbatim = matches[-1].group(1)
    if verbatim.lower() == "low/info":
        return "low", verbatim, warnings
    severity = _SEVERITY_NORMALISE.get(verbatim.lower(), "undetermined")
    return severity, verbatim, warnings


def _sb_has_severity_context(full_text: str, body: str, start_offset: int) -> bool:
    """Return true when an SB candidate is inside an explicit severity context."""
    if _SB_SEVERITY_RE.search(body):
        return True
    severity, _verbatim, warnings = _sb_severity_from_context(full_text, start_offset)
    return severity != "undetermined" and "missing-severity-section" not in warnings


def _sb_parse_body(
    body: str,
    *,
    full_text: str,
    start_offset: int,
) -> tuple[str, str, str, str, str, str, str, str, str, list[str]]:
    warnings: list[str] = []

    sev_match = _SB_SEVERITY_RE.search(body)
    if sev_match:
        severity_verbatim = sev_match.group(1)
        severity = _SEVERITY_NORMALISE.get(severity_verbatim.lower(), "undetermined")
    else:
        severity, severity_verbatim, sev_warnings = _sb_severity_from_context(
            full_text,
            start_offset,
        )
        warnings.extend(sev_warnings)

    description = _sb_section_after_header(
        body,
        _SB_DESCRIPTION_HEADERS,
        _SB_RECOMMENDATION_HEADERS
        + _SB_POC_HEADERS
        + _SB_IMPACT_HEADERS
        + _SB_RESOLUTION_HEADERS
        + ("Link",),
    )
    impact = _sb_section_after_header(
        body,
        _SB_IMPACT_HEADERS,
        _SB_RECOMMENDATION_HEADERS + _SB_POC_HEADERS + _SB_RESOLUTION_HEADERS + ("Link",),
    )
    poc = _sb_section_after_header(
        body,
        _SB_POC_HEADERS,
        _SB_RECOMMENDATION_HEADERS + _SB_RESOLUTION_HEADERS + ("Link",),
    )
    recommendation = _sb_section_after_header(
        body,
        _SB_RECOMMENDATION_HEADERS,
        _SB_RESOLUTION_HEADERS + ("Link",),
    )
    resolution_note = _sb_section_after_header(
        body,
        _SB_RESOLUTION_HEADERS,
        ("Link",) + _SB_STOP_HEADERS,
    )
    resolution_status = ""
    if resolution_note:
        first = resolution_note.splitlines()[0].strip()
        if first:
            resolution_status = re.sub(r"[^A-Za-z0-9]+", "", first)[:40]

    summary_seed = description or impact or poc or body.strip().split("\n\n", 1)[0]
    summary = summary_seed.split("\n\n", 1)[0] if summary_seed else ""

    return (
        severity,
        severity_verbatim,
        description,
        recommendation,
        poc,
        impact,
        resolution_status,
        resolution_note,
        summary,
        warnings,
    )


def _extract_sb_security_bracket_findings(
    full_text: str,
    page_offsets: Sequence[tuple[int, int]],
) -> List[SBSecurityFinding]:
    matches = list(_SB_BRACKET_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    candidates: dict[str, dict[str, object]] = {}
    duplicate_ids: set[str] = set()
    for i, m in enumerate(matches):
        code = m.group(1).upper()
        index_str = m.group(2)
        finding_id = f"{code}-{index_str}"
        title, title_warnings = _clean_sb_title(m.group(3))
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        score = 0
        if _SB_SEVERITY_RE.search(body):
            score += 8
        if any(
            re.search(
                rf"^\s*{re.escape(h)}\s*:?",
                body,
                re.IGNORECASE | re.MULTILINE,
            )
            for h in _SB_STOP_HEADERS
        ):
            score += 5
        if _extract_lines_cited(body):
            score += 3
        if len(body.strip()) > 200:
            score += 1
        if re.search(r"\.{2,}\s*\d+\s*$", m.group(3)):
            score -= 20

        candidate = {
            "match": m,
            "section_end": section_end,
            "finding_id": finding_id,
            "title": title,
            "title_warnings": title_warnings,
            "body": body,
            "score": score,
            "severity_code": code,
        }
        existing = candidates.get(finding_id)
        if existing is None:
            candidates[finding_id] = candidate
            continue
        duplicate_ids.add(finding_id)
        if score > existing["score"]:
            candidates[finding_id] = candidate

    ordered_candidates = [
        candidate
        for candidate in sorted(
            candidates.values(),
            key=lambda item: item["match"].start(),  # type: ignore[index,union-attr]
        )
        if int(candidate["score"]) > 0
    ]

    findings: list[SBSecurityFinding] = []
    for order, candidate in enumerate(ordered_candidates, start=1):
        m = candidate["match"]  # type: ignore[assignment]
        body = str(candidate["body"])
        section_end = int(candidate["section_end"])
        finding_id = str(candidate["finding_id"])
        title = str(candidate["title"])
        severity_code = str(candidate["severity_code"])
        title_warnings = list(candidate["title_warnings"])  # type: ignore[arg-type]

        (
            severity,
            severity_verbatim,
            description,
            recommendation,
            poc,
            impact,
            resolution_status,
            resolution_note,
            summary,
            warnings,
        ) = _sb_parse_body(body, full_text=full_text, start_offset=m.start())

        if not _SB_SEVERITY_RE.search(body):
            severity, severity_verbatim = _SB_BRACKET_CODE_TO_SEVERITY[severity_code]
            warnings = [w for w in warnings if w != "missing-severity-section"]
            warnings.append("sb-security-severity-from-bracket-id")

        warnings.extend(title_warnings)
        if finding_id in duplicate_ids:
            warnings.append("sb-security-duplicate-heading-suppressed")

        lines_cited = _extract_lines_cited(body)
        confidence = 1.0
        if not severity_verbatim:
            confidence -= 0.3
            warnings.append("missing-severity-field")
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            SBSecurityFinding(
                finding_index=order,
                finding_id=finding_id,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                summary=summary[:2000],
                description=description[:6000],
                recommendation=recommendation[:4000],
                proof_of_concept=poc[:4000],
                impact=impact[:4000],
                resolution_status=resolution_status,
                resolution_note=resolution_note[:2000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


def extract_sb_security_findings(result: ExtractionResult) -> List[SBSecurityFinding]:
    """SBSecurity numbered-section finding extractor.

    Returns bracket-id findings when normal ``N.N.N Title`` anchors are absent
    or all normal anchors are methodology/table-of-contents ghosts.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)
    matches = list(_SB_TITLE_RE.finditer(full_text))
    if not matches:
        return _extract_sb_security_bracket_findings(full_text, page_offsets)

    candidates: dict[str, dict[str, object]] = {}
    duplicate_ids: set[str] = set()
    for i, m in enumerate(matches):
        finding_id = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
        title, title_warnings = _clean_sb_title(m.group(4))
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]
        score = 0
        if _SB_SEVERITY_RE.search(body):
            score += 8
        if any(re.search(rf"^\s*{re.escape(h)}\s*:?", body, re.IGNORECASE | re.MULTILINE) for h in _SB_STOP_HEADERS):
            score += 5
        if _extract_lines_cited(body):
            score += 3
        if len(body.strip()) > 200:
            score += 1
        if re.search(r"\.{2,}\s*\d+\s*$", m.group(4)):
            score -= 20
        candidate = {
            "match": m,
            "section_end": section_end,
            "finding_id": finding_id,
            "title": title,
            "title_warnings": title_warnings,
            "body": body,
            "score": score,
            "has_severity_context": _sb_has_severity_context(full_text, body, m.start()),
        }
        existing = candidates.get(finding_id)
        if existing is None:
            candidates[finding_id] = candidate
            continue
        duplicate_ids.add(finding_id)
        if score > existing["score"]:
            candidates[finding_id] = candidate

    ordered_candidates = [
        candidate
        for candidate in sorted(
            candidates.values(),
            key=lambda item: item["match"].start(),  # type: ignore[index,union-attr]
        )
        if int(candidate["score"]) > 0 and bool(candidate.get("has_severity_context"))
    ]

    findings: list[SBSecurityFinding] = []
    for order, candidate in enumerate(ordered_candidates, start=1):
        if int(candidate["score"]) <= 0:
            continue

        m = candidate["match"]  # type: ignore[assignment]
        body = str(candidate["body"])
        section_end = int(candidate["section_end"])
        finding_id = str(candidate["finding_id"])
        title = str(candidate["title"])
        title_warnings = list(candidate["title_warnings"])  # type: ignore[arg-type]

        (
            severity,
            severity_verbatim,
            description,
            recommendation,
            poc,
            impact,
            resolution_status,
            resolution_note,
            summary,
            warnings,
        ) = _sb_parse_body(body, full_text=full_text, start_offset=m.start())
        warnings.extend(title_warnings)
        if finding_id in duplicate_ids:
            warnings.append("sb-security-duplicate-heading-suppressed")

        lines_cited = _extract_lines_cited(body)
        confidence = 1.0
        if not severity_verbatim:
            confidence -= 0.3
            warnings.append("missing-severity-field")
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            SBSecurityFinding(
                finding_index=order,
                finding_id=finding_id,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                summary=summary[:2000],
                description=description[:6000],
                recommendation=recommendation[:4000],
                proof_of_concept=poc[:4000],
                impact=impact[:4000],
                resolution_status=resolution_status,
                resolution_note=resolution_note[:2000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    if not findings:
        return _extract_sb_security_bracket_findings(full_text, page_offsets)
    return findings


# ---------------------------------------------------------------------------
# Zellic-specific finding extractor.
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ZellicFinding:
    """One Zellic-style finding extracted from a PDF.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.2.

    Zellic ships per-finding numbered tables under ``Finding N: <title>``
    (or ``Finding #N: <title>``) headings. Each finding carries
    ``Severity:`` / ``Impact:`` / ``Likelihood:`` labels followed by
    ``Description`` and ``Recommendation`` paragraph sections. Severity
    text may be in a coloured badge in real PDFs - ``pypdf`` only surfaces
    the textual label, which is what the parser keys on.
    """

    finding_index: int                  # 1-based as it appears in the PDF
    title: str
    severity: str                       # normalised lowercase
    severity_verbatim: str
    impact: str = ""
    likelihood: str = ""
    summary: str = ""
    description: str = ""
    recommendation: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    code_snippet_pre_fix: str = ""
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


# Zellic finding heading. Accept both ``Finding 1:`` and ``Finding #1:``
# spellings; allow trailing whitespace before the colon. Title body must
# start with an uppercase letter to avoid false positives on body prose
# like ``finding the cause``.
_ZELLIC_TITLE_RE = re.compile(
    r"^\s*Finding\s+#?(\d{1,3})\s*[:\.]\s+([A-Z][^\n]{2,200})\s*$",
    re.MULTILINE,
)
_ZELLIC_SEVERITY_RE = re.compile(
    r"Severity\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|Note|Undetermined|None|Gas|Best\s+Practice)",
    re.IGNORECASE,
)
_ZELLIC_IMPACT_RE = re.compile(
    r"Impact\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|None|Undetermined)",
    re.IGNORECASE,
)
_ZELLIC_LIKELIHOOD_RE = re.compile(
    r"Likelihood\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|None|Undetermined)",
    re.IGNORECASE,
)
_ZELLIC_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Remediation",
    "Mitigation",
)
_ZELLIC_DESCRIPTION_HEADERS = (
    "Description",
    "Summary",
    "Details",
)
_ZELLIC_STOP_HEADERS = (
    "References",
    "Appendix",
)
_ZELLIC_LINES_CITED_RE = _TOB_LINES_CITED_RE
_ZELLIC_SEVERITY_NORMALISE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "note": "informational",
    "none": "informational",
    "gas": "gas",
    "best practice": "informational",
    "undetermined": "undetermined",
}


def _zellic_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """Zellic-flavoured ``_section_after_header`` that also stops on the
    next ``Finding N:`` heading regardless of where it lives in the body.
    """
    lines = text.splitlines()
    start_idx: Optional[int] = None
    for i, line in enumerate(lines):
        stripped = line.strip().rstrip(":")
        if stripped in header_options:
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    for line in lines[start_idx:]:
        stripped = line.strip().rstrip(":")
        if stripped in stop_headers:
            break
        # Stop when we hit the next Zellic finding heading.
        if _ZELLIC_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def extract_zellic_findings(result: ExtractionResult) -> List[ZellicFinding]:
    """Zellic-firm finding extractor.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.2.

    Robust to ``pypdf`` extraction noise: missing impact / likelihood
    labels and absent recommendation sections produce ``parser_warnings``
    rather than dropping the finding.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)

    matches = list(_ZELLIC_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[ZellicFinding] = []
    for i, m in enumerate(matches):
        finding_index = int(m.group(1))
        title = m.group(2).strip()
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        sev_match = _ZELLIC_SEVERITY_RE.search(body)
        severity_verbatim = sev_match.group(1) if sev_match else ""
        severity_key = re.sub(r"\s+", " ", severity_verbatim.strip().lower()) if severity_verbatim else ""
        severity = _ZELLIC_SEVERITY_NORMALISE.get(severity_key, "undetermined") if severity_key else "undetermined"

        impact_match = _ZELLIC_IMPACT_RE.search(body)
        impact = impact_match.group(1) if impact_match else ""

        likelihood_match = _ZELLIC_LIKELIHOOD_RE.search(body)
        likelihood = likelihood_match.group(1) if likelihood_match else ""

        description = _zellic_section_after_header(body, _ZELLIC_DESCRIPTION_HEADERS, _ZELLIC_RECOMMENDATION_HEADERS)
        recommendation = _zellic_section_after_header(body, _ZELLIC_RECOMMENDATION_HEADERS, _ZELLIC_STOP_HEADERS)
        summary = description.split("\n\n", 1)[0] if description else body.strip().split("\n\n", 1)[0]

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        warnings: list[str] = []
        if not severity_verbatim:
            confidence -= 0.3
            warnings.append("missing-severity-field")
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        if not impact:
            warnings.append("missing-impact-field")
        if not likelihood:
            warnings.append("missing-likelihood-field")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            ZellicFinding(
                finding_index=finding_index,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                impact=impact,
                likelihood=likelihood,
                summary=summary[:2000],
                description=description[:6000],
                recommendation=recommendation[:4000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Cyfrin-specific finding extractor.
# ---------------------------------------------------------------------------
#
# Cyfrin public audit reports (``Cyfrin/audit-reports``) ship with
# bracketed severity-coded finding IDs:
#
#   [C-1] Title here          (Critical)
#   [H-2] Title here          (High)
#   [M-3] Title here          (Medium)
#   [L-4] Title here          (Low)
#   [I-5] Title here          (Informational)
#   [G-6] Title here          (Gas optimization)
#
# Each finding body typically carries Description, Impact, Proof of
# Concept (PoC; ~50 % prevalence), and Recommended Mitigation /
# Recommendation subsections. Some reports append a resolution status
# line shaped like ``Resolution: Fixed in commit 1a2b3c4d`` or
# ``Status: Acknowledged`` after the recommendation.
#
# Spec ref: ``docs/HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md``
# (Cyfrin section).


@dataclasses.dataclass
class CyfrinFinding:
    """One Cyfrin-style finding extracted from a PDF."""

    finding_index: int                  # numeric portion of e.g. H-1
    finding_id: str                     # e.g. "H-1"
    title: str
    severity: str                       # normalised lowercase (critical/high/medium/low/informational/gas/undetermined)
    severity_verbatim: str
    severity_code: str = ""             # bracket-prefix letter (C/H/M/L/I/G)
    description: str = ""
    impact: str = ""
    proof_of_concept: str = ""
    recommendation: str = ""
    resolution_status: Optional[str] = None        # Fixed|Acknowledged|Resolved|None
    resolution_commit_ref: Optional[str] = None    # e.g. "1a2b3c4d"
    summary: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    code_snippet_pre_fix: str = ""
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


# Cyfrin uses bracketed severity-coded IDs ``[X-N] Title`` where X is one
# of C / H / M / L / I / G (Gas). Allow optional whitespace before the
# title and require at least 2 chars in the title body.
_CYFRIN_TITLE_RE = re.compile(
    r"^\s*\[(C|H|M|L|I|G)-(\d{1,3})\]\s+([^\n]{2,300})\s*$",
    re.MULTILINE,
)

_CYFRIN_SEVERITY_RE = re.compile(
    r"Severity\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|Gas|Undetermined)",
    re.IGNORECASE,
)

_CYFRIN_DESCRIPTION_HEADERS = ("Description", "Summary", "Details")
_CYFRIN_IMPACT_HEADERS = ("Impact",)
_CYFRIN_POC_HEADERS = ("Proof of Concept", "PoC", "Proof-of-Concept")
_CYFRIN_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Recommended Mitigation",
    "Recommended Fix",
    "Mitigation",
)
_CYFRIN_RESOLUTION_HEADERS = (
    "Resolution",
    "Status",
    "Fix Status",
)
_CYFRIN_STOP_HEADERS = ("References", "Appendix")

# Resolution-status patterns. ``Fixed in commit 1a2b3c4d`` and
# ``Resolved in PR #123`` are common shapes; bare ``Acknowledged`` /
# ``Fixed`` / ``Resolved`` also appear on a single line.
_CYFRIN_RESOLUTION_STATUS_RE = re.compile(
    r"(?:Resolution|Status|Fix\s+Status)\s*[:\|]?\s*"
    r"(Fixed|Acknowledged|Resolved|Unresolved|Won't\s+Fix|Wontfix)"
    r"(?:\s+in\s+(?:commit\s+)?([0-9a-fA-F]{6,40}))?",
    re.IGNORECASE,
)

_CYFRIN_CODE_TO_SEVERITY = {
    "C": ("critical", "Critical"),
    "H": ("high", "High"),
    "M": ("medium", "Medium"),
    "L": ("low", "Low"),
    "I": ("informational", "Informational"),
    "G": ("gas", "Gas"),
}

_CYFRIN_SEVERITY_NORMALISE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "gas": "gas",
    "undetermined": "undetermined",
}


def _cyfrin_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """Cyfrin variant of ``_section_after_header``.

    Stops on Cyfrin's bracketed heading (next finding) or any of the
    enumerated stop-headers (other recognised subsections).
    """
    lines = text.splitlines()
    start_idx: Optional[int] = None
    for i, line in enumerate(lines):
        stripped = line.strip().rstrip(":")
        if stripped in header_options:
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    for line in lines[start_idx:]:
        stripped = line.strip().rstrip(":")
        if stripped in stop_headers:
            break
        if _CYFRIN_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _parse_cyfrin_resolution(body: str) -> tuple[Optional[str], Optional[str]]:
    """Return ``(status, commit_ref)`` for a Cyfrin finding body.

    Recognises both inline (``Resolution: Fixed in commit 1a2b3c4d``) and
    bare (``Status: Acknowledged``) shapes. Commit ref is normalised
    lower-case; status is title-case.
    """
    m = _CYFRIN_RESOLUTION_STATUS_RE.search(body)
    if not m:
        return None, None
    raw_status = m.group(1).strip()
    # Normalise "Won't Fix" / "Wontfix" to "Acknowledged" tier.
    normalised = raw_status.replace("'", "").lower()
    if normalised in ("wont fix", "wontfix"):
        status = "Acknowledged"
    else:
        status = raw_status.title()
        if status.lower() == "wont fix":
            status = "Acknowledged"
    commit_ref = m.group(2).lower() if m.group(2) else None
    return status, commit_ref


def extract_cyfrin_findings(result: ExtractionResult) -> List[CyfrinFinding]:
    """Cyfrin bracketed-severity-prefix finding extractor.

    Spec ref: ``docs/HACKERMAN_AUDIT_FIRM_PDF_PREVIEW_2026-05-16.md``
    (Cyfrin section). Mirrors ``extract_pashov_findings`` but adds Gas
    severity, an explicit ``Impact`` subsection capture, and a
    resolution-status / commit-ref pair on the returned dataclass.

    Returns an empty list when no findings are detectable; callers must
    not raise on the empty result.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)
    matches = list(_CYFRIN_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[CyfrinFinding] = []
    for i, m in enumerate(matches):
        code = m.group(1).upper()
        index_str = m.group(2)
        title = m.group(3).strip()
        try:
            finding_index = int(index_str)
        except ValueError:
            finding_index = i + 1
        finding_id = f"{code}-{finding_index}"

        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        # Severity: prefer the bracketed prefix; let an explicit
        # ``Severity:`` body field override only when it disagrees with
        # the code AND the prefix value is unexpected.
        severity, severity_verbatim = _CYFRIN_CODE_TO_SEVERITY[code]
        sev_match = _CYFRIN_SEVERITY_RE.search(body)
        if sev_match:
            body_verbatim = sev_match.group(1)
            body_norm = _CYFRIN_SEVERITY_NORMALISE.get(
                body_verbatim.lower(), severity
            )
            # Use body label as the verbatim source when present, but
            # the bracketed code remains authoritative for the
            # normalised severity tier (Cyfrin convention).
            severity_verbatim = body_verbatim
            severity = body_norm if body_norm != "undetermined" else severity

        description = _cyfrin_section_after_header(
            body,
            _CYFRIN_DESCRIPTION_HEADERS,
            _CYFRIN_IMPACT_HEADERS
            + _CYFRIN_POC_HEADERS
            + _CYFRIN_RECOMMENDATION_HEADERS
            + _CYFRIN_RESOLUTION_HEADERS,
        )
        impact = _cyfrin_section_after_header(
            body,
            _CYFRIN_IMPACT_HEADERS,
            _CYFRIN_POC_HEADERS
            + _CYFRIN_RECOMMENDATION_HEADERS
            + _CYFRIN_RESOLUTION_HEADERS,
        )
        poc = _cyfrin_section_after_header(
            body,
            _CYFRIN_POC_HEADERS,
            _CYFRIN_RECOMMENDATION_HEADERS + _CYFRIN_RESOLUTION_HEADERS,
        )
        recommendation = _cyfrin_section_after_header(
            body,
            _CYFRIN_RECOMMENDATION_HEADERS,
            _CYFRIN_RESOLUTION_HEADERS + _CYFRIN_STOP_HEADERS,
        )

        resolution_status, resolution_commit_ref = _parse_cyfrin_resolution(body)

        # Summary seed: description + impact + poc concatenated; first
        # paragraph survives.
        summary_parts: list[str] = []
        if description:
            summary_parts.append(description)
        if impact:
            summary_parts.append(impact)
        if poc:
            summary_parts.append(poc)
        summary_seed = "\n\n".join(summary_parts) if summary_parts else body.strip()
        summary = summary_seed.split("\n\n", 1)[0] if summary_seed else ""

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        warnings: list[str] = []
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if code != "G" and not impact:
            # Gas findings frequently omit Impact (no security impact),
            # so do not penalise their absence.
            confidence -= 0.1
            warnings.append("missing-impact")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        if resolution_status is None:
            warnings.append("no-resolution-status")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            CyfrinFinding(
                finding_index=finding_index,
                finding_id=finding_id,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                severity_code=code,
                description=description[:6000],
                impact=impact[:4000],
                proof_of_concept=poc[:4000],
                recommendation=recommendation[:4000],
                resolution_status=resolution_status,
                resolution_commit_ref=resolution_commit_ref,
                summary=summary[:2000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings





# ---------------------------------------------------------------------------
# Spearbit-specific finding extractor.
# ---------------------------------------------------------------------------
#
# Spearbit audit reports (``spearbit/portfolio``, 300+ PDFs) follow a
# numbered-section layout with per-finding section headings shaped as::
#
#   5.1.1 Title here
#   5.2.1 Another title
#
# Findings nest under top-level severity-group sections (5.1 = Critical,
# 5.2 = High, 5.3 = Medium, 5.4 = Low, 5.5 = Informational, 5.6 = Gas)
# but the canonical per-finding severity is restated inline with a
# ``Severity: <Tier> Risk`` literal at the top of the section body. Common
# subsections:
#
#   Severity: <Tier> Risk
#   Context: <description>
#   Impact: <impact paragraph>
#   Recommendation: <fix paragraph>
#   Resolution: Fixed | Acknowledged | Disputed (optional commit / PR ref)
#
# Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.x
# (Spearbit variant). The driver mirrors the Zellic / Pashov / Cyfrin
# shape; only the parser regexes and dataclass shape differ.


@dataclasses.dataclass
class SpearbitFinding:
    """One Spearbit-style finding extracted from a PDF.

    The Spearbit signature element is ``Severity: <Tier> Risk`` (e.g.
    ``Severity: High Risk``) which distinguishes the firm from Sherlock's
    bracketed ``H-N`` style and Zellic's plain ``Severity:`` label.
    """

    section_id: str                     # canonical dotted section id (e.g. "5.1.1")
    title: str
    severity: str                       # normalised lowercase
    severity_verbatim: str              # "<Tier> Risk" (or "Informational", "Gas Optimization")
    context: str = ""
    impact: str = ""
    recommendation: str = ""
    resolution_status: Optional[str] = None    # "Fixed" | "Acknowledged" | "Disputed" | None
    resolution_note: Optional[str] = None      # trailing prose after the status keyword
    summary: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


# Spearbit section heading. Three-level dotted form ``5.1.1 Title``.
# Title must start with an uppercase letter so we do not gobble inline
# prose like ``5.1.1 of the standard``.
_SPEARBIT_TITLE_RE = re.compile(
    r"^\s*(\d{1,2}\.\d{1,2}\.\d{1,3})\s+([A-Z][^\n]{2,240})\s*$",
    re.MULTILINE,
)

# Severity: <Tier> Risk (Spearbit signature). Allow optional trailing
# qualifiers ("- exploitable", "(downgraded)", etc.); we only key on the
# tier itself for normalisation but preserve the verbatim phrase.
_SPEARBIT_SEVERITY_RE = re.compile(
    r"Severity\s*[:\|]\s*"
    r"(Critical|High|Medium|Low)\s+Risk"
    r"(?:\s*[-–—:(][^\n]{0,200})?",
    re.IGNORECASE,
)

# Spearbit also files "Informational" and "Gas Optimization" rows that do
# NOT carry the "Risk" suffix.
_SPEARBIT_SEVERITY_NONRISK_RE = re.compile(
    r"Severity\s*[:\|]\s*(Informational|Info|Gas\s+Optimization|Gas)\b",
    re.IGNORECASE,
)

_SPEARBIT_CONTEXT_HEADERS = ("Context", "Description")
_SPEARBIT_IMPACT_HEADERS = ("Impact",)
_SPEARBIT_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Mitigation",
    "Recommended Mitigation",
)
_SPEARBIT_RESOLUTION_HEADERS = ("Resolution", "Status", "Response", "Spearbit Response")
_SPEARBIT_STOP_HEADERS = (
    "References",
    "Appendix",
)

_SPEARBIT_RESOLUTION_STATUS_RE = re.compile(
    r"\b(Fixed|Acknowledged|Disputed|Resolved|Won't\s+Fix|Wont\s+Fix|Mitigated)\b",
    re.IGNORECASE,
)

_SPEARBIT_SEVERITY_NORMALISE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "info": "informational",
    "gas optimization": "gas",
    "gas": "gas",
}


def _spearbit_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """Spearbit-flavoured header walker.

    Accepts BOTH renderings ``pypdf`` produces:

    1. ``Header: <value>`` on a single line (inline).
    2. ``Header`` alone on its own line followed by the body (the common
       shape because Spearbit PDFs render section labels as bold-on-line
       which pypdf flattens to a bare label).

    Stops on the next Spearbit section heading (``X.Y.Z Title``) or any
    other recognised stop-header.
    """
    lines = text.splitlines()
    header_alts = "|".join(re.escape(h) for h in header_options)
    inline_match_re = re.compile(
        r"^\s*(" + header_alts + r")\s*[:\|]\s*(.*)$",
        re.IGNORECASE,
    )
    bare_match_re = re.compile(
        r"^\s*(" + header_alts + r")\s*[:\|]?\s*$",
        re.IGNORECASE,
    )
    stop_match_re = re.compile(
        r"^\s*(" + "|".join(re.escape(h) for h in stop_headers) + r")\s*[:\|]?\s*$",
        re.IGNORECASE,
    )

    start_idx: Optional[int] = None
    prefix_text = ""
    for i, line in enumerate(lines):
        bare = bare_match_re.match(line)
        if bare:
            start_idx = i + 1
            prefix_text = ""
            break
        m = inline_match_re.match(line)
        if m:
            prefix_text = m.group(2).strip()
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    if prefix_text:
        out.append(prefix_text)
    for line in lines[start_idx:]:
        if stop_match_re.match(line):
            break
        if _SPEARBIT_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _spearbit_parse_resolution(blob: str) -> tuple[Optional[str], Optional[str]]:
    """Split a Resolution body into ``(status, note)``.

    ``Resolution: Fixed in commit abc123`` -> ``("Fixed", "in commit abc123")``.
    ``Resolution: Acknowledged`` -> ``("Acknowledged", None)``.
    ``Resolution:`` empty -> ``(None, None)``.
    """
    if not blob:
        return None, None
    cleaned = blob.strip()
    m = _SPEARBIT_RESOLUTION_STATUS_RE.search(cleaned)
    if not m:
        return None, cleaned[:400] or None
    status_raw = m.group(1)
    lowered = status_raw.lower().replace("'", "").replace("won t fix", "wont fix")
    canonical = {
        "fixed": "Fixed",
        "acknowledged": "Acknowledged",
        "disputed": "Disputed",
        "resolved": "Fixed",
        "wont fix": "WontFix",
        "mitigated": "Fixed",
    }.get(lowered.strip(), status_raw.title())
    tail = cleaned[m.end():].strip(" :-–—.")
    return canonical, (tail or None)


def extract_spearbit_findings(result: ExtractionResult) -> List[SpearbitFinding]:
    """Spearbit-firm finding extractor.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md`` §5.x
    (Spearbit variant).

    Strategy:

    1. Scan for headings matching the ``X.Y.Z Title`` dotted form.
    2. For each section, search the body for ``Severity: <Tier> Risk``
       (canonical Spearbit signature) OR ``Severity: Informational`` /
       ``Severity: Gas Optimization``.
    3. Walk the body to extract ``Context``, ``Impact``, ``Recommendation``,
       and ``Resolution`` sub-sections.
    4. Decompose ``Resolution`` into a status keyword (Fixed / Acknowledged /
       Disputed / WontFix / Mitigated) and an optional trailing note.

    Robust to ``pypdf`` extraction noise: missing severity / resolution
    fields surface as ``parser_warnings`` instead of dropping the finding.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)
    matches = list(_SPEARBIT_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[SpearbitFinding] = []
    for i, m in enumerate(matches):
        section_id = m.group(1).strip()
        title = m.group(2).strip()
        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        # Severity: prefer "<Tier> Risk" (Spearbit canonical) then fall
        # back to "Informational" / "Gas Optimization".
        sev_match = _SPEARBIT_SEVERITY_RE.search(body)
        severity_verbatim = ""
        severity_key = ""
        if sev_match:
            tier = sev_match.group(1)
            severity_verbatim = f"{tier.title()} Risk"
            severity_key = tier.lower()
        else:
            nonrisk_match = _SPEARBIT_SEVERITY_NONRISK_RE.search(body)
            if nonrisk_match:
                raw = nonrisk_match.group(1).strip()
                normalised = re.sub(r"\s+", " ", raw)
                if normalised.lower() in ("informational", "info"):
                    severity_verbatim = "Informational"
                    severity_key = "informational"
                else:
                    severity_verbatim = "Gas Optimization"
                    severity_key = "gas optimization"

        severity = (
            _SPEARBIT_SEVERITY_NORMALISE.get(severity_key, "undetermined")
            if severity_key
            else "undetermined"
        )

        context = _spearbit_section_after_header(
            body,
            _SPEARBIT_CONTEXT_HEADERS,
            _SPEARBIT_IMPACT_HEADERS + _SPEARBIT_RECOMMENDATION_HEADERS + _SPEARBIT_RESOLUTION_HEADERS + _SPEARBIT_STOP_HEADERS,
        )
        impact = _spearbit_section_after_header(
            body,
            _SPEARBIT_IMPACT_HEADERS,
            _SPEARBIT_RECOMMENDATION_HEADERS + _SPEARBIT_RESOLUTION_HEADERS + _SPEARBIT_STOP_HEADERS,
        )
        recommendation = _spearbit_section_after_header(
            body,
            _SPEARBIT_RECOMMENDATION_HEADERS,
            _SPEARBIT_RESOLUTION_HEADERS + _SPEARBIT_STOP_HEADERS,
        )
        resolution_blob = _spearbit_section_after_header(
            body,
            _SPEARBIT_RESOLUTION_HEADERS,
            _SPEARBIT_STOP_HEADERS,
        )
        resolution_status, resolution_note = _spearbit_parse_resolution(resolution_blob)

        summary_seed = context or impact or body.strip()
        summary = summary_seed.split("\n\n", 1)[0] if summary_seed else ""

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        warnings: list[str] = []
        if not severity_verbatim:
            confidence -= 0.3
            warnings.append("missing-severity-field")
        if not context:
            confidence -= 0.15
            warnings.append("missing-context")
        if not impact:
            confidence -= 0.1
            warnings.append("missing-impact")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not resolution_status and not resolution_blob:
            warnings.append("missing-resolution")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            SpearbitFinding(
                section_id=section_id,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                context=context[:6000],
                impact=impact[:4000],
                recommendation=recommendation[:4000],
                resolution_status=resolution_status,
                resolution_note=resolution_note[:1000] if resolution_note else None,
                summary=summary[:2000],
                lines_cited=lines_cited,
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# ChainSecurity firm variant (Wave-2 W2.4 PR-Wave2-B).
# ---------------------------------------------------------------------------
#
# ChainSecurity public audit reports use a bracketed sequential finding
# ID prefix paired with a separate severity label:
#
#   [CS-1] Title here          (severity rendered nearby as Critical/High/...)
#   [CS-2] Title here
#   [CS-3] Title here
#
# Each finding body typically carries Description, Acceptance Criteria
# (unique to ChainSecurity - an explicit success condition the team
# committed to), Recommendation, and an Acknowledgement subsection.
# Resolution wording uses ChainSecurity-specific phrasing such as
# ``Code Corrected``, ``Acknowledged``, or ``Risk Accepted``.
#
# Severity labels may include the ChainSecurity-specific
# ``Best Practice`` tier which we normalise to ``informational``.
#
# Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md``
# (ChainSecurity variant).


@dataclasses.dataclass
class ChainSecurityFinding:
    """One ChainSecurity-style finding extracted from a PDF."""

    finding_index: int
    finding_id: str
    title: str
    severity: str
    severity_verbatim: str
    description: str = ""
    acceptance_criteria: Optional[str] = None
    recommendation: str = ""
    resolution_status: Optional[str] = None
    resolution_note: Optional[str] = None
    summary: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    code_snippet_pre_fix: str = ""
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


_CHAINSEC_TITLE_RE = re.compile(
    r"^\s*\[CS-(\d{1,3})\]\s+([^\n]{2,300})\s*$",
    re.MULTILINE,
)

_CHAINSEC_SEVERITY_INLINE_RE = re.compile(
    r"Severity\s*[:\|]\s*(Critical|High|Medium|Low|Informational|Info|Best\s+Practice)",
    re.IGNORECASE,
)
_CHAINSEC_SEVERITY_BARE_RE = re.compile(
    r"^\s*(Critical|High|Medium|Low|Informational|Info|Best\s+Practice)\s*$",
    re.IGNORECASE | re.MULTILINE,
)

_CHAINSEC_DESCRIPTION_HEADERS = ("Description", "Summary", "Details")
_CHAINSEC_ACCEPTANCE_HEADERS = (
    "Acceptance Criteria",
    "Acceptance criteria",
    "Acceptance",
)
_CHAINSEC_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Recommended Fix",
    "Mitigation",
)
_CHAINSEC_RESOLUTION_HEADERS = (
    "Acknowledgement",
    "Acknowledgment",
    "Resolution",
    "Status",
    "Response",
)
_CHAINSEC_STOP_HEADERS = ("References", "Appendix")

_CHAINSEC_RESOLUTION_STATUS_RE = re.compile(
    r"(Code\s+Corrected|Code\s+Partially\s+Corrected|Acknowledged|Risk\s+Accepted|"
    r"No\s+Action\s+Required|Fixed|Resolved)",
    re.IGNORECASE,
)

_CHAINSEC_SEVERITY_NORMALISE = {
    "critical": ("critical", "Critical"),
    "high": ("high", "High"),
    "medium": ("medium", "Medium"),
    "low": ("low", "Low"),
    "informational": ("informational", "Informational"),
    "info": ("informational", "Informational"),
    "best practice": ("informational", "Best Practice"),
}


def _chainsec_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """ChainSecurity section extractor.

    Stops on the next ``[CS-N]`` title or any enumerated stop-header.
    """
    lines = text.splitlines()
    start_idx: Optional[int] = None
    for i, line in enumerate(lines):
        stripped = line.strip().rstrip(":")
        if stripped in header_options:
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    for line in lines[start_idx:]:
        stripped = line.strip().rstrip(":")
        if stripped in stop_headers:
            break
        if _CHAINSEC_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _parse_chainsec_resolution(body: str) -> tuple[Optional[str], Optional[str]]:
    """Return ``(normalised_status, verbatim_note)`` for a ChainSecurity finding."""
    m = _CHAINSEC_RESOLUTION_STATUS_RE.search(body)
    if not m:
        return None, None
    raw = m.group(1).strip()
    collapsed = re.sub(r"\s+", " ", raw).lower()
    if collapsed in ("code corrected", "code partially corrected", "fixed", "resolved"):
        status = "CodeCorrected"
    elif collapsed == "risk accepted":
        status = "RiskAccepted"
    elif collapsed in ("acknowledged", "no action required"):
        status = "Acknowledged"
    else:
        status = "Acknowledged"
    note = re.sub(r"\s+", " ", raw)
    return status, note


def _chainsec_severity_for_body(body: str) -> tuple[str, str]:
    """Pull the severity label for a ChainSecurity finding body."""
    inline = _CHAINSEC_SEVERITY_INLINE_RE.search(body)
    if inline:
        raw = inline.group(1).strip()
        key = re.sub(r"\s+", " ", raw).lower()
        norm = _CHAINSEC_SEVERITY_NORMALISE.get(key)
        if norm:
            return norm[0], norm[1]
        return "undetermined", raw

    head_lines: list[str] = []
    for line in body.splitlines():
        if line.strip():
            head_lines.append(line)
        if len(head_lines) >= 12:
            break
    head = "\n".join(head_lines)
    bare = _CHAINSEC_SEVERITY_BARE_RE.search(head)
    if bare:
        raw = bare.group(1).strip()
        key = re.sub(r"\s+", " ", raw).lower()
        norm = _CHAINSEC_SEVERITY_NORMALISE.get(key)
        if norm:
            return norm[0], norm[1]
        return "undetermined", raw

    return "undetermined", ""


def extract_chainsecurity_findings(result: ExtractionResult) -> List[ChainSecurityFinding]:
    """ChainSecurity bracketed-sequential-ID finding extractor.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md``
    (ChainSecurity variant). Recognises ``[CS-N]`` prefix, captures
    ``Acceptance Criteria``, and normalises ``Code Corrected`` /
    ``Risk Accepted`` / ``Acknowledged`` verbatim.

    Returns an empty list when no findings are detectable.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)
    matches = list(_CHAINSEC_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[ChainSecurityFinding] = []
    for i, m in enumerate(matches):
        index_str = m.group(1)
        title = m.group(2).strip()
        try:
            finding_index = int(index_str)
        except ValueError:
            finding_index = i + 1
        finding_id = f"CS-{finding_index}"

        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        severity, severity_verbatim = _chainsec_severity_for_body(body)

        description = _chainsec_section_after_header(
            body,
            _CHAINSEC_DESCRIPTION_HEADERS,
            _CHAINSEC_ACCEPTANCE_HEADERS
            + _CHAINSEC_RECOMMENDATION_HEADERS
            + _CHAINSEC_RESOLUTION_HEADERS,
        )
        acceptance = _chainsec_section_after_header(
            body,
            _CHAINSEC_ACCEPTANCE_HEADERS,
            _CHAINSEC_RECOMMENDATION_HEADERS + _CHAINSEC_RESOLUTION_HEADERS,
        )
        recommendation = _chainsec_section_after_header(
            body,
            _CHAINSEC_RECOMMENDATION_HEADERS,
            _CHAINSEC_RESOLUTION_HEADERS + _CHAINSEC_STOP_HEADERS,
        )
        ack_body = _chainsec_section_after_header(
            body,
            _CHAINSEC_RESOLUTION_HEADERS,
            _CHAINSEC_STOP_HEADERS,
        )

        if ack_body:
            resolution_status, resolution_note = _parse_chainsec_resolution(ack_body)
            if resolution_status is None and ack_body.strip():
                resolution_note = re.sub(r"\s+", " ", ack_body.strip())[:1000]
        else:
            resolution_status, resolution_note = _parse_chainsec_resolution(body)

        summary_parts: list[str] = []
        if description:
            summary_parts.append(description)
        if acceptance:
            summary_parts.append(acceptance)
        summary_seed = "\n\n".join(summary_parts) if summary_parts else body.strip()
        summary = summary_seed.split("\n\n", 1)[0] if summary_seed else ""

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        warnings: list[str] = []
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        if severity == "undetermined":
            confidence -= 0.15
            warnings.append("missing-severity-label")
        if resolution_status is None:
            warnings.append("no-resolution-status")
        if not acceptance:
            warnings.append("no-acceptance-criteria")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            ChainSecurityFinding(
                finding_index=finding_index,
                finding_id=finding_id,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                description=description[:6000],
                acceptance_criteria=(acceptance[:4000] if acceptance else None),
                recommendation=recommendation[:4000],
                resolution_status=resolution_status,
                resolution_note=(resolution_note[:1000] if resolution_note else None),
                summary=summary[:2000],
                lines_cited=lines_cited,
                code_snippet_pre_fix="",
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# OpenZeppelin-specific finding extractor.
# ---------------------------------------------------------------------------
#
# OpenZeppelin audit reports (https://blog.openzeppelin.com/security-audits)
# use a bracketed severity-coded ID layout similar to Cyfrin but with
# 2-digit IDs and a distinct severity-code letter set::
#
#   [C-01] Critical title here
#   [H-01] High title here
#   [M-01] Medium title here
#   [L-01] Low title here
#   [N-01] Note / "None" tier
#   [I-01] Informational
#
# Per-finding subsection labels:
#
#   Description         (required)
#   Recommendation      (canonical)
#   Mitigation          (alternative to Resolution on some OZ reports)
#   Resolution          (Fixed | Acknowledged | Resolved | Partially Fixed)
#
# Resolution lines frequently reference a fix PR or commit, e.g.
# ``Fixed in PR #1234`` or ``Resolved at commit 1a2b3c4d``.
#
# Differences vs Cyfrin (which uses the same bracket-style):
#
#   * OZ uses 2-digit zero-padded IDs (H-01, H-10, H-11 ...).
#   * OZ uses ``N`` for the Note / "None" tier (Cyfrin does not).
#   * OZ adds an explicit ``Mitigation`` label sometimes used in place of
#     ``Resolution``; both are accepted by the parser.
#   * OZ frequently cites ``PR #1234`` rather than a raw commit SHA;
#     ``resolution_ref`` captures either shape.


@dataclasses.dataclass
class OpenZeppelinFinding:
    """One OpenZeppelin-style finding extracted from a PDF."""

    finding_index: int                  # numeric portion of e.g. H-01
    finding_id: str                     # e.g. "H-01"
    title: str
    severity: str                       # normalised lowercase
    severity_verbatim: str
    severity_code: str = ""             # bracket-prefix letter (C/H/M/L/N/I)
    description: str = ""
    recommendation: str = ""
    mitigation: Optional[str] = None    # alternative to resolution on some OZ reports
    resolution_status: Optional[str] = None  # Fixed|Acknowledged|Resolved|PartiallyFixed|None
    resolution_ref: Optional[str] = None     # PR# or commit SHA captured verbatim
    summary: str = ""
    lines_cited: List[dict] = dataclasses.field(default_factory=list)
    page_range: List[int] = dataclasses.field(default_factory=list)
    parser_confidence: float = 1.0
    parser_warnings: List[str] = dataclasses.field(default_factory=list)


# OpenZeppelin bracketed-ID regex. Accepts 1-3 digit IDs (canonical OZ
# format is 2-digit zero-padded but earlier reports use single-digit and
# extremely large engagements occasionally overflow to 3 digits).
_OZ_TITLE_RE = re.compile(
    r"^\s*\[(C|H|M|L|N|I)-(\d{1,3})\]\s+([^\n]{2,300})\s*$",
    re.MULTILINE,
)

_OZ_SEVERITY_RE = re.compile(
    r"Severity\s*[:\|]\s*"
    r"(Critical|High|Medium|Low|Note|None|Informational|Info)\b",
    re.IGNORECASE,
)

_OZ_DESCRIPTION_HEADERS = ("Description", "Summary", "Details")
_OZ_RECOMMENDATION_HEADERS = (
    "Recommendation",
    "Recommendations",
    "Recommended Mitigation",
    "Recommended Fix",
)
_OZ_MITIGATION_HEADERS = ("Mitigation",)
_OZ_RESOLUTION_HEADERS = (
    "Resolution",
    "Status",
    "Fix Status",
    "Update from the OpenZeppelin team",
    "Update from the team",
)
_OZ_STOP_HEADERS = ("References", "Appendix")

# Resolution status patterns. Order matters: "Partially Fixed" must be
# matched before plain "Fixed" so the greedier label wins. The token
# allows interior whitespace and optional hyphen ("Partially-Fixed",
# "Partially Fixed").
_OZ_RESOLUTION_STATUS_RE = re.compile(
    r"\b(Partially[\s\-]+Fixed|Fixed|Acknowledged|Resolved|Won't\s+Fix|Wontfix)\b",
    re.IGNORECASE,
)

# Capture PR# / commit-SHA references on a Resolution line.
_OZ_PR_REF_RE = re.compile(r"PR\s*#?(\d{1,6})", re.IGNORECASE)
_OZ_COMMIT_REF_RE = re.compile(r"\bcommit\s+([0-9a-fA-F]{6,40})", re.IGNORECASE)

_OZ_CODE_TO_SEVERITY = {
    "C": ("critical", "Critical"),
    "H": ("high", "High"),
    "M": ("medium", "Medium"),
    "L": ("low", "Low"),
    "N": ("note", "Note"),
    "I": ("informational", "Informational"),
}

_OZ_SEVERITY_NORMALISE = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "note": "note",
    "none": "note",
    "informational": "informational",
    "info": "informational",
}


def _openzeppelin_section_after_header(
    text: str,
    header_options: tuple[str, ...],
    stop_headers: tuple[str, ...],
) -> str:
    """OZ variant of ``_section_after_header``.

    Mirrors the Cyfrin walker shape: bare-label-on-line OR inline
    ``Header: value`` style, stopping on the next OZ bracketed heading
    or any enumerated stop header.
    """
    lines = text.splitlines()
    header_alts = "|".join(re.escape(h) for h in header_options)
    inline_re = re.compile(
        r"^\s*(" + header_alts + r")\s*[:\|]\s*(.*)$",
        re.IGNORECASE,
    )
    bare_re = re.compile(
        r"^\s*(" + header_alts + r")\s*[:\|]?\s*$",
        re.IGNORECASE,
    )
    stop_re = re.compile(
        r"^\s*(" + "|".join(re.escape(h) for h in stop_headers) + r")\s*[:\|]?\s*$",
        re.IGNORECASE,
    )

    start_idx: Optional[int] = None
    prefix_text = ""
    for i, line in enumerate(lines):
        bare = bare_re.match(line)
        if bare:
            start_idx = i + 1
            prefix_text = ""
            break
        m = inline_re.match(line)
        if m:
            prefix_text = m.group(2).strip()
            start_idx = i + 1
            break
    if start_idx is None:
        return ""

    out: list[str] = []
    if prefix_text:
        out.append(prefix_text)
    for line in lines[start_idx:]:
        if stop_re.match(line):
            break
        if _OZ_TITLE_RE.match(line):
            break
        out.append(line)
    return "\n".join(out).strip()


def _parse_openzeppelin_resolution(
    body: str,
) -> tuple[Optional[str], Optional[str]]:
    """Return ``(status, resolution_ref)`` for an OZ finding body.

    ``status`` is one of ``Fixed`` / ``Acknowledged`` / ``Resolved`` /
    ``PartiallyFixed`` (camel-cased, internal spaces collapsed). ``ref``
    is the captured PR or commit reference verbatim (e.g. ``"PR #1234"``
    or ``"1a2b3c4d"``) or None.
    """
    status_match = _OZ_RESOLUTION_STATUS_RE.search(body)
    if not status_match:
        return None, None
    raw = status_match.group(1).strip()
    normalised = re.sub(r"[\s\-]+", " ", raw).lower()
    canonical = {
        "fixed": "Fixed",
        "acknowledged": "Acknowledged",
        "resolved": "Resolved",
        "partially fixed": "PartiallyFixed",
        "won't fix": "Acknowledged",
        "wontfix": "Acknowledged",
    }.get(normalised, raw.title())

    pr_m = _OZ_PR_REF_RE.search(body)
    if pr_m:
        ref: Optional[str] = f"PR #{pr_m.group(1)}"
    else:
        commit_m = _OZ_COMMIT_REF_RE.search(body)
        ref = commit_m.group(1).lower() if commit_m else None

    return canonical, ref


def extract_openzeppelin_findings(
    result: ExtractionResult,
) -> List[OpenZeppelinFinding]:
    """OpenZeppelin bracketed-severity-prefix finding extractor.

    Spec ref: ``docs/WAVE2_W24_PDF_DEEPMINE_SPEC_2026-05-16.md``
    (OpenZeppelin variant, PR-Wave2-B task brief). Mirrors the Cyfrin
    extractor structure but accepts the ``N`` (Note) tier, 2-digit IDs,
    and a ``Mitigation`` label alongside ``Resolution``.

    Returns an empty list when no findings are detectable; callers must
    not raise on the empty result.
    """
    if not result.pages:
        return []

    full_text, page_offsets = _collect_full_text(result)
    matches = list(_OZ_TITLE_RE.finditer(full_text))
    if not matches:
        return []

    findings: list[OpenZeppelinFinding] = []
    for i, m in enumerate(matches):
        code = m.group(1).upper()
        index_str = m.group(2)
        title = m.group(3).strip()
        try:
            finding_index = int(index_str)
        except ValueError:
            finding_index = i + 1
        # Preserve the verbatim zero-padded ID (canonical OZ form keeps
        # the leading zero on "H-01"). Falls back to the raw integer if
        # the source already lacked padding.
        finding_id = f"{code}-{index_str}"

        section_start = m.end()
        section_end = matches[i + 1].start() if i + 1 < len(matches) else len(full_text)
        body = full_text[section_start:section_end]

        severity, severity_verbatim = _OZ_CODE_TO_SEVERITY[code]
        sev_match = _OZ_SEVERITY_RE.search(body)
        if sev_match:
            body_verbatim = sev_match.group(1)
            body_norm = _OZ_SEVERITY_NORMALISE.get(body_verbatim.lower(), severity)
            severity_verbatim = body_verbatim
            if body_norm in _OZ_SEVERITY_NORMALISE.values():
                severity = body_norm

        description = _openzeppelin_section_after_header(
            body,
            _OZ_DESCRIPTION_HEADERS,
            _OZ_RECOMMENDATION_HEADERS
            + _OZ_MITIGATION_HEADERS
            + _OZ_RESOLUTION_HEADERS
            + _OZ_STOP_HEADERS,
        )
        recommendation = _openzeppelin_section_after_header(
            body,
            _OZ_RECOMMENDATION_HEADERS,
            _OZ_MITIGATION_HEADERS + _OZ_RESOLUTION_HEADERS + _OZ_STOP_HEADERS,
        )
        mitigation = _openzeppelin_section_after_header(
            body,
            _OZ_MITIGATION_HEADERS,
            _OZ_RESOLUTION_HEADERS + _OZ_STOP_HEADERS,
        )
        resolution_blob = _openzeppelin_section_after_header(
            body,
            _OZ_RESOLUTION_HEADERS,
            _OZ_STOP_HEADERS,
        )

        # If the Mitigation block carries a resolution-status keyword,
        # treat it as the resolution source.
        resolution_source = resolution_blob or mitigation or ""
        resolution_status, resolution_ref = _parse_openzeppelin_resolution(
            resolution_source
        )

        summary_seed = description or body.strip()
        summary = summary_seed.split("\n\n", 1)[0] if summary_seed else ""

        lines_cited = _extract_lines_cited(body)

        confidence = 1.0
        warnings: list[str] = []
        if not description:
            confidence -= 0.2
            warnings.append("missing-description")
        if not recommendation and not mitigation:
            confidence -= 0.2
            warnings.append("missing-recommendation")
        if not lines_cited:
            confidence -= 0.1
            warnings.append("no-lines-cited")
        if resolution_status is None:
            warnings.append("no-resolution-status")
        confidence = max(0.3, confidence)

        start_page = _page_for_offset(m.start(), page_offsets)
        end_page = _page_for_offset(section_end - 1, page_offsets)

        findings.append(
            OpenZeppelinFinding(
                finding_index=finding_index,
                finding_id=finding_id,
                title=title,
                severity=severity,
                severity_verbatim=severity_verbatim,
                severity_code=code,
                description=description[:6000],
                recommendation=recommendation[:4000],
                mitigation=mitigation[:4000] if mitigation else None,
                resolution_status=resolution_status,
                resolution_ref=resolution_ref,
                summary=summary[:2000],
                lines_cited=lines_cited,
                page_range=[start_page, end_page],
                parser_confidence=confidence,
                parser_warnings=warnings,
            )
        )

    return findings
