#!/usr/bin/env python3
# r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE registered in .auditooor/agent_pathspec.json
"""
hackenproof-plain-export.py
Rule 37 emit tier: tool utility (no corpus record emitted)

Convert an auditooor paste-ready MD submission draft into HackenProof's
4-section plain-text submission format.

HackenProof form sections:
  1. Title           (one line)
  2. Vulnerability details  (max 10000 chars)
  3. Validation steps       (max 10000 chars)
  4. Supporting files / PoC (file list)

Usage:
  python3 tools/hackenproof-plain-export.py --draft <path.md> [--out <path.txt>] [--json] [--strict]
  python3 tools/hackenproof-plain-export.py --validate <path.txt> [--json] [--strict]

--draft   : convert an MD draft to the 4-section plain-text format.
--validate: check an already-written .txt is a paste-ready HackenProof
            submission (4 sections in order, section 2 and 3 each <=10000
            chars, ASCII-only, no markdown / HTML-comment / internal-label
            residue). Use this on a hand-trimmed final .txt.

Exits non-zero when --strict and any section exceeds 10000 chars (export)
or any validation check fails (validate).
"""

import argparse
import json
import os
import re
import sys
import unicodedata

SECTION_LIMIT = 10000

# ---------------------------------------------------------------------------
# Text hygiene
# ---------------------------------------------------------------------------

# Smart quote / Unicode normalisation map
_UNICODE_REPLACEMENTS = {
    "—": "-",   # em-dash
    "–": "-",   # en-dash
    "‒": "-",   # figure dash
    "‐": "-",   # hyphen (Unicode)
    "‑": "-",   # non-breaking hyphen
    "‘": "'",   # left single quotation mark
    "’": "'",   # right single quotation mark
    "“": '"',   # left double quotation mark
    "”": '"',   # right double quotation mark
    "…": "...", # horizontal ellipsis
    " ": " ",   # non-breaking space
    "​": "",    # zero-width space
    "‌": "",    # zero-width non-joiner
    "‍": "",    # zero-width joiner
    "﻿": "",    # BOM
}

def _replace_unicode(text: str) -> str:
    for ch, replacement in _UNICODE_REPLACEMENTS.items():
        text = text.replace(ch, replacement)
    return text


# r36-rebuttal: registered lane EXPORT-TABLE-FIX (hackenproof-plain-export.py + its test)
def _convert_markdown_tables(text: str) -> str:
    """Convert GFM markdown tables into plain-text labeled blocks.

    HackenProof plain-text has no table rendering, and a bare pipe->space
    collapse leaves an unreadable, unaligned mess plus a stray '--- --- ---'
    separator line. Instead, render each data row as a labeled block:

        | Defense | Code path | Result |
        |---|---|---|
        | gate X  | foo.sol:1 | wins  |
      ->
        - Defense: gate X
          Code path: foo.sol:1
          Result: wins

    (blank line between rows). Runs BEFORE the generic pipe-strip so real
    tables are handled cleanly; stray single-pipe lines still fall through.
    """
    def _is_row(s: str) -> bool:
        st = s.strip()
        return st.startswith("|") and st.endswith("|") and st.count("|") >= 2

    def _is_sep(s: str) -> bool:
        st = s.strip()
        return ("-" in st and "|" in st
                and re.match(r"^\|?[\s:|-]+\|?$", st) is not None)

    def _cells(s: str):
        st = s.strip()
        if st.startswith("|"):
            st = st[1:]
        if st.endswith("|"):
            st = st[:-1]
        return [c.strip() for c in st.split("|")]

    lines = text.split("\n")
    out = []
    i, n = 0, len(lines)
    while i < n:
        if _is_row(lines[i]) and i + 1 < n and _is_sep(lines[i + 1]):
            header = _cells(lines[i])
            j = i + 2
            rows = []
            while j < n and _is_row(lines[j]):
                rows.append(_cells(lines[j]))
                j += 1
            for r in rows:
                blk = []
                for k, h in enumerate(header):
                    val = r[k] if k < len(r) else ""
                    blk.append((f"- {h}: {val}" if k == 0 else f"  {h}: {val}"))
                out.append("\n".join(blk))
                out.append("")
            i = j
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def _strip_markdown(text: str) -> str:
    """Remove markdown formatting from text, converting to plain prose."""
    # Remove HTML comments (internal labels like <!-- r38-rebuttal: ... -->)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    # Markdown tables -> plain-text labeled blocks (BEFORE generic pipe-strip)
    text = _convert_markdown_tables(text)
    # Remove fenced code blocks - keep content, drop fences
    text = re.sub(r"^```[^\n]*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^```$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^~~~[^\n]*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"^~~~$", "", text, flags=re.MULTILINE)
    # Remove inline code backticks - keep content
    text = re.sub(r"`([^`]*)`", r"\1", text)
    # Remove triple backtick inline
    text = re.sub(r"```([^`]*)```", r"\1", text)
    # ATX headings -> plain text (strip #)
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    # Bold/italic: **text** __text__ *text* _text_
    # Only match when delimiters are at non-word-char boundaries (avoid snake_case identifiers)
    text = re.sub(r"\*\*([^*]+)\*\*", r"\1", text)
    text = re.sub(r"(?<!\w)__([^_]+)__(?!\w)", r"\1", text)
    # Italic *text*: require non-whitespace at delimiter inner-edges so arithmetic
    # like `u128::MAX * 5 + 7 -> ~u128::MAX * 0` is NOT eaten as one emphasis span.
    # Gap 19 fix (2026-05-25, DRILL-6 anchor).
    text = re.sub(r"(?<![*\w])\*(?!\s)([^*\n]+?)(?<!\s)\*(?![*\w])", r"\1", text)
    text = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"\1", text)
    # Links: [text](url) -> text (url)
    text = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", r"\1 (\2)", text)
    # Reference links: [text][ref] -> text
    text = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", text)
    # Bare URL angle brackets: <url>
    text = re.sub(r"<(https?://[^>]+)>", r"\1", text)
    # Strikethrough: ~~text~~
    text = re.sub(r"~~([^~]*)~~", r"\1", text)
    # Table rows: collapse pipes to spaces
    text = re.sub(r"^\|.*\|$", lambda m: re.sub(r"\|", "  ", m.group(0)).strip(), text, flags=re.MULTILINE)
    # Table separator lines: |---|---| -> blank
    text = re.sub(r"^\s*\|[-| :]+\|\s*$", "", text, flags=re.MULTILINE)
    # Horizontal rules
    text = re.sub(r"^(-{3,}|_{3,}|\*{3,})\s*$", "", text, flags=re.MULTILINE)
    # Blockquotes: > text -> text
    text = re.sub(r"^>\s?", "", text, flags=re.MULTILINE)
    # Ordered list markers: "1. ", "2. " etc - keep as "N. "
    # (already plain, no change needed)
    # Unordered list markers: "- " "* " "+ " -> keep "- " (already uses hyphen)
    text = re.sub(r"^\s*[*+]\s", "- ", text, flags=re.MULTILINE)
    # Collapse multiple blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def _looks_like_poc_source_block(lang: str, body: str) -> bool:
    """Heuristic for stripping inline PoC source blocks in hackenproof mode."""
    lang = (lang or "").strip().lower()
    source_langs = {
        "solidity", "sol", "rust", "rs", "move", "cairo", "vyper",
        "python", "py", "javascript", "js", "typescript", "ts",
        "go", "golang", "java", "c", "cpp", "c++",
    }
    transcript_langs = {"bash", "sh", "shell", "console", "text", "txt", "log"}
    if lang in source_langs:
        return True
    if lang in transcript_langs:
        return False

    # Unlabeled/unknown fences: strip only if source-like and not transcript-like.
    source_markers = [
        r"\b(contract|interface|library|struct|enum|impl|trait|fn|function|pragma|import)\b",
        r"[{};]{2,}",
        r"\b(assert|require|revert|return)\b",
    ]
    transcript_markers = [
        r"(?m)^\s*\$ ",
        r"(?m)^\s*(cargo|forge|cast|anvil|npm|pnpm|yarn|python|pytest|go test|curl|wget|make)\b",
        r"\brunning \d+ tests?\b",
        r"\btest result:\b",
    ]
    src_like = any(re.search(pat, body, flags=re.IGNORECASE) for pat in source_markers)
    transcript_like = any(re.search(pat, body, flags=re.IGNORECASE) for pat in transcript_markers)
    return src_like and not transcript_like


# r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE
def _strip_inline_poc_source_blocks(text: str) -> str:
    """Drop fenced source blocks while preserving surrounding narrative/transcript text."""
    fence_re = re.compile(r"(?ms)^(```|~~~)([^\n]*)\n(.*?)\n\1\s*$")

    def _repl(match):
        lang = match.group(2).strip()
        body = match.group(3)
        if _looks_like_poc_source_block(lang, body):
            return ""
        return match.group(0)

    return re.sub(fence_re, _repl, text)


# Threshold above which an inline source fence is summarised rather than kept.
_POC_SUMMARY_FENCE_LINES = 25

# Lines worth keeping verbatim from a transcript fence (invocation + result).
_KEEP_TRANSCRIPT_RE = re.compile(
    r"(?im)^\s*(\$\s+)?(cargo|forge|cast|anvil|npm|pnpm|yarn|python|pytest|go\s+test|make|curl|wget)\b"
    r"|^\s*running\s+\d+\s+tests?\b"
    r"|\btest result:\b"
    r"|\bSuite result:\s*ok\b"
    r"|^\s*ok\b"
    r"|\bexit\s+(code\s+)?0\b"
    r"|\b\d+\s+passed\b"
)

# Lines naming a test (fn / #[test] / test_*) - kept as "test names" in the summary.
_TEST_NAME_RE = re.compile(
    r"(?im)\b(?:fn|test|it|describe)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|#\[test\]"
    r"|\btest\s+([A-Za-z_][A-Za-z0-9_]*)\s+\.\.\.\s+ok\b"
)


def summarize_poc_for_zip(text: str, zip_files):
    """Replace large inline PoC SOURCE fences with a concise summary that references
    the attached -poc.zip.

    HackenProof convention: the runnable harness + transcript ship in the attached
    zip; the .txt PoC section is a concise description that references the attachment.

    For each fenced block over _POC_SUMMARY_FENCE_LINES lines that looks like full
    PoC source (fn / #[test] / contract / assert_ / pragma), replace it with:
      - the test names found in the block (if any),
      - a one-line "Full runnable harness + transcript: see attached <zip> (<files>)."

    Transcript-style fences (cargo/forge invocation, running N tests, result: ok)
    are NOT removed - they carry the load-bearing evidence the triager reads inline,
    but oversized transcript fences are trimmed to the invocation + result lines.

    Returns (transformed_text, summary_meta) where summary_meta lists the referenced
    zip + harness file names so the caller can verify they exist in the zip.
    """
    fence_re = re.compile(r"(?ms)^(```|~~~)([^\n]*)\n(.*?)\n\1\s*$")
    zip_name = None
    file_list = list(zip_files or [])
    for f in file_list:
        if f.lower().endswith("-poc.zip") or f.lower().endswith(".zip"):
            zip_name = f
            break
    # Names of harness/transcript files (drop the zip itself).
    attached_files = [f for f in file_list if f != zip_name]
    files_str = ", ".join(attached_files) if attached_files else "harness source + run.sh + transcript"
    zip_ref = zip_name or "<slug>-poc.zip"

    summarized = {"zip": zip_name, "summarized_blocks": 0, "harness_files": attached_files}

    def _summary_for(body: str) -> str:
        # Collect distinct test names.
        names = []
        for m in _TEST_NAME_RE.finditer(body):
            for g in m.groups():
                if g and g not in names:
                    names.append(g)
        lines = []
        if names:
            lines.append("PoC test(s): " + ", ".join(names[:12]) + ".")
        lines.append(
            f"Full runnable harness + transcript: see attached {zip_ref} ({files_str})."
        )
        return "\n".join(lines)

    def _trim_transcript(body: str) -> str:
        kept = [ln for ln in body.splitlines() if _KEEP_TRANSCRIPT_RE.search(ln)]
        if not kept:
            return body  # nothing recognisable; keep as-is
        return "\n".join(kept)

    def _repl(match):
        fence = match.group(1)
        lang = (match.group(2) or "").strip()
        body = match.group(3)
        line_count = body.count("\n") + 1
        if line_count <= _POC_SUMMARY_FENCE_LINES:
            return match.group(0)  # small fence: keep verbatim
        if _looks_like_poc_source_block(lang, body):
            # Large source fence -> concise summary + zip reference (no fence).
            summarized["summarized_blocks"] += 1
            return _summary_for(body)
        # Large transcript fence -> trim to invocation + result lines, keep fence.
        trimmed = _trim_transcript(body)
        if trimmed != body:
            return f"{fence}{(' ' + lang) if lang else ''}\n{trimmed}\n{fence}"
        return match.group(0)

    transformed = re.sub(fence_re, _repl, text)
    return transformed, summarized


# Internal-process labels to scrub from output
_INTERNAL_LABEL_PATTERNS = [
    # Gate rebuttals
    r"<!--\s*r\d+-rebuttal:[^>]*-->",
    r"<!--\s*l\d+-rebuttal:[^>]*-->",
    r"<!--\s*r30-rebuttal:[^>]*-->",
    # Severity/rubric fields
    r"^-\s*severity_tier:\s.*$",
    r"^-\s*listed_impact_proven:\s.*$",
    r"^-\s*evidence_class:\s.*$",
    r"^-\s*oos_traps:\s.*$",
    r"^-\s*stop_condition:\s.*$",
    r"^-\s*selected_impact:\s",
    r"^-?\s*attack_class:\s.*$",
    r"^-?\s*rubric_row:\s.*$",
    # Impact Contract section
    r"^##\s+Impact Contract\s*$",
    # Internal file paths
    r"submissions/(staging|paste_ready|held|superseded)/[^\s)]+",
    r"auditooor-mcp/[^\s)]+",
    r"~/audits/[^\s)]+",
    r"/Users/wolf/[^\s)]+",
    r"agent_outputs/[^\s)]+",
    # Agent/orchestrator labels
    r"\bcontext_pack_id\b[^\n]*",
    r"\bcontext_pack_hash\b[^\n]*",
    r"\borchestrator\b",
    r"\bWorker-[A-Z]+\b",
    r"\bnext-loop\b",
    r"\bTier-[0-9]\b",
    r"^\s*[-*+]?\s*(?:V3[- ]grade|[LR][0-9]{2}(?:[-_][A-Za-z0-9_-]+)?|MCP|vault_[A-Za-z0-9_]+|context_pack[A-Za-z0-9_]*|internal-(?:label|note|state|workflow)|agent[_-](?:loop|state|output|label|trace|worker))\s*[:=].*$",
    r"^\s*[-*+]?\s*(?:MCP\b.*\bvault_[A-Za-z0-9_]+|vault_[A-Za-z0-9_]+.*\bMCP\b).*$",
    r"^\s*[-*+]?\s*V3[- ]grade\b.*$",
    r"^\s*[-*+]?\s*lane(?:_name)?\s*:\s*.*$",
    r"^\s*[-*+]?\s*lane-[A-Za-z0-9_-]+\s*:\s*.*$",
    # V3 Gate Rebuttals section header
    r"^##\s+V3 Gate Rebuttals\s*$",
    # Verbatim rubric row section (internal boilerplate)
    r"^##\s+Verbatim rubric row.*$",
]


def _scrub_internal_labels(text: str) -> str:
    """Remove internal-process labels not intended for external consumption."""
    # Scrub entire named sections that are purely internal boilerplate
    _INTERNAL_SECTION_NAMES = [
        r"Impact Contract",
        r"V3 Gate Rebuttals?",
        r"Verbatim rubric row[^#\n]*",
    ]
    for sec_name in _INTERNAL_SECTION_NAMES:
        # Match the ## heading through the next ## heading (or end of string)
        text = re.sub(
            r"^##\s+" + sec_name + r"\s*\n.*?(?=^##\s|\Z)",
            "",
            text,
            flags=re.MULTILINE | re.DOTALL | re.IGNORECASE,
        )
    for pattern in _INTERNAL_LABEL_PATTERNS:
        text = re.sub(pattern, "", text, flags=re.MULTILINE | re.IGNORECASE)
    # Remove lines that are now empty after scrubbing (but preserve blank-line spacing)
    text = re.sub(r"^\s*\n", "\n", text, flags=re.MULTILINE)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def _to_ascii(text: str) -> str:
    """Ensure output is ASCII-only; replace known non-ASCII, then drop rest."""
    text = _replace_unicode(text)
    # Normalise to NFKD and drop combining chars
    normalised = unicodedata.normalize("NFKD", text)
    ascii_bytes = normalised.encode("ascii", errors="replace")
    return ascii_bytes.decode("ascii").replace("?", "")


def clean_text(text: str, platform: str = "generic", poc_zip_files=None) -> str:  # r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE
    """Full hygiene pipeline: scrub labels -> strip markdown -> ASCII-only.

    For platform='hackenproof': large inline PoC SOURCE fences are summarised
    into a concise zip-reference (PoC-to-zip transform) when poc_zip_files is
    provided; otherwise (no zip context) they are stripped outright. Either way
    the harness source does not survive inline in the HackenProof .txt.
    """
    if platform == "hackenproof":
        if poc_zip_files:
            text, _ = summarize_poc_for_zip(text, poc_zip_files)
        # Belt-and-suspenders: drop any large source fence the summary missed.
        text = _strip_inline_poc_source_blocks(text)
    text = _scrub_internal_labels(text)
    text = _strip_markdown(text)
    text = _to_ascii(text)
    text = text.strip()
    return text


# r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE
def _run_poc_not_inline_gate(txt_path: str):
    """Invoke the sibling hackenproof-poc-not-inline-check gate on the produced .txt.

    Returns the gate result dict, or None if the gate tool is unavailable.
    Keeps the export path from emitting a .txt that re-inlines the PoC harness or
    references a -poc.zip that is missing a harness file.
    """
    import importlib.util
    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "hackenproof-poc-not-inline-check.py")
    if not os.path.isfile(gate_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location("_hp_poc_not_inline_gate", gate_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.check(txt_path)
    except Exception:  # noqa: BLE001 - gate must never crash the export
        return None


# ---------------------------------------------------------------------------
# MD draft parser
# ---------------------------------------------------------------------------

def _split_sections(md: str) -> dict:
    """
    Split an auditooor MD draft into named section buckets keyed by their
    ## heading text (lowercased, stripped). The pseudo-key '_preamble' holds
    content before the first heading. Also parse the H1 title.
    """
    lines = md.splitlines(keepends=True)
    sections = {}
    current_key = "_preamble"
    current_lines = []
    h1_title = ""

    for line in lines:
        h1_match = re.match(r"^#\s+(.+)$", line)
        h2_match = re.match(r"^##\s+(.+)$", line)
        if h1_match and not h1_title:
            h1_title = h1_match.group(1).strip()
            current_lines.append(line)
        elif h2_match:
            sections[current_key] = "".join(current_lines)
            current_key = h2_match.group(1).strip().lower()
            current_lines = []
        else:
            current_lines.append(line)

    sections[current_key] = "".join(current_lines)
    return sections, h1_title


def _extract_title(sections: dict, h1_title: str, raw_md: str) -> str:
    """Extract the submission title from the draft."""
    # Prefer explicit 'Title:' field in preamble
    preamble = sections.get("_preamble", "")
    m = re.search(r"^-?\s*[Tt]itle:\s*(.+)$", preamble, re.MULTILINE)
    if m:
        return m.group(1).strip()
    # Fall back to H1
    if h1_title:
        return h1_title
    # Try first non-blank line
    for line in raw_md.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if stripped:
            return stripped
    return "Untitled"


# Section key sets that map to each HackenProof section

_VULN_KEYS = {
    "summary",
    "in-scope trigger / poisoned state creation path / root cause",
    "in-scope trigger",
    "root cause",
    "file:line and code analysis",
    "file:line",
    "code analysis",
    "production reachability",
    "production-reachability",
    "production path",
    "actor model",
    "actors",
    "impact",
    "impact path",
    "impact analysis",
    "scope notes",
    "scope and originality",
    "defenses considered",
    "defenses",
    "vulnerability details",
    "vulnerability",
    "description",
    "overview",
    "severity justification",
    "likelihood",
}

_VALIDATION_KEYS = {
    "proof of concept",
    "poc",
    "validation steps",
    "reproduction steps",
    "reproduction",
    "steps to reproduce",
    "test transcript",
    "transcript",
    "recommended fix",
    "recommended",
    "recommendation",
    "fix",
    "remediation",
}

_POC_FILE_KEYS = {
    "supporting files",
    "poc files",
    "attachments",
    "uploads",
}

# Sections that contain only internal-process metadata and MUST NOT appear in output
_ALWAYS_EXCLUDE_KEYS = {
    "impact contract",
    "v3 gate rebuttals",
    "verbatim rubric row",
    "v3 gate rebuttal",
}


def _collect_sections(sections: dict, key_set: set) -> str:
    """Collect all section bodies whose lowercased keys are in key_set."""
    parts = []
    for key, body in sections.items():
        key_lower = key.lower()
        # Always exclude internal-only sections
        if any(excl in key_lower for excl in _ALWAYS_EXCLUDE_KEYS):
            continue
        if key_lower in key_set or any(k in key_lower for k in key_set):
            if body.strip():
                parts.append(body.strip())
    return "\n\n".join(parts)


def _extract_poc_files(md: str) -> list:
    """
    Heuristic: find lines that look like file paths / upload instructions.
    Also captures explicit 'Upload:' or 'poc-tests/*.zip' patterns.
    """
    files = []
    # Allowed extensions per HackenProof
    ext_pattern = re.compile(
        r"\b[\w./-]+\.(bmp|gif|jpeg|jpg|png|pdf|mpeg|mp4|mov|csv|txt|zip|sol|rs|md|ts|go)\b",
        re.IGNORECASE,
    )
    # Look in the poc/supporting-files section first
    for key, body in _SECTION_CACHE.items() if hasattr(_extract_poc_files, '_cache') else []:
        pass

    for line in md.splitlines():
        m = ext_pattern.search(line)
        if m:
            candidate = m.group(0)
            # Skip internal tool paths
            if any(skip in candidate for skip in ("auditooor-mcp/", "/Users/wolf/", "submissions/")):
                continue
            if candidate not in files:
                files.append(candidate)
    return files[:5]  # HackenProof cap: 5 files


# r36-rebuttal: lane TASK-D-HP-OPTIMISM-REGEN declared in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
def _resolve_poc_zip_members(out_path: str) -> list:
    """Return [<zip-basename>, <member1>, <member2>, ...] for the -poc.zip that ships
    beside the .hackenproof-plain.txt output, or [] if no zip is found.

    The returned list feeds the PoC-to-zip summary's "(files)" parenthetical so it
    lists the REAL attachment contents, not source-citation tokens scraped from prose.
    """
    import glob as _glob
    import zipfile as _zipfile

    out_dir = os.path.dirname(os.path.abspath(out_path))
    base = os.path.basename(out_path)
    slug = base[: -len(".hackenproof-plain.txt")] if base.endswith(".hackenproof-plain.txt") else None

    candidates = []
    if slug:
        cand = os.path.join(out_dir, f"{slug}-poc.zip")
        if os.path.isfile(cand):
            candidates.append(cand)
    if not candidates:
        candidates = sorted(_glob.glob(os.path.join(out_dir, "*-poc.zip"))) or \
                     sorted(_glob.glob(os.path.join(out_dir, "*.zip")))
    if not candidates:
        return []
    zip_path = candidates[0]
    try:
        with _zipfile.ZipFile(zip_path) as zf:
            members = [os.path.basename(m) for m in zf.namelist() if not m.endswith("/")]
    except (OSError, _zipfile.BadZipFile):
        return []
    return [os.path.basename(zip_path)] + members


def parse_draft(md: str) -> dict:
    """
    Parse the MD draft and return a dict with:
      title, vuln_details_raw, validation_raw, poc_files
    """
    sections, h1_title = _split_sections(md)
    title = _extract_title(sections, h1_title, md)

    # Build vuln details: summary + root cause + file:line + actors + impact + scope + defenses
    vuln_raw = _collect_sections(sections, _VULN_KEYS)
    if not vuln_raw.strip():
        # Fall back: everything except preamble, PoC, and always-excluded sections
        exclude = _VALIDATION_KEYS | _POC_FILE_KEYS | _ALWAYS_EXCLUDE_KEYS | {"_preamble"}
        parts = []
        for key, body in sections.items():
            if key.lower() not in exclude and not any(excl in key.lower() for excl in _ALWAYS_EXCLUDE_KEYS) and body.strip():
                parts.append(body.strip())
        vuln_raw = "\n\n".join(parts)

    # Build validation steps: PoC + transcript + recommended fix
    valid_raw = _collect_sections(sections, _VALIDATION_KEYS)

    # Extract PoC files from the whole document
    poc_files = _extract_poc_files(md)

    return {
        "title": title,
        "vuln_details_raw": vuln_raw,
        "validation_raw": valid_raw,
        "poc_files": poc_files,
    }


# ---------------------------------------------------------------------------
# Char-limit enforcement
# ---------------------------------------------------------------------------

def check_limits(s2: str, s3: str) -> dict:
    c2 = len(s2)
    c3 = len(s3)
    return {
        "section2_chars": c2,
        "section3_chars": c3,
        "section2_over_limit": c2 > SECTION_LIMIT,
        "section3_over_limit": c3 > SECTION_LIMIT,
        "section2_overage": max(0, c2 - SECTION_LIMIT),
        "section3_overage": max(0, c3 - SECTION_LIMIT),
    }


# ---------------------------------------------------------------------------
# Residue checks
# ---------------------------------------------------------------------------

def check_residue(text: str) -> dict:
    """Check for markdown or non-ASCII residue in output text."""
    has_markdown = bool(re.search(r"[#*`]|^\|", text, re.MULTILINE))
    non_ascii_chars = [ch for ch in text if ord(ch) > 127]
    return {
        "has_markdown_residue": has_markdown,
        "non_ascii_count": len(non_ascii_chars),
        "non_ascii_sample": non_ascii_chars[:5],
    }


# ---------------------------------------------------------------------------
# Output assembly
# ---------------------------------------------------------------------------

def build_plain_text(title: str, s2: str, s3: str, poc_files: list) -> str:
    """Assemble the 4-section HackenProof plain-text output."""
    file_block = ""
    if poc_files:
        file_block = "\n".join(f"- {f}" for f in poc_files)
    else:
        file_block = "(No specific files identified in draft - attach PoC archive manually)"

    return (
        f"1. Title\n\n{title}\n\n"
        f"2. Vulnerability details\n\n{s2}\n\n"
        f"3. Validation steps\n\n{s3}\n\n"
        f"4. Supporting files / PoC\n\n{file_block}\n"
    )


# ---------------------------------------------------------------------------
# JSON schema
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.hackenproof_plain_export.v1"


def build_json(title: str, s2: str, s3: str, poc_files: list,
               limits: dict, residue: dict) -> dict:
    return {
        "schema": SCHEMA,
        "title": title,
        "section2_chars": limits["section2_chars"],
        "section3_chars": limits["section3_chars"],
        "section2_over_limit": limits["section2_over_limit"],
        "section3_over_limit": limits["section3_over_limit"],
        "section2_overage": limits["section2_overage"],
        "section3_overage": limits["section3_overage"],
        "has_markdown_residue": residue["has_markdown_residue"],
        "non_ascii_count": residue["non_ascii_count"],
        "poc_files": poc_files,
    }


# ---------------------------------------------------------------------------
# Validation of an already-written plain-text file
# ---------------------------------------------------------------------------

VALIDATE_SCHEMA = "auditooor.hackenproof_plain_validate.v1"

_SECTION_HEADERS = [
    "1. Title",
    "2. Vulnerability details",
    "3. Validation steps",
    "4. Supporting files / PoC",
]

# Internal labels that must never leak into a submitted .txt
_LEAK_PATTERNS = [
    (r"<!--", "html-comment"),
    (r"/Users/wolf/", "absolute-user-path"),
    (r"\bcontext_pack_id\b", "context-pack-id"),
    (r"\bcontext_pack_hash\b", "context-pack-hash"),
    (r"\bRG-[A-Z0-9]", "internal-finding-label"),
    (r"\bWorker-[A-Z]", "worker-label"),
    (r"agent_outputs/", "agent-outputs-path"),
    (r"\borchestrator\b", "orchestrator-label"),
    (r"\bnext-loop\b", "next-loop-label"),
    (r"r\d{2}-rebuttal\s*:", "gate-rebuttal-marker"),
    (r"l\d{2}-rebuttal\s*:", "gate-rebuttal-marker"),
    (r"(?m)^\s*[-*+]?\s*V3[- ]grade\b.*$", "v3-grade-internal-label"),
    (r"(?m)^\s*[-*+]?\s*(?:MCP\b.*\bvault_[A-Za-z0-9_]+|vault_[A-Za-z0-9_]+.*\bMCP\b).*$", "mcp-vault-internal-label"),
    (r"(?m)^\s*[-*+]?\s*(?:context_pack[A-Za-z0-9_]*|agent[_-](?:loop|state|output|label|trace|worker)|internal-(?:label|note|state|workflow))\s*[:=]", "internal-metadata-label"),
    (r"(?m)^\s*[-*+]?\s*lane(?:_name)?\s*:", "lane-metadata-label"),
    (r"(?m)^\s*[-*+]?\s*lane-[A-Za-z0-9_-]+\s*:", "lane-metadata-label"),
]


def validate_plain_text(path: str) -> dict:
    """
    Validate a finished HackenProof plain-text submission file.
    Returns a result dict; `ok` is True only when every check passes.
    """
    failures = []
    warnings = []

    with open(path, "r", encoding="utf-8") as f:
        text = f.read()

    # 1. Four section headers, present and in order.
    positions = []
    for hdr in _SECTION_HEADERS:
        m = re.search(r"(?m)^" + re.escape(hdr) + r"\s*$", text)
        positions.append(m.start() if m else -1)
    for hdr, pos in zip(_SECTION_HEADERS, positions):
        if pos == -1:
            failures.append(f"missing section header: '{hdr}'")
    ordered = [p for p in positions if p != -1]
    if ordered and ordered != sorted(ordered):
        failures.append("section headers are out of order")

    # 2. Section 2 and 3 body char counts.
    s2_chars = s3_chars = -1
    if all(p != -1 for p in positions):
        bounds = positions + [len(text)]
        s2_chars = bounds[2] - bounds[1]
        s3_chars = bounds[3] - bounds[2]
        if s2_chars > SECTION_LIMIT:
            failures.append(
                f"section 2 (Vulnerability details) is {s2_chars} chars, "
                f"over the {SECTION_LIMIT} limit by {s2_chars - SECTION_LIMIT}")
        if s3_chars > SECTION_LIMIT:
            failures.append(
                f"section 3 (Validation steps) is {s3_chars} chars, "
                f"over the {SECTION_LIMIT} limit by {s3_chars - SECTION_LIMIT}")

    # 3. ASCII-only (em/en dashes and smart quotes count as non-ASCII).
    non_ascii = sorted({ch for ch in text if ord(ch) > 127})
    if non_ascii:
        failures.append(
            "non-ASCII characters present: "
            + " ".join(f"U+{ord(c):04X}" for c in non_ascii[:8]))

    # 4. Markdown residue: ATX headings, code fences, pipe tables, bold markers.
    if re.search(r"(?m)^#{1,6}\s", text):
        failures.append("markdown heading (#) residue")
    if re.search(r"(?m)^```", text) or re.search(r"(?m)^~~~", text):
        failures.append("markdown code-fence residue")
    if re.search(r"(?m)^\s*\|.*\|\s*$", text):
        failures.append("markdown pipe-table residue")
    if re.search(r"\*\*[^*\n]+\*\*", text):
        failures.append("markdown bold (**) residue")

    # 5. Internal-label leaks.
    for pat, label in _LEAK_PATTERNS:
        if re.search(pat, text):
            failures.append(f"internal-label leak: {label}")

    # Advisory: a near-limit section.
    for n, c in (("2", s2_chars), ("3", s3_chars)):
        if 0 < c <= SECTION_LIMIT and c > SECTION_LIMIT - 300:
            warnings.append(f"section {n} is within 300 chars of the limit ({c})")

    return {
        "schema": VALIDATE_SCHEMA,
        "path": path,
        "ok": not failures,
        "section2_chars": s2_chars,
        "section3_chars": s3_chars,
        "non_ascii_count": len(non_ascii),
        "failures": failures,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Export an auditooor paste-ready MD draft to HackenProof 4-section plain-text format."
    )
    parser.add_argument("--draft", help="Path to the paste-ready MD draft file (export mode).")
    parser.add_argument("--validate", help="Path to a finished .txt to validate (validate mode).")
    parser.add_argument("--out", help="Output path for the plain-text file. Defaults to <draft>.hackenproof-plain.txt")
    parser.add_argument("--json", action="store_true", dest="emit_json",
                        help="Also write a JSON sidecar (export) or print the JSON result (validate).")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero if any section exceeds 10000 chars (export) or any check fails (validate).")
    parser.add_argument("--platform", choices=["generic", "hackenproof"], default="generic",
                        help="Export cleaning mode. Use 'hackenproof' to strip inline PoC source blocks.")
    args = parser.parse_args()

    if bool(args.draft) == bool(args.validate):
        print("ERROR: pass exactly one of --draft (export) or --validate (check a finished .txt)",
              file=sys.stderr)
        sys.exit(1)

    # --- Validate mode -----------------------------------------------------
    if args.validate:
        vpath = os.path.abspath(args.validate)
        if not os.path.isfile(vpath):
            print(f"ERROR: file not found: {vpath}", file=sys.stderr)
            sys.exit(1)
        result = validate_plain_text(vpath)
        if args.emit_json:
            print(json.dumps(result, indent=2))
        else:
            tag = "PASS" if result["ok"] else "FAIL"
            print(f"[{tag}] {vpath}")
            print(f"  section 2: {result['section2_chars']} chars   "
                  f"section 3: {result['section3_chars']} chars   "
                  f"(limit {SECTION_LIMIT})")
            for w in result["warnings"]:
                print(f"  warning: {w}")
            for fail in result["failures"]:
                print(f"  FAIL: {fail}")
        if args.strict and not result["ok"]:
            sys.exit(2)
        sys.exit(0 if result["ok"] else 1)

    # --- Export mode -------------------------------------------------------
    draft_path = os.path.abspath(args.draft)
    if not os.path.isfile(draft_path):
        print(f"ERROR: draft file not found: {draft_path}", file=sys.stderr)
        sys.exit(1)

    with open(draft_path, "r", encoding="utf-8") as f:
        md = f.read()

    parsed = parse_draft(md)  # r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE
    poc_files = parsed["poc_files"]

    # r36-rebuttal: lane TASK-D-HP-OPTIMISM-REGEN declared in .auditooor/agent_pathspec.json
    # Determine output path early so the PoC-to-zip summary references the REAL zip members.
    if args.out:
        out_path = os.path.abspath(args.out)
    else:
        base = draft_path[:-3] if draft_path.endswith(".md") else draft_path
        out_path = base + ".hackenproof-plain.txt"

    # For HackenProof, the harness file list cited in the "see attached <zip> (...)"
    # summary must be the ACTUAL contents of the -poc.zip that ships with the finding,
    # not arbitrary *.ext tokens scraped from prose (those are source citations like
    # lib.rs:185 / request.rs:87, NOT attachment files). Resolve the zip beside the
    # output and prefer its real members.
    if args.platform == "hackenproof":
        zip_members = _resolve_poc_zip_members(out_path)
        if zip_members:
            poc_files = zip_members

    title = clean_text(parsed["title"], platform=args.platform)
    s2 = clean_text(parsed["vuln_details_raw"], platform=args.platform, poc_zip_files=poc_files)
    # PoC lives in section 3 (validation steps): apply the PoC-to-zip summary so the
    # harness source references the attachment instead of being inlined.
    s3 = clean_text(parsed["validation_raw"], platform=args.platform, poc_zip_files=poc_files)

    limits = check_limits(s2, s3)
    residue = check_residue(s2 + "\n" + s3)

    plain = build_plain_text(title, s2, s3, poc_files)

    # out_path was resolved above (early) so the PoC-to-zip summary could reference the
    # real zip members. r36-rebuttal: lane TASK-D-HP-OPTIMISM-REGEN.
    with open(out_path, "w", encoding="utf-8") as f:  # r36-rebuttal: lane TASK-B-HP-POC-NOT-INLINE
        f.write(plain)

    # PoC-not-inline gate (HackenProof only): a bad export must not be produced.
    # Fail loudly if the harness was re-inlined, or a referenced PoC file is missing
    # from the attached -poc.zip.
    if args.platform == "hackenproof" and out_path.endswith(".hackenproof-plain.txt"):
        gate = _run_poc_not_inline_gate(out_path)
        if gate is not None and not gate.get("ok", True):
            print(f"ERROR: HackenProof PoC-not-inline gate failed: "
                  f"{gate.get('verdict')}: {gate.get('detail')}", file=sys.stderr)
            sys.exit(3)

    print(f"Written: {out_path}")
    print(f"Section 2 (Vulnerability details): {limits['section2_chars']} chars", end="")
    if limits["section2_over_limit"]:
        print(f"  WARNING: OVER LIMIT by {limits['section2_overage']} chars")
    else:
        print(" [OK]")
    print(f"Section 3 (Validation steps):      {limits['section3_chars']} chars", end="")
    if limits["section3_over_limit"]:
        print(f"  WARNING: OVER LIMIT by {limits['section3_overage']} chars")
    else:
        print(" [OK]")

    if residue["has_markdown_residue"]:
        print("WARNING: markdown residue detected in output (# * ` or | at line start)")
    if residue["non_ascii_count"] > 0:
        print(f"WARNING: {residue['non_ascii_count']} non-ASCII characters in output")

    if args.emit_json:
        sidecar = build_json(title, s2, s3, poc_files, limits, residue)
        json_path = out_path.replace(".txt", ".json") if out_path.endswith(".txt") else out_path + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(sidecar, f, indent=2)
        print(f"JSON sidecar: {json_path}")

    # Strict mode: exit non-zero on over-limit
    if args.strict and (limits["section2_over_limit"] or limits["section3_over_limit"]):
        over_secs = []
        if limits["section2_over_limit"]:
            over_secs.append(f"Section 2 (+{limits['section2_overage']} chars)")
        if limits["section3_over_limit"]:
            over_secs.append(f"Section 3 (+{limits['section3_overage']} chars)")
        print(f"STRICT MODE FAIL: {', '.join(over_secs)} exceed 10000-char limit", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
