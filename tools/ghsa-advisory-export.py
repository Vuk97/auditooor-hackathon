#!/usr/bin/env python3
# r36-rebuttal: lane ZEBRA-GHSA-EXPORT registered in .auditooor/agent_pathspec.json
"""
ghsa-advisory-export.py
Rule 37 emit tier: tool utility (no corpus record emitted)

Convert an auditooor GHSA-format paste-ready MD submission draft into the
artifacts a GitHub Security Advisory (private "Report a vulnerability") needs:
a plain-text advisory body (.advisory.txt) and a structured JSON sidecar
(.advisory.json) mirroring the GHSA submission form fields.

Mirrors tools/hackenproof-plain-export.py but targets the GHSA form shape
documented in docs/GHSA_ZEBRA_PASTE_TEMPLATE.md:

  - Title (one line, impact-forward)
  - Description = 4 fixed sections rendered as markdown:
        ### Summary / ### Details / ### PoC / ### Impact
  - Affected products: ecosystem, package, affected versions, patched versions
  - Severity: a CVSS:3.1 vector string + severity band
  - Weaknesses: >=1 CWE id

Usage:
  python3 tools/ghsa-advisory-export.py --draft <path.md> [--out <path>] [--json] [--strict]
  python3 tools/ghsa-advisory-export.py --validate <path.advisory.txt> [--json] [--strict]

--draft    : parse the MD draft and emit <draft>.advisory.txt (+ .advisory.json
             with --json). The .txt is the maintainer-facing advisory body
             (Title + the 4 markdown sections); the .json carries the structured
             Affected-products / Severity / Weaknesses fields for the form.
             ALSO emits <draft>.advisory.md by default: a pure-markdown paste
             (GitHub "Report a vulnerability" renders markdown and wants the
             PoC INLINE) that is a filtered passthrough of the source draft -
             leading HTML-comment rebuttal markers stripped, internal gate-only
             sections (## Originality / ## Prior-Audit Supersede Scan /
             ## Rubric Row Mapping / ## Escalate-First Attempt) dropped, PoC
             kept inline (NO PoC-to-zip transform - that is HackenProof-only).
             Use --no-md to suppress the .advisory.md emit.
--validate : check an emitted/hand-edited advisory body has the 4 sections in
             order, a CVSS:3.1 vector, and >=1 CWE.

--strict exits non-zero on a structural failure (missing section, no CVSS
vector, no CWE, internal-label residue).
"""

import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Text hygiene (shared shape with hackenproof-plain-export)
# ---------------------------------------------------------------------------

_UNICODE_REPLACEMENTS = {
    "—": "-",   # em-dash
    "–": "-",   # en-dash
    "‒": "-",   # figure dash
    "‐": "-",   # hyphen (Unicode)
    "‑": "-",   # non-breaking hyphen
    "‘": "'",   # left single quote
    "’": "'",   # right single quote
    "“": '"',   # left double quote
    "”": '"',   # right double quote
    "…": "...", # ellipsis
    " ": " ",   # non-breaking space
    "​": "",    # zero-width space
    "‌": "",    # zero-width non-joiner
    "‍": "",    # zero-width joiner
    "﻿": "",    # BOM
}


def _replace_unicode(text: str) -> str:
    for ch, rep in _UNICODE_REPLACEMENTS.items():
        text = text.replace(ch, rep)
    return text


# HTML-comment markers (l34-rebuttal / escalation-rebuttal / r*-rebuttal) and
# other internal-only residue that must not leak into a maintainer-facing body.
_INTERNAL_LINE_PATTERNS = [
    re.compile(r"^\s*<!--.*?-->\s*$"),                          # whole-line HTML comment
    re.compile(r"\bcontext_pack_id\b.*$"),
    re.compile(r"\bcontext_pack_hash\b.*$"),
    re.compile(r"\bWorker-[A-Z]+\b"),
]

# Internal-only sections to drop from the maintainer-facing body. These exist
# in the draft for the toolkit gates (R47/R52/R53/Check #127) but are not part
# of the GHSA advisory itself.
_INTERNAL_SECTION_HEADERS = (
    "originality",
    "prior-audit supersede scan",
    "prior audit supersede scan",
    "rubric row mapping",
    "escalate-first attempt",
)


def _strip_internal_comments(text: str) -> str:
    out = []
    for line in text.split("\n"):
        if any(p.match(line) or p.search(line) for p in _INTERNAL_LINE_PATTERNS):
            continue
        out.append(line)
    return "\n".join(out)


def clean_text(text: str) -> str:
    text = _replace_unicode(text)
    text = _strip_internal_comments(text)
    # collapse >2 blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ---------------------------------------------------------------------------
# .advisory.md : pure-markdown paste for GitHub GHSA "Report a vulnerability"
# (markdown is rendered; the PoC stays INLINE - the opposite of HackenProof's
# PoC-in-zip). This is a FILTERED PASSTHROUGH of the source draft, NOT a
# re-render from parsed fields, so author-formatted markdown (tables, fenced
# code, inline transcripts) is preserved byte-for-byte minus the filtered bits.
# ---------------------------------------------------------------------------

# `##` section headers whose whole block must be dropped from the .advisory.md
# paste. These are toolkit-gate evidence sections (R47/R52/R53/Rule-14), not
# GHSA form fields. They remain in the source draft; only the paste omits them.
_INTERNAL_MD_SECTION_RE = re.compile(
    r"^##\s+("
    r"originality"
    r"|prior[- ]audit\s+supersede\s+scan"
    r"|rubric\s+row\s+mapping"
    r"|escalate[- ]first\s+attempt"
    r")\b",
    re.IGNORECASE,
)


def _strip_leading_html_comments(md: str) -> str:
    """Drop every standalone HTML-comment line anywhere in the body.

    GHSA renders markdown; HTML comments would not display but they are still
    internal rebuttal-marker residue and must not ship. We drop any line that is
    wholly an HTML comment (single-line or the lines of a multi-line comment),
    but only OUTSIDE fenced code blocks so a `<!-- ... -->` inside a ```code```
    fence (e.g. an HTML snippet in a PoC) is preserved.
    """
    out = []
    in_fence = False
    fence_re = re.compile(r"^\s*(```|~~~)")
    # multi-line HTML comment state
    in_comment = False
    for line in md.split("\n"):
        if fence_re.match(line):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        stripped = line.strip()
        if in_comment:
            # inside a multi-line comment; drop until we see the closer
            if "-->" in stripped:
                in_comment = False
            continue
        if stripped.startswith("<!--"):
            if "-->" in stripped:
                # whole single-line comment -> drop
                continue
            # opener without closer on this line -> enter multi-line drop
            in_comment = True
            continue
        out.append(line)
    return "\n".join(out)


def _drop_internal_md_sections(md: str) -> str:
    """Remove every internal `## <gate>` section block (header -> next `## `)."""
    lines = md.split("\n")
    out = []
    in_fence = False
    fence_re = re.compile(r"^\s*(```|~~~)")
    dropping = False
    for line in lines:
        if fence_re.match(line):
            in_fence = not in_fence
            if not dropping:
                out.append(line)
            continue
        if in_fence:
            if not dropping:
                out.append(line)
            continue
        if line.startswith("## "):
            if _INTERNAL_MD_SECTION_RE.match(line):
                dropping = True
                continue
            # any other `## ` header ends a drop region and is kept
            dropping = False
            out.append(line)
            continue
        if dropping:
            continue
        out.append(line)
    return "\n".join(out)


def build_advisory_md(md: str) -> str:
    """Build the pure-markdown GHSA paste from the raw source draft markdown.

    Filtered passthrough: strip Unicode dashes/quotes, strip standalone HTML
    comments (outside code fences), drop internal gate-only `##` sections,
    collapse >2 blank lines. The PoC body and all fenced code stay INLINE.
    """
    md = _replace_unicode(md)
    md = _strip_leading_html_comments(md)
    md = _drop_internal_md_sections(md)
    md = re.sub(r"\n{3,}", "\n\n", md)
    return md.strip() + "\n"


# ---------------------------------------------------------------------------
# Draft parsing
# ---------------------------------------------------------------------------

_SECTION_KEYS = ["summary", "details", "poc", "impact"]


def _first_h1(md: str) -> str:
    for line in md.split("\n"):
        s = line.strip()
        if s.startswith("# ") and not s.startswith("## "):
            return s[2:].strip()
    return ""


def _explicit_title(md: str) -> str:
    """Honor a `**Title:** ...` line if present (template uses it)."""
    m = re.search(r"^\s*\*\*Title:?\*\*\s*(.+?)\s*$", md, re.MULTILINE)
    if m:
        return m.group(1).strip().strip("`")
    return ""


def _extract_sections(md: str):
    """Pull the 4 `### Summary/Details/PoC/Impact` blocks (case-insensitive)."""
    sections = {k: "" for k in _SECTION_KEYS}
    # Match level-3 headers; capture body until the next level-1/2/3 header.
    header_re = re.compile(r"^###\s+(.+?)\s*$", re.MULTILINE)
    matches = list(header_re.finditer(md))
    for i, m in enumerate(matches):
        name = m.group(1).strip().lower()
        body_start = m.end()
        body_end = matches[i + 1].start() if i + 1 < len(matches) else len(md)
        # but stop early at a level-1/2 header inside the body
        body = md[body_start:body_end]
        h12 = re.search(r"^#{1,2}\s+\S", body, re.MULTILINE)
        if h12:
            body = body[: h12.start()]
        key = None
        if name.startswith("summary"):
            key = "summary"
        elif name.startswith("details"):
            key = "details"
        elif name.startswith("poc") or "proof of concept" in name:
            key = "poc"
        elif name.startswith("impact"):
            key = "impact"
        if key and not sections[key]:
            sections[key] = body.strip()
    return sections


def _extract_affected(md: str):
    """Parse the `## Affected products` block."""
    out = {"ecosystem": "", "package": "", "affected_versions": "",
           "patched_versions": ""}
    block = _section_block(md, "Affected products")
    if not block:
        return out
    patterns = {
        "ecosystem": r"\*\*Ecosystem:?\*\*\s*(.+)",
        "package": r"\*\*Package name:?\*\*\s*(.+)",
        "affected_versions": r"\*\*Affected versions:?\*\*\s*(.+)",
        "patched_versions": r"\*\*Patched versions:?\*\*\s*(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, block)
        if m:
            # take just the first line / clause
            val = m.group(1).strip()
            val = val.split("\n")[0].strip()
            out[key] = val
    return out


def _extract_cvss(md: str) -> str:
    m = re.search(r"CVSS:3\.1/(?:[A-Z]{1,2}:[A-Z](?:/)?)+", md)
    return m.group(0).rstrip("/") if m else ""


def _extract_severity_band(md: str) -> str:
    m = re.search(r"\*\*Severity band:?\*\*\s*([A-Za-z]+)", md)
    if m:
        return m.group(1).strip()
    # fallback: severity in title slug
    for band in ("Critical", "High", "Medium", "Moderate", "Low"):
        if re.search(rf"\b{band}\b", md):
            return band
    return ""


def _extract_cwes(md: str):
    return sorted(set(re.findall(r"CWE-\d+", md)), key=lambda s: int(s.split("-")[1]))


def _section_block(md: str, header_name: str) -> str:
    """Return the body of a `## <header_name>` block."""
    pat = re.compile(rf"^##\s+{re.escape(header_name)}\s*$", re.MULTILINE | re.IGNORECASE)
    m = pat.search(md)
    if not m:
        return ""
    start = m.end()
    nxt = re.search(r"^##\s+\S", md[start:], re.MULTILINE)
    return md[start:start + nxt.start()].strip() if nxt else md[start:].strip()


def parse_draft(md: str):
    title = _explicit_title(md) or _first_h1(md)
    sections = _extract_sections(md)
    affected = _extract_affected(md)
    return {
        "title": title,
        "sections": sections,
        "affected": affected,
        "cvss": _extract_cvss(md),
        "severity_band": _extract_severity_band(md),
        "cwes": _extract_cwes(md),
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def build_advisory_body(parsed) -> str:
    title = clean_text(parsed["title"])
    s = parsed["sections"]
    parts = [f"# {title}", ""]
    for key, head in (("summary", "Summary"), ("details", "Details"),
                      ("poc", "PoC"), ("impact", "Impact")):
        body = clean_text(s.get(key, ""))
        parts.append(f"### {head}")
        parts.append(body if body else "(missing)")
        parts.append("")
    return "\n".join(parts).strip() + "\n"


def build_json(parsed):
    return {
        "schema": "auditooor.ghsa_advisory_export.v1",
        "title": clean_text(parsed["title"]),
        "summary": clean_text(parsed["sections"].get("summary", "")),
        "details": clean_text(parsed["sections"].get("details", "")),
        "poc": clean_text(parsed["sections"].get("poc", "")),
        "impact": clean_text(parsed["sections"].get("impact", "")),
        "affected_products": {
            "ecosystem": parsed["affected"]["ecosystem"],
            "package": parsed["affected"]["package"],
            "affected_versions": parsed["affected"]["affected_versions"],
            "patched_versions": parsed["affected"]["patched_versions"],
        },
        "severity": {
            "band": parsed["severity_band"],
            "cvss_v3_vector": parsed["cvss"],
        },
        "weaknesses": parsed["cwes"],
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_advisory(parsed, body: str):
    failures = []
    warnings = []
    for key in _SECTION_KEYS:
        if not parsed["sections"].get(key):
            failures.append(f"missing/empty section: {key}")
    if not parsed["cvss"]:
        failures.append("no CVSS:3.1 vector string found")
    if not parsed["cwes"]:
        failures.append("no CWE id found (>=1 required)")
    aff = parsed["affected"]
    if not aff["ecosystem"]:
        warnings.append("affected products: ecosystem missing")
    if not aff["package"]:
        warnings.append("affected products: package name missing")
    if not aff["affected_versions"]:
        warnings.append("affected products: affected versions missing")
    # residue check on the emitted body
    if re.search(r"<!--.*?-->", body):
        failures.append("internal HTML-comment residue in advisory body")
    if re.search(r"\bcontext_pack_id\b|\bcontext_pack_hash\b|\bWorker-[A-Z]", body):
        failures.append("internal-label residue in advisory body")
    for h in _INTERNAL_SECTION_HEADERS:
        if re.search(rf"###\s+{re.escape(h)}", body, re.IGNORECASE):
            failures.append(f"internal section leaked into body: {h}")
    return {"ok": not failures, "failures": failures, "warnings": warnings}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Export an auditooor GHSA-format MD draft to a GitHub "
                    "Security Advisory body (.advisory.txt) + JSON sidecar.")
    parser.add_argument("--draft", help="Path to the GHSA-format MD draft (export mode).")
    parser.add_argument("--validate", help="Path to an emitted advisory body to validate.")
    parser.add_argument("--out", help="Output path. Default <draft>.advisory.txt")
    parser.add_argument("--json", action="store_true", dest="emit_json",
                        help="Also write/print the JSON sidecar.")
    parser.add_argument("--no-md", action="store_true", dest="no_md",
                        help="Suppress the default <draft>.advisory.md (markdown "
                             "paste) emit; only write the .advisory.txt.")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero on any structural failure.")
    args = parser.parse_args(argv)

    if bool(args.draft) == bool(args.validate):
        print("ERROR: pass exactly one of --draft or --validate", file=sys.stderr)
        return 1

    target = args.draft or args.validate
    path = os.path.abspath(target)
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 1

    with open(path, "r", encoding="utf-8") as f:
        md = f.read()

    parsed = parse_draft(md)
    body = build_advisory_body(parsed)
    result = validate_advisory(parsed, body)

    # --- Validate mode ---
    if args.validate:
        if args.emit_json:
            print(json.dumps({"ok": result["ok"], **build_json(parsed),
                              "failures": result["failures"],
                              "warnings": result["warnings"]}, indent=2))
        else:
            tag = "PASS" if result["ok"] else "FAIL"
            print(f"[{tag}] {path}")
            for w in result["warnings"]:
                print(f"  warning: {w}")
            for fl in result["failures"]:
                print(f"  FAIL: {fl}")
        if args.strict and not result["ok"]:
            return 2
        return 0 if result["ok"] else 1

    # --- Export mode ---
    if args.out:
        out_path = os.path.abspath(args.out)
    else:
        base = path[:-3] if path.endswith(".md") else path
        out_path = base + ".advisory.txt"

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(body)
    print(f"Written: {out_path}")

    # Pure-markdown GHSA paste (PoC inline) - default unless --no-md.
    if not args.no_md:
        md_body = build_advisory_md(md)
        if out_path.endswith(".advisory.txt"):
            md_path = out_path[: -len(".txt")] + ".md"
        elif out_path.endswith(".txt"):
            md_path = out_path[:-4] + ".advisory.md"
        else:
            md_path = out_path + ".advisory.md"
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_body)
        print(f"Markdown paste: {md_path}")

    sidecar = build_json(parsed)
    print(f"Title: {sidecar['title']}")
    print(f"Ecosystem/Package: {sidecar['affected_products']['ecosystem']} / "
          f"{sidecar['affected_products']['package']}")
    print(f"Affected: {sidecar['affected_products']['affected_versions']}  "
          f"Patched: {sidecar['affected_products']['patched_versions']}")
    print(f"CVSS: {sidecar['severity']['cvss_v3_vector']}  "
          f"Band: {sidecar['severity']['band']}")
    print(f"CWEs: {', '.join(sidecar['weaknesses']) or '(none)'}")
    for w in result["warnings"]:
        print(f"  warning: {w}")
    for fl in result["failures"]:
        print(f"  FAIL: {fl}")

    if args.emit_json:
        json_path = (out_path[:-4] + ".json") if out_path.endswith(".txt") else out_path + ".json"
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(sidecar, f, indent=2)
        print(f"JSON sidecar: {json_path}")

    if args.strict and not result["ok"]:
        print(f"STRICT MODE FAIL: {len(result['failures'])} failure(s)", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
