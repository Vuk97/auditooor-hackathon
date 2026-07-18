#!/usr/bin/env python3
"""
audit-pdf-to-patterns.py — Phase D corpus mining tool.

Discovers audit reports (PDF or pre-extracted .txt siblings) across
known workspace directories, extracts candidate finding patterns, and
emits *.yaml.candidate files under reference/patterns.dsl/r99_pdf_mined/.

Usage:
    python3 tools/audit-pdf-to-patterns.py [options]

Options:
    --input-dir DIR   Additional input directories (repeatable)
    --out-dir DIR     Output directory (default: reference/patterns.dsl/r99_pdf_mined)
    --min-pdfs N      Exit 1 if fewer than N source files found (default: 10)
    --min-candidates N  Exit 1 if fewer than N candidates extracted (default: 30)
    --quiet           Suppress progress output
"""

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime, timezone

SKIP_DIRS = {"lib", "external", "src", "chimera_harnesses", "repos", "node_modules"}
AUDIT_SUBDIRS = {
    "prior_audits", "audit-pdfs", "cantina-pdfs",
    "external-prior-audits", "known-vulns-pdf",
}

# Finding-section markers — order matters (more specific first)
FINDING_MARKERS = [
    re.compile(r"^\s*\[([HMLCI])-\d+\]", re.MULTILINE),
    re.compile(r"^\s*(Finding|Issue|Vulnerability|Bug)\s*[#\d:]", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*\d+\.\d+\s+(Critical|High|Medium|Low|Informational|Info)\s*Risk", re.MULTILINE | re.IGNORECASE),
]
SEVERITY_PATTERN = re.compile(
    r"\b(Critical|High|Medium|Low|Informational|Info)\b", re.IGNORECASE
)
# Lines that look like finding titles (not table-of-contents dots)
TITLE_LINE_RE = re.compile(r"^(.{10,120}?)(?:\s*\.{3,}.*)?$")


def _is_skip_path(path: Path) -> bool:
    """Return True if any component of path is in SKIP_DIRS."""
    return any(part in SKIP_DIRS for part in path.parts)


def _candidate_slug(source_file: str, title: str, index: int) -> str:
    base = os.path.basename(source_file).replace(".txt", "").replace(".pdf", "")
    # sanitise title
    slug_title = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40]
    raw = f"{base}-{slug_title}-{index}"
    h = hashlib.md5(raw.encode()).hexdigest()[:8]
    return f"{raw}-{h}"


def _discover_sources(input_dirs: list[str]) -> list[Path]:
    """Return list of .txt (preferred) or .pdf source files from audit dirs."""
    sources: list[Path] = []
    seen_stems: set[str] = set()

    for base in input_dirs:
        base_path = Path(base).expanduser()
        if not base_path.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base_path):
            dpath = Path(dirpath)
            # Only prune SKIP_DIRS when NOT yet inside an AUDIT_SUBDIRS tree.
            # Bug fix (CAP-GAP-79 2026-05-27): "lib" in SKIP_DIRS caused
            # evm/lib/sp1-contracts/audits/*.pdf to be silently skipped;
            # once inside an audits/ dir we must descend into all subdirs.
            in_audit_subdir = any(p in AUDIT_SUBDIRS for p in dpath.parts)
            if not in_audit_subdir:
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            # Only collect files if this dir (or a parent) is an audit subdir
            if not in_audit_subdir:
                if dpath.name not in AUDIT_SUBDIRS:
                    continue
            for fname in filenames:
                fpath = dpath / fname
                if not in_audit_subdir and _is_skip_path(fpath):
                    continue
                if fname.endswith(".txt"):
                    sources.append(fpath)
                    seen_stems.add(str(fpath.with_suffix("")))
                elif fname.endswith(".pdf"):
                    # only add PDF if no .txt sibling already found
                    stem = str(fpath.with_suffix(""))
                    if stem not in seen_stems:
                        sources.append(fpath)
    return sorted(set(sources))


def _read_text(source: Path) -> str | None:
    """Read text content; for PDFs try pypdf/pdfplumber, else return None."""
    if source.suffix == ".txt":
        try:
            return source.read_text(errors="replace")
        except Exception:
            return None
    # PDF fallback — try optional libs
    try:
        import pypdf  # type: ignore
        reader = pypdf.PdfReader(str(source))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n".join(pages)
    except ImportError:
        pass
    try:
        import pdfplumber  # type: ignore
        with pdfplumber.open(str(source)) as pdf:
            pages = [p.extract_text() or "" for p in pdf.pages]
        return "\n".join(pages)
    except ImportError:
        pass
    return None  # no PDF lib available; skip this PDF


def _extract_findings(text: str) -> list[dict]:
    """Extract candidate findings from raw text."""
    findings: list[dict] = []
    lines = text.splitlines()
    n = len(lines)

    i = 0
    while i < n:
        line = lines[i]
        matched_severity = None
        matched_marker = False

        # Check for bracketed severity tag [H-1], [M-3], etc.
        bracket_match = re.match(r"^\s*\[([HMLCI])-(\d+)\](.*)$", line)
        if bracket_match:
            sev_code = bracket_match.group(1).upper()
            sev_map = {"H": "High", "M": "Medium", "L": "Low", "C": "Critical", "I": "Informational"}
            matched_severity = sev_map.get(sev_code, "Unknown")
            title_rest = bracket_match.group(3).strip()
            title = title_rest if len(title_rest) > 8 else (lines[i + 1].strip() if i + 1 < n else "")
            matched_marker = True

        if not matched_marker:
            # Check for "Severity: X" block-style (Informal Systems pattern)
            if re.match(r"^\s*Severity\s*$", line, re.IGNORECASE):
                sev_line = lines[i + 1].strip() if i + 1 < n else ""
                sev_match = SEVERITY_PATTERN.match(sev_line)
                if sev_match:
                    matched_severity = sev_match.group(1).capitalize()
                    # title is typically a few lines back — walk back
                    title = ""
                    for back in range(1, 8):
                        candidate = lines[i - back].strip() if i - back >= 0 else ""
                        if len(candidate) > 10 and not re.match(r"^\d+$", candidate):
                            title = candidate
                            break
                    if title:
                        matched_marker = True

        if not matched_marker:
            # Inline "Severity: High" or "Critical Risk" patterns
            inline = re.match(
                r"^\s*(?:Severity\s*:?\s*)?(Critical|High|Medium|Low)\s*(Risk|Finding|Issue)?\s*$",
                line, re.IGNORECASE
            )
            if inline:
                matched_severity = inline.group(1).capitalize()
                # title is nearby — look ahead/back
                title = ""
                for delta in (-2, -1, 1, 2):
                    candidate_idx = i + delta
                    if 0 <= candidate_idx < n:
                        candidate = lines[candidate_idx].strip()
                        if len(candidate) > 10 and not re.match(r"^[\d.]+$", candidate):
                            title = candidate
                            break
                if title:
                    matched_marker = True

        if matched_marker and matched_severity and title:
            # Collect a 2-sentence summary from context window
            context_lines = lines[i + 1: i + 8]
            summary_raw = " ".join(l.strip() for l in context_lines if l.strip())
            # trim to ~200 chars
            summary = re.sub(r"\s+", " ", summary_raw)[:200].strip()

            findings.append({
                "title": title[:120],
                "severity": matched_severity,
                "summary": summary,
            })

        i += 1

    # Deduplicate by title
    seen_titles: set[str] = set()
    deduped: list[dict] = []
    for f in findings:
        key = f["title"].lower()[:60]
        if key not in seen_titles:
            seen_titles.add(key)
            deduped.append(f)

    return deduped


def _write_candidate(out_dir: Path, slug: str, finding: dict, source_file: str) -> Path:
    out_path = out_dir / f"{slug}.yaml.candidate"
    category = _infer_category(finding["title"] + " " + finding["summary"])
    content = (
        f"name: {json.dumps(finding['title'])}\n"
        f"category: {category}\n"
        f"severity_hint: {finding['severity']}\n"
        f"source_pdf: {json.dumps(os.path.basename(source_file))}\n"
        f"source_page: null\n"
        f"summary: {json.dumps(finding['summary'])}\n"
        f"extraction_method: text-pattern\n"
        f"confidence: low\n"
    )
    out_path.write_text(content)
    return out_path


def _infer_category(text: str) -> str:
    text_lower = text.lower()
    if any(w in text_lower for w in ("reentr", "reentry")):
        return "reentrancy"
    if any(w in text_lower for w in ("overflow", "underflow", "arithmetic", "integer")):
        return "arithmetic"
    if any(w in text_lower for w in ("access control", "ownership", "privilege", "unauthorized")):
        return "access-control"
    if any(w in text_lower for w in ("oracle", "price manip", "price feed")):
        return "oracle"
    if any(w in text_lower for w in ("liquidat",)):
        return "liquidation"
    if any(w in text_lower for w in ("dos", "denial", "grief", "spam", "halt")):
        return "dos"
    if any(w in text_lower for w in ("flash loan", "flashloan")):
        return "flashloan"
    if any(w in text_lower for w in ("front.?run", "mev", "sandwich")):
        return "mev"
    if any(w in text_lower for w in ("signature", "replay", "nonce")):
        return "signature"
    if any(w in text_lower for w in ("initializ",)):
        return "initialization"
    return "misc"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit PDF/TXT to pattern candidates miner.")
    parser.add_argument("--input-dir", dest="input_dirs", action="append", default=[],
                        metavar="DIR", help="Input directory to scan (repeatable)")
    parser.add_argument("--out-dir", default="reference/patterns.dsl/r99_pdf_mined",
                        help="Output directory for .yaml.candidate files")
    parser.add_argument("--min-pdfs", type=int, default=10,
                        help="Minimum source files required (exit 1 if not met)")
    parser.add_argument("--min-candidates", type=int, default=30,
                        help="Minimum candidates required (exit 1 if not met)")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output")
    args = parser.parse_args(argv)

    # Default discovery dirs — only used when no --input-dir is given
    if args.input_dirs:
        input_dirs = args.input_dirs
    else:
        input_dirs = [str(Path("~/audits").expanduser())]

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    def log(msg: str) -> None:
        if not args.quiet:
            print(msg)

    sources = _discover_sources(input_dirs)
    log(f"[audit-pdf-to-patterns] Discovered {len(sources)} source files.")

    all_candidates: list[dict] = []
    per_pdf: dict[str, int] = {}

    for source in sources:
        log(f"  Processing: {source}")
        text = _read_text(source)
        if text is None:
            log(f"    SKIP (no PDF lib and not a .txt file)")
            per_pdf[str(source)] = 0
            continue
        findings = _extract_findings(text)
        count = 0
        for idx, finding in enumerate(findings):
            slug = _candidate_slug(str(source), finding["title"], idx)
            _write_candidate(out_dir, slug, finding, str(source))
            all_candidates.append({**finding, "source": str(source), "slug": slug})
            count += 1
        per_pdf[str(source)] = count
        log(f"    -> {count} candidates extracted")

    # Emit summary JSON
    summary = {
        "run_ts": datetime.now(timezone.utc).isoformat(),
        "sources_scanned": len(sources),
        "total_candidates": len(all_candidates),
        "per_source": per_pdf,
    }
    summary_path = Path(".auditooor/audit_pdf_mining_run.json")
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(summary, indent=2))
    log(f"[audit-pdf-to-patterns] Summary written to {summary_path}")
    log(f"[audit-pdf-to-patterns] Total candidates: {len(all_candidates)}")

    exit_code = 0
    if len(sources) < args.min_pdfs:
        print(f"ERROR: Only {len(sources)} sources found; --min-pdfs={args.min_pdfs} not satisfied.", file=sys.stderr)
        exit_code = 1
    if len(all_candidates) < args.min_candidates:
        print(f"ERROR: Only {len(all_candidates)} candidates; --min-candidates={args.min_candidates} not satisfied.", file=sys.stderr)
        exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
