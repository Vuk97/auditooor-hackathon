#!/usr/bin/env python3
"""pdf_finding_extractor.py - Extract text from a single audit PDF.

Uses pdftotext (poppler) as primary extractor, falls back to pypdf.
Writes extracted text to --out path.

Exits:
  0  - extraction succeeded, non-empty text written to --out
  1  - extraction failed (encrypted, scanned-image, or unsupported format)
  2  - usage error

Rule 37: this tool emits at tier-2 (public audit PDF parsed; >=3 mandatory
shape fields extracted when used in corpus-mining mode).
R36: lane cap79-pdf-extractor-hyperbridge-2026-05-27 registered.
"""

import argparse
import subprocess
import sys
from pathlib import Path


def _pdftotext(pdf_path: Path, out_path: Path) -> bool:
    """Try pdftotext (poppler). Return True if non-empty output produced."""
    try:
        result = subprocess.run(
            ["pdftotext", "-q", str(pdf_path), str(out_path)],
            capture_output=True,
            timeout=60,
        )
        if result.returncode != 0:
            return False
        return out_path.exists() and out_path.stat().st_size > 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _pypdf(pdf_path: Path, out_path: Path) -> bool:
    """Try pypdf. Return True if non-empty output produced."""
    try:
        import pypdf  # type: ignore
    except ImportError:
        return False
    try:
        reader = pypdf.PdfReader(str(pdf_path))
        if reader.is_encrypted:
            return False
        pages = []
        for page in reader.pages:
            try:
                text = page.extract_text()
                if text:
                    pages.append(text)
            except Exception:
                pass
        content = "\n".join(pages)
        if not content.strip():
            return False
        out_path.write_text(content, encoding="utf-8")
        return True
    except Exception:
        return False


def _classify_failure(pdf_path: Path) -> str:
    """Best-effort failure classification for a PDF that produced no text."""
    try:
        import pypdf  # type: ignore
        reader = pypdf.PdfReader(str(pdf_path))
        if reader.is_encrypted:
            return "encrypted"
        if len(reader.pages) > 0:
            sample = ""
            try:
                sample = reader.pages[0].extract_text() or ""
            except Exception:
                pass
            if not sample.strip():
                return "scanned-ocr-needed"
    except Exception:
        pass
    return "parser-failure"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract text from a single audit PDF (pdftotext primary, pypdf fallback)."
    )
    parser.add_argument("--pdf", required=True, help="Input PDF path")
    parser.add_argument("--out", required=True, help="Output .txt path")
    parser.add_argument(
        "--classify-on-failure",
        action="store_true",
        help="On failure, print a JSON classification line to stderr",
    )
    args = parser.parse_args()

    pdf_path = Path(args.pdf).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()

    if not pdf_path.exists():
        print(f"ERROR: PDF not found: {pdf_path}", file=sys.stderr)
        return 2

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Primary: pdftotext
    if _pdftotext(pdf_path, out_path):
        chars = out_path.stat().st_size
        print(f"OK pdftotext: {pdf_path.name} -> {out_path} ({chars} bytes)")
        return 0

    # Fallback: pypdf
    if _pypdf(pdf_path, out_path):
        chars = out_path.stat().st_size
        print(f"OK pypdf: {pdf_path.name} -> {out_path} ({chars} bytes)")
        return 0

    # Failed
    failure_class = _classify_failure(pdf_path)
    if args.classify_on_failure:
        import json
        print(
            json.dumps({"pdf": str(pdf_path), "failure_class": failure_class}),
            file=sys.stderr,
        )
    print(
        f"FAIL [{failure_class}]: {pdf_path.name} - no text extracted",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
