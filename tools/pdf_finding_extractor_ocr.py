#!/usr/bin/env python3
"""pdf_finding_extractor_ocr.py - OCR fallback wrapper for pdf_finding_extractor.py.

When the standard pdftotext/pypdf extractor produces empty output (scanned PDFs),
this wrapper attempts OCR via ocrmypdf + tesseract if available.

Usage:
    python3 tools/pdf_finding_extractor_ocr.py --pdf <path> --out <path.txt>

Exits:
  0  - OCR succeeded, non-empty text written to --out
  1  - OCR unavailable or failed
  2  - usage error

R36: lane cap79-pdf-extractor-hyperbridge-2026-05-27 registered.
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def _tesseract_available() -> bool:
    return shutil.which("tesseract") is not None


def _ocrmypdf_available() -> bool:
    return shutil.which("ocrmypdf") is not None


def _ocr_with_ocrmypdf(pdf_path: Path, out_path: Path) -> bool:
    """Run ocrmypdf to add OCR layer, then pdftotext to extract. Return True on success."""
    with tempfile.TemporaryDirectory() as tmp:
        ocr_pdf = Path(tmp) / "ocr_output.pdf"
        result = subprocess.run(
            ["ocrmypdf", "--quiet", "--redo-ocr", str(pdf_path), str(ocr_pdf)],
            capture_output=True,
            timeout=300,
        )
        if result.returncode not in (0, 6):  # 6 = already has OCR layer
            return False
        if not ocr_pdf.exists():
            return False
        txt_result = subprocess.run(
            ["pdftotext", "-q", str(ocr_pdf), str(out_path)],
            capture_output=True,
            timeout=60,
        )
        return txt_result.returncode == 0 and out_path.exists() and out_path.stat().st_size > 0


def _ocr_with_tesseract(pdf_path: Path, out_path: Path) -> bool:
    """Convert PDF pages to images and OCR with tesseract. Return True on success."""
    try:
        from pdf2image import convert_from_path  # type: ignore
    except ImportError:
        return False

    try:
        pages = convert_from_path(str(pdf_path), dpi=300)
    except Exception:
        return False

    texts = []
    for i, page_img in enumerate(pages):
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmp_img:
            page_img.save(tmp_img.name, "PNG")
            result = subprocess.run(
                ["tesseract", tmp_img.name, "stdout", "-l", "eng"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            Path(tmp_img.name).unlink(missing_ok=True)
            if result.returncode == 0:
                texts.append(result.stdout)

    combined = "
".join(texts)
    if not combined.strip():
        return False
    out_path.write_text(combined, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="OCR fallback wrapper for pdf_finding_extractor.py."
    )
    parser.add_argument("--pdf", required=True, help="Input PDF path")
    parser.add_argument("--out", required=True, help="Output .txt path")
    args = parser.parse_args()

    pdf_path = Path(args.pdf).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()

    if not pdf_path.exists():
        print(f"ERROR: PDF not found: {pdf_path}", file=sys.stderr)
        return 2

    out_path.parent.mkdir(parents=True, exist_ok=True)

    if _ocrmypdf_available():
        if _ocr_with_ocrmypdf(pdf_path, out_path):
            chars = out_path.stat().st_size
            print(f"OK ocrmypdf: {pdf_path.name} -> {out_path} ({chars} bytes)")
            return 0
        print(f"ocrmypdf failed for {pdf_path.name}, trying tesseract direct", file=sys.stderr)

    if _tesseract_available():
        if _ocr_with_tesseract(pdf_path, out_path):
            chars = out_path.stat().st_size
            print(f"OK tesseract: {pdf_path.name} -> {out_path} ({chars} bytes)")
            return 0

    print(
        f"FAIL [ocr-unavailable]: {pdf_path.name} - no OCR tool available (install ocrmypdf or tesseract)",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
