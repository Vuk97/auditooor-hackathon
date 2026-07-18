#!/usr/bin/env bash
# extract-pdfs.sh — extract PDFs to plain text for grep
#
# Usage:
#   ./tools/extract-pdfs.sh <pdf-dir> [output-dir]
#
# Fixes SKILL_ISSUES #29: the prior version used pypdf as the primary extractor,
# which silently produces 0-byte output on many real-world PDFs (Hexens archive
# produced 181 empty files before this fix). Now prefers poppler's `pdftotext`
# (gold standard) with a pdfminer.six fallback, then pypdf as a last resort,
# and fail-fasts with a clear error if an extraction yields an empty file.
#
# Priority order:
#   1. pdftotext (poppler-utils)  — fastest, most reliable, handles nearly all PDFs
#   2. pdfminer.six                — pure Python, good for complex layouts
#   3. pypdf                       — pure Python, fast but fragile on real audits
#
# Exit status:
#   0 — all PDFs extracted, every output file non-empty
#   1 — usage error / setup error
#   2 — at least one PDF produced an empty .txt file (operator must inspect)

set -uo pipefail

if [ $# -lt 1 ]; then
    cat <<EOF
Usage: $0 <pdf-dir> [output-dir]
       $0 --help

Extracts every .pdf under <pdf-dir> to a .txt file. Uses pdftotext (poppler)
by default; falls back to pdfminer.six then pypdf if pdftotext is unavailable.

If output-dir is omitted, .txt files are written alongside the .pdf files.
If output-dir is given, the directory is created if missing.

Fail-fast: if any PDF produces an empty .txt file, the script exits with
code 2 after finishing the batch and lists the failed PDFs. This prevents
silent corpus-incompletion that causes false-clean originality-grep results.

Examples:
    $0 ~/Downloads/target-audits /tmp/extracted
    $0 /tmp/hexens-reports
EOF
    exit 1
fi

PDF_DIR="$1"
OUT_DIR="${2:-}"

if [ ! -d "$PDF_DIR" ]; then
    echo "Error: $PDF_DIR is not a directory"
    exit 1
fi

# ------------------------------------------------------------------------
# Extractor detection — try pdftotext first, fall back to Python extractors
# ------------------------------------------------------------------------

EXTRACTOR=""
if command -v pdftotext >/dev/null 2>&1; then
    EXTRACTOR="pdftotext"
    echo "[ok] using pdftotext ($(pdftotext -v 2>&1 | head -1))"
elif python3 -c "import pdfminer" 2>/dev/null; then
    EXTRACTOR="pdfminer"
    echo "[ok] using pdfminer.six (pdftotext not installed)"
elif python3 -c "import pypdf" 2>/dev/null; then
    EXTRACTOR="pypdf"
    echo "[warn] falling back to pypdf — produces empty output on many real PDFs"
    echo "       strongly recommend: brew install poppler  (or apt-get install poppler-utils)"
else
    echo "[info] no PDF extractor installed — attempting to install one"
    if command -v brew >/dev/null 2>&1; then
        echo "  trying: brew install poppler"
        if brew install poppler >/dev/null 2>&1; then
            EXTRACTOR="pdftotext"
            echo "[ok] installed poppler; using pdftotext"
        fi
    fi
    if [ -z "$EXTRACTOR" ] && command -v apt-get >/dev/null 2>&1; then
        echo "  trying: apt-get install poppler-utils"
        if sudo apt-get install -y poppler-utils >/dev/null 2>&1; then
            EXTRACTOR="pdftotext"
        fi
    fi
    if [ -z "$EXTRACTOR" ]; then
        echo "  trying: pip install pdfminer.six"
        if pip3 install --break-system-packages pdfminer.six >/dev/null 2>&1 || \
           pip3 install --user pdfminer.six >/dev/null 2>&1; then
            EXTRACTOR="pdfminer"
        fi
    fi
    if [ -z "$EXTRACTOR" ]; then
        echo "Error: could not install any PDF extractor"
        echo "  manually install one of: poppler (pdftotext), pdfminer.six, pypdf"
        exit 1
    fi
fi

# ------------------------------------------------------------------------
# Extract each PDF. Track failures for fail-fast reporting.
# ------------------------------------------------------------------------

COUNT=0
SKIP=0
FAIL=0
FAILED_FILES=()

# Use null-delimited find to handle filenames with spaces / special chars
while IFS= read -r -d '' pdf; do
    if [ -n "$OUT_DIR" ]; then
        mkdir -p "$OUT_DIR"
        base=$(basename "$pdf" .pdf)
        txt="$OUT_DIR/$base.txt"
    else
        txt="${pdf%.pdf}.txt"
    fi

    # Skip if we already have non-empty output for this PDF
    if [ -f "$txt" ] && [ -s "$txt" ]; then
        SKIP=$((SKIP + 1))
        continue
    fi

    case "$EXTRACTOR" in
        pdftotext)
            pdftotext -layout "$pdf" "$txt" 2>/dev/null
            ;;
        pdfminer)
            python3 -c "
import sys
from pdfminer.high_level import extract_text
try:
    text = extract_text('$pdf')
    sys.stdout.write(text or '')
except Exception as e:
    sys.stderr.write(f'pdfminer error: {e}\n')
    sys.exit(1)
" > "$txt" 2>/dev/null
            ;;
        pypdf)
            python3 -c "
from pypdf import PdfReader
import sys
try:
    reader = PdfReader('$pdf')
    for page in reader.pages:
        try:
            print(page.extract_text() or '')
        except Exception:
            pass
except Exception as e:
    print(f'# ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" > "$txt" 2>/dev/null
            ;;
    esac

    # Fail-fast check: if the output is empty, it's a silent failure.
    if [ ! -s "$txt" ]; then
        FAIL=$((FAIL + 1))
        FAILED_FILES+=("$pdf")
        # Remove the empty file so a re-run doesn't mistake it for cached output
        rm -f "$txt"
    else
        COUNT=$((COUNT + 1))
    fi
done < <(find "$PDF_DIR" -name '*.pdf' -print0)

# ------------------------------------------------------------------------
# Report
# ------------------------------------------------------------------------

echo
echo "Extracted: $COUNT new, $SKIP skipped, $FAIL failed"

if [ $FAIL -gt 0 ]; then
    echo
    echo "[fail] $FAIL PDF(s) produced empty output — likely scanned/image-based"
    echo "       or encrypted. Inspect manually or try OCR (tesseract + ocrmypdf)."
    printf '       %s\n' "${FAILED_FILES[@]}" | head -20
    if [ $FAIL -gt 20 ]; then
        echo "       ... and $((FAIL - 20)) more"
    fi
    echo
    echo "       Use: ocrmypdf --redo-ocr <input.pdf> <output.pdf>"
    echo "       Then re-run this script."
    exit 2
fi
