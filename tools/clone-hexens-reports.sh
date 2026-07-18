#!/usr/bin/env bash
# clone-hexens-reports.sh — clone the Hexens audit report archive for originality checks
#
# Usage:
#   ./tools/clone-hexens-reports.sh [target-dir]
#
# Default target-dir: /tmp/hexens-reports
#
# What it does:
#   1. Clones Hexens/Smart-Contract-Review-Public-Reports (~70MB of PDFs)
#   2. Extracts every PDF to plain text in the same directory
#   3. Prints the grep commands you can use for originality checks

set -euo pipefail

TARGET_DIR="${1:-/tmp/hexens-reports}"

if [ -d "$TARGET_DIR/.git" ]; then
    echo "Repo already exists at $TARGET_DIR. Pulling latest..."
    git -C "$TARGET_DIR" pull --quiet
else
    echo "Cloning Hexens/Smart-Contract-Review-Public-Reports to $TARGET_DIR..."
    git clone --depth 1 https://github.com/Hexens/Smart-Contract-Review-Public-Reports.git "$TARGET_DIR"
fi

echo "Counting PDFs..."
PDF_COUNT=$(find "$TARGET_DIR" -name '*.pdf' | wc -l | tr -d ' ')
echo "Found $PDF_COUNT PDFs."

# Check if pypdf is installed
if ! python3 -c "import pypdf" 2>/dev/null; then
    echo "pypdf not installed. Installing via pip3..."
    pip3 install --break-system-packages pypdf 2>/dev/null || \
        pip3 install --user pypdf 2>/dev/null || \
        pip3 install pypdf
fi

echo "Extracting PDFs to plain text (skipping already-extracted)..."
EXTRACTED=0
SKIPPED=0
for pdf in $(find "$TARGET_DIR" -name '*.pdf'); do
    txt="${pdf%.pdf}.txt"
    if [ -f "$txt" ] && [ -s "$txt" ]; then
        SKIPPED=$((SKIPPED + 1))
        continue
    fi
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
" > "$txt" 2>/dev/null || true
    EXTRACTED=$((EXTRACTED + 1))
done

echo
echo "Extracted: $EXTRACTED new, $SKIPPED already existed"
echo
echo "=============================================="
echo "Originality check workflow:"
echo "=============================================="
echo
echo "Grep all Hexens reports for a keyword:"
echo "  grep -rl 'YourKeyword' $TARGET_DIR --include='*.txt'"
echo
echo "Grep with context:"
echo "  grep -rn -C 3 'YourKeyword' $TARGET_DIR --include='*.txt' | head -40"
echo
echo "Count hits per file:"
echo "  grep -rc 'YourKeyword' $TARGET_DIR --include='*.txt' | grep -v ':0'"
echo
echo "Search by vulnerability class:"
echo "  grep -rl -E 'reentran|access control|rounding' $TARGET_DIR --include='*.txt'"
echo
echo "For a specific finding, grep the function name + the word 'vulnerability':"
echo "  grep -rn 'myFunction' $TARGET_DIR --include='*.txt' | grep -i 'vuln\\|bug\\|flaw\\|finding'"
echo
