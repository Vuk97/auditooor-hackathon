#!/usr/bin/env bash
# mine-audit-to-patterns.sh — extract a non-EVM audit report (PDF or txt) into
# stub Rust/Soroban (or other non-EVM) detector pattern YAMLs.
#
# Wraps:
#   - pdftotext (if input is .pdf)
#   - tools/mine-audit-to-patterns.py
#
# Usage:
#   ./tools/mine-audit-to-patterns.sh <audit-pdf-or-txt> <source-slug> [language] [platform] [out-dir]
#
# Example (K2):
#   ./tools/mine-audit-to-patterns.sh \
#       /Users/wolf/audits/k2/src/k2-borrow-lend-protocol-ssc.pdf \
#       halborn-2025-09 \
#       rust \
#       soroban \
#       detectors/_specs/drafts_halborn_k2
#
# Defaults:
#   language = rust
#   platform = soroban
#   out-dir  = detectors/_specs/drafts_<source-slug>
set -u

if [ "$#" -lt 2 ]; then
    cat >&2 <<USAGE
usage: $0 <audit-pdf-or-txt> <source-slug> [language] [platform] [out-dir]

Examples:
  $0 /path/to/halborn.pdf halborn-2025-09
  $0 /path/to/watchpug.txt watchpug-rev3 rust soroban detectors/_specs/drafts_watchpug
USAGE
    exit 2
fi

INPUT="$1"
SOURCE="$2"
LANG="${3:-rust}"
PLATFORM="${4:-soroban}"
OUT_DIR="${5:-detectors/_specs/drafts_${SOURCE}}"

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

if [ ! -f "$INPUT" ]; then
    echo "[err] input file not found: $INPUT" >&2
    exit 2
fi

# Resolve output dir to absolute under repo if relative
case "$OUT_DIR" in
    /*) ABS_OUT="$OUT_DIR" ;;
    *)  ABS_OUT="$REPO/$OUT_DIR" ;;
esac

# pdftotext if needed
case "$INPUT" in
    *.pdf|*.PDF)
        TXT_TMP="$(mktemp -t mine-audit.XXXXXX.txt)"
        if ! command -v pdftotext >/dev/null 2>&1; then
            echo "[err] pdftotext not installed (brew install poppler)" >&2
            exit 3
        fi
        echo "[setup] pdftotext $INPUT -> $TXT_TMP"
        pdftotext "$INPUT" "$TXT_TMP"
        TEXT="$TXT_TMP"
        ;;
    *)
        TEXT="$INPUT"
        ;;
esac

mkdir -p "$ABS_OUT"

echo "[setup] source=$SOURCE language=$LANG platform=$PLATFORM out=$ABS_OUT"

python3 "$HERE/mine-audit-to-patterns.py" \
    --text-file "$TEXT" \
    --source "$SOURCE" \
    --language "$LANG" \
    --platform "$PLATFORM" \
    --out-dir "$ABS_OUT"

EXIT=$?

# Cleanup
case "$INPUT" in
    *.pdf|*.PDF)
        rm -f "$TXT_TMP"
        ;;
esac

exit $EXIT
