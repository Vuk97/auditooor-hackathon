#!/usr/bin/env bash
# fetch-scope.sh — pull the full bounty program page into workspace/SCOPE.md
#
# Usage:
#   ./tools/fetch-scope.sh <workspace-dir> <program-url>
#
# Example:
#   ./tools/fetch-scope.sh /path/to/workspace https://cantina.xyz/bounties/polymarket
#
# Downloads the bounty program HTML, extracts the IN-SCOPE asset list AND the
# OUT-OF-SCOPE / KNOWN ISSUES sections. Writes to workspace/SCOPE.md in a form
# suitable for reading during orient and for including in agent briefs.
#
# Why this exists: `scope.json` (the machine-readable asset list) only contains
# in-scope assets. The actual exclusion rubric — centralization-by-design, prior
# audit carveouts, $50M+ capital exploits, known issues — lives only on the
# program page. Missing it leads to pursuing findings that fall in explicit
# exclusion classes.
#
# Fixes Issue 15 from SKILL_ISSUES.md — scope-match must happen on iter 1, not
# at draft-submission time.

set -uo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <workspace-dir> <program-url>"
    exit 1
fi

WS="$1"
URL="$2"

if [ ! -d "$WS" ]; then
    echo "Error: workspace $WS not found"
    exit 1
fi

OUT="$WS/SCOPE.md"
RAW="$WS/.scope-raw.html"

# Fetch the page. Use a normal UA so cloudflare/captcha doesn't block.
curl -sSL \
    -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36' \
    "$URL" > "$RAW" || {
    echo "Error: failed to fetch $URL"
    rm -f "$RAW"
    exit 1
}

if [ ! -s "$RAW" ]; then
    echo "Error: empty response from $URL"
    rm -f "$RAW"
    exit 1
fi

# Strip HTML tags to plain text. Prefer python if available for better extraction.
if command -v python3 >/dev/null 2>&1; then
    python3 - "$RAW" > "$OUT" <<'PY'
import sys, re, html
with open(sys.argv[1]) as f:
    raw = f.read()
# Strip scripts / styles
raw = re.sub(r'<script[^>]*>.*?</script>', '', raw, flags=re.S|re.I)
raw = re.sub(r'<style[^>]*>.*?</style>', '', raw, flags=re.S|re.I)
# Convert block-level tags to newlines
raw = re.sub(r'<(br|p|div|li|h[1-6]|section|article)[^>]*>', '\n', raw, flags=re.I)
raw = re.sub(r'</(p|div|li|h[1-6]|section|article)>', '\n', raw, flags=re.I)
# Strip remaining tags
raw = re.sub(r'<[^>]+>', '', raw)
# Decode entities and collapse whitespace
raw = html.unescape(raw)
raw = re.sub(r'[ \t]+', ' ', raw)
raw = re.sub(r'\n\s*\n\s*\n+', '\n\n', raw)
raw = raw.strip()
print("# Scope — fetched from bounty program page")
print()
print(f"**Source:** {sys.argv[1].replace('.scope-raw.html', '(bounty program URL)')}  ")
print()
print("This is the full program page including in-scope assets, severity rewards,")
print("out-of-scope classes, and known issues. Read ALL of it during iter 1 orient.")
print("For every candidate finding, grep this file for related exclusion keywords.")
print()
print("---")
print()
print(raw)
PY
else
    echo "# Scope — raw HTML (python3 not available for cleanup)" > "$OUT"
    echo "" >> "$OUT"
    cat "$RAW" >> "$OUT"
fi

rm -f "$RAW"
echo "Wrote $OUT"
wc -l "$OUT" | awk '{print "Lines:", $1}'

# Pull out the Out-of-Scope section into a separate file for easy agent-brief inclusion
awk '
    /[Oo]ut[ -][Ss]cope/ { in_oos = 1 }
    /[Ss]everity/ && in_oos { exit }
    /[Ii]n[ -][Ss]cope/ && in_oos { in_oos = 0 }
    in_oos { print }
' "$OUT" > "$WS/SCOPE_OUT_OF_SCOPE.md" 2>/dev/null || true

if [ -s "$WS/SCOPE_OUT_OF_SCOPE.md" ]; then
    echo "Extracted out-of-scope section to $WS/SCOPE_OUT_OF_SCOPE.md"
fi
