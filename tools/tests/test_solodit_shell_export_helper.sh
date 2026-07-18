#!/usr/bin/env bash
# test_solodit_shell_export_helper.sh — smoke test for solodit-shell-export-helper.sh
# Run: bash tools/tests/test_solodit_shell_export_helper.sh

set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")/.." && pwd)/solodit-shell-export-helper.sh"
PASS=0; FAIL=0

ok() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== solodit-shell-export-helper smoke tests ==="

# 1. Script exists and is executable (or at least readable by bash)
if [[ -f "$SCRIPT" ]]; then ok "script exists"; else fail "script not found at $SCRIPT"; exit 1; fi

# 2. --help exits 0
if bash "$SCRIPT" --help >/dev/null 2>&1; then ok "--help exits 0"; else fail "--help non-zero exit"; fi

# 3. --detect mode finds key (exits 0)
if bash "$SCRIPT" --detect >/dev/null 2>&1; then ok "--detect exits 0 (key found)"; else fail "--detect failed (key not found or script error)"; fi

# 4. --detect output contains masked key prefix "sk_"
OUTPUT="$(bash "$SCRIPT" --detect 2>&1)"
if echo "$OUTPUT" | grep -q "sk_"; then ok "--detect output contains sk_ prefix"; else fail "--detect output missing sk_ prefix: $OUTPUT"; fi

# 5. --reveal outputs a valid export line starting with "export SOLODIT_API_KEY="
REVEAL="$(bash "$SCRIPT" --reveal 2>&1)"
if echo "$REVEAL" | grep -q "^export SOLODIT_API_KEY="; then ok "--reveal output is valid export line"; else fail "--reveal output malformed: $REVEAL"; fi

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
