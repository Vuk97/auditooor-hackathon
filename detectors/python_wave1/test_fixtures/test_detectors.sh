#!/usr/bin/env bash
# test_detectors.sh — regression-check each python_wave1 detector.
set -u
set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$HERE/../../../tools"
TMPLOG="$(mktemp -t py-detect-test.XXXXXX.log)"
TMPOUT="$(mktemp -t py-detect-test.XXXXXX.out)"
trap 'rm -f "$TMPLOG" "$TMPOUT"' EXIT

find_python_with_parser() {
    if [[ -n "${AUDITOOOR_PYTHON_AST:-}" ]] && "$AUDITOOOR_PYTHON_AST" -c 'from tree_sitter_language_pack import get_parser; get_parser("python")' >/dev/null 2>&1; then
        printf '%s\n' "$AUDITOOOR_PYTHON_AST"
        return 0
    fi
    local py
    for py in python3 python3.14 python3.13 python3.12 python3.11; do
        if command -v "$py" >/dev/null 2>&1 && "$py" -c 'from tree_sitter_language_pack import get_parser; get_parser("python")' >/dev/null 2>&1; then
            command -v "$py"
            return 0
        fi
    done
    return 1
}

PYTHON_AST="$(find_python_with_parser || true)"
if [[ -z "$PYTHON_AST" ]]; then
    echo "  FAIL  dependency preflight  (no Python interpreter can load tree-sitter parser for python)"
    echo "    Set AUDITOOOR_PYTHON_AST=/path/to/python or install tree_sitter_language_pack/tree_sitter_python."
    exit 1
fi

DETECTORS=(
    proof_of_life
)

PASS=0
FAIL=0
FAIL_LINES=()

count_hits() {
    local det="$1"; local log="$2"
    "$PYTHON_AST" -c "
import re, sys
pat = re.compile(r'^=== ' + re.escape('$det') + r'\s+\((\d+) hits\)')
for line in open('$log', errors='ignore'):
    m = pat.match(line)
    if m:
        print(m.group(1)); sys.exit(0)
print(0)
"
}

for det in "${DETECTORS[@]}"; do
    for mode in positive negative; do
        fixture="$HERE/${det}_${mode}.py"
        if [[ ! -f "$fixture" ]]; then
            echo "  MISS $det $mode"
            FAIL=$((FAIL+1))
            FAIL_LINES+=("$det $mode: fixture missing")
            continue
        fi
        "$PYTHON_AST" "$TOOLS/lang-detect.py" --lang python "$HERE" \
            --only "$det" --file "$fixture" \
            --log "$TMPLOG" >"$TMPOUT" 2>&1
        rc=$?
        hits="$(count_hits "$det" "$TMPLOG")"
        hits="${hits:-0}"
        if (( rc != 0 )) || grep -qE '^# files: .* parse_errors: [1-9]' "$TMPLOG"; then
            echo "  FAIL  $det $mode  (lang-detect dependency/parse failure)"
            tail -20 "$TMPOUT" | sed 's/^/    /'
            FAIL=$((FAIL+1))
            FAIL_LINES+=("$det $mode: lang-detect dependency/parse failure")
            continue
        fi
        if [[ "$mode" == "positive" ]]; then
            if (( hits >= 1 )); then
                echo "  PASS  $det positive  ($hits hits)"
                PASS=$((PASS+1))
            else
                echo "  FAIL  $det positive  (expected >=1, got $hits)"
                FAIL=$((FAIL+1))
                FAIL_LINES+=("$det positive")
            fi
        else
            if (( hits == 0 )); then
                echo "  PASS  $det negative  (0 hits)"
                PASS=$((PASS+1))
            else
                echo "  FAIL  $det negative  (expected 0, got $hits)"
                FAIL=$((FAIL+1))
                FAIL_LINES+=("$det negative: got $hits")
            fi
        fi
    done
done

echo ""
echo "========================================="
echo " Python wave1 regression:  $PASS/$((PASS+FAIL)) passed"
echo "========================================="
(( FAIL > 0 )) && { printf '  - %s\n' "${FAIL_LINES[@]}"; exit 1; }
exit 0
