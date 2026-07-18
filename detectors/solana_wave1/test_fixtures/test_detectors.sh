#!/usr/bin/env bash
# test_detectors.sh — regression-check each solana_wave1 detector against its
# positive/negative Rust fixtures.
#
# solana_wave1 detectors are engine-first (`run(engine, filepath)`), same
# contract as go_wave1, but their source language is Rust (.rs). lang-detect.py
# hardcodes the detector dir as detectors/<lang>_wave1, so it cannot load
# solana_wave1 directly. This harness reuses tools/solana-detect.py — a thin
# orchestrator that points the same AstEngine("rust", ...) loop at
# detectors/solana_wave1/.
set -u
set -o pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$HERE/../../../tools"
TMPLOG="$(mktemp -t solana-detect-test.XXXXXX.log)"
TMPOUT="$(mktemp -t solana-detect-test.XXXXXX.out)"
trap 'rm -f "$TMPLOG" "$TMPOUT"' EXIT

find_python_with_parser() {
    if [[ -n "${AUDITOOOR_PYTHON_AST:-}" ]] && "$AUDITOOOR_PYTHON_AST" -c 'from tree_sitter_language_pack import get_parser; get_parser("rust")' >/dev/null 2>&1; then
        printf '%s\n' "$AUDITOOOR_PYTHON_AST"
        return 0
    fi
    local py
    for py in python3 python3.14 python3.13 python3.12 python3.11; do
        if command -v "$py" >/dev/null 2>&1 && "$py" -c 'from tree_sitter_language_pack import get_parser; get_parser("rust")' >/dev/null 2>&1; then
            command -v "$py"
            return 0
        fi
    done
    return 1
}

PYTHON_AST="$(find_python_with_parser || true)"
if [[ -z "$PYTHON_AST" ]]; then
    echo "  FAIL  dependency preflight  (no Python interpreter can load tree-sitter parser for rust)"
    echo "    Set AUDITOOOR_PYTHON_AST=/path/to/python or install tree_sitter_language_pack/tree_sitter_rust."
    exit 1
fi

DETECTORS=(
    proof_of_life
    solana_missing_signer_check
    solana_missing_owner_check
    solana_missing_is_writable_check
    solana_account_type_cosplay
    solana_missing_rent_exemption_check
    solana_unchecked_cpi_program_id
    solana_lamport_math_overflow
    solana_pda_bump_not_canonical
    solana_close_account_without_zeroing
    solana_sysvar_account_spoofing
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
        fixture="$HERE/${det}_${mode}.rs"
        if [[ ! -f "$fixture" ]]; then
            echo "  MISS $det $mode"
            FAIL=$((FAIL+1))
            FAIL_LINES+=("$det $mode: fixture missing")
            continue
        fi
        "$PYTHON_AST" "$TOOLS/solana-detect.py" "$HERE" \
            --only "$det" --file "$fixture" \
            --log "$TMPLOG" >"$TMPOUT" 2>&1
        rc=$?
        hits="$(count_hits "$det" "$TMPLOG")"
        hits="${hits:-0}"
        if (( rc != 0 )) || grep -qE '^# files: .* parse_errors: [1-9]' "$TMPLOG"; then
            echo "  FAIL  $det $mode  (solana-detect dependency/parse failure)"
            tail -20 "$TMPOUT" | sed 's/^/    /'
            FAIL=$((FAIL+1))
            FAIL_LINES+=("$det $mode: solana-detect dependency/parse failure")
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
echo " Solana wave1 regression:  $PASS/$((PASS+FAIL)) passed"
echo "========================================="
(( FAIL > 0 )) && { printf '  - %s\n' "${FAIL_LINES[@]}"; exit 1; }
exit 0
