#!/usr/bin/env bash
# mixed-pragma-build.sh — R80 T10: build every pragma-group in a Polymarket-style
# workspace so downstream Slither / run_custom.py can scan all of it.
#
# Background: Polymarket ships 5+ different pragmas across src/:
#   - src/factories/ProxyFactory.sol          pragma ^0.5.0
#   - src/v1/fee-module/*.sol                  pragma =0.8.13
#   - src/v1/exchange/*.sol                    pragma 0.8.15
#   - src/v1/uma/*.sol                         pragma 0.8.15
#   - src/v1/neg-risk/*.sol                    pragma 0.8.19
#   - src/exchange/*.sol                       pragma 0.8.30
#   - src/collateral/ + src/adapters/          pragma 0.8.34
# A single `forge build` with `auto_detect_solc=true` still fails because
# some files import across pragma boundaries (e.g. test helpers on 0.8.15
# importing OZ v5 which requires ^0.8.20).
#
# This script runs `forge build` once per pragma-group, isolating each
# subtree into a temporary dir with just its own sources + required libs.
# Output goes to <workspace>/out-mixed/<pragma>/ — can be consumed by
# `run_custom.py` per subtree.
#
# Usage:
#   bash tools/mixed-pragma-build.sh <workspace>
#
# Exit: 0 if ≥1 group built successfully, 1 otherwise.

set -u
WS="${1:-}"
[ -z "$WS" ] || [ ! -d "$WS" ] && { echo "usage: $0 <workspace>" >&2; exit 1; }
WS_ABS=$(cd "$WS" && pwd)

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Discover subtrees using the shared skip-paths (same rules as the Python analyzers)
SKIP_RE='/(test|tests|mock|mocks|dev|script|scripts|lib|out|cache|node_modules|economic_hypotheses|ARCHIVED_FOR_SCAN)(/|$)'

# 1. Enumerate each leaf src-subtree that has at least one .sol file.
SUBTREES=$(find "$WS_ABS" -maxdepth 4 -type d 2>/dev/null | \
    awk '/\/src[^\/]*\/[^\/]+$/' | \
    grep -vE "$SKIP_RE" | sort -u)

if [ -z "$SUBTREES" ]; then
    echo "[err] no subtrees found under $WS/src*/" >&2
    exit 1
fi

echo "[mixed-pragma-build] discovered subtrees:"
printf '  %s\n' $SUBTREES

# 2. Detect dominant pragma per subtree (same logic as multisolc scanner).
detect_pragma() {
    local subdir="$1"
    local p
    p=$(grep -hE '^[[:space:]]*pragma[[:space:]]+solidity' \
         "$subdir"/*.sol 2>/dev/null | head -20 | \
         grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | \
         grep -vE '^(0\.9\.|1\.|0\.[0-3]\.)' | \
         sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
    if [ -z "$p" ]; then
        p=$(grep -rhE '^[[:space:]]*pragma[[:space:]]+solidity' \
             "$subdir" --include="*.sol" 2>/dev/null | head -40 | \
             grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | \
             grep -vE '^(0\.9\.|1\.|0\.[0-3]\.)' | \
             sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
    fi
    if [[ "$p" =~ ^[0-9]+\.[0-9]+$ ]]; then p="${p}.0"; fi
    echo "$p"
}

# 3. For each subtree, build in isolation.
OUT_ROOT="$WS_ABS/out-mixed"
mkdir -p "$OUT_ROOT"
: > "$OUT_ROOT/build-report.log"

OK=0
FAIL=0
for subdir in $SUBTREES; do
    name="${subdir#$WS_ABS/}"
    pragma=$(detect_pragma "$subdir")
    if [ -z "$pragma" ]; then
        echo "[skip] $name — no pragma detected" | tee -a "$OUT_ROOT/build-report.log"
        FAIL=$((FAIL + 1)); continue
    fi

    echo "[build] $name  pragma=$pragma" | tee -a "$OUT_ROOT/build-report.log"
    solc-select install "$pragma" >/dev/null 2>&1 || true
    if ! solc-select use "$pragma" >/dev/null 2>&1; then
        echo "  [fail] solc-select $pragma unavailable" | tee -a "$OUT_ROOT/build-report.log"
        FAIL=$((FAIL + 1)); continue
    fi

    # Isolate into temp dir
    tmpdir="$(mktemp -d -t "poly-${pragma//./-}.XXXXXX")"
    mkdir -p "$tmpdir/src" "$tmpdir/lib"
    cp -r "$subdir"/* "$tmpdir/src/" 2>/dev/null
    # Copy the workspace's lib/ so imports resolve
    [ -d "$WS_ABS/lib" ] && cp -r "$WS_ABS/lib/"* "$tmpdir/lib/" 2>/dev/null

    # Remove test/mock/script artefacts from the isolated source
    find "$tmpdir/src" -name "*.t.sol" -delete 2>/dev/null
    find "$tmpdir/src" -name "*.s.sol" -delete 2>/dev/null
    find "$tmpdir/src" -type d \( -name test -o -name tests -o -name mock -o -name mocks -o -name dev -o -name script -o -name scripts \) -exec rm -rf {} + 2>/dev/null

    cat > "$tmpdir/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "$pragma"
evm_version = "paris"
optimizer = true
EOF

    # Inherit remappings from workspace if present
    if [ -f "$WS_ABS/remappings.txt" ]; then
        cp "$WS_ABS/remappings.txt" "$tmpdir/remappings.txt"
        # Rewrite ./  remappings to point at the tmpdir (T5 fix)
        bash "$AUDITOOOR_DIR/tools/fix-remappings.sh" "$tmpdir" >/dev/null 2>&1 || true
    fi

    if (cd "$tmpdir" && forge build --skip test --skip script 2>&1 | tail -3) | \
        grep -qE "^Error|^error"; then
        echo "  [fail] forge build failed in $tmpdir" | tee -a "$OUT_ROOT/build-report.log"
        FAIL=$((FAIL + 1))
    else
        # Copy build-info to the workspace's output root for downstream Slither
        target_out="$OUT_ROOT/${pragma}_$(echo "$name" | tr / _)"
        rm -rf "$target_out"
        mkdir -p "$target_out"
        [ -d "$tmpdir/out" ] && cp -r "$tmpdir/out/"* "$target_out/" 2>/dev/null
        # Also keep the tmpdir path for per-subtree slither scans
        echo "$pragma|$name|$tmpdir|$target_out" >> "$OUT_ROOT/subtree-map.txt"
        OK=$((OK + 1))
        echo "  [ok] build artifacts → $target_out" | tee -a "$OUT_ROOT/build-report.log"
    fi
done

echo
echo "[mixed-pragma-build] summary: OK=$OK FAIL=$FAIL"
echo "  build-report: $OUT_ROOT/build-report.log"
echo "  subtree-map:  $OUT_ROOT/subtree-map.txt"

[ "$OK" -ge 1 ] && exit 0 || exit 1
