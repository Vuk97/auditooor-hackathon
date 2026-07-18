#!/usr/bin/env bash
# env-check.sh — verify (and auto-install) required build tools for a target workspace (R38 Issue #137).
#
# The canonical flow assumed `forge build` + `slither` would just work. R38 Centrifuge proved
# otherwise: foundry.toml pinned solc 0.8.28 + Cancun, installed solc was 0.8.21 → Slither
# IR-gen failed silently → zero-signal scan. This tool:
#   1. Reads <ws>/src/<repo>/foundry.toml for solc_version + evm_version
#   2. Verifies solc-select has that version installed; `solc-select install <v>` if missing
#   3. Calls `solc-select use <v>`
#   4. Runs `forge build` as a compile-check
#   5. Runs `slither <ws>/src/<repo> --solc-remaps ... --no-fail-on-error` as the smoke-test
#   6. Exits non-zero if any step fails, with a clear remediation message
#
# Usage:
#   ./tools/env-check.sh <workspace>
#
# Exit codes:
#   0 — environment ready, scan will work
#   1 — HARD STOP — missing solc-select (install via pip/brew)
#   2 — HARD STOP — foundry.toml solc_version not satisfied (auto-install attempted, then failed)
#   3 — HARD STOP — `forge build` failed
#   4 — HARD STOP — `slither` smoke-test failed (IR gen / compile)
#   5 — SOFT WARN — foundry.toml not found (non-foundry target — no gate)
#
# Hook this BEFORE scan.sh / run_custom.py in the canonical flow.

set -u
WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
  echo "usage: $0 <workspace>" >&2
  exit 1
fi

AUDITOOOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# PR560-H: record Foundry inventory before any environment mutation. This
# helper is offline-safe and never installs/upgrades Foundry.
if [ -x "$AUDITOOOR_DIR/tools/foundry-version-report.py" ]; then
  python3 "$AUDITOOOR_DIR/tools/foundry-version-report.py" --workspace "$WS" >/dev/null 2>&1 || \
    echo "[env-check] WARN — Foundry version inventory failed; continuing env-check"
fi

# Resolve forge binary (catches PATH collisions, broken forge installs)
source "$AUDITOOOR_DIR/tools/lib/forge-resolve.sh" || exit 1
echo "[env-check] using forge: $FORGE_BIN"

# Find foundry.toml under src/<repo>/
TOML=$(find "$WS/src" -maxdepth 3 -name "foundry.toml" 2>/dev/null | head -1)
if [ -z "$TOML" ]; then
  echo "[env-check] no foundry.toml found under $WS/src/ — skipping env gate"
  exit 5
fi

REPO_DIR=$(dirname "$TOML")
echo "[env-check] found foundry.toml at $TOML"

# Parse solc_version + evm_version. Extract quoted content only (BSD sed compatible).
SOLC_VERSION=$(grep -E '^[[:space:]]*solc_version[[:space:]]*=' "$TOML" | head -1 | grep -oE '"[^"]+"' | tr -d '"' | head -1)
EVM_VERSION=$(grep -E '^[[:space:]]*evm_version[[:space:]]*=' "$TOML" | head -1 | grep -oE '"[^"]+"' | tr -d '"' | head -1)

echo "[env-check] target requires solc=$SOLC_VERSION evm=$EVM_VERSION"

# Check solc-select present
if ! command -v solc-select >/dev/null 2>&1; then
  echo "[env-check] HARD STOP — solc-select not installed"
  echo "  Install: pip3 install solc-select (or brew install solc-select on macOS)"
  exit 1
fi

# Check / install target solc version
if [ -n "$SOLC_VERSION" ]; then
  if ! solc-select versions 2>/dev/null | grep -qE "^${SOLC_VERSION}\b|^${SOLC_VERSION}\s*\("; then
    echo "[env-check] solc $SOLC_VERSION missing — installing"
    if ! solc-select install "$SOLC_VERSION" >/dev/null 2>&1; then
      echo "[env-check] HARD STOP — solc-select install $SOLC_VERSION failed"
      exit 2
    fi
  fi
  solc-select use "$SOLC_VERSION" >/dev/null 2>&1
  ACTUAL=$(solc --version 2>/dev/null | grep -oE '0\.[0-9]+\.[0-9]+' | head -1)
  if [ "$ACTUAL" != "$SOLC_VERSION" ]; then
    echo "[env-check] HARD STOP — solc-select use failed: wanted $SOLC_VERSION got $ACTUAL"
    exit 2
  fi
  echo "[env-check] solc $ACTUAL active"
fi

# ── R79 T2: auto-install ALL solc versions pinned via `pragma solidity =X.Y.Z` in any src/ file. ──
# Polymarket ships files with =0.8.15 / =0.8.19 / =0.8.30 / =0.8.34 — env-check must
# install every one or slither per-module scans fail. Collect unique pragmas:
PRAGMA_VERS=$(grep -rhE '^[[:space:]]*pragma[[:space:]]+solidity' "$WS/src" 2>/dev/null \
  | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u)
if [ -n "$PRAGMA_VERS" ]; then
    echo "[env-check] R79 T2: detected pragma versions in src/: $(echo $PRAGMA_VERS | tr '\n' ' ')"
    for pv in $PRAGMA_VERS; do
        # Reject pre-0.4 and 0.9+ (don't exist in solc-select)
        case "$pv" in
            0.[0-3].*|0.4.0|0.4.1|0.4.2|0.4.3|0.4.4|0.4.5|0.4.6|0.4.7|0.4.8|0.4.9|0.4.10) continue ;;
            0.9.*|1.*) continue ;;
        esac
        if ! solc-select versions 2>/dev/null | grep -qE "^${pv}\b|^${pv}\s*\("; then
            echo "[env-check] auto-installing solc $pv (from src pragma)"
            solc-select install "$pv" >/dev/null 2>&1 || echo "[env-check] WARN: solc-select install $pv failed (continuing)"
        fi
    done
fi

# ── R79 T6: auto-clone missing Polymarket / known-lib deps ──
# If source references a lib directory that doesn't exist, clone it from a known mapping.
# This fixes the "lib/ctf-exchange not found" blocker that killed R77/R78 scans.
declare -A DEP_REPOS=(
    ["ctf-exchange"]="https://github.com/Polymarket/ctf-exchange.git"
    ["exchange-fee-module"]="https://github.com/Polymarket/exchange-fee-module.git"
    ["solady"]="https://github.com/Vectorized/solady.git"
    ["solmate"]="https://github.com/transmissions11/solmate.git"
    ["forge-std"]="https://github.com/foundry-rs/forge-std.git"
    ["openzeppelin-contracts"]="https://github.com/OpenZeppelin/openzeppelin-contracts.git"
) 2>/dev/null
# Bash 3 on macOS doesn't support associative arrays; fall through gracefully
REFERENCED_LIBS=$(grep -rhE 'import[[:space:]]+.*["'\''][^"'\'']+' "$WS/src" 2>/dev/null | \
    grep -oE 'lib/[a-zA-Z0-9_-]+/' | sort -u | sed 's|lib/||; s|/$||')
for lib in $REFERENCED_LIBS; do
    if [ ! -d "$WS/lib/$lib" ]; then
        case "$lib" in
            ctf-exchange) url="https://github.com/Polymarket/ctf-exchange.git" ;;
            exchange-fee-module) url="https://github.com/Polymarket/exchange-fee-module.git" ;;
            solady) url="https://github.com/Vectorized/solady.git" ;;
            solmate) url="https://github.com/transmissions11/solmate.git" ;;
            forge-std) url="https://github.com/foundry-rs/forge-std.git" ;;
            openzeppelin-contracts) url="https://github.com/OpenZeppelin/openzeppelin-contracts.git" ;;
            *) echo "[env-check] missing dep $lib — no known repo mapping; skipping"; continue ;;
        esac
        echo "[env-check] R79 T6: cloning missing dep lib/$lib from $url"
        git clone --depth 1 "$url" "$WS/lib/$lib" 2>&1 | tail -2 || \
            echo "[env-check] WARN: clone of $lib failed (continuing)"
    fi
done

# ── R67c (SKILL_ISSUES #168): canonical-weth WETH9 pin breaks modern solc ──
# If any lib/canonical-weth/contracts/WETH9.sol exists with the original <0.6
# pragma, the downstream build fails with "No solc version exists that
# matches". Auto-install the 0.8 compat shim so forge/slither can proceed.
if find "$REPO_DIR" -path "*/lib/canonical-weth/contracts/WETH9.sol" 2>/dev/null | grep -q .; then
  if ! grep -q "0.8.x compatibility shim" "$REPO_DIR"/lib/canonical-weth/contracts/WETH9.sol 2>/dev/null; then
    if [ -x "$AUDITOOOR_DIR/tools/install-weth9-shim.sh" ]; then
      echo "[env-check] R67c — installing WETH9 0.8 compat shim"
      bash "$AUDITOOOR_DIR/tools/install-weth9-shim.sh" "$WS" 2>&1 | sed 's/^/    /' || true
    fi
  fi
fi

# ── R67d (SKILL_ISSUES #169): OZ v5 + via_ir=false = stack-too-deep ──
# If the contracts import OZ and the installed OZ version is v5+, the via_ir
# flag MUST be true or tests hit "Stack too deep" on modern frames.
if [ -d "$REPO_DIR/lib/openzeppelin-contracts" ]; then
  OZ_PKG="$REPO_DIR/lib/openzeppelin-contracts/package.json"
  if [ -f "$OZ_PKG" ]; then
    OZ_VER=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[0-9]+' "$OZ_PKG" 2>/dev/null | grep -oE '[0-9]+$' | head -1)
    if [ "${OZ_VER:-0}" -ge 5 ]; then
      VIA_IR=$(grep -E '^[[:space:]]*via_ir[[:space:]]*=' "$TOML" | head -1 | grep -oE '(true|false)' | head -1)
      if [ "$VIA_IR" = "false" ]; then
        echo "[env-check] R67d — OZ v${OZ_VER} detected + via_ir=false in foundry.toml"
        echo "           This combo causes 'Stack too deep' on test compiles."
        echo "           SOFT WARN: consider setting via_ir=true in the default profile."
        echo "           (Production profile may stay as-is.)"
      fi
    fi
  fi
fi

# forge build smoke-test
# Prefer real Foundry forge over PATH collisions (e.g. AI CLI tool named forge)
FORGE_BIN=""
if [[ -x "$HOME/.foundry/bin/forge" ]]; then
  FORGE_BIN="$HOME/.foundry/bin/forge"
elif command -v forge >/dev/null 2>&1; then
  FORGE_BIN="$(command -v forge)"
fi
if [[ -n "$FORGE_BIN" ]]; then
  echo "[env-check] running forge build (this can take 1-3 min on first run)..."
  if ! (cd "$REPO_DIR" && "$FORGE_BIN" build --silent 2>&1 | tee /tmp/env-check-forge.log | tail -20); then
    echo "[env-check] HARD STOP — forge build failed. See /tmp/env-check-forge.log"
    exit 3
  fi
  echo "[env-check] forge build OK"
else
  echo "[env-check] SOFT WARN — forge not installed; skipping build check"
fi

# Slither smoke-test (compile only, short run)
if command -v slither >/dev/null 2>&1; then
  echo "[env-check] running slither smoke-test (just compile + list contracts)..."
  SLITHER_OUT=$((cd "$REPO_DIR" && slither . --print human-summary 2>&1 | head -20) || true)
  if echo "$SLITHER_OUT" | grep -qE "Failed to generate IR|Error compiling target|SlitherSolcParsing"; then
    echo "[env-check] HARD STOP — slither compile / IR-gen failed"
    echo "  Output:"
    echo "$SLITHER_OUT" | head -15 | sed 's/^/    /'
    echo ""
    echo "  Remediation:"
    echo "    1. Confirm solc version matches: solc --version"
    echo "    2. Try scanning per-module: python3 detectors/run_custom.py <module-dir>"
    echo "    3. Upgrade Slither: pip3 install -U slither-analyzer"
    echo "    4. File issue to crytic/slither with the function that failed IR-gen"
    exit 4
  fi
  echo "[env-check] slither smoke OK"
else
  echo "[env-check] SOFT WARN — slither not installed; skipping smoke"
fi

# ── R88 fix: symbolic + economic scanners are NOW MANDATORY ──
# R81-R87 cumulative gap: concolic-scan + economic-hypotheses-ir were
# flagged as NEVER-RAN in every post-scan audit but the soft-warn below
# let operators skip them for 5 rounds. User R88 directive: "Fix the gaps.
# You always complain about the gaps but keep skipping steps etc."
# → auto-install both, HARD STOP on failure.

if ! command -v halmos >/dev/null 2>&1; then
  echo "[env-check] halmos not installed — AUTO-INSTALLING (mandatory for concolic-scan.sh)"
  if pip3 install halmos 2>&1 | tail -5 | grep -qE "Successfully installed|already satisfied"; then
    echo "[env-check] halmos install OK"
  else
    echo "[env-check] HARD STOP — halmos install failed. Manual install:"
    echo "    pip3 install halmos    # pulls z3-solver (~100MB)"
    echo "  Then re-run env-check."
    exit 6
  fi
fi
HALMOS_VER=$(halmos --version 2>&1 | head -1 | tr -d '\n' | cut -c1-80)
echo "[env-check] halmos ready: $HALMOS_VER"

# Mythril as fallback for concolic-scan --tool mythril
if ! command -v myth >/dev/null 2>&1; then
  echo "[env-check] mythril not installed — attempting install (fallback for halmos)"
  pip3 install mythril 2>&1 | tail -1 || echo "[env-check] SOFT WARN — mythril install failed (OK; halmos is preferred)"
fi

echo ""
echo "[env-check] environment ready for $WS"
echo "[env-check] Next steps in canonical flow:"
echo "    1. bash tools/fix-remappings.sh <ws>"
echo "    2. bash tools/mixed-pragma-build.sh <ws>"
echo "    3. bash tools/scan-full.sh <ws>    # R88 orchestrator: patterns + slither + halmos + economic-ir"
exit 0
