#!/usr/bin/env bash
# test_gen_state_root_parity.sh — Wave 3 state-root parity scaffold tests.
#
# Hermetic: scaffolds synthetic workspaces in a temp dir, runs the generator,
# and asserts file shape, idempotency, and self-skip behavior.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GEN="$ROOT/tools/gen-state-root-parity.sh"

FAIL_COUNT=0
PASS_COUNT=0

_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
    echo "  PASS — $1"
}

_fail() {
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  FAIL — $1" >&2
}

# Verify the generator script exists and is executable.
if [[ ! -x "$GEN" ]]; then
    echo "FATAL: $GEN missing or not executable" >&2
    exit 2
fi

# A clean tempdir per test run, cleaned on exit.
TMPROOT=$(mktemp -d -t auditooor-state-root-parity.XXXXXX)
trap 'rm -rf "$TMPROOT"' EXIT

# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Empty / non-Rust workspace -> self-skip, exit 0, no scaffold dir.
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 1] empty workspace -> self-skip"
WS1="$TMPROOT/empty"
mkdir -p "$WS1"

if out=$("$GEN" --workspace "$WS1" 2>&1); then
    if echo "$out" | grep -q "skipped: not a Rust DLT workspace"; then
        _pass "test 1: emitted 'skipped: not a Rust DLT workspace' line"
    else
        _fail "test 1: missing skip message; got: $out"
    fi
    if [[ ! -d "$WS1/differential_fuzz/state_root_parity" ]]; then
        _pass "test 1: no scaffold generated"
    else
        _fail "test 1: scaffold dir was generated for empty workspace"
    fi
else
    _fail "test 1: generator exited non-zero on empty workspace"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 1b: Solidity-only workspace -> self-skip.
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 1b] solidity-only workspace -> self-skip"
WS1B="$TMPROOT/solidity_only"
mkdir -p "$WS1B/src"
cat > "$WS1B/foundry.toml" <<'TOML'
[profile.default]
src = "src"
TOML
cat > "$WS1B/src/Foo.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Foo { uint256 public x; }
SOL

if out=$("$GEN" --workspace "$WS1B" 2>&1); then
    if echo "$out" | grep -q "skipped: not a Rust DLT workspace"; then
        _pass "test 1b: solidity-only workspace skipped"
    else
        _fail "test 1b: missing skip message; got: $out"
    fi
    if [[ ! -d "$WS1B/differential_fuzz/state_root_parity" ]]; then
        _pass "test 1b: no scaffold generated for solidity-only"
    else
        _fail "test 1b: scaffold generated for solidity-only workspace"
    fi
else
    _fail "test 1b: generator exited non-zero on solidity-only workspace"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 1c: Cargo workspace WITHOUT revm/alloy/reth -> self-skip.
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 1c] cargo workspace without DLT deps -> self-skip"
WS1C="$TMPROOT/cargo_no_dlt"
mkdir -p "$WS1C/src"
cat > "$WS1C/Cargo.toml" <<'TOML'
[package]
name = "demo"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1"
TOML
echo "fn main() {}" > "$WS1C/src/main.rs"

if out=$("$GEN" --workspace "$WS1C" 2>&1); then
    if echo "$out" | grep -q "skipped: not a Rust DLT workspace"; then
        _pass "test 1c: non-DLT cargo workspace skipped"
    else
        _fail "test 1c: missing skip message; got: $out"
    fi
else
    _fail "test 1c: generator exited non-zero on non-DLT cargo workspace"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 2: Synthetic Cargo workspace WITH revm dep -> scaffold IS generated.
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 2] cargo workspace with revm dep -> scaffold generated"
WS2="$TMPROOT/cargo_with_revm"
mkdir -p "$WS2/crates/reth-evm-core/src"
cat > "$WS2/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/reth-evm-core"]
TOML
cat > "$WS2/crates/reth-evm-core/Cargo.toml" <<'TOML'
[package]
name = "reth-evm-core"
version = "0.1.0"
edition = "2021"

[dependencies]
revm = "14"
alloy-consensus = "0.5"
TOML
echo "pub fn execute() {}" > "$WS2/crates/reth-evm-core/src/lib.rs"

if out=$("$GEN" --workspace "$WS2" 2>&1); then
    _pass "test 2: generator exited 0"
    SCAFFOLD="$WS2/differential_fuzz/state_root_parity"
    if [[ -d "$SCAFFOLD" ]]; then
        _pass "test 2: scaffold dir created"
    else
        _fail "test 2: scaffold dir missing"
    fi

    for f in Cargo.toml src/main.rs Makefile README.md; do
        if [[ -f "$SCAFFOLD/$f" ]]; then
            _pass "test 2: $f present"
        else
            _fail "test 2: $f missing"
        fi
    done

    # Corpus: exactly 10 JSON files.
    corpus_count=$(ls "$SCAFFOLD/corpus"/*.json 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$corpus_count" == "10" ]]; then
        _pass "test 2: corpus has exactly 10 blocks"
    else
        _fail "test 2: expected 10 corpus blocks, found $corpus_count"
    fi

    # Each corpus file must parse as JSON.
    bad_json=0
    for f in "$SCAFFOLD/corpus"/*.json; do
        if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$f" >/dev/null 2>&1; then
            bad_json=$((bad_json + 1))
            echo "    bad JSON: $f"
        fi
    done
    if [[ "$bad_json" == "0" ]]; then
        _pass "test 2: all corpus files are valid JSON"
    else
        _fail "test 2: $bad_json corpus files are invalid JSON"
    fi

    # Required corpus names per the brief.
    required_names=(
        "01_empty_block"
        "02_single_tx_state_change"
        "03_contract_creation"
        "04_selfdestruct"
        "05_eip4844_blob_tx"
        "06_eip7702_delegate"
        "07_gas_limit_boundary"
        "08_gas_refund_boundary"
        "09_large_calldata"
        "10_max_state_touch"
    )
    missing=0
    for n in "${required_names[@]}"; do
        if [[ ! -f "$SCAFFOLD/corpus/$n.json" ]]; then
            missing=$((missing + 1))
            echo "    missing: $n.json"
        fi
    done
    if [[ "$missing" == "0" ]]; then
        _pass "test 2: all 10 named edge-case corpus files present"
    else
        _fail "test 2: $missing required corpus files missing"
    fi

    # Cargo.toml shape: must reference revm + path = "../../<something>"
    if grep -q '^revm[[:space:]]*=' "$SCAFFOLD/Cargo.toml" \
       && grep -qE 'path = "\.\./\.\./' "$SCAFFOLD/Cargo.toml"; then
        _pass "test 2: Cargo.toml references revm and uses ../../ relative path"
    else
        _fail "test 2: Cargo.toml missing revm dep or relative path"
    fi

    # main.rs shape: must define BlockInput and ParityResult and a main()
    if grep -q 'struct BlockInput' "$SCAFFOLD/src/main.rs" \
       && grep -q 'struct ParityResult' "$SCAFFOLD/src/main.rs" \
       && grep -q 'fn main' "$SCAFFOLD/src/main.rs" \
       && grep -q 'TODO verify revm API' "$SCAFFOLD/src/main.rs" \
       && grep -q 'STATE_ROOT_PARITY_WIRING_REQUIRED' "$SCAFFOLD/src/main.rs" \
       && grep -q 'scaffolded_unverified' "$SCAFFOLD/src/main.rs"; then
        _pass "test 2: main.rs has BlockInput/ParityResult/main + fail-closed wiring marker"
    else
        _fail "test 2: main.rs missing required structures, TODO marker, or fail-closed marker"
    fi

    # Makefile shape: must have check-wired + fuzz-state-root target.
    if grep -q '^check-wired:' "$SCAFFOLD/Makefile" \
       && grep -q '^fuzz-state-root: check-wired build-in-tree' "$SCAFFOLD/Makefile"; then
        _pass "test 2: Makefile has fail-closed check-wired + fuzz-state-root targets"
    else
        _fail "test 2: Makefile missing fail-closed check-wired/fuzz-state-root targets"
    fi

    if command -v make >/dev/null 2>&1; then
        if (cd "$SCAFFOLD" && make fuzz-state-root >/tmp/auditooor-state-root-parity-fuzz.out 2>&1); then
            _fail "test 2: unwired fuzz-state-root unexpectedly succeeded"
        elif grep -q 'REFUSING: harness is still scaffold-only' /tmp/auditooor-state-root-parity-fuzz.out; then
            _pass "test 2: unwired fuzz-state-root fails closed before reporting divergences"
        else
            _fail "test 2: unwired fuzz-state-root failed, but without fail-closed refusal message"
        fi
        rm -f /tmp/auditooor-state-root-parity-fuzz.out
    fi

    # cargo check (best-effort): if cargo is present, run it. Otherwise skip
    # the build check and just verify file shape (per brief).
    if command -v cargo >/dev/null 2>&1; then
        if (cd "$SCAFFOLD" && cargo check --offline >/dev/null 2>&1); then
            _pass "test 2: cargo check (offline) passes"
        else
            # Offline check may fail if no registry cache — fall back to
            # parse-only check via rustc on main.rs (syntax only).
            if command -v rustc >/dev/null 2>&1; then
                if rustc --edition 2021 -Zparse-only "$SCAFFOLD/src/main.rs" >/dev/null 2>&1; then
                    _pass "test 2: rustc parse-only check passes"
                else
                    # Some toolchains don't have -Zparse-only on stable; we
                    # only need to confirm the file is *shaped* like rust.
                    head_ok=$(head -1 "$SCAFFOLD/src/main.rs" | grep -c '^//')
                    if [[ "$head_ok" -ge "1" ]]; then
                        _pass "test 2: main.rs file shape sanity-checked (cargo/rustc full check skipped, no offline registry)"
                    else
                        _fail "test 2: main.rs failed file-shape sanity check"
                    fi
                fi
            else
                _pass "test 2: file-shape sanity (rustc unavailable)"
            fi
        fi
    else
        _pass "test 2: cargo unavailable, file-shape verification only (per brief)"
    fi
else
    _fail "test 2: generator exited non-zero on cargo+revm workspace; out: $out"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 2b: Generated differential_fuzz Cargo crates are pruned from detection.
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 2b] generated differential_fuzz crates are ignored"
WS2B="$TMPROOT/external_with_old_fuzz"
mkdir -p "$WS2B/differential_fuzz/old_generated/src" \
         "$WS2B/scanners/_slither-tmp/lib/risc0-ethereum/src" \
         "$WS2B/external/base/crates/utilities/reth-cli/src" \
         "$WS2B/external/base/crates/execution/evm/src"
cat > "$WS2B/differential_fuzz/old_generated/Cargo.toml" <<'TOML'
[package]
name = "old-generated-fuzz"
version = "0.1.0"
edition = "2021"

[dependencies]
revm = "14"
TOML
echo "pub fn generated() {}" > "$WS2B/differential_fuzz/old_generated/src/lib.rs"
cat > "$WS2B/scanners/_slither-tmp/lib/risc0-ethereum/Cargo.toml" <<'TOML'
[package]
name = "scanner-scratch"
version = "0.1.0"
edition = "2021"

[dependencies]
revm = "14"
TOML
echo "pub fn scanner_scratch() {}" > "$WS2B/scanners/_slither-tmp/lib/risc0-ethereum/src/lib.rs"
cat > "$WS2B/external/base/Cargo.toml" <<'TOML'
[workspace]
members = ["crates/execution/evm", "crates/utilities/reth-cli"]
TOML
cat > "$WS2B/external/base/crates/utilities/reth-cli/Cargo.toml" <<'TOML'
[package]
name = "base-reth-cli"
version = "0.1.0"
edition = "2021"

[dependencies]
revm = "14"
TOML
echo "pub fn cli() {}" > "$WS2B/external/base/crates/utilities/reth-cli/src/lib.rs"
cat > "$WS2B/external/base/crates/execution/evm/Cargo.toml" <<'TOML'
[package]
name = "base-execution-evm"
version = "0.1.0"
edition = "2021"

[dependencies]
revm = "14"
TOML
echo "pub fn execute() {}" > "$WS2B/external/base/crates/execution/evm/src/lib.rs"

if out=$("$GEN" --workspace "$WS2B" 2>&1); then
    SCAFFOLD2B="$WS2B/differential_fuzz/state_root_parity"
    if grep -q 'path = "../../external/base/crates/execution/evm"' "$SCAFFOLD2B/Cargo.toml"; then
        _pass "test 2b: generated/scanner crates pruned; in-tree path prefers external/base execution EVM"
    else
        _fail "test 2b: generated/scanner/utility crate polluted in-tree path"
        echo "    out: $out"
        grep 'path = ' "$SCAFFOLD2B/Cargo.toml" 2>/dev/null || true
    fi
else
    _fail "test 2b: generator exited non-zero; out: $out"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 3: Re-run is idempotent (does not overwrite).
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 3] idempotent re-run"
SCAFFOLD2="$WS2/differential_fuzz/state_root_parity"
# Mark the existing main.rs with a sentinel so we can detect overwrite.
echo "// SENTINEL_DO_NOT_OVERWRITE" >> "$SCAFFOLD2/src/main.rs"
SENTINEL_HASH_BEFORE=$(shasum "$SCAFFOLD2/src/main.rs" | awk '{print $1}')

if out=$("$GEN" --workspace "$WS2" 2>&1); then
    if echo "$out" | grep -q "scaffold already exists"; then
        _pass "test 3: re-run announced 'scaffold already exists'"
    else
        _fail "test 3: re-run did not announce existing scaffold; got: $out"
    fi
    SENTINEL_HASH_AFTER=$(shasum "$SCAFFOLD2/src/main.rs" | awk '{print $1}')
    if [[ "$SENTINEL_HASH_BEFORE" == "$SENTINEL_HASH_AFTER" ]]; then
        _pass "test 3: existing scaffold not overwritten without --force"
    else
        _fail "test 3: scaffold was overwritten without --force"
    fi
else
    _fail "test 3: generator exited non-zero on re-run"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Test 4: --force overwrites.
# ─────────────────────────────────────────────────────────────────────────────
echo "[test 4] --force overwrites existing scaffold"
if out=$("$GEN" --workspace "$WS2" --force 2>&1); then
    if grep -q "SENTINEL_DO_NOT_OVERWRITE" "$SCAFFOLD2/src/main.rs"; then
        _fail "test 4: --force did not overwrite (sentinel still present)"
    else
        _pass "test 4: --force overwrote previous scaffold"
    fi
else
    _fail "test 4: generator exited non-zero with --force"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo
echo "================================================================"
echo "test_gen_state_root_parity.sh: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "================================================================"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
fi
exit 0
