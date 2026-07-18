#!/usr/bin/env bash
# test_deep_runner_auto_pick.sh — I15 (#331) + I16 (#332) regression tests
# for tools/symbolic-runner.sh and tools/fuzz-runner.sh `--contract`
# / `--test-contract` auto-pick from <ws>/swarm/mining_priorities.json.
#
# Background:
#   * symbolic-runner used to accept ONLY entry.contract (singular). PR
#     202+ added entry.contracts[] (plural). This PR (#331) adds a final
#     title-regex fallback for the empty `contracts: []` shape that the
#     mining-prioritizer emits on monetrix and base-azul, e.g.
#         "title": "Unauthenticated state write: MonetrixAccountant.initialize"
#         "contracts": []
#     Without the fallback, audit-deep --live --engine halmos exits at
#     startup with "A-AUTH target not provided".
#   * fuzz-runner had NO auto-pick at all. Medusa would then exit at
#     startup with "no targets specified". This PR (#332) adds the same
#     three-shape pick (contract / contracts[] / title regex) without
#     filtering by --angle (fuzzers are angle-agnostic).
#
# Hermetic: each test scaffolds a tempdir + a fake mining_priorities.json,
# invokes the runner with --out-dir into the same tempdir, and reads
# back contract.txt (symbolic-runner) or the generated command line
# (fuzz-runner).
#
# Pure shell, no python/forge/foundry/halmos/medusa dependency. The
# auto-pick block is implemented in pure-Python via a heredoc inside
# the runners; we only need python3 on PATH.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYMBOLIC_RUNNER="$ROOT/tools/symbolic-runner.sh"
FUZZ_RUNNER="$ROOT/tools/fuzz-runner.sh"

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

_make_fake_engine() {
    # Fake `medusa` binary that records its argv to $1/argv.txt and
    # exits 0 so the wrapper classifier records status=pass.
    local bin_dir="$1"
    local engine="$2"
    mkdir -p "$bin_dir"
    cat > "$bin_dir/$engine" <<EOF
#!/usr/bin/env bash
case "\$1" in
    --version|-v|version)
        echo "fake-$engine 0.0.0-test"; exit 0 ;;
esac
echo "fake-$engine argv=\$*" > "$bin_dir/argv.txt"
exit 0
EOF
    chmod +x "$bin_dir/$engine"
}

# --------------------------------------------------------------------------
# I15 — symbolic-runner auto-pick fallbacks (use ANGLE=A-ORACLE so the
# scaffolded-only path emits a manifest without needing halmos / foundry.toml,
# but the auto-pick block has already populated CONTRACT before that exit).
# --------------------------------------------------------------------------

_run_symbolic_oracle_auto_pick() {
    # Shared invocation: write a mining_priorities.json containing one or
    # more entries with id=A-ORACLE, run the symbolic-runner with
    # --angle A-ORACLE (so we exit via the scaffolded path), and emit
    # `<out>/contract.txt`.
    local ws="$1"
    local out="$2"
    SYMBOLIC_DRY_RUN=1 \
    bash "$SYMBOLIC_RUNNER" "$ws" \
        --engine halmos \
        --angle A-ORACLE \
        --out-dir "$out" \
        --timeout 30 \
        >/dev/null 2>&1
}

test_symbolic_picks_singular_contract() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"angle":"A-ORACLE","contract":"OracleSingular","title":"X"}]
EOF
    _run_symbolic_oracle_auto_pick "$ws" "$out"
    if [ "$(cat "$out/contract.txt" 2>/dev/null)" = "OracleSingular" ]; then
        _pass "symbolic-runner: singular entry.contract is honored"
    else
        _fail "symbolic-runner: singular contract not picked (got: $(cat "$out/contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_picks_contracts_array() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-ORACLE","contracts":["FirstChoice","SecondChoice"],"title":"X"}]
EOF
    _run_symbolic_oracle_auto_pick "$ws" "$out"
    if [ "$(cat "$out/contract.txt" 2>/dev/null)" = "FirstChoice" ]; then
        _pass "symbolic-runner: entry.contracts[0] is picked when contract is absent"
    else
        _fail "symbolic-runner: contracts[] not picked (got: $(cat "$out/contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_picks_title_regex_when_contracts_empty() {
    # I15 fix core case: contracts is [] but the title encodes the
    # contract name — exact monetrix shape.
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-ORACLE","contracts":[],"title":"Unauthenticated state write: MonetrixAccountant.initialize"}]
EOF
    _run_symbolic_oracle_auto_pick "$ws" "$out"
    if [ "$(cat "$out/contract.txt" 2>/dev/null)" = "MonetrixAccountant" ]; then
        _pass "symbolic-runner: title regex falls back to ContractName.method"
    else
        _fail "symbolic-runner: title-regex fallback FAILED (got: $(cat "$out/contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_title_regex_centrifuge_shape() {
    # base-azul / centrifuge-style title verifying the colon-anchored
    # regex picks the SECOND identifier (after the colon) and not the
    # leading word.
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-ORACLE","contracts":[],"title":"Cross-contract reentrancy: BalanceSheet.submitQueuedAssets"}]
EOF
    _run_symbolic_oracle_auto_pick "$ws" "$out"
    if [ "$(cat "$out/contract.txt" 2>/dev/null)" = "BalanceSheet" ]; then
        _pass "symbolic-runner: title regex anchors to ': Name.method' shape"
    else
        _fail "symbolic-runner: title regex picked wrong identifier (got: $(cat "$out/contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_skips_non_matching_angle() {
    # Higher-ranked entry is for a DIFFERENT angle — auto-pick must
    # walk past it and pick the first A-ORACLE entry.
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[
  {"rank":1,"id":"A-AUTH","contracts":["AuthOnly"],"title":"Unauthenticated: AuthOnly.fn"},
  {"rank":2,"id":"A-ORACLE","contracts":["Wanted"],"title":"X"}
]
EOF
    _run_symbolic_oracle_auto_pick "$ws" "$out"
    if [ "$(cat "$out/contract.txt" 2>/dev/null)" = "Wanted" ]; then
        _pass "symbolic-runner: skips non-matching angle entries during auto-pick"
    else
        _fail "symbolic-runner: angle filter did not skip the wrong-angle entry (got: $(cat "$out/contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_falls_through_when_all_shapes_empty() {
    # Defensive: title has no PascalCase.method match. CONTRACT stays
    # empty and the scaffolded path emits contract.txt as just a
    # newline. We DO NOT exit non-zero for A-ORACLE.
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-ORACLE","contracts":[],"title":"some lowercase title with no captures"}]
EOF
    _run_symbolic_oracle_auto_pick "$ws" "$out"
    # contract.txt contains a single newline (echo of empty CONTRACT).
    local got
    got="$(cat "$out/contract.txt" 2>/dev/null)"
    if [ -z "$got" ]; then
        _pass "symbolic-runner: exhausted fallbacks leaves contract empty (advisory; A-ORACLE allows empty)"
    else
        _fail "symbolic-runner: extracted unexpected contract from non-matching title: '$got'"
    fi
    rm -rf "$td"
}

# --------------------------------------------------------------------------
# I16 — fuzz-runner auto-pick (mirrors symbolic-runner I15 fallbacks but
# does NOT filter by --angle: any entry with an extractable contract wins).
# Tested by checking the rendered command (medusa argv) so we don't need
# a real medusa binary.
# --------------------------------------------------------------------------

_run_fuzz_dry_with_priorities() {
    # Scaffolds: (a) priorities JSON in $ws/swarm/, (b) foundry.toml
    # so the project-root resolver passes, (c) fake medusa on PATH so
    # chosen_engine != "" and the dry-run writes a non-trivial argv.
    local ws="$1"
    local out="$2"
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    local bin_dir="$ws/bin"
    _make_fake_engine "$bin_dir" medusa
    PATH="$bin_dir:$PATH" \
        bash "$FUZZ_RUNNER" "$ws" \
            --engine medusa \
            --out-dir "$out" \
            --timeout 60 \
            --dry-run \
            >/dev/null 2>&1
}

test_fuzz_picks_singular_contract() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contract":"FuzzSingular","title":"X"}]
EOF
    _run_fuzz_dry_with_priorities "$ws" "$out"
    if grep -q -- "--target-contracts FuzzSingular" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: singular entry.contract is auto-picked into --target-contracts"
    else
        _fail "fuzz-runner: singular contract not threaded (command.txt: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_picks_contracts_array() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contracts":["FirstFuzz","Second"],"title":"X"}]
EOF
    _run_fuzz_dry_with_priorities "$ws" "$out"
    if grep -q -- "--target-contracts FirstFuzz" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: entry.contracts[0] picked when contract is absent"
    else
        _fail "fuzz-runner: contracts[] not threaded (command.txt: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_picks_title_regex_when_contracts_empty() {
    # I16 core case: empty contracts:[] + title encoding the name.
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contracts":[],"title":"Cross-contract reentrancy: AsyncRequestManager.callback"}]
EOF
    _run_fuzz_dry_with_priorities "$ws" "$out"
    if grep -q -- "--target-contracts AsyncRequestManager" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: title regex falls back to ContractName.method"
    else
        _fail "fuzz-runner: title-regex fallback FAILED (command.txt: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_explicit_test_contract_overrides_auto_pick() {
    # Operator-supplied --test-contract MUST WIN over the auto-pick
    # block (the auto-pick block guards on `[ -z "$TEST_CONTRACT" ]`).
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contract":"AutoPicked"}]
EOF
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    local bin_dir="$ws/bin"
    _make_fake_engine "$bin_dir" medusa
    PATH="$bin_dir:$PATH" \
        bash "$FUZZ_RUNNER" "$ws" \
            --engine medusa \
            --test-contract OperatorChose \
            --out-dir "$out" \
            --timeout 60 \
            --dry-run \
            >/dev/null 2>&1
    if grep -q -- "--target-contracts OperatorChose" "$out/command.txt" 2>/dev/null \
       && ! grep -q "AutoPicked" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: explicit --test-contract overrides auto-pick"
    else
        _fail "fuzz-runner: explicit --test-contract was ignored (command.txt: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_does_not_filter_by_angle() {
    # fuzz-runner is angle-agnostic — it must pick the FIRST entry
    # with any extractable contract regardless of angle id.
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[
  {"rank":1,"id":"A-AUTH","contracts":["FirstWins"],"title":"X"},
  {"rank":2,"id":"A-ORACLE","contracts":["NotPicked"],"title":"Y"}
]
EOF
    _run_fuzz_dry_with_priorities "$ws" "$out"
    if grep -q -- "--target-contracts FirstWins" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: picks highest-ranked entry irrespective of angle"
    else
        _fail "fuzz-runner: ranked-first not picked (command.txt: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_no_priorities_file_leaves_target_unset() {
    # No mining_priorities.json → no --target-contracts in argv. This
    # is the pre-PR-#332 status quo and must remain a graceful fall-
    # through (medusa will emit its own error; the wrapper does not).
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws"
    _run_fuzz_dry_with_priorities "$ws" "$out"
    if ! grep -q -- "--target-contracts" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: missing priorities file leaves --target-contracts unset"
    else
        _fail "fuzz-runner: ghost --target-contracts when no priorities file (command.txt: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

# --------------------------------------------------------------------------
# I19 (#339): when an I17 scaffold exists at <ws>/poc-tests/Invariant_X.t.sol,
# symbolic-runner must pass --contract Invariant_X (not bare X) so halmos's
# --match-contract filter actually matches the harness. Same for medusa's
# --target-contracts. Fall through to bare name when no scaffold is present
# (operators with hand-written tests in `contract X is Test` still match).
# --------------------------------------------------------------------------

test_symbolic_uses_invariant_prefix_when_scaffold_exists() {
    # Use --angle A-AUTH (which goes through the regular halmos path)
    # + --dry-run so engine_contract.txt is written before early exit.
    # The A-ORACLE scaffolded-only path exits early (line ~510) before
    # engine_contract.txt is set.
    local td ws out bin_dir
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    bin_dir="$td/bin"
    mkdir -p "$ws/swarm" "$ws/test"
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-AUTH","contracts":[],"title":"X: ScaffoldedToken.fn"}]
EOF
    cat > "$ws/test/Invariant_ScaffoldedToken.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Invariant_ScaffoldedToken {}
SOL
    _make_fake_engine "$bin_dir" halmos
    PATH="$bin_dir:$PATH" \
    bash "$SYMBOLIC_RUNNER" "$ws" \
        --engine halmos \
        --angle A-AUTH \
        --out-dir "$out" \
        --timeout 30 \
        --dry-run \
        >/dev/null 2>&1
    if [ "$(cat "$out/engine_contract.txt" 2>/dev/null)" = "Invariant_ScaffoldedToken" ]; then
        _pass "symbolic-runner: I19 uses Invariant_<X> when scaffold exists"
    else
        _fail "symbolic-runner: I19 did not resolve harness contract name (got: $(cat "$out/engine_contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_falls_back_to_bare_when_no_scaffold() {
    local td ws out bin_dir
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    bin_dir="$td/bin"
    mkdir -p "$ws/swarm"
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-AUTH","contracts":[],"title":"X: BareToken.fn"}]
EOF
    _make_fake_engine "$bin_dir" halmos
    PATH="$bin_dir:$PATH" \
    bash "$SYMBOLIC_RUNNER" "$ws" \
        --engine halmos \
        --angle A-AUTH \
        --out-dir "$out" \
        --timeout 30 \
        --dry-run \
        >/dev/null 2>&1
    if [ "$(cat "$out/engine_contract.txt" 2>/dev/null)" = "BareToken" ]; then
        _pass "symbolic-runner: I19 falls back to bare name when no scaffold"
    else
        _fail "symbolic-runner: bare-name fallback FAILED (got: $(cat "$out/engine_contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_uses_invariant_prefix_when_scaffold_exists() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm" "$ws/test"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contract":"FuzzScaffolded","title":"X"}]
EOF
    cat > "$ws/test/Invariant_FuzzScaffolded.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Invariant_FuzzScaffolded {}
SOL
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    local bin_dir="$ws/bin"
    _make_fake_engine "$bin_dir" medusa
    PATH="$bin_dir:$PATH" \
        bash "$FUZZ_RUNNER" "$ws" \
            --engine medusa \
            --out-dir "$out" \
            --timeout 60 \
            --dry-run \
            >/dev/null 2>&1
    if grep -q -- "--target-contracts Invariant_FuzzScaffolded" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: I19 uses Invariant_<X> when scaffold exists"
    else
        _fail "fuzz-runner: I19 harness-aware target-contracts FAILED (cmd: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

# --------------------------------------------------------------------------
# I21 (#342): medusa prefers Property_<X> over Invariant_<X> when both exist.
# --------------------------------------------------------------------------

test_fuzz_prefers_property_over_invariant_for_medusa() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm" "$ws/test"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contract":"DualHarness","title":"X"}]
EOF
    cat > "$ws/test/Invariant_DualHarness.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Invariant_DualHarness {}
SOL
    cat > "$ws/test/Property_DualHarness.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Property_DualHarness {}
SOL
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    local bin_dir="$ws/bin"
    _make_fake_engine "$bin_dir" medusa
    PATH="$bin_dir:$PATH" \
        bash "$FUZZ_RUNNER" "$ws" \
            --engine medusa \
            --out-dir "$out" \
            --timeout 60 \
            --dry-run \
            >/dev/null 2>&1
    if grep -q -- "--target-contracts Property_DualHarness" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: I21 medusa prefers Property_<X> over Invariant_<X>"
    else
        _fail "fuzz-runner: I21 medusa did not prefer Property_<X> (cmd: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    if grep -q -- "--compilation-target .*Property_DualHarness.t.sol" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: I22 medusa compiles selected Property_<X> test file"
    else
        _fail "fuzz-runner: I22 medusa command missing --compilation-target for Property_<X> (cmd: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_fuzz_falls_back_to_invariant_when_no_property() {
    local td ws out
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    mkdir -p "$ws/swarm" "$ws/test"
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"contract":"OnlyInvariant","title":"X"}]
EOF
    cat > "$ws/test/Invariant_OnlyInvariant.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Invariant_OnlyInvariant {}
SOL
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    local bin_dir="$ws/bin"
    _make_fake_engine "$bin_dir" medusa
    PATH="$bin_dir:$PATH" \
        bash "$FUZZ_RUNNER" "$ws" \
            --engine medusa \
            --out-dir "$out" \
            --timeout 60 \
            --dry-run \
            >/dev/null 2>&1
    if grep -q -- "--target-contracts Invariant_OnlyInvariant" "$out/command.txt" 2>/dev/null; then
        _pass "fuzz-runner: I21 medusa falls back to Invariant_<X> when Property absent"
    else
        _fail "fuzz-runner: I21 medusa did not fall back to Invariant_<X> (cmd: $(cat "$out/command.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

test_symbolic_tries_property_prefix_when_no_invariant() {
    local td ws out bin_dir
    td="$(mktemp -d)"
    ws="$td/ws"
    out="$td/out"
    bin_dir="$td/bin"
    mkdir -p "$ws/swarm" "$ws/test"
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
EOF
    cat > "$ws/swarm/mining_priorities.json" <<'EOF'
[{"rank":1,"id":"A-AUTH","contracts":[],"title":"X: PropToken.fn"}]
EOF
    cat > "$ws/test/Property_PropToken.t.sol" <<'SOL'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Property_PropToken {}
SOL
    _make_fake_engine "$bin_dir" halmos
    PATH="$bin_dir:$PATH" \
    bash "$SYMBOLIC_RUNNER" "$ws" \
        --engine halmos \
        --angle A-AUTH \
        --out-dir "$out" \
        --timeout 30 \
        --dry-run \
        >/dev/null 2>&1
    if [ "$(cat "$out/engine_contract.txt" 2>/dev/null)" = "Property_PropToken" ]; then
        _pass "symbolic-runner: I21 tries Property_<X> when Invariant absent"
    else
        _fail "symbolic-runner: I21 did not resolve Property_<X> (got: $(cat "$out/engine_contract.txt" 2>/dev/null))"
    fi
    rm -rf "$td"
}

echo "[test_deep_runner_auto_pick.sh] running 18 tests"
test_symbolic_picks_singular_contract
test_symbolic_picks_contracts_array
test_symbolic_picks_title_regex_when_contracts_empty
test_symbolic_title_regex_centrifuge_shape
test_symbolic_skips_non_matching_angle
test_symbolic_falls_through_when_all_shapes_empty
test_fuzz_picks_singular_contract
test_fuzz_picks_contracts_array
test_fuzz_picks_title_regex_when_contracts_empty
test_fuzz_explicit_test_contract_overrides_auto_pick
test_fuzz_does_not_filter_by_angle
test_fuzz_no_priorities_file_leaves_target_unset
test_symbolic_uses_invariant_prefix_when_scaffold_exists
test_symbolic_falls_back_to_bare_when_no_scaffold
test_fuzz_uses_invariant_prefix_when_scaffold_exists
test_fuzz_prefers_property_over_invariant_for_medusa
test_fuzz_falls_back_to_invariant_when_no_property
test_symbolic_tries_property_prefix_when_no_invariant

echo
echo "[test_deep_runner_auto_pick.sh] PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
