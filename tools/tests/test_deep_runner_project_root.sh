#!/usr/bin/env bash
# test_deep_runner_project_root.sh — I13 (#328) regression tests for
# tools/symbolic-runner.sh + tools/fuzz-runner.sh `--project-root` flag.
#
# Background: the wrappers used to invoke halmos / medusa / echidna from
# the auditooor-repo CWD. crytic-compile (used by all three engines)
# looks for `out/`, `lib/`, `foundry.toml` under CWD and fails in <1s
# when those don't exist. The wrappers now resolve a forge project root
# and `cd` into it before invoking. Resolution order:
#   1. --project-root <path>
#   2. <WORKSPACE>/foundry.toml (single-project workspace)
#   3. <WORKSPACE>/src/<repo>/foundry.toml (shallowest non-lib match)
#   4. exit 2 with "cannot-run: no-forge-project"
#
# Hermetic: each test scaffolds a tempdir + writes a fake
# foundry.toml + a fake `halmos` / `medusa` binary that records which
# CWD it was invoked from, then asserts the recorded CWD matches the
# expected project root.
#
# Pure shell (no python/forge dependency) so it runs in CI under the
# offline-tests workflow.

# Note: NOT `set -e` because tests intentionally exercise non-zero exit
# paths (e.g. cannot-run: no-forge-project returns 2). We capture each
# wrapper invocation's rc explicitly via `|| rc=$?` instead.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SYMBOLIC_RUNNER="$ROOT/tools/symbolic-runner.sh"
FUZZ_RUNNER="$ROOT/tools/fuzz-runner.sh"

# Track failures so we can print a useful tail rather than die-on-first.
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

# Each test scaffolds a fake binary at $bin_dir/<engine> that records
# the working directory it was invoked from to $bin_dir/cwd.txt.
_make_fake_engine() {
    local bin_dir="$1"
    local engine="$2"
    mkdir -p "$bin_dir"
    cat > "$bin_dir/$engine" <<EOF
#!/usr/bin/env bash
# Fake $engine for I13 wrapper test.
# Record CWD + arguments ONLY when called for a real run (not the
# --version probe the wrappers do early to populate engine_version).
# The CWD record is what the test asserts against.
case "\$1" in
    --version|-v|version)
        echo "fake-$engine 0.0.0-test"
        exit 0
        ;;
esac
echo "fake-$engine invoked-from=\$(pwd) args=\$*" > "$bin_dir/cwd.txt"
# Engines exit with a "compile completed" style message under normal
# conditions; emit one so the wrapper's classifier doesn't trip.
echo "Compiled with no errors"
exit 0
EOF
    chmod +x "$bin_dir/$engine"
}

# --- Test 1: --project-root override is honored ---------------------------
test_project_root_override() {
    local td bin_dir ws project
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    project="$td/elsewhere"
    mkdir -p "$ws" "$project"
    cat > "$project/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _make_fake_engine "$bin_dir" halmos

    # Use /usr/bin/env's PATH override; the wrapper's `command -v halmos`
    # will resolve to the fake.
    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --project-root "$project" \
            --timeout 30 \
            >/dev/null 2>&1 || true

    if [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$project" "$bin_dir/cwd.txt"; then
        _pass "symbolic-runner --project-root cd's into the override path"
    else
        _fail "symbolic-runner --project-root did NOT cd into $project (cwd record: $(cat "$bin_dir/cwd.txt" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

# --- Test 2: auto-detect <ws>/foundry.toml --------------------------------
test_auto_detect_workspace_root() {
    local td bin_dir ws
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    mkdir -p "$ws"
    cat > "$ws/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _make_fake_engine "$bin_dir" halmos

    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --timeout 30 \
            >/dev/null 2>&1 || true

    if [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$ws" "$bin_dir/cwd.txt"; then
        _pass "symbolic-runner auto-detects <ws>/foundry.toml"
    else
        _fail "symbolic-runner did not auto-detect single-project workspace (record: $(cat "$bin_dir/cwd.txt" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

# --- Test 3: auto-detect <ws>/src/<repo>/foundry.toml ---------------------
test_auto_detect_multi_project_workspace() {
    local td bin_dir ws sub
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    sub="$ws/src/protocol"
    mkdir -p "$sub"
    cat > "$sub/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _make_fake_engine "$bin_dir" halmos

    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --timeout 30 \
            >/dev/null 2>&1 || true

    if [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$sub" "$bin_dir/cwd.txt"; then
        _pass "symbolic-runner auto-detects <ws>/src/<repo>/foundry.toml"
    else
        _fail "symbolic-runner did not auto-detect multi-project workspace (record: $(cat "$bin_dir/cwd.txt" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

# --- Test 4: missing forge project fails loudly with cannot-run ----------
test_no_forge_project_fails_loud() {
    local td bin_dir ws
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    mkdir -p "$ws"
    # NO foundry.toml anywhere under workspace.
    _make_fake_engine "$bin_dir" halmos

    local stderr_file="$td/stderr.log"
    local rc=0
    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --timeout 30 \
            2>"$stderr_file" >/dev/null || rc=$?

    if [ "$rc" -eq 2 ] && grep -q "cannot-run: no-forge-project" "$stderr_file"; then
        _pass "symbolic-runner fails loudly with cannot-run on missing forge project"
    else
        _fail "symbolic-runner did not exit 2/cannot-run on missing forge project (rc=$rc, stderr=$(cat "$stderr_file"))"
    fi
    # Engine must NOT have been invoked (no cwd record written).
    if [ ! -f "$bin_dir/cwd.txt" ]; then
        _pass "symbolic-runner did NOT invoke engine when forge project missing"
    else
        _fail "symbolic-runner invoked engine despite missing forge project"
    fi
    rm -rf "$td"
}

# --- Test 5: lib/ subdirectory foundry.toml is ignored --------------------
test_lib_foundry_toml_skipped() {
    local td bin_dir ws lib_proj real_proj
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    real_proj="$ws/src/protocol"
    lib_proj="$ws/src/protocol/lib/forge-std"
    mkdir -p "$real_proj" "$lib_proj"
    cat > "$real_proj/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    cat > "$lib_proj/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _make_fake_engine "$bin_dir" halmos

    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --timeout 30 \
            >/dev/null 2>&1 || true

    if [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$real_proj" "$bin_dir/cwd.txt"; then
        _pass "symbolic-runner picks shallowest non-lib forge project (skips lib/forge-std)"
    elif [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$lib_proj" "$bin_dir/cwd.txt"; then
        _fail "symbolic-runner picked the lib/ foundry.toml — should have skipped it"
    else
        _fail "symbolic-runner unexpected cwd record (record: $(cat "$bin_dir/cwd.txt" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

# --- Test 6: fuzz-runner mirrors symbolic-runner contract ----------------
test_fuzz_runner_project_root() {
    local td bin_dir ws sub
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    sub="$ws/src/protocol"
    mkdir -p "$sub"
    cat > "$sub/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _make_fake_engine "$bin_dir" medusa

    PATH="$bin_dir:$PATH" \
        bash "$FUZZ_RUNNER" "$ws" \
            --engine medusa \
            --timeout 30 \
            >/dev/null 2>&1 || true

    if [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$sub" "$bin_dir/cwd.txt"; then
        _pass "fuzz-runner auto-detects <ws>/src/<repo>/foundry.toml"
    else
        _fail "fuzz-runner did not auto-detect multi-project workspace (record: $(cat "$bin_dir/cwd.txt" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

# --- Test 7: dry-run path skips the cd entirely (no engine call) ----------
test_dry_run_skips_engine_cwd_check() {
    local td bin_dir ws
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    mkdir -p "$ws"
    # NO foundry.toml — but --dry-run should still emit a manifest
    # without resolving / cd-ing.
    _make_fake_engine "$bin_dir" halmos

    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --timeout 30 \
            --dry-run \
            >/dev/null 2>&1
    # Either rc=0 (dry-run completed successfully even without project)
    # OR rc=2 (no-forge-project before dry-run). The current
    # implementation does the project-root check first so rc=2 is the
    # observed behaviour. Document the expected behaviour here so
    # future changes don't regress silently.
    # We do NOT assert rc — both behaviours are acceptable. We only
    # assert the engine was NOT actually invoked.
    if [ ! -f "$bin_dir/cwd.txt" ]; then
        _pass "symbolic-runner --dry-run never invokes the engine"
    else
        _fail "symbolic-runner --dry-run invoked the engine (cwd record: $(cat "$bin_dir/cwd.txt"))"
    fi
    rm -rf "$td"
}

# --- Test 8: directory containing "lib" as substring is NOT falsely skipped ---
# Kimi caught this in pre-commit review: my original `case ... */lib/*) continue ;;`
# would falsely skip `<ws>/src/library-foo/foundry.toml` because the path
# substring `/lib` matches. Fix: basename match against the parent dir.
test_substring_lib_not_falsely_skipped() {
    local td bin_dir ws sub
    td="$(mktemp -d)"
    bin_dir="$td/bin"
    ws="$td/ws"
    sub="$ws/src/library-foo"
    mkdir -p "$sub"
    cat > "$sub/foundry.toml" <<EOF
[profile.default]
src = "src"
out = "out"
EOF
    _make_fake_engine "$bin_dir" halmos

    PATH="$bin_dir:$PATH" \
        bash "$SYMBOLIC_RUNNER" "$ws" \
            --engine halmos \
            --angle A-AUTH \
            --contract Foo \
            --timeout 30 \
            >/dev/null 2>&1 || true

    if [ -f "$bin_dir/cwd.txt" ] && grep -q "invoked-from=$sub" "$bin_dir/cwd.txt"; then
        _pass "symbolic-runner does NOT falsely skip dirs with 'lib' substring (library-foo)"
    else
        _fail "symbolic-runner falsely skipped 'library-foo' (substring match bug; cwd record: $(cat "$bin_dir/cwd.txt" 2>/dev/null || echo MISSING))"
    fi
    rm -rf "$td"
}

echo "[test_deep_runner_project_root.sh] running 8 tests"
test_project_root_override
test_auto_detect_workspace_root
test_auto_detect_multi_project_workspace
test_no_forge_project_fails_loud
test_lib_foundry_toml_skipped
test_fuzz_runner_project_root
test_dry_run_skips_engine_cwd_check
test_substring_lib_not_falsely_skipped

echo
echo "[test_deep_runner_project_root.sh] PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
    exit 1
fi
