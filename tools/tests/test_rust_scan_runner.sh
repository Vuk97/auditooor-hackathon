#!/usr/bin/env bash
# test_rust_scan_runner.sh — smoke tests for tools/rust-scan-runner.sh
#
# Shell-level asserts (bats-compatible layout would be overkill for a
# 3-scenario suite). Each test creates an isolated workspace + PATH shim and
# validates the emitted SCAN_RUST_SUMMARY.json.
#
# Run:
#   bash tools/tests/test_rust_scan_runner.sh

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUNNER="$REPO/tools/rust-scan-runner.sh"

FAIL=0
PASS=0
REPORT=()

assert_true() {
    local msg="$1"; shift
    if "$@"; then
        PASS=$((PASS + 1))
        REPORT+=("PASS: $msg")
    else
        FAIL=$((FAIL + 1))
        REPORT+=("FAIL: $msg")
    fi
}

make_tmp_ws() {
    local d
    d="$(mktemp -d)"
    printf '%s' "$d"
}

# ---------------------------------------------------------------------------
# Test 1: cargo audit + semgrep missing → summary still written, exit 2
#         (no roots scanned means no OK scanners — per spec, exit 2 when no
#         scanner ran). We fake this by pointing PATH at an empty dir so
#         neither tool resolves AND we still include a Cargo.toml so the
#         "no roots" short-circuit does not mask the test.
# ---------------------------------------------------------------------------

test1() {
    local ws shim_bin rc
    ws="$(make_tmp_ws)"
    shim_bin="$(mktemp -d)"

    # Synthetic Rust root
    mkdir -p "$ws/src"
    cat >"$ws/Cargo.toml" <<'EOF'
[package]
name = "synthetic"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/src/main.rs"

    # Shim PATH: keep python3 + core utilities but drop cargo/semgrep
    mkdir -p "$shim_bin"
    for cmd in python3 bash sh sed awk grep cut tr head tail sort date dirname basename mktemp find printf mkdir chmod cd tee cat rm ls timeout gtimeout readlink uname stat od xargs env which wc; do
        src="$(command -v "$cmd" 2>/dev/null || true)"
        [ -n "$src" ] && ln -sf "$src" "$shim_bin/$cmd"
    done

    local out_dir="$ws/scanners/rust"
    env -i \
        HOME="$HOME" PATH="$shim_bin" \
        bash "$RUNNER" "$ws" --out "$out_dir"
    rc=$?

    assert_true "T1: runner exits non-zero (2) when tools missing" \
        [ "$rc" -eq 2 ]
    assert_true "T1: SCAN_RUST_SUMMARY.json exists" \
        [ -f "$out_dir/SCAN_RUST_SUMMARY.json" ]
    assert_true "T1: summary documents missing cargo-audit" \
        python3 -c "
import json, sys
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
assert 'cargo-audit' in (d.get('missing_tools') or []), d.get('missing_tools')
assert d['tool_available']['cargo_audit'] is False
assert d['tool_available']['semgrep'] is False
"
    assert_true "T1: semantic inventory still runs when cargo/semgrep are missing" \
        python3 -c "
import json
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
sem=d.get('semantic_inventory') or {}
assert sem.get('source_graph', {}).get('status') == 'OK', sem
assert sem.get('source_graph', {}).get('crate_count') == 1, sem
acct=d.get('semantic_depth_accounting') or {}
assert acct.get('item_count') == 50, acct
assert acct.get('blocked_count', 0) > 0, acct
"

    rm -rf "$ws" "$shim_bin"
}

# ---------------------------------------------------------------------------
# Test 2: empty-Cargo workspace → exits 0 with empty findings
#         (tools installed but synthetic crate produces no vulns/lints).
#
#         If cargo-audit/semgrep/clippy are NOT installed on this host, we
#         degrade the assertion to "exit 2 and summary records missing
#         tools", matching Test 1 behavior — this lets the test run on
#         barebones CI and still exercise the path.
# ---------------------------------------------------------------------------

test2() {
    local ws rc out_dir
    ws="$(make_tmp_ws)"
    mkdir -p "$ws/src"
    cat >"$ws/Cargo.toml" <<'EOF'
[package]
name = "empty"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/src/main.rs"
    out_dir="$ws/scanners/rust"

    bash "$RUNNER" "$ws" --out "$out_dir" --timeout 60 >/tmp/rust-scan-test2.log 2>&1
    rc=$?

    # The summary should always be written
    assert_true "T2: summary JSON written" [ -f "$out_dir/SCAN_RUST_SUMMARY.json" ]
    assert_true "T2: summary MD written"   [ -f "$out_dir/SCAN_RUST_SUMMARY.md" ]
    assert_true "T2: summary schema and root count written" \
        python3 -c "
import json
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
assert d.get('schema') == 'auditooor.rust_scan_summary.v1', d.get('schema')
assert d.get('root_count') == len(d.get('roots') or []), (d.get('root_count'), d.get('roots'))
"

    # If cargo-audit and semgrep are both available, we expect exit 0 + empty findings.
    # Otherwise, the runner must exit 2 and list missing tools honestly.
    local have_audit=0 have_semgrep=0
    command -v cargo >/dev/null && cargo audit --version >/dev/null 2>&1 && have_audit=1
    command -v semgrep >/dev/null 2>&1 && have_semgrep=1

    if [ "$have_audit" = 1 ] && [ "$have_semgrep" = 1 ]; then
        assert_true "T2: rc==0 when tools available" [ "$rc" -eq 0 ]
        assert_true "T2: zero CVEs on empty crate" \
            python3 -c "
import json
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
tot=sum(v.get('cve_count',0) for v in (d.get('cargo_audit') or {}).values())
assert tot == 0, f'expected 0 CVEs, got {tot}'
"
    else
        assert_true "T2: rc==2 when tools missing" [ "$rc" -eq 2 ]
        assert_true "T2: summary lists missing tools" \
            python3 -c "
import json
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
assert d.get('missing_tools'), d
"
    fi
    assert_true "T2: semantic inventory paths and counts are recorded" \
        python3 -c "
import json
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
src=(d.get('semantic_inventory') or {}).get('source_graph') or {}
cross=(d.get('semantic_inventory') or {}).get('cross_crate_graph') or {}
assert src.get('status') == 'OK', src
assert src.get('path','').endswith('.auditooor/rust_source_graph.json'), src
assert src.get('entrypoint_count') == 0, src
assert cross.get('status') == 'OK', cross
assert cross.get('path','').endswith('.auditooor/rust_cross_crate_graph.json'), cross
"

    rm -rf "$ws"
}

# ---------------------------------------------------------------------------
# Test 3: --strict with a mocked critical CVE in SCAN_RUST_SUMMARY.json
#         → rerun the strict-check fragment and assert non-zero.
#
#         Because we cannot force a real CVE into an empty crate, we
#         post-hoc mutate the summary and re-invoke just the strict-check
#         fragment by calling python directly (mirrors the runner logic).
# ---------------------------------------------------------------------------

test3() {
    local ws out_dir
    ws="$(make_tmp_ws)"
    mkdir -p "$ws/src"
    cat >"$ws/Cargo.toml" <<'EOF'
[package]
name = "synthetic-strict"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/src/main.rs"
    out_dir="$ws/scanners/rust"

    bash "$RUNNER" "$ws" --out "$out_dir" --timeout 60 >/tmp/rust-scan-test3.log 2>&1 || true

    # Mutate summary to inject a high-severity CVE
    python3 -c "
import json
p='$out_dir/SCAN_RUST_SUMMARY.json'
d=json.load(open(p))
d.setdefault('cargo_audit', {})
d['cargo_audit']['_mock'] = {
    'status':'OK',
    'cve_count':1,
    'warnings':0,
    'severity_breakdown': {'high': 1},
}
json.dump(d, open(p,'w'), indent=2, sort_keys=True)
"

    # Re-run the strict check logic directly (mirrors runner)
    local bad
    bad=$(python3 - "$out_dir/SCAN_RUST_SUMMARY.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
bad = 0
for r, v in (doc.get("cargo_audit") or {}).items():
    sb = v.get("severity_breakdown") or {}
    for k, n in sb.items():
        if k.lower() in ("critical", "high") and n:
            bad += int(n)
print(bad)
PY
    )
    assert_true "T3: --strict detects high-severity CVE (python fragment)" [ "${bad:-0}" -gt 0 ]

    rm -rf "$ws"
}

# ---------------------------------------------------------------------------
# Test 4: real shell-invoked --strict path, exercising the full runner.
#         PATH-shim `cargo` so `cargo audit --json` emits a fake
#         high-severity advisory. Expect the runner to exit 2 and log the
#         strict trip on stderr. Validates the actual CLI exit-path that T3
#         skips.
# ---------------------------------------------------------------------------

test4() {
    local ws shim_bin rc log
    ws="$(make_tmp_ws)"
    shim_bin="$(mktemp -d)"

    mkdir -p "$ws/src"
    cat >"$ws/Cargo.toml" <<'EOF'
[package]
name = "synthetic-strict-shim"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/src/main.rs"

    # Link core utils into the shim dir so the runner still resolves them.
    mkdir -p "$shim_bin"
    for cmd in python3 bash sh sed awk grep cut tr head tail sort date dirname basename mktemp find printf mkdir chmod cd tee cat rm ls timeout gtimeout readlink uname stat od xargs env which wc; do
        src="$(command -v "$cmd" 2>/dev/null || true)"
        [ -n "$src" ] && ln -sf "$src" "$shim_bin/$cmd"
    done

    # Fake `cargo` binary:
    #   `cargo audit --version`       -> "cargo-audit-shim 0.0.0", rc 0
    #   `cargo audit --json`          -> HIGH-severity advisory JSON, rc 1
    #   anything else (clippy, etc.)  -> rc 127, stderr "unsupported"
    # The rc-1 on cargo-audit-with-findings mimics real cargo-audit behavior.
    cat >"$shim_bin/cargo" <<'SHIM'
#!/usr/bin/env bash
sub="${1:-}"
case "$sub" in
    audit)
        shift
        for a in "$@"; do
            case "$a" in
                --version) echo "cargo-audit-shim 0.0.0"; exit 0 ;;
            esac
        done
        # emit a fake HIGH-severity advisory and exit 1
        cat <<'JSON'
{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-9999-0001",
          "package": "fake-crate",
          "title": "Shim high-severity advisory",
          "severity": "high"
        },
        "versions": { "patched": ["^1.2.3"] }
      }
    ]
  },
  "warnings": {}
}
JSON
        exit 1 ;;
    *)
        echo "cargo-shim: unsupported subcommand: $sub" >&2
        exit 127 ;;
esac
SHIM
    chmod +x "$shim_bin/cargo"

    local out_dir="$ws/scanners/rust"
    log="/tmp/rust-scan-test4.log"

    # PATH includes the shim dir only (plus whatever symlinks we made).
    # semgrep + cargo-clippy absent -> MISSING_TOOLS, but cargo-audit runs.
    env -i HOME="$HOME" PATH="$shim_bin" \
        bash "$RUNNER" "$ws" --out "$out_dir" --timeout 30 --strict \
        >"$log" 2>&1
    rc=$?

    assert_true "T4: --strict exits 2 on HIGH severity advisory" \
        [ "$rc" -eq 2 ]
    assert_true "T4: --strict trip message on stderr/stdout" \
        grep -q 'strict' "$log"
    assert_true "T4: summary JSON written with cve_count>=1" \
        python3 -c "
import json
d=json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
total = sum(v.get('cve_count',0) for v in (d.get('cargo_audit') or {}).values())
assert total >= 1, (total, d.get('cargo_audit'))
# severity breakdown must include 'high'
has_high = any(
    'high' in (v.get('severity_breakdown') or {})
    for v in (d.get('cargo_audit') or {}).values()
)
assert has_high, d.get('cargo_audit')
"

    rm -rf "$ws" "$shim_bin"
}

# ---------------------------------------------------------------------------
# Test 5: multi-root severity-breakdown isolation (regression for the pipe-
#         delimiter collision Codex flagged on PR #115). A two-root
#         workspace where root #1 has zero CVEs and root #2 has one HIGH
#         advisory must produce a SCAN_RUST_SUMMARY.json that records
#         high=1 on root #2 (NOT root #1, NOT missing) and exits non-zero
#         under --strict.
#
#         The shim `cargo audit --json` switches its output based on the
#         current working directory: it returns an empty advisory list for
#         root1 and a HIGH advisory for root2. Switching by CWD lets the
#         shim mimic real cargo-audit, which the runner invokes via
#         `cd "$root_abs" && cargo audit --json`.
# ---------------------------------------------------------------------------

test5_multi_root_severity_breakdown() {
    local ws shim_bin rc log
    ws="$(make_tmp_ws)"
    shim_bin="$(mktemp -d)"

    # Two synthetic Rust roots.
    mkdir -p "$ws/root1/src" "$ws/root2/src"
    cat >"$ws/root1/Cargo.toml" <<'EOF'
[package]
name = "synthetic-root1"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/root1/src/main.rs"
    cat >"$ws/root2/Cargo.toml" <<'EOF'
[package]
name = "synthetic-root2"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/root2/src/main.rs"

    # Shim PATH with core utils.
    mkdir -p "$shim_bin"
    for cmd in python3 bash sh sed awk grep cut tr head tail sort date dirname basename mktemp find printf mkdir chmod cd tee cat rm ls timeout gtimeout readlink uname stat od xargs env which wc pwd; do
        src="$(command -v "$cmd" 2>/dev/null || true)"
        [ -n "$src" ] && ln -sf "$src" "$shim_bin/$cmd"
    done

    # Fake `cargo` whose `audit --json` output depends on CWD basename:
    #   root1 -> empty advisory list
    #   root2 -> single HIGH advisory
    cat >"$shim_bin/cargo" <<'SHIM'
#!/usr/bin/env bash
sub="${1:-}"
case "$sub" in
    audit)
        shift
        for a in "$@"; do
            case "$a" in
                --version) echo "cargo-audit-shim 0.0.0"; exit 0 ;;
            esac
        done
        cwd_base="$(basename "$PWD")"
        if [ "$cwd_base" = "root2" ]; then
            cat <<'JSON'
{
  "vulnerabilities": {
    "found": true,
    "count": 1,
    "list": [
      {
        "advisory": {
          "id": "RUSTSEC-9999-0002",
          "package": "fake-crate-2",
          "title": "Multi-root regression HIGH advisory",
          "severity": "high"
        },
        "versions": { "patched": ["^1.2.3"] }
      }
    ]
  },
  "warnings": {}
}
JSON
            exit 1
        else
            cat <<'JSON'
{
  "vulnerabilities": { "found": false, "count": 0, "list": [] },
  "warnings": {}
}
JSON
            exit 0
        fi ;;
    *)
        echo "cargo-shim: unsupported subcommand: $sub" >&2
        exit 127 ;;
esac
SHIM
    chmod +x "$shim_bin/cargo"

    local out_dir="$ws/scanners/rust"
    log="/tmp/rust-scan-test5.log"

    env -i HOME="$HOME" PATH="$shim_bin" \
        bash "$RUNNER" "$ws" --out "$out_dir" --timeout 30 --strict \
        >"$log" 2>&1
    rc=$?

    assert_true "T5: multi-root --strict exits non-zero on root2 HIGH severity" \
        [ "$rc" -ne 0 ]
    assert_true "T5: SCAN_RUST_SUMMARY.json places high=1 on root2 (not root1)" \
        python3 -c "
import json
d = json.load(open('$out_dir/SCAN_RUST_SUMMARY.json'))
ca = d.get('cargo_audit') or {}
# Both roots must be present
assert 'root1' in ca, ('root1 missing', list(ca))
assert 'root2' in ca, ('root2 missing', list(ca))
# root1 must have zero high/critical
sb1 = ca['root1'].get('severity_breakdown') or {}
assert sb1.get('high', 0) == 0, ('root1 wrongly attributed high', sb1)
assert sb1.get('critical', 0) == 0, ('root1 wrongly attributed critical', sb1)
# root2 must have exactly high=1
sb2 = ca['root2'].get('severity_breakdown') or {}
assert sb2.get('high') == 1, ('root2 high != 1', sb2)
assert ca['root2'].get('cve_count') == 1, ('root2 cve_count != 1', ca['root2'])
"

    rm -rf "$ws" "$shim_bin"
}

# ---------------------------------------------------------------------------
# Test 6: readiness mode is non-destructive and actionable. It must not write
#         SCAN_RUST_SUMMARY, must write RUST_SCAN_READINESS, and --strict must
#         fail when no Rust roots are present.
# ---------------------------------------------------------------------------

test6_readiness_mode() {
    local ws rc out_dir
    ws="$(make_tmp_ws)"
    mkdir -p "$ws"
    out_dir="$ws/scanners/rust"

    bash "$RUNNER" "$ws" --out "$out_dir" --readiness --strict >/tmp/rust-scan-test6.log 2>&1
    rc=$?

    assert_true "T6: readiness --strict exits 2 when roots are missing" \
        [ "$rc" -eq 2 ]
    assert_true "T6: readiness JSON written" \
        [ -f "$out_dir/RUST_SCAN_READINESS.json" ]
    assert_true "T6: readiness does not write scan summary" \
        [ ! -f "$out_dir/SCAN_RUST_SUMMARY.json" ]
    assert_true "T6: readiness records missing root blocker" \
        python3 -c "
import json
d=json.load(open('$out_dir/RUST_SCAN_READINESS.json'))
assert d.get('mode') == 'readiness_only_no_scanners_executed', d
assert d.get('root_count') == 0, d
assert 'rust_roots_missing' in (d.get('blockers') or []), d
assert d.get('can_run_scan_rust') is False, d
"

    rm -rf "$ws"
}

# ---------------------------------------------------------------------------
# Test 7: submission artifact mirrors are excluded from root discovery.
#         A canonical PoC root under `poc-tests/` plus mirrored copies under
#         every submission status dir must yield only the canonical root in
#         readiness output.
# ---------------------------------------------------------------------------

test7_excludes_submission_artifact_roots() {
    local ws rc out_dir
    ws="$(make_tmp_ws)"
    out_dir="$ws/scanners/rust"

    mkdir -p "$ws/poc-tests/demo/src"
    cat >"$ws/poc-tests/demo/Cargo.toml" <<'EOF'
[package]
name = "demo"
version = "0.0.1"
edition = "2021"
EOF
    echo 'fn main(){}' >"$ws/poc-tests/demo/src/main.rs"

    for status in staging ready filed packaged held paste_ready superseded _killed _oos_rejected; do
        mkdir -p "$ws/submissions/$status/poc-tests/demo/src"
        cat >"$ws/submissions/$status/poc-tests/demo/Cargo.toml" <<'EOF'
[package]
name = "demo-mirror"
version = "0.0.1"
edition = "2021"
EOF
        echo 'fn main(){}' >"$ws/submissions/$status/poc-tests/demo/src/main.rs"
    done

    bash "$RUNNER" "$ws" --out "$out_dir" --readiness >/tmp/rust-scan-test7.log 2>&1
    rc=$?

    assert_true "T7: readiness exits 0 for canonical root plus mirrored submission roots" \
        [ "$rc" -eq 0 ]
    assert_true "T7: readiness writes JSON" \
        [ -f "$out_dir/RUST_SCAN_READINESS.json" ]
    assert_true "T7: readiness excludes submission status mirrors from roots" \
        python3 -c "
import json
d=json.load(open('$out_dir/RUST_SCAN_READINESS.json'))
roots=d.get('roots') or []
assert roots == ['poc-tests/demo'], roots
assert d.get('root_count') == 1, d
"

    rm -rf "$ws"
}

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

test1
test2
test3
test4
test5_multi_root_severity_breakdown
test6_readiness_mode
test7_excludes_submission_artifact_roots

echo ""
echo "===== rust-scan-runner test report ====="
for line in "${REPORT[@]}"; do
    echo "$line"
done
echo "----------------------------------------"
echo "PASS=$PASS FAIL=$FAIL"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
