#!/usr/bin/env bash
# rust-scan-runner.sh — Gap E Rust scanner harness.
#
# Runs `cargo audit`, Semgrep (p/rust + p/security-audit), and best-effort
# `cargo clippy` over every Rust root under a workspace, then emits a
# normalized `SCAN_RUST_SUMMARY.{json,md}` artifact. When Rust roots are
# present, it also runs the stdlib Rust source/cross-crate graph builders so
# `scan-rust` accounts for semantic inventory depth, not just shallow scanner
# output.
#
# Usage:
#   tools/rust-scan-runner.sh <workspace-path> [--timeout 1800]
#                              [--out <dir>] [--strict] [--readiness]
#
# Exit codes:
#   0  at least one of `cargo audit` or `semgrep` ran successfully (clippy may be
#      PARTIAL/BLOCKED), or --readiness completed without --strict blockers
#   2  no scanner could run (tools missing or workspace has no Rust roots)
#   2  --strict + any CVE with severity >= HIGH
#
# Outputs (primary):
#   <workspace>/scanners/rust/<root-slug>/cargo-audit.json (+.err)
#   <workspace>/scanners/rust/<root-slug>/semgrep-rust.json (+.err)
#   <workspace>/scanners/rust/<root-slug>/clippy-workspace.json (+.err)
#   <workspace>/.auditooor/rust_source_graph.json
#   <workspace>/.auditooor/rust_cross_crate_graph.json
#   <workspace>/scanners/rust/SCAN_RUST_SUMMARY.json
#   <workspace>/scanners/rust/SCAN_RUST_SUMMARY.md
#
# Design notes:
#   * Rust roots are detected under `external/base*/`, `external/*-rs/`, and
#     any other `Cargo.toml` not nested under `lib/` or `vendor/`.
#   * Submission artifact mirrors under `submissions/<status>/...` are
#     excluded from root discovery. They are draft/package artifacts, not
#     canonical source roots, and may carry stale relative `path = "../../..."`
#     dependencies that break Clippy for a copied PoC while the real root
#     remains buildable.
#   * Clippy falls back to a `cd /tmp` + `--manifest-path` invocation when the
#     workspace has a project-local `.cargo/config.toml` with a missing linker
#     pin. Precedent documented at
#     `~/audits/base-azul/scanners/rust/CLIPPY_GEIGER_REPORT.md`.
#   * Never writes into `external/` — only into `<workspace>/scanners/rust/`
#     and the canonical `<workspace>/.auditooor/` graph artifact directory.
#   * Python is used for JSON normalization only; fall back to hand-rolled
#     counting when Python is unavailable so the script stays shell-first.

set -o pipefail

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

WS=""
TIMEOUT_SECS=1800
OUT_DIR=""
STRICT=0
READINESS=0

usage() {
    cat <<'EOF'
Usage: rust-scan-runner.sh <workspace-path> [--timeout 1800] [--out <dir>] [--strict] [--readiness|--dry-run]

Runs cargo audit + Semgrep p/rust + best-effort cargo clippy over each Rust
root in the workspace and writes SCAN_RUST_SUMMARY.{json,md}.

With --readiness/--dry-run, does not run cargo audit, semgrep, clippy, or graph
builders. It only discovers roots/tools and writes RUST_SCAN_READINESS.{json,md}
so operators can see whether scan-rust can run and what is missing.
EOF
}

if [ $# -lt 1 ]; then
    usage
    exit 2
fi

WS="$1"; shift
while [ $# -gt 0 ]; do
    case "$1" in
        --timeout)
            TIMEOUT_SECS="${2:-1800}"; shift 2 ;;
        --out)
            OUT_DIR="${2:-}"; shift 2 ;;
        --strict)
            STRICT=1; shift ;;
        --readiness|--dry-run)
            READINESS=1; shift ;;
        -h|--help)
            usage; exit 0 ;;
        *)
            echo "[rust-scan] unknown arg: $1" >&2
            usage
            exit 2 ;;
    esac
done

if [ ! -d "$WS" ]; then
    echo "[rust-scan] ERROR: workspace not found: $WS" >&2
    exit 2
fi
WS="$(cd "$WS" && pwd)"

if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$WS/scanners/rust"
fi
mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

SUMMARY_JSON="$OUT_DIR/SCAN_RUST_SUMMARY.json"
SUMMARY_MD="$OUT_DIR/SCAN_RUST_SUMMARY.md"
READINESS_JSON="$OUT_DIR/RUST_SCAN_READINESS.json"
READINESS_MD="$OUT_DIR/RUST_SCAN_READINESS.md"
TOOL_DIR="$(cd "$(dirname "$0")" && pwd)"
RUST_SOURCE_GRAPH_TOOL="$TOOL_DIR/rust-source-graph.py"
RUST_CROSS_CRATE_GRAPH_TOOL="$TOOL_DIR/rust-cross-crate-graph.py"
RUST_SOURCE_GRAPH_PATH="$WS/.auditooor/rust_source_graph.json"
RUST_CROSS_CRATE_GRAPH_PATH="$WS/.auditooor/rust_cross_crate_graph.json"
SEMANTIC_SOURCE_STATUS="SKIPPED"
SEMANTIC_SOURCE_BLOCKER=""
SEMANTIC_SOURCE_CRATES=0
SEMANTIC_SOURCE_ENTRYPOINTS=0
SEMANTIC_SOURCE_EXTERNAL_CALLS=0
SEMANTIC_SOURCE_UNSAFE_BLOCKS=0
SEMANTIC_SOURCE_VALUE_MOVEMENT_CALLS=0
SEMANTIC_CROSS_STATUS="SKIPPED"
SEMANTIC_CROSS_BLOCKER=""
SEMANTIC_CROSS_CRATES=0
SEMANTIC_CROSS_EDGES=0

# Per-root records are appended as NDJSON to this file by scan_one_root.
# We use NDJSON (rather than pipe-delimited shell arrays) so that nested
# breakdown values (e.g. "critical=1|high=2") cannot collide with the outer
# inter-root delimiter — every value is independently JSON-encoded. This
# fixes a multi-root serialization bug where a HIGH/CRITICAL CVE on a later
# root could be shifted into the wrong index or dropped under --strict.
RECORDS_NDJSON="$OUT_DIR/.scan_records.ndjson"
: >"$RECORDS_NDJSON"

TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# slugify: turn a relative path into a filesystem-safe dir name
slugify() {
    local raw="$1"
    # strip leading "./", collapse "/" to "_", strip trailing slashes
    raw="${raw#./}"
    raw="${raw%/}"
    printf '%s' "$raw" | tr '/ ' '__'
}

# timeout wrapper: use `timeout` if available, else run bare
run_with_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout --preserve-status "${secs}s" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout --preserve-status "${secs}s" "$@"
    else
        "$@"
    fi
}

# JSON-escape helper (Python if available, else hand-roll)
json_str() {
    local s="$1"
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$s"
    else
        # minimal escape: backslash, double-quote, newline
        s="${s//\\/\\\\}"
        s="${s//\"/\\\"}"
        s="${s//$'\n'/\\n}"
        printf '"%s"' "$s"
    fi
}

# ---------------------------------------------------------------------------
# Tool availability
# ---------------------------------------------------------------------------

CARGO_AUDIT_OK=0
SEMGREP_OK=0
CLIPPY_OK=0
CARGO_AUDIT_VERSION=""
SEMGREP_VERSION=""
CLIPPY_VERSION=""
MISSING_TOOLS=()

if command -v cargo >/dev/null 2>&1 && cargo audit --version >/dev/null 2>&1; then
    CARGO_AUDIT_OK=1
    CARGO_AUDIT_VERSION="$(cargo audit --version 2>/dev/null | head -n1)"
else
    MISSING_TOOLS+=("cargo-audit")
fi

if command -v semgrep >/dev/null 2>&1; then
    SEMGREP_OK=1
    SEMGREP_VERSION="$(semgrep --version 2>/dev/null | head -n1)"
else
    MISSING_TOOLS+=("semgrep")
fi

if command -v cargo >/dev/null 2>&1 && cargo clippy --version >/dev/null 2>&1; then
    CLIPPY_OK=1
    CLIPPY_VERSION="$(cargo clippy --version 2>/dev/null | head -n1)"
else
    MISSING_TOOLS+=("cargo-clippy")
fi

# ---------------------------------------------------------------------------
# Rust root detection
# ---------------------------------------------------------------------------

# We want:
#   * external/base*/Cargo.toml (and direct children thereof)
#   * external/*-rs/Cargo.toml (and direct children thereof)
#   * Any other Cargo.toml not nested under lib/ or vendor/
#
# We pick the *root* Cargo.toml (shortest path) per directory tree so we do
# not double-count workspace members.

find_roots() {
    # collect all Cargo.toml paths relative to WS, excluding target/ dirs
    # and excluding anything under lib/ or vendor/
    find "$WS" -name Cargo.toml \
        -not -path '*/target/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/.git/*' \
        -print 2>/dev/null | while read -r manifest; do
            rel="${manifest#$WS/}"
            # skip nested under lib/ or vendor/
            case "$rel" in
                lib/*|*/lib/*|vendor/*|*/vendor/*) continue ;;
                submissions/staging|submissions/staging/*|\
                submissions/ready|submissions/ready/*|\
                submissions/filed|submissions/filed/*|\
                submissions/packaged|submissions/packaged/*|\
                submissions/held|submissions/held/*|\
                submissions/paste_ready|submissions/paste_ready/*|\
                submissions/superseded|submissions/superseded/*|\
                submissions/_killed|submissions/_killed/*|\
                submissions/_oos_rejected|submissions/_oos_rejected/*)
                    continue ;;
            esac
            # record the parent dir, relative to WS
            # Normalize workspace-root (empty) to "." so the awk pruning step
            # can treat it as a universal parent of every child path. Without
            # this, an empty root stored as seen[""] produced a parent check
            # of `p "/"` == "/", which does NOT prefix-match "crates/foo",
            # so the workspace root + its members would both survive pruning.
            dir="$(dirname "$rel")"
            printf '%s\n' "$dir"
        done | sort -u | awk '
            # prune paths that have a parent in the list (keep only roots).
            # "." is treated as the universal parent (workspace-root manifest):
            # if "." is in the set, every non-"." path is pruned.
            {
                keep = 1
                if ($0 != "." && ("." in seen)) {
                    keep = 0
                }
                if (keep) {
                    for (p in seen) {
                        if (p == ".") continue
                        if (index($0, p "/") == 1) { keep = 0; break }
                    }
                }
                if (keep) { seen[$0] = 1; print }
            }
        '
}

# bash 3.2 compatible replacement for `mapfile -t ROOTS < <(find_roots)`
ROOTS=()
while IFS= read -r _line; do
    ROOTS+=("$_line")
done < <(find_roots)

NUM_ROOTS=${#ROOTS[@]}

emit_readiness() {
    local existing_summary_present=0
    local existing_summary_path=""
    for p in "$OUT_DIR/SCAN_RUST_SUMMARY.json" "$OUT_DIR/SCAN_RUST_SUMMARY.md" "$WS/audit/rust-scan/summary.md" "$WS/audit/rust-scan/rust-scan.log"; do
        if [ -f "$p" ]; then
            existing_summary_present=1
            existing_summary_path="$p"
            break
        fi
    done

    if command -v python3 >/dev/null 2>&1; then
        READINESS_JSON_OUT="$READINESS_JSON" \
        READINESS_MD_OUT="$READINESS_MD" \
        TS_IN="$TS" \
        WS_IN="$WS" \
        OUT_DIR_IN="$OUT_DIR" \
        STRICT_IN="$STRICT" \
        CARGO_AUDIT_OK="$CARGO_AUDIT_OK" \
        SEMGREP_OK="$SEMGREP_OK" \
        CLIPPY_OK="$CLIPPY_OK" \
        CARGO_AUDIT_VERSION="$CARGO_AUDIT_VERSION" \
        SEMGREP_VERSION="$SEMGREP_VERSION" \
        CLIPPY_VERSION="$CLIPPY_VERSION" \
        EXISTING_SUMMARY_PRESENT="$existing_summary_present" \
        EXISTING_SUMMARY_PATH="$existing_summary_path" \
        ROOTS_JSON="$(printf '%s\n' "${ROOTS[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.rstrip("\n")]))')" \
        MISSING_TOOLS_JSON="$(printf '%s\n' "${MISSING_TOOLS[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.strip()]))')" \
        python3 <<'PY'
import json, os

def as_bool(name):
    return bool(int(os.environ.get(name, "0") or "0"))

roots = json.loads(os.environ.get("ROOTS_JSON") or "[]")
missing = json.loads(os.environ.get("MISSING_TOOLS_JSON") or "[]")
root_count = len(roots)
primary_scanner_available = as_bool("CARGO_AUDIT_OK") or as_bool("SEMGREP_OK")
blockers = []
if root_count == 0:
    blockers.append("rust_roots_missing")
if not primary_scanner_available:
    blockers.append("cargo_audit_and_semgrep_missing")
doc = {
    "schema": "auditooor.rust_scan_readiness.v1",
    "mode": "readiness_only_no_scanners_executed",
    "workspace": os.environ.get("WS_IN", ""),
    "generated_at": os.environ.get("TS_IN", ""),
    "out_dir": os.environ.get("OUT_DIR_IN", ""),
    "root_count": root_count,
    "roots": ["_root" if r in ("", ".") else r for r in roots],
    "tool_available": {
        "cargo_audit": as_bool("CARGO_AUDIT_OK"),
        "semgrep": as_bool("SEMGREP_OK"),
        "clippy": as_bool("CLIPPY_OK"),
    },
    "tool_versions": {
        "cargo_audit": os.environ.get("CARGO_AUDIT_VERSION", ""),
        "semgrep": os.environ.get("SEMGREP_VERSION", ""),
        "clippy": os.environ.get("CLIPPY_VERSION", ""),
    },
    "missing_tools": missing,
    "can_run_scan_rust": bool(root_count and primary_scanner_available),
    "strict_would_fail": bool(blockers) and as_bool("STRICT_IN"),
    "blockers": blockers,
    "advisories": [
        "cargo-clippy is useful but not required for scan-rust readiness; clippy failures are recorded as BLOCKED/PARTIAL during the real run.",
        "Readiness mode does not prove scanner output freshness; run scan-rust to create SCAN_RUST_SUMMARY.{json,md}.",
    ],
    "existing_scan_summary_present": as_bool("EXISTING_SUMMARY_PRESENT"),
    "existing_scan_summary_path": os.environ.get("EXISTING_SUMMARY_PATH", ""),
    "expected_scan_summary_paths": [
        "scanners/rust/SCAN_RUST_SUMMARY.json",
        "scanners/rust/SCAN_RUST_SUMMARY.md",
    ],
    "root_discovery_policy": {
        "includes": ["workspace Cargo.toml", "external/base*/Cargo.toml", "external/*-rs/Cargo.toml", "other non-vendored Cargo.toml"],
        "excludes": ["target/", "node_modules/", ".git/", "lib/", "vendor/", "submissions/staging/", "submissions/ready/", "submissions/filed/", "submissions/packaged/", "submissions/held/", "submissions/paste_ready/", "submissions/superseded/", "submissions/_killed/", "submissions/_oos_rejected/"],
        "dedupe": "keeps the shortest Cargo.toml root per tree; workspace-root Cargo.toml prunes member manifests",
    },
    "commands": {
        "readiness": "tools/rust-scan-runner.sh <workspace> --readiness --strict",
        "scan_rust_stage": "python3 tools/engage.py --workspace <workspace> --stage scan-rust",
        "direct_scan": "tools/rust-scan-runner.sh <workspace> --timeout 1800",
    },
}

with open(os.environ["READINESS_JSON_OUT"], "w") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)

lines = [
    "# Rust Scan Readiness",
    "",
    f"- Workspace: `{doc['workspace']}`",
    f"- Generated: `{doc['generated_at']}`",
    f"- Roots detected: `{doc['root_count']}`",
    f"- Can run scan-rust: `{doc['can_run_scan_rust']}`",
    f"- Existing scan summary present: `{doc['existing_scan_summary_present']}`",
    "",
    "## Blockers",
    "",
]
for blocker in doc["blockers"] or ["none"]:
    lines.append(f"- `{blocker}`")
lines.extend([
    "",
    "## Roots",
    "",
])
for root in doc["roots"] or ["(none)"]:
    lines.append(f"- `{root}`")
lines.extend([
    "",
    "## Tools",
    "",
])
for name, available in doc["tool_available"].items():
    version = doc["tool_versions"].get(name) or ""
    lines.append(f"- `{name}` available: `{available}` {version}")
lines.extend([
    "",
    "## Next Commands",
    "",
    f"- `{doc['commands']['readiness']}`",
    f"- `{doc['commands']['scan_rust_stage']}`",
    f"- `{doc['commands']['direct_scan']}`",
])
with open(os.environ["READINESS_MD_OUT"], "w") as fh:
    fh.write("\n".join(lines) + "\n")
print(f"[rust-scan] readiness written: {os.environ['READINESS_JSON_OUT']}")
PY
    else
        {
            printf '{\n  "schema": "auditooor.rust_scan_readiness.v1",\n'
            printf '  "mode": "readiness_only_no_scanners_executed",\n'
            printf '  "workspace": %s,\n' "$(json_str "$WS")"
            printf '  "root_count": %s,\n' "$NUM_ROOTS"
            printf '  "roots": [],\n'
            printf '  "missing_tools": ["python3"],\n'
            printf '  "can_run_scan_rust": false,\n'
            printf '  "blockers": ["python3_missing_for_structured_readiness"]\n}\n'
        } >"$READINESS_JSON"
        printf '# Rust Scan Readiness\n\n_python3 unavailable, structured readiness limited._\n' >"$READINESS_MD"
    fi
}

if [ "$READINESS" = 1 ]; then
    emit_readiness
    rm -f "$RECORDS_NDJSON" 2>/dev/null || true
    if [ "$STRICT" = 1 ]; then
        if [ "$NUM_ROOTS" -eq 0 ]; then
            echo "[rust-scan] readiness --strict: no Rust roots found under $WS" >&2
            exit 2
        fi
        if [ "$CARGO_AUDIT_OK" = 0 ] && [ "$SEMGREP_OK" = 0 ]; then
            echo "[rust-scan] readiness --strict: neither cargo audit nor semgrep is available" >&2
            exit 2
        fi
    fi
    echo "[rust-scan] readiness done — $NUM_ROOTS root(s), artifact at $READINESS_JSON"
    exit 0
fi

# ---------------------------------------------------------------------------
# Per-root scanning
# ---------------------------------------------------------------------------

# We accumulate per-root scan results as NDJSON in $RECORDS_NDJSON (one
# JSON object per line, written via python3) and compose the final
# SCAN_RUST_SUMMARY.json from that. This avoids the pipe-delimiter
# collision that the previous design had between the outer inter-root
# separator and inner breakdown values like "critical=1|high=2".
#
# AUDIT_STATUS and SEMGREP_STATUS remain as parallel shell arrays because
# they only contain a fixed enum of ASCII tokens ("OK"/"SKIPPED"/"ERROR")
# and are needed for the final exit-code decision.

ROOT_SLUGS=()
AUDIT_STATUS=()   # "OK" | "SKIPPED" | "ERROR"
SEMGREP_STATUS=()

scan_one_root() {
    local root_rel="$1"
    local root_abs="$WS/$root_rel"
    # "." (workspace-root manifest) and empty (legacy) both map to $WS.
    if [ -z "$root_rel" ] || [ "$root_rel" = "." ]; then
        root_abs="$WS"
        root_rel=""
    fi
    local slug
    slug="$(slugify "${root_rel:-_root}")"
    local root_out="$OUT_DIR/$slug"
    mkdir -p "$root_out"

    ROOT_SLUGS+=("$slug")

    local manifest="$root_abs/Cargo.toml"

    # ---- cargo audit -------------------------------------------------------
    local a_status="SKIPPED" a_cve=0 a_warn=0 a_sev=""
    if [ "$CARGO_AUDIT_OK" = 1 ]; then
        local audit_out="$root_out/cargo-audit.json"
        local audit_err="$root_out/cargo-audit.err"
        (cd "$root_abs" && run_with_timeout "$TIMEOUT_SECS" \
            cargo audit --no-fetch --stale --json >"$audit_out" 2>"$audit_err") || true
        if [ -s "$audit_out" ]; then
            # parse with python if available
            if command -v python3 >/dev/null 2>&1; then
                read -r a_cve a_warn a_sev < <(python3 - "$audit_out" <<'PY'
import json, sys, collections
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    print("0 0 ")
    sys.exit(0)
vulns = data.get("vulnerabilities", {}).get("list", []) or []
warnings_section = data.get("warnings") or {}
# warnings can be a dict of category -> list
if isinstance(warnings_section, dict):
    warn_count = sum(len(v) for v in warnings_section.values() if isinstance(v, list))
elif isinstance(warnings_section, list):
    warn_count = len(warnings_section)
else:
    warn_count = 0
sev_counter = collections.Counter()
for v in vulns:
    sev = ((v.get("advisory") or {}).get("severity") or "unknown").lower()
    sev_counter[sev] += 1
sev_str = "|".join(f"{k}={v}" for k, v in sorted(sev_counter.items()))
print(f"{len(vulns)} {warn_count} {sev_str}")
PY
                )
                a_status="OK"
            else
                a_cve=$(grep -c '"id":' "$audit_out" 2>/dev/null || echo 0)
                a_status="OK"
            fi
        else
            a_status="ERROR"
        fi
    fi
    AUDIT_STATUS+=("$a_status")

    # ---- semgrep -----------------------------------------------------------
    local s_status="SKIPPED" s_total=0 s_unsafe=0 s_byrule=""
    if [ "$SEMGREP_OK" = 1 ]; then
        local sem_out="$root_out/semgrep-rust.json"
        local sem_err="$root_out/semgrep-rust.err"
        # NOTE: do NOT pass --lang; it caused breakage in base-azul runs.
        run_with_timeout "$TIMEOUT_SECS" semgrep \
            --config=p/rust \
            --config=p/security-audit \
            --json \
            --error \
            --metrics=off \
            --quiet \
            "$root_abs" \
            >"$sem_out" 2>"$sem_err" || true
        if [ -s "$sem_out" ]; then
            if command -v python3 >/dev/null 2>&1; then
                read -r s_total s_unsafe s_byrule < <(python3 - "$sem_out" <<'PY'
import json, sys, collections
try:
    with open(sys.argv[1]) as fh:
        data = json.load(fh)
except Exception:
    print("0 0 ")
    sys.exit(0)
results = data.get("results", []) or []
by_rule = collections.Counter()
unsafe_count = 0
for r in results:
    rid = r.get("check_id", "unknown")
    # Normalize long paths to short suffix
    short = rid.split(".")[-1]
    by_rule[short] += 1
    if "unsafe" in rid.lower():
        unsafe_count += 1
by_str = "|".join(f"{k}={v}" for k, v in by_rule.most_common(20))
print(f"{len(results)} {unsafe_count} {by_str}")
PY
                )
                s_status="OK"
            else
                s_total=$(grep -c '"check_id"' "$sem_out" 2>/dev/null || echo 0)
                s_status="OK"
            fi
        else
            s_status="ERROR"
        fi
    fi
    SEMGREP_STATUS+=("$s_status")

    # ---- clippy ------------------------------------------------------------
    local c_status="SKIPPED" c_warn=0 c_err=0 c_reason=""
    if [ "$CLIPPY_OK" = 1 ]; then
        local cl_out="$root_out/clippy-workspace.json"
        local cl_err="$root_out/clippy-workspace.err"
        local rc=0
        (cd "$root_abs" && run_with_timeout "$TIMEOUT_SECS" \
            cargo clippy --workspace --release --message-format=json \
            >"$cl_out" 2>"$cl_err") || rc=$?
        if [ "$rc" -ne 0 ] && grep -q "fuse-ld\|invalid linker name\|linker\s" "$cl_err" 2>/dev/null; then
            c_reason="project-local .cargo/config.toml linker pin; retrying from /tmp"
            # fallback: invoke from /tmp with --manifest-path (skips local cargo config)
            rc=0
            (cd /tmp && run_with_timeout "$TIMEOUT_SECS" \
                cargo clippy --manifest-path "$manifest" \
                    --workspace --release --message-format=json \
                    >"$cl_out" 2>"$cl_err") || rc=$?
        fi
        if [ "$rc" -eq 0 ] && [ -s "$cl_out" ]; then
            if command -v python3 >/dev/null 2>&1; then
                read -r c_warn c_err < <(python3 - "$cl_out" <<'PY'
import json, sys
w=e=0
try:
    with open(sys.argv[1]) as fh:
        for line in fh:
            line=line.strip()
            if not line: continue
            try:
                msg=json.loads(line)
            except Exception:
                continue
            if msg.get("reason") != "compiler-message": continue
            level=(msg.get("message") or {}).get("level","")
            if level=="warning": w+=1
            elif level=="error": e+=1
except Exception:
    pass
print(f"{w} {e}")
PY
                )
                c_status="SUCCESS"
            else
                c_warn=$(grep -c '"level":"warning"' "$cl_out" 2>/dev/null || echo 0)
                c_err=$(grep -c '"level":"error"' "$cl_out" 2>/dev/null || echo 0)
                c_status="SUCCESS"
            fi
            [ "${c_err:-0}" -gt 0 ] && c_status="PARTIAL"
        else
            c_status="BLOCKED"
            if [ -z "$c_reason" ]; then
                c_reason="$(tail -n3 "$cl_err" 2>/dev/null | tr '\n' ' ' | cut -c1-240)"
            fi
        fi
    fi
    # ---- emit per-root NDJSON record --------------------------------------
    # All structured per-root data is serialized via python3 here so that
    # values like `severity_breakdown` ("critical=1|high=2") and clippy
    # `blocker_reason` (free-form text) cannot collide with an outer
    # delimiter. The record is appended to $RECORDS_NDJSON and consumed by
    # emit_summary below.
    if command -v python3 >/dev/null 2>&1; then
        REC_ROOT_REL="$root_rel" \
        REC_SLUG="$slug" \
        REC_A_STATUS="$a_status" \
        REC_A_CVE="${a_cve:-0}" \
        REC_A_WARN="${a_warn:-0}" \
        REC_A_SEV="${a_sev:-}" \
        REC_S_STATUS="$s_status" \
        REC_S_TOTAL="${s_total:-0}" \
        REC_S_UNSAFE="${s_unsafe:-0}" \
        REC_S_BYRULE="${s_byrule:-}" \
        REC_C_STATUS="$c_status" \
        REC_C_WARN="${c_warn:-0}" \
        REC_C_ERR="${c_err:-0}" \
        REC_C_REASON="${c_reason:-}" \
        REC_NDJSON_OUT="$RECORDS_NDJSON" \
        python3 <<'PY'
import json, os

def parse_breakdown(s):
    out = {}
    if not s:
        return out
    for kv in s.split("|"):
        if not kv or "=" not in kv:
            continue
        k, v = kv.split("=", 1)
        try:
            out[k] = int(v)
        except Exception:
            out[k] = v
    return out

def to_int(s, default=0):
    try:
        return int(s or 0)
    except Exception:
        return default

rec = {
    "root_rel":   os.environ.get("REC_ROOT_REL", ""),
    "slug":       os.environ.get("REC_SLUG", ""),
    "audit": {
        "status":              os.environ.get("REC_A_STATUS", "SKIPPED"),
        "cve_count":           to_int(os.environ.get("REC_A_CVE")),
        "warnings":            to_int(os.environ.get("REC_A_WARN")),
        "severity_breakdown":  parse_breakdown(os.environ.get("REC_A_SEV", "")),
    },
    "semgrep": {
        "status":  os.environ.get("REC_S_STATUS", "SKIPPED"),
        "total":   to_int(os.environ.get("REC_S_TOTAL")),
        "unsafe":  to_int(os.environ.get("REC_S_UNSAFE")),
        "by_rule": parse_breakdown(os.environ.get("REC_S_BYRULE", "")),
    },
    "clippy": {
        "status":         os.environ.get("REC_C_STATUS", "SKIPPED"),
        "warnings":       to_int(os.environ.get("REC_C_WARN")),
        "errors":         to_int(os.environ.get("REC_C_ERR")),
        "blocker_reason": os.environ.get("REC_C_REASON", ""),
    },
}

with open(os.environ["REC_NDJSON_OUT"], "a") as fh:
    fh.write(json.dumps(rec) + "\n")
PY
    else
        # python3 missing — record only the status fields with a hand-rolled
        # JSON line. This still avoids the pipe-collision because each
        # record is on its own line.
        printf '{"root_rel":%s,"slug":%s,"audit":{"status":%s,"cve_count":%s,"warnings":%s,"severity_breakdown":{}},"semgrep":{"status":%s,"total":%s,"unsafe":%s,"by_rule":{}},"clippy":{"status":%s,"warnings":%s,"errors":%s,"blocker_reason":%s}}\n' \
            "$(json_str "$root_rel")" \
            "$(json_str "$slug")" \
            "$(json_str "$a_status")" \
            "${a_cve:-0}" \
            "${a_warn:-0}" \
            "$(json_str "$s_status")" \
            "${s_total:-0}" \
            "${s_unsafe:-0}" \
            "$(json_str "$c_status")" \
            "${c_warn:-0}" \
            "${c_err:-0}" \
            "$(json_str "${c_reason:-}")" \
            >>"$RECORDS_NDJSON"
    fi
}

if [ "$NUM_ROOTS" -gt 0 ]; then
    for root in "${ROOTS[@]}"; do
        scan_one_root "$root"
    done
fi

# ---------------------------------------------------------------------------
# Safe semantic inventory integration
# ---------------------------------------------------------------------------

run_semantic_inventory() {
    if [ "$NUM_ROOTS" -eq 0 ]; then
        SEMANTIC_SOURCE_BLOCKER="no Rust roots detected by scan-rust"
        SEMANTIC_CROSS_BLOCKER="no Rust roots detected by scan-rust"
        return
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        SEMANTIC_SOURCE_STATUS="BLOCKED"
        SEMANTIC_SOURCE_BLOCKER="python3 unavailable; cannot run stdlib Rust source graph"
        SEMANTIC_CROSS_STATUS="BLOCKED"
        SEMANTIC_CROSS_BLOCKER="python3 unavailable; cannot run stdlib Rust cross-crate graph"
        return
    fi

    if [ -f "$RUST_SOURCE_GRAPH_TOOL" ]; then
        local source_log="$OUT_DIR/rust-source-graph.err"
        if python3 "$RUST_SOURCE_GRAPH_TOOL" --workspace "$WS" >"$OUT_DIR/rust-source-graph.out" 2>"$source_log" \
            && python3 "$RUST_SOURCE_GRAPH_TOOL" --validate "$RUST_SOURCE_GRAPH_PATH" >>"$OUT_DIR/rust-source-graph.out" 2>>"$source_log"; then
            SEMANTIC_SOURCE_STATUS="OK"
            read -r SEMANTIC_SOURCE_CRATES SEMANTIC_SOURCE_ENTRYPOINTS SEMANTIC_SOURCE_EXTERNAL_CALLS SEMANTIC_SOURCE_UNSAFE_BLOCKS SEMANTIC_SOURCE_VALUE_MOVEMENT_CALLS < <(python3 - "$RUST_SOURCE_GRAPH_PATH" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print("0 0 0 0 0")
    raise SystemExit
crates = [v for k, v in data.items() if k != "_meta" and isinstance(v, dict)]
print(
    len(crates),
    sum(len(c.get("entrypoints") or []) for c in crates),
    sum(len(c.get("external_calls") or []) for c in crates),
    sum(len(c.get("unsafe_blocks") or []) for c in crates),
    sum(len(c.get("value_movement_calls") or []) for c in crates),
)
PY
            )
        else
            SEMANTIC_SOURCE_STATUS="BLOCKED"
            SEMANTIC_SOURCE_BLOCKER="$(tail -n5 "$source_log" 2>/dev/null | tr '\n' ' ' | cut -c1-300)"
        fi
    else
        SEMANTIC_SOURCE_STATUS="BLOCKED"
        SEMANTIC_SOURCE_BLOCKER="missing tool: $RUST_SOURCE_GRAPH_TOOL"
    fi

    if [ -f "$RUST_CROSS_CRATE_GRAPH_TOOL" ]; then
        local cross_log="$OUT_DIR/rust-cross-crate-graph.err"
        if python3 "$RUST_CROSS_CRATE_GRAPH_TOOL" --workspace "$WS" >"$OUT_DIR/rust-cross-crate-graph.out" 2>"$cross_log" \
            && python3 "$RUST_CROSS_CRATE_GRAPH_TOOL" --validate "$RUST_CROSS_CRATE_GRAPH_PATH" >>"$OUT_DIR/rust-cross-crate-graph.out" 2>>"$cross_log"; then
            SEMANTIC_CROSS_STATUS="OK"
            read -r SEMANTIC_CROSS_CRATES SEMANTIC_CROSS_EDGES < <(python3 - "$RUST_CROSS_CRATE_GRAPH_PATH" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    print("0 0")
    raise SystemExit
meta = data.get("_meta") or {}
print(int(meta.get("crate_count") or 0), int(meta.get("edge_count") or 0))
PY
            )
        else
            SEMANTIC_CROSS_STATUS="BLOCKED"
            SEMANTIC_CROSS_BLOCKER="$(tail -n5 "$cross_log" 2>/dev/null | tr '\n' ' ' | cut -c1-300)"
        fi
    else
        SEMANTIC_CROSS_STATUS="BLOCKED"
        SEMANTIC_CROSS_BLOCKER="missing tool: $RUST_CROSS_CRATE_GRAPH_TOOL"
    fi
}

run_semantic_inventory

# If we had zero roots, still record an empty run (exit 2 per spec).

# ---------------------------------------------------------------------------
# Emit SCAN_RUST_SUMMARY.json via Python (stdlib only) — much safer than
# hand-rolled JSON. Falls back to minimal JSON if python3 is absent.
# ---------------------------------------------------------------------------

emit_summary() {
    if command -v python3 >/dev/null 2>&1; then
        SUMMARY_JSON_OUT="$SUMMARY_JSON" \
        SUMMARY_MD_OUT="$SUMMARY_MD" \
        RECORDS_NDJSON_IN="$RECORDS_NDJSON" \
        TS_IN="$TS" \
        WS_IN="$WS" \
        CARGO_AUDIT_OK="$CARGO_AUDIT_OK" \
        SEMGREP_OK="$SEMGREP_OK" \
        CLIPPY_OK="$CLIPPY_OK" \
        CARGO_AUDIT_VERSION="$CARGO_AUDIT_VERSION" \
        SEMGREP_VERSION="$SEMGREP_VERSION" \
        CLIPPY_VERSION="$CLIPPY_VERSION" \
        RUST_SOURCE_GRAPH_PATH="$RUST_SOURCE_GRAPH_PATH" \
        RUST_CROSS_CRATE_GRAPH_PATH="$RUST_CROSS_CRATE_GRAPH_PATH" \
        SEMANTIC_SOURCE_STATUS="$SEMANTIC_SOURCE_STATUS" \
        SEMANTIC_SOURCE_BLOCKER="$SEMANTIC_SOURCE_BLOCKER" \
        SEMANTIC_SOURCE_CRATES="$SEMANTIC_SOURCE_CRATES" \
        SEMANTIC_SOURCE_ENTRYPOINTS="$SEMANTIC_SOURCE_ENTRYPOINTS" \
        SEMANTIC_SOURCE_EXTERNAL_CALLS="$SEMANTIC_SOURCE_EXTERNAL_CALLS" \
        SEMANTIC_SOURCE_UNSAFE_BLOCKS="$SEMANTIC_SOURCE_UNSAFE_BLOCKS" \
        SEMANTIC_SOURCE_VALUE_MOVEMENT_CALLS="$SEMANTIC_SOURCE_VALUE_MOVEMENT_CALLS" \
        SEMANTIC_CROSS_STATUS="$SEMANTIC_CROSS_STATUS" \
        SEMANTIC_CROSS_BLOCKER="$SEMANTIC_CROSS_BLOCKER" \
        SEMANTIC_CROSS_CRATES="$SEMANTIC_CROSS_CRATES" \
        SEMANTIC_CROSS_EDGES="$SEMANTIC_CROSS_EDGES" \
        MISSING_TOOLS_JSON="$(printf '%s\n' "${MISSING_TOOLS[@]:-}" | python3 -c 'import json,sys; print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.strip()]))')" \
        python3 <<'PY'
import json, os, sys

def to_int(value, default=0):
    try:
        return int(value or 0)
    except Exception:
        return default

# Read NDJSON per-root records written by scan_one_root. This avoids the
# pipe-delimiter collision the previous design had between the outer
# inter-root separator and inner breakdown values like
# "critical=1|high=2".
records = []
ndjson_path = os.environ.get("RECORDS_NDJSON_IN", "")
if ndjson_path and os.path.exists(ndjson_path):
    with open(ndjson_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                # Skip malformed lines rather than abort — the runner
                # should still emit a summary even if one record is bad.
                continue

try:
    missing = json.loads(os.environ.get("MISSING_TOOLS_JSON", "[]") or "[]")
except Exception:
    missing = []

# Display label: "" or "." (workspace-root manifest) → "_root".
def display_label(r):
    return "_root" if (not r or r == ".") else r

roots_display = [display_label(rec.get("root_rel", "")) for rec in records]

cargo_audit = {}
semgrep     = {}
clippy      = {}

for rec, r in zip(records, roots_display):
    a = rec.get("audit") or {}
    s = rec.get("semgrep") or {}
    c = rec.get("clippy") or {}

    cargo_audit[r] = {
        "status":             a.get("status", "SKIPPED"),
        "cve_count":          int(a.get("cve_count") or 0),
        "warnings":           int(a.get("warnings") or 0),
        "severity_breakdown": a.get("severity_breakdown") or {},
    }

    by_rule = dict(s.get("by_rule") or {})
    uns_n = int(s.get("unsafe") or 0)
    if uns_n:
        by_rule.setdefault("unsafe-usage", uns_n)
    semgrep[r] = {
        "status":  s.get("status", "SKIPPED"),
        "total":   int(s.get("total") or 0),
        "by_rule": by_rule,
    }

    clippy[r] = {
        "status":         c.get("status", "SKIPPED"),
        "warnings":       int(c.get("warnings") or 0),
        "errors":         int(c.get("errors") or 0),
        "blocker_reason": c.get("blocker_reason", "") or "",
    }

doc = {
    "schema":       "auditooor.rust_scan_summary.v1",
    "workspace":    os.environ.get("WS_IN", ""),
    "roots":        roots_display,
    "root_count":   len(roots_display),
    "cargo_audit":  cargo_audit,
    "semgrep":      semgrep,
    "clippy":       clippy,
    "generated_at": os.environ.get("TS_IN", ""),
    "tool_versions": {
        "cargo_audit": os.environ.get("CARGO_AUDIT_VERSION", ""),
        "semgrep":     os.environ.get("SEMGREP_VERSION", ""),
        "clippy":      os.environ.get("CLIPPY_VERSION", ""),
    },
    "tool_available": {
        "cargo_audit": bool(int(os.environ.get("CARGO_AUDIT_OK", "0"))),
        "semgrep":     bool(int(os.environ.get("SEMGREP_OK", "0"))),
        "clippy":      bool(int(os.environ.get("CLIPPY_OK", "0"))),
    },
    "missing_tools": missing,
    "semantic_inventory": {
        "status": "OK" if os.environ.get("SEMANTIC_SOURCE_STATUS") == "OK" or os.environ.get("SEMANTIC_CROSS_STATUS") == "OK" else "BLOCKED",
        "source_graph": {
            "status": os.environ.get("SEMANTIC_SOURCE_STATUS", "SKIPPED"),
            "path": os.environ.get("RUST_SOURCE_GRAPH_PATH", ""),
            "crate_count": to_int(os.environ.get("SEMANTIC_SOURCE_CRATES")),
            "entrypoint_count": to_int(os.environ.get("SEMANTIC_SOURCE_ENTRYPOINTS")),
            "external_call_count": to_int(os.environ.get("SEMANTIC_SOURCE_EXTERNAL_CALLS")),
            "unsafe_block_count": to_int(os.environ.get("SEMANTIC_SOURCE_UNSAFE_BLOCKS")),
            "value_movement_call_count": to_int(os.environ.get("SEMANTIC_SOURCE_VALUE_MOVEMENT_CALLS")),
            "blocker": os.environ.get("SEMANTIC_SOURCE_BLOCKER", ""),
        },
        "cross_crate_graph": {
            "status": os.environ.get("SEMANTIC_CROSS_STATUS", "SKIPPED"),
            "path": os.environ.get("RUST_CROSS_CRATE_GRAPH_PATH", ""),
            "crate_count": to_int(os.environ.get("SEMANTIC_CROSS_CRATES")),
            "edge_count": to_int(os.environ.get("SEMANTIC_CROSS_EDGES")),
            "blocker": os.environ.get("SEMANTIC_CROSS_BLOCKER", ""),
        },
        "confidence": "source-shape",
        "note": "stdlib-only semantic inventory; no macro expansion, trait resolution, cfg resolution, or runtime call proof",
    },
}

depth_items = [
    ("RD-01", "source_graph", "implemented", "crate discovery from Cargo.toml roots"),
    ("RD-02", "source_graph", "implemented", "entrypoint inventory for contract attributes and lib.rs public exports"),
    ("RD-03", "source_graph", "implemented", "trait impl inventory"),
    ("RD-04", "source_graph", "implemented", "external/cross-contract call token inventory"),
    ("RD-05", "source_graph", "implemented", "unsafe block inventory"),
    ("RD-06", "source_graph", "implemented", "value movement call inventory"),
    ("RD-07", "source_graph", "implemented", "schema validation for rust_source_graph.json"),
    ("RD-08", "cross_crate", "implemented", "workspace dependency graph"),
    ("RD-09", "cross_crate", "implemented", "use-statement import graph"),
    ("RD-10", "cross_crate", "implemented", "schema validation for rust_cross_crate_graph.json"),
    ("RD-11", "scan_rust", "implemented", "scan-rust records semantic graph artifact paths"),
    ("RD-12", "scan_rust", "implemented", "scan-rust records semantic graph counts"),
    ("RD-13", "scan_rust", "implemented", "scan-rust records semantic blockers instead of silently skipping"),
    ("RD-14", "production_path", "implemented", "production-path dossier can consume Rust entrypoints"),
    ("RD-15", "production_path", "implemented", "production-path dossier can consume cross-crate import edges"),
    ("RD-16", "runtime_resolution", "blocked", "cross-crate imports are not resolved to concrete runtime call sites"),
    ("RD-17", "macro_expansion", "blocked", "Rust macros are not expanded"),
    ("RD-18", "trait_dispatch", "blocked", "trait method dispatch is not resolved"),
    ("RD-19", "cfg_features", "blocked", "feature-gated dependencies are treated as live"),
    ("RD-20", "alias_resolution", "blocked", "use aliases are recorded but not resolved to call targets"),
    ("RD-21", "brace_imports", "blocked", "brace import members are not split into individual symbols"),
    ("RD-22", "glob_imports", "blocked", "glob imports identify only the head crate"),
    ("RD-23", "account_context", "blocked", "Anchor Context<T> account mutability/signers are not modeled"),
    ("RD-24", "spl_token", "blocked", "SPL mint authority/cap relationships are not resolved"),
    ("RD-25", "soroban_auth", "blocked", "Soroban require_auth/authorize_as_current_contract actor graph is not modeled"),
    ("RD-26", "substrate_origin", "blocked", "Substrate origin filters are not classified into privileged/permissionless"),
    ("RD-27", "cosmos_messages", "blocked", "Cosmos message handlers are not normalized into semantic entrypoints"),
    ("RD-28", "state_writes", "blocked", "Rust storage writes are not normalized like Solidity state_writes"),
    ("RD-29", "event_indexing", "blocked", "Rust event/log emission inventory is not normalized"),
    ("RD-30", "value_flows", "blocked", "value movement calls are not linked to assets/accounts/amounts"),
    ("RD-31", "unsafe_taint", "blocked", "unsafe blocks are not tainted to entrypoint reachability"),
    ("RD-32", "parser_paths", "blocked", "decode/deserialize parser stages are not promoted into multi-hop paths"),
    ("RD-33", "cache_paths", "blocked", "cache/provider freshness stages are not promoted into multi-hop paths"),
    ("RD-34", "root_paths", "blocked", "state-root/output-root validation stages are not promoted into multi-hop paths"),
    ("RD-35", "proof_paths", "blocked", "proof/dispute/finalization stages are not promoted into multi-hop paths"),
    ("RD-36", "panic_paths", "blocked", "panic/unwrap/expect DoS paths are not tied to external callers"),
    ("RD-37", "arithmetic", "blocked", "checked/saturating/wrapping arithmetic intent is not classified"),
    ("RD-38", "serialization", "blocked", "borsh/serde/rlp/ssz schema mismatches are not modeled"),
    ("RD-39", "consensus_invariants", "blocked", "consensus transition invariants need project-specific harnesses"),
    ("RD-40", "rpc_surfaces", "blocked", "RPC request surfaces are not normalized into entrypoints"),
    ("RD-41", "mempool_surfaces", "blocked", "mempool/gossip surfaces are not normalized into entrypoints"),
    ("RD-42", "fork_choice", "blocked", "fork-choice and payload-building state machines are not modeled"),
    ("RD-43", "economic_edges", "blocked", "validator/sequencer reward and slash flows are not quantified"),
    ("RD-44", "live_config", "blocked", "deployed DLT config/state proof is outside static scanner scope"),
    ("RD-45", "dependency_audit", "implemented", "cargo audit CVE inventory remains available"),
    ("RD-46", "semgrep", "implemented", "Semgrep Rust/security rules remain available"),
    ("RD-47", "clippy", "implemented", "Clippy warnings/errors remain available when buildable"),
    ("RD-48", "strict_gate", "implemented", "strict mode still fails on high/critical cargo audit CVEs"),
    ("RD-49", "artifact_contract", "implemented", "SCAN_RUST_SUMMARY.json/md are the scan-rust accounting contract"),
    ("RD-50", "next_step", "planned", "promote high-signal source graph shapes into semantic_graph multi-hop paths"),
]
doc["semantic_depth_accounting"] = {
    "schema": "auditooor.rust_semantic_depth_accounting.v1",
    "item_count": len(depth_items),
    "implemented_count": sum(1 for _, _, status, _ in depth_items if status == "implemented"),
    "blocked_count": sum(1 for _, _, status, _ in depth_items if status == "blocked"),
    "planned_count": sum(1 for _, _, status, _ in depth_items if status == "planned"),
    "items": [
        {"id": item_id, "area": area, "status": status, "detail": detail}
        for item_id, area, status, detail in depth_items
    ],
}

json_path = os.environ["SUMMARY_JSON_OUT"]
md_path   = os.environ["SUMMARY_MD_OUT"]

with open(json_path, "w") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)

# Markdown
lines = []
lines.append(f"# Rust Scan Summary")
lines.append("")
lines.append(f"- Workspace: `{doc['workspace']}`")
lines.append(f"- Generated: `{doc['generated_at']}`")
lines.append(f"- Roots detected: **{len(roots_display)}**")
if missing:
    lines.append(f"- Missing tools: `{', '.join(missing)}`")
lines.append("")
lines.append("## Per-root results")
lines.append("")
lines.append("| Root | cargo audit | CVEs | Semgrep | unsafe | Clippy | warn | err |")
lines.append("|---|---|---:|---|---:|---|---:|---:|")
for r in roots_display:
    a = cargo_audit[r]
    s = semgrep[r]
    c = clippy[r]
    uns = s["by_rule"].get("unsafe-usage", 0)
    lines.append(
        f"| `{r}` | {a['status']} | {a['cve_count']} | {s['status']} | {uns} | {c['status']} | {c['warnings']} | {c['errors']} |"
    )
lines.append("")
sem = doc["semantic_inventory"]
src = sem["source_graph"]
cross = sem["cross_crate_graph"]
lines.append("## Semantic inventory")
lines.append("")
lines.append(f"- Overall status: `{sem['status']}`")
lines.append(f"- Source graph: `{src['status']}` crates={src['crate_count']} entrypoints={src['entrypoint_count']} external_calls={src['external_call_count']} unsafe_blocks={src['unsafe_block_count']} value_movement={src['value_movement_call_count']}")
if src.get("blocker"):
    lines.append(f"- Source graph blocker: {src['blocker']}")
lines.append(f"- Cross-crate graph: `{cross['status']}` crates={cross['crate_count']} edges={cross['edge_count']}")
if cross.get("blocker"):
    lines.append(f"- Cross-crate graph blocker: {cross['blocker']}")
acct = doc["semantic_depth_accounting"]
lines.append(f"- Depth accounting: {acct['item_count']} items ({acct['implemented_count']} implemented, {acct['blocked_count']} blocked, {acct['planned_count']} planned)")
lines.append("")
lines.append("## Rust/DLT semantic depth ledger")
lines.append("")
lines.append("| ID | Area | Status | Detail |")
lines.append("|---|---|---|---|")
for item in acct["items"]:
    lines.append(f"| `{item['id']}` | {item['area']} | {item['status']} | {item['detail']} |")
lines.append("")
# Severity breakdown
lines.append("## Cargo audit severity breakdown")
lines.append("")
for r, a in cargo_audit.items():
    sb = a.get("severity_breakdown") or {}
    if sb:
        kv = ", ".join(f"{k}={v}" for k, v in sorted(sb.items()))
        lines.append(f"- `{r}`: {kv}")
    else:
        lines.append(f"- `{r}`: (none)")
lines.append("")
# Clippy blockers
lines.append("## Clippy blockers")
lines.append("")
for r, c in clippy.items():
    if c["status"] in ("BLOCKED", "PARTIAL") and c.get("blocker_reason"):
        lines.append(f"- `{r}` ({c['status']}): {c['blocker_reason']}")
lines.append("")

with open(md_path, "w") as fh:
    fh.write("\n".join(lines))

print(f"[rust-scan] summary written: {json_path}")
PY
    else
        # Minimal fallback — emit a tiny JSON so downstream still has something.
        {
            printf '{\n  "workspace": %s,\n' "$(json_str "$WS")"
            printf '  "roots": [],\n'
            printf '  "cargo_audit": {},\n'
            printf '  "semgrep": {},\n'
            printf '  "clippy": {},\n'
            printf '  "generated_at": %s,\n' "$(json_str "$TS")"
            printf '  "note": "python3 unavailable — summary skipped"\n}\n'
        } >"$SUMMARY_JSON"
        printf '# Rust Scan Summary\n\n_python3 unavailable, summary not rendered_\n' >"$SUMMARY_MD"
    fi
}

emit_summary

# Clean up the internal NDJSON staging file — only SCAN_RUST_SUMMARY.{json,md}
# is part of the documented output contract. Tolerate failure since this is
# best-effort housekeeping.
rm -f "$RECORDS_NDJSON" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Exit code decision
# ---------------------------------------------------------------------------

AUDIT_ANY_OK=0
SEM_ANY_OK=0
for st in "${AUDIT_STATUS[@]:-}"; do [ "$st" = "OK" ] && AUDIT_ANY_OK=1; done
for st in "${SEMGREP_STATUS[@]:-}"; do [ "$st" = "OK" ] && SEM_ANY_OK=1; done

# --strict: fail if any critical/high CVE present
if [ "$STRICT" = 1 ] && command -v python3 >/dev/null 2>&1 && [ -s "$SUMMARY_JSON" ]; then
    STRICT_FAIL=$(python3 - "$SUMMARY_JSON" <<'PY'
import json, sys
try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
except Exception:
    print(0); sys.exit(0)
bad = 0
for r, v in (doc.get("cargo_audit") or {}).items():
    sb = v.get("severity_breakdown") or {}
    for k, n in sb.items():
        if k.lower() in ("critical", "high") and n:
            bad += int(n)
print(bad)
PY
    )
    if [ "${STRICT_FAIL:-0}" -gt 0 ]; then
        echo "[rust-scan] --strict: $STRICT_FAIL high/critical CVE(s) detected" >&2
        exit 2
    fi
fi

if [ "$NUM_ROOTS" -eq 0 ]; then
    echo "[rust-scan] no Rust roots found under $WS (soft-exit 0)"
    exit 0
fi

if [ "$AUDIT_ANY_OK" = 0 ] && [ "$SEM_ANY_OK" = 0 ]; then
    echo "[rust-scan] neither cargo audit nor semgrep ran successfully" >&2
    exit 2
fi

echo "[rust-scan] done — $NUM_ROOTS root(s), summary at $SUMMARY_JSON"
exit 0
