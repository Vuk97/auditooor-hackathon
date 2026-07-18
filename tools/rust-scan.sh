#!/usr/bin/env bash
# rust-scan.sh — Rust/Soroban equivalent of scan-full.sh.
#
# Mirrors the EVM scan-full.sh orchestrator pattern: resilient (one layer
# failing does not kill the rest), timestamp-ordered logging, final summary
# at the end. Ships seven layers:
#
#   1. cargo clippy            — rustc lint (--workspace --all-targets)
#   2. cargo audit             — RustSec CVE feed
#   3. semgrep (p/rust + p/security-audit) — pattern rules (SARIF output)
#   4. cargo geiger            — unsafe usage counts per crate
#   5. cargo deny              — supply-chain (uses minimal stub cfg)
#   6. AST stat survey         — wc + grep for Soroban-specific attributes
#                                (#[contractimpl], require_auth, panic_with_error,
#                                unwrap, unwrap_or, expect, unsafe, pub fn)
#   7. summary.md              — counts by lint / severity / attribute top hits
#
# Usage:
#   bash tools/rust-scan.sh <workspace>            # workspace must contain Cargo.toml
#   bash tools/rust-scan.sh --help                 # print usage and exit 0
#   bash tools/rust-scan.sh <ws> --strict          # abort on any layer failure
#   bash tools/rust-scan.sh <ws> --skip LAYER      # skip e.g. --skip geiger
#
# Idempotence: re-running APPENDS a new date-stamped log block per layer
# (clippy.log, cargo-audit.log, etc) so prior output survives. summary.md is
# rewritten each run (always reflects the most recent pass). Layer output
# files (semgrep.sarif, geiger.log as JSON, ast-stats.txt) are rewritten
# per run — their per-run history is captured in the appended .log files.
#
# Exit codes:
#   0 — at least one layer completed (or --strict and all passed)
#   1 — usage error / workspace missing
#   2 — --strict + any layer failed

set -u

# ── arg parse ──────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
rust-scan.sh — Rust/Soroban audit orchestrator (7 layers)

Usage:
    bash tools/rust-scan.sh <workspace>                  # run all layers
    bash tools/rust-scan.sh --help                       # this message
    bash tools/rust-scan.sh <workspace> --strict         # abort on any failure
    bash tools/rust-scan.sh <workspace> --skip LAYER     # skip named layer

Layers:
    clippy         cargo clippy --workspace --all-targets (json)
    cargo-audit    RustSec advisory DB against Cargo.lock
    semgrep        p/rust + p/security-audit rulesets (SARIF)
    geiger         cargo geiger unsafe counts (json)
    deny           cargo deny check with minimal stub cfg
    ast-stats      per-file wc + attribute grep survey
    summary        aggregates counts into audit/rust-scan/summary.md

Outputs land in <workspace>/audit/rust-scan/.
EOF
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
    usage
    exit 0
fi

WS="${1:-}"
if [ -z "$WS" ] || [ ! -d "$WS" ]; then
    echo "usage: $0 <workspace> [--strict] [--skip LAYER]" >&2
    echo "       $0 --help" >&2
    exit 1
fi
if [ ! -f "$WS/Cargo.toml" ]; then
    echo "[err] $WS does not contain a Cargo.toml at root" >&2
    exit 1
fi
WS="$(cd "$WS" && pwd)"  # absolute
shift || true

STRICT=0
SKIP_STEPS=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --strict) STRICT=1; shift ;;
        --skip)   SKIP_STEPS="$SKIP_STEPS $2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "[err] unknown arg: $1" >&2; exit 1 ;;
    esac
done

# ── paths ──────────────────────────────────────────────────────────────────
OUT="$WS/audit/rust-scan"
mkdir -p "$OUT"
LOG="$OUT/rust-scan.log"
SUMMARY="$OUT/summary.md"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# start a new log block (append — do not truncate)
{
    echo ""
    echo "================================================================"
    echo "# rust-scan.sh run @ $STAMP"
    echo "# workspace: $WS"
    echo "================================================================"
} >> "$LOG"

pass_count=0
fail_count=0
declare -a step_results=()  # "name|status|note"

_should_skip() {
    local name="$1"
    for skip in $SKIP_STEPS; do
        if [ "$skip" = "$name" ]; then
            return 0
        fi
    done
    return 1
}

_run_layer() {
    local name="$1"
    local logfile="$2"
    shift 2
    # remaining args are the command

    if _should_skip "$name"; then
        echo "[rust-scan] $name: SKIPPED (--skip)" | tee -a "$LOG"
        step_results+=("$name|SKIPPED|--skip")
        return 0
    fi

    echo "" | tee -a "$LOG"
    echo "---- layer: $name @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ----" | tee -a "$LOG"

    # append a run header to the per-layer log so old output survives
    {
        echo ""
        echo "### rust-scan run @ $STAMP — layer: $name"
        echo ""
    } >> "$logfile"

    local rc=0
    # run command, append stdout+stderr to both per-layer log and master log
    "$@" >> "$logfile" 2>&1 || rc=$?
    # mirror tail into master log for at-a-glance debugging
    tail -20 "$logfile" >> "$LOG" 2>/dev/null || true

    if [ "$rc" -eq 0 ]; then
        pass_count=$((pass_count + 1))
        echo "[rust-scan] $name: OK" | tee -a "$LOG"
        step_results+=("$name|OK|rc=0")
    else
        fail_count=$((fail_count + 1))
        echo "[rust-scan] $name: FAIL rc=$rc" | tee -a "$LOG"
        step_results+=("$name|FAIL|rc=$rc")
        if [ "$STRICT" -eq 1 ]; then
            echo "[rust-scan] STRICT mode — aborting after $name" >&2
            _write_summary
            exit 2
        fi
    fi
    return 0
}

# ── tool presence helpers ──────────────────────────────────────────────────
_have() { command -v "$1" >/dev/null 2>&1; }

# ── ensure Cargo.lock exists before cargo-audit ────────────────────────────
_ensure_lockfile() {
    if [ ! -f "$WS/Cargo.lock" ]; then
        echo "[rust-scan] no Cargo.lock found — running cargo generate-lockfile" | tee -a "$LOG"
        ( cd "$WS" && cargo generate-lockfile ) >>"$LOG" 2>&1 || {
            echo "[rust-scan] cargo generate-lockfile failed — cargo-audit will likely fail too" | tee -a "$LOG"
        }
    fi
}

# ── write minimal deny.toml stub if missing ────────────────────────────────
DENY_CFG="$OUT/deny.toml"
if [ ! -f "$DENY_CFG" ]; then
    cat > "$DENY_CFG" <<'EOF'
# rust-scan.sh — minimal cargo-deny stub. Start empty; bans/allowances
# accrue here over time.
[graph]
all-features = false

[licenses]
confidence-threshold = 0.8
allow = [
    "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016",
    "Unicode-3.0", "CC0-1.0", "Zlib", "MPL-2.0", "0BSD",
]

[bans]
multiple-versions = "allow"
wildcards = "warn"
# deny = [{ name = "openssl", version = "*" }]  # example stub

[advisories]
yanked = "warn"
ignore = []

[sources]
unknown-registry = "warn"
unknown-git = "allow"
EOF
fi

# ═══ LAYER 1: clippy ═══════════════════════════════════════════════════════
_layer_clippy() {
    if ! _have cargo-clippy && ! rustup component list --installed 2>/dev/null | grep -q clippy; then
        echo "[rust-scan] clippy not installed — skipping" | tee -a "$LOG"
        step_results+=("clippy|FAIL|not-installed")
        fail_count=$((fail_count + 1))
        return
    fi
    _run_layer "clippy" "$OUT/clippy.log" \
        bash -c "cd '$WS' && cargo clippy --workspace --all-targets --message-format=json 2>&1"
}

# ═══ LAYER 2: cargo audit ══════════════════════════════════════════════════
_layer_cargo_audit() {
    if ! _have cargo-audit; then
        echo "[rust-scan] cargo-audit not installed — skipping" | tee -a "$LOG"
        step_results+=("cargo-audit|FAIL|not-installed")
        fail_count=$((fail_count + 1))
        return
    fi
    _ensure_lockfile
    _run_layer "cargo-audit" "$OUT/cargo-audit.log" \
        bash -c "cd '$WS' && cargo audit --json 2>&1"
}

# ═══ LAYER 3: semgrep ══════════════════════════════════════════════════════
_layer_semgrep() {
    if ! _have semgrep; then
        echo "[rust-scan] semgrep not installed — skipping" | tee -a "$LOG"
        step_results+=("semgrep|FAIL|not-installed")
        fail_count=$((fail_count + 1))
        return
    fi
    _run_layer "semgrep" "$OUT/semgrep.log" \
        semgrep --config p/rust --config p/security-audit \
                --sarif --output "$OUT/semgrep.sarif" \
                --metrics=off "$WS"
}

# ═══ LAYER 4: cargo geiger ═════════════════════════════════════════════════
_layer_geiger() {
    if ! _have cargo-geiger; then
        echo "[rust-scan] cargo-geiger not installed — skipping" | tee -a "$LOG"
        step_results+=("geiger|FAIL|not-installed")
        fail_count=$((fail_count + 1))
        return
    fi
    _run_layer "geiger" "$OUT/geiger.log" \
        bash -c "cd '$WS' && cargo geiger --workspace --output-format Json 2>&1"
}

# ═══ LAYER 5: cargo deny ═══════════════════════════════════════════════════
_layer_deny() {
    if ! _have cargo-deny; then
        echo "[rust-scan] cargo-deny not installed — skipping" | tee -a "$LOG"
        step_results+=("deny|FAIL|not-installed")
        fail_count=$((fail_count + 1))
        return
    fi
    _ensure_lockfile
    _run_layer "deny" "$OUT/deny.log" \
        bash -c "cd '$WS' && cargo deny --log-level warn --manifest-path '$WS/Cargo.toml' check --config '$DENY_CFG' 2>&1"
}

# ═══ LAYER 6: AST stats ════════════════════════════════════════════════════
_layer_ast_stats() {
    if _should_skip "ast-stats"; then
        echo "[rust-scan] ast-stats: SKIPPED (--skip)" | tee -a "$LOG"
        step_results+=("ast-stats|SKIPPED|--skip")
        return
    fi
    echo "" | tee -a "$LOG"
    echo "---- layer: ast-stats @ $(date -u +%Y-%m-%dT%H:%M:%SZ) ----" | tee -a "$LOG"

    local out="$OUT/ast-stats.txt"
    local stats_log="$OUT/ast-stats.log"
    {
        echo ""
        echo "### rust-scan run @ $STAMP — layer: ast-stats"
        echo ""
    } >> "$stats_log"

    {
        echo "# rust-scan ast-stats — $STAMP"
        echo "# workspace: $WS"
        echo ""
        echo "## per-file line counts (.rs)"
        # exclude target/ and common vendor dirs
        find "$WS" -name '*.rs' -type f \
            -not -path '*/target/*' \
            -not -path '*/.git/*' \
            -not -path '*/node_modules/*' \
            -print0 | xargs -0 wc -l 2>/dev/null | sort -rn | head -200
        echo ""
        echo "## attribute / call-site hit counts (grep -cE, per-file top 30)"
        for pat_name_expr in \
            "pub_fn:pub fn " \
            "contractimpl:#\\[contractimpl\\]" \
            "contract:#\\[contract\\]" \
            "contracttype:#\\[contracttype\\]" \
            "require_auth:require_auth" \
            "panic_with_error:panic_with_error" \
            "unwrap:\\.unwrap\\(" \
            "unwrap_or:\\.unwrap_or[\\(_]" \
            "expect:\\.expect\\(" \
            "unsafe:\\bunsafe\\b" \
            "unchecked:_unchecked" \
            "todo:\\btodo!\\(" \
            "unimplemented:\\bunimplemented!\\(" \
            "transfer:\\.transfer\\(" \
            "from_env:env\\.storage"
        do
            local label="${pat_name_expr%%:*}"
            local expr="${pat_name_expr#*:}"
            echo ""
            echo "### $label   (regex: $expr)"
            local total
            total=$(find "$WS" -name '*.rs' -type f \
                -not -path '*/target/*' \
                -not -path '*/.git/*' \
                -print0 | xargs -0 grep -cE "$expr" 2>/dev/null | awk -F: '{ s += $2 } END { print s+0 }')
            echo "total hits: $total"
            echo "top files:"
            find "$WS" -name '*.rs' -type f \
                -not -path '*/target/*' \
                -not -path '*/.git/*' \
                -print0 | xargs -0 grep -cE "$expr" 2>/dev/null \
                | awk -F: '$2 > 0' | sort -t: -k2 -rn | head -30
        done
    } > "$out" 2>>"$stats_log"

    if [ -s "$out" ]; then
        pass_count=$((pass_count + 1))
        echo "[rust-scan] ast-stats: OK ($(wc -l < "$out") lines)" | tee -a "$LOG"
        step_results+=("ast-stats|OK|$(wc -l < "$out") lines")
    else
        fail_count=$((fail_count + 1))
        echo "[rust-scan] ast-stats: FAIL (empty output)" | tee -a "$LOG"
        step_results+=("ast-stats|FAIL|empty")
    fi
}

# ═══ LAYER 7: summary ══════════════════════════════════════════════════════
_count_clippy() {
    # count jsonl warnings from clippy --message-format=json
    local f="$OUT/clippy.log"
    [ -f "$f" ] || { echo "0"; return; }
    # lines shaped like {"reason":"compiler-message", ... "message":{"level":"warning"}
    grep -c '"level":"warning"' "$f" 2>/dev/null || echo 0
}

_count_clippy_by_lint() {
    local f="$OUT/clippy.log"
    [ -f "$f" ] || return
    # extract "code":{"code":"clippy::NAME"} occurrences
    grep -oE '"code":"clippy::[a-z_:]+"' "$f" 2>/dev/null \
        | sed 's/"code":"//; s/"$//' \
        | sort | uniq -c | sort -rn | head -10
}

_count_audit() {
    local f="$OUT/cargo-audit.log"
    [ -f "$f" ] || { echo "0"; return; }
    # cargo-audit JSON has "vulnerabilities":{"count":N}
    grep -oE '"count":[0-9]+' "$f" 2>/dev/null | head -1 | awk -F: '{print $2+0}'
}

_count_semgrep() {
    local f="$OUT/semgrep.sarif"
    [ -f "$f" ] || { echo "0 total"; return; }
    # count "level": entries under results[]
    python3 - "$f" <<'PY' 2>/dev/null || echo "0 total"
import json, sys
try:
    with open(sys.argv[1]) as fh:
        doc = json.load(fh)
except Exception as e:
    print(f"0 total ({e})")
    sys.exit(0)
runs = doc.get("runs", [])
sev_counts = {}
total = 0
for r in runs:
    for res in r.get("results", []):
        total += 1
        lvl = res.get("level", "note")
        sev_counts[lvl] = sev_counts.get(lvl, 0) + 1
parts = ", ".join(f"{k}={v}" for k, v in sorted(sev_counts.items(), key=lambda x: -x[1]))
print(f"{total} total ({parts})" if parts else f"{total} total")
PY
}

_count_geiger() {
    local f="$OUT/geiger.log"
    [ -f "$f" ] || { echo "no-log"; return; }
    python3 - "$f" <<'PY' 2>/dev/null || echo "parse-failed"
import json, sys, re
txt = open(sys.argv[1]).read()
# geiger prints json at end of log (stdout interleaved with cargo chatter)
idx = txt.find("{")
pkgs = []
if idx >= 0:
    # try full json first
    try:
        doc = json.loads(txt[idx:])
        pkgs = doc.get("packages", [])
    except Exception:
        pass
# regex fallback: count exprs/functions flagged unsafe anywhere in text
funcs = sum(int(x) for x in re.findall(r'"functions"\s*:\s*\{[^}]*?"unsafe_"\s*:\s*(\d+)', txt))
exprs = sum(int(x) for x in re.findall(r'"exprs"\s*:\s*\{[^}]*?"unsafe_"\s*:\s*(\d+)', txt))
print(f"{funcs + exprs} unsafe items across {len(pkgs)} pkgs (used+unused)")
PY
}

_count_deny() {
    local f="$OUT/deny.log"
    [ -f "$f" ] || { echo "0 errors, 0 warnings"; return; }
    local errs warns
    errs=$(grep -cE '^error\[' "$f" 2>/dev/null || echo 0)
    warns=$(grep -cE '^warning\[' "$f" 2>/dev/null || echo 0)
    echo "$errs errors, $warns warnings"
}

_ast_top() {
    local label="$1"
    local f="$OUT/ast-stats.txt"
    [ -f "$f" ] || { echo "(no stats)"; return; }
    # print the line after "### <label>"
    awk -v L="### $label" '
        $0 ~ L { found=1; next }
        found && /^total hits:/ { print $0; exit }
    ' "$f"
}

_write_summary() {
    {
        echo "# rust-scan.sh summary"
        echo ""
        echo "- Workspace: \`$WS\`"
        echo "- Last run: $STAMP"
        echo "- Output dir: \`$OUT\`"
        echo ""
        echo "## Layer status"
        echo ""
        echo "| Layer | Status | Note |"
        echo "|---|---|---|"
        for r in "${step_results[@]}"; do
            IFS='|' read -r n s note <<<"$r"
            echo "| $n | $s | $note |"
        done
        echo ""
        echo "**Totals: $pass_count OK, $fail_count FAIL**"
        echo ""

        echo "## 1. clippy"
        echo ""
        local clippy_warn; clippy_warn="$(_count_clippy)"
        echo "- warnings emitted: $clippy_warn"
        echo ""
        echo "Top lint codes:"
        echo ""
        echo '```'
        _count_clippy_by_lint || true
        echo '```'
        echo ""

        echo "## 2. cargo-audit"
        echo ""
        echo "- advisory count: $(_count_audit)"
        echo ""

        echo "## 3. semgrep (p/rust + p/security-audit)"
        echo ""
        echo "- findings: $(_count_semgrep)"
        echo ""

        echo "## 4. cargo-geiger"
        echo ""
        echo "- unsafe: $(_count_geiger)"
        echo ""

        echo "## 5. cargo-deny"
        echo ""
        echo "- $(_count_deny)"
        echo ""

        echo "## 6. AST stats (top totals)"
        echo ""
        echo "| label | total hits |"
        echo "|---|---|"
        for lbl in pub_fn contractimpl contract contracttype require_auth panic_with_error unwrap unwrap_or expect unsafe unchecked todo unimplemented transfer from_env; do
            local t; t="$(_ast_top "$lbl")"
            echo "| $lbl | ${t#total hits: } |"
        done
        echo ""
        echo "See \`ast-stats.txt\` for per-file top-30 lists per attribute."
        echo ""

        echo "## Files"
        echo ""
        echo "- \`clippy.log\` — clippy JSONL (appended each run)"
        echo "- \`cargo-audit.log\` — advisory JSON (appended)"
        echo "- \`semgrep.sarif\` + \`semgrep.log\` — SARIF + run log"
        echo "- \`geiger.log\` — geiger JSON (appended)"
        echo "- \`deny.log\` — cargo-deny output (appended)"
        echo "- \`deny.toml\` — minimal stub config"
        echo "- \`ast-stats.txt\` — AST survey (rewritten each run)"
        echo "- \`ast-stats.log\` — stderr trail (appended)"
        echo "- \`rust-scan.log\` — master orchestrator log (appended)"
    } > "$SUMMARY"
}

# ═══ drive ═════════════════════════════════════════════════════════════════
_layer_clippy
_layer_cargo_audit
_layer_semgrep
_layer_geiger
_layer_deny
_layer_ast_stats
_write_summary

echo ""
echo "[rust-scan] done. $pass_count OK, $fail_count FAIL"
echo "[rust-scan] summary: $SUMMARY"
echo "[rust-scan] log:     $LOG"

if [ "$STRICT" -eq 1 ] && [ "$fail_count" -gt 0 ]; then
    exit 2
fi
exit 0
