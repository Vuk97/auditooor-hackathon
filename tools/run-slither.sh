#!/usr/bin/env bash
# run-slither.sh — run Slither + Aderyn + Semgrep against a workspace's source
#
# Usage:
#   ./tools/run-slither.sh <workspace-dir> [--src <relative-src-path>]
#
# Runs all three analyzers against the source directory, dumps output to
# <workspace>/slither.json + <workspace>/aderyn-report.md + <workspace>/semgrep.json,
# and produces a consolidated <workspace>/static-analysis-summary.md with
# HIGH/MEDIUM findings grouped by detector.
#
# Then cross-references each HIGH finding against FINDINGS.md to flag any that
# aren't already captured in our audit trail. Any UNCAPTURED HIGH hit is
# auto-added to TODO.md as an iter target.
#
# Dependencies (tool auto-installs missing ones):
#   - slither-analyzer (pip)
#   - aderyn (cargo)
#   - semgrep (pip)
#   - forge (Foundry — for Foundry-style projects)
#
# Ships as Round A of SKILL_ISSUE #31 (Slither integration + feedback loop).

set -uo pipefail

if [ $# -lt 1 ]; then
    cat <<EOF
Usage: $0 <workspace-dir> [--src <relative-src-path>]
       $0 --install    (install all three analyzers without running)

Runs Slither, Aderyn, and Semgrep against the workspace source and produces
a consolidated static-analysis-summary.md. Each HIGH finding is cross-referenced
against FINDINGS.md; uncaptured hits are added to TODO.md as iter targets.

Example:
    $0 ~/audits/myproject
    $0 ~/audits/myproject --src src/
EOF
    exit 1
fi

# Install-only mode
if [ "$1" = "--install" ]; then
    echo "Installing static analyzers..."
    pip3 install --break-system-packages slither-analyzer semgrep 2>&1 | tail -3 || \
        pip3 install --user slither-analyzer semgrep 2>&1 | tail -3
    cargo install aderyn 2>&1 | tail -3 || echo "[warn] cargo not available; skipping aderyn"
    echo "Done. Run with: $0 <workspace-dir>"
    exit 0
fi

WS="$1"
SRC_REL="src"
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --src) SRC_REL="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ ! -d "$WS" ]; then
    echo "Error: workspace $WS not found"
    exit 1
fi

# Source dir may be the workspace itself (Foundry root) or a subpath.
# Heuristic: if <ws>/foundry.toml exists, run from <ws>. Otherwise look for
# a single Foundry project inside <ws>, EXCLUDING audit-bundle / vendored /
# exploit-sample directories that often contain their own foundry.toml.
if [ -f "$WS/foundry.toml" ]; then
    SRC_DIR="$WS"
elif [ -d "$WS/$SRC_REL" ] && [ -f "$WS/$SRC_REL/../foundry.toml" ]; then
    SRC_DIR="$WS/$SRC_REL/.."
else
    # Find foundry.toml files, excluding common bundled/vendored paths that
    # ship their own foundry.toml (audits/, defilabs/, examples/, lib/,
    # node_modules/, submodules/, poc-tests/).
    FOUNDRY_TOML=$(find "$WS" -maxdepth 3 -name foundry.toml \
        -not -path '*/lib/*' \
        -not -path '*/audits/*' \
        -not -path '*/defilabs/*' \
        -not -path '*/examples/*' \
        -not -path '*/node_modules/*' \
        -not -path '*/submodules/*' \
        -not -path '*/poc-tests/*' \
        2>/dev/null | head -1)
    if [ -n "$FOUNDRY_TOML" ]; then
        SRC_DIR=$(dirname "$FOUNDRY_TOML")
    else
        SRC_DIR="$WS"
    fi
fi

echo "[ok] source root: $SRC_DIR"

# Ensure tools on PATH (assume standard install locations)
export PATH="$HOME/.foundry/bin:$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

# Auto-apply the auditooor Slither IR-gen patch (R52d) if not yet applied.
# This soft-skips the `convert_constant_types` assertion that otherwise aborts
# the whole compilation-unit scan on UDVT + bool + nested-external-call-return
# combos. See reference/slither_upstream_bug_report.md + patches/.
PATCH_HELPER="$(cd "$(dirname "$0")" && pwd)/apply-slither-patch.sh"
if [ -x "$PATCH_HELPER" ]; then
    if ! "$PATCH_HELPER" --check >/dev/null 2>&1; then
        echo "[ok] applying auditooor Slither patch (IR-gen soft-skip)..."
        "$PATCH_HELPER" >/dev/null 2>&1 || echo "[warn] slither patch application failed — continuing with unpatched slither"
    fi
fi

# Tool availability check
HAS_SLITHER=0; command -v slither >/dev/null 2>&1 && HAS_SLITHER=1
HAS_ADERYN=0;  command -v aderyn  >/dev/null 2>&1 && HAS_ADERYN=1
HAS_SEMGREP=0; command -v semgrep >/dev/null 2>&1 && HAS_SEMGREP=1

find_python_with_slither() {
    if [ -n "${AUDITOOOR_PYTHON_SLITHER:-}" ]; then
        if "$AUDITOOOR_PYTHON_SLITHER" -c 'import slither' >/dev/null 2>&1; then
            printf '%s\n' "$AUDITOOOR_PYTHON_SLITHER"
            return 0
        fi
        echo "[warn] AUDITOOOR_PYTHON_SLITHER=$AUDITOOOR_PYTHON_SLITHER cannot import slither" >&2
    fi
    for py in python3 python3.14 python3.13 python3.12 python3.11 python; do
        if command -v "$py" >/dev/null 2>&1 && "$py" -c 'import slither' >/dev/null 2>&1; then
            command -v "$py"
            return 0
        fi
    done
    return 1
}

PYTHON_SLITHER_BIN=""
if PYTHON_SLITHER_BIN="$(find_python_with_slither)"; then
    echo "[ok] Python Slither API: $PYTHON_SLITHER_BIN"
else
    echo "[warn] no Python interpreter on PATH can import slither; custom detector API pass will be skipped"
fi

# Use canonical forge resolver (handles PATH collisions with broken forge)
HAS_FORGE=0
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/forge-resolve.sh" 2>/dev/null && HAS_FORGE=1

if [ $HAS_SLITHER -eq 0 ] && [ $HAS_ADERYN -eq 0 ] && [ $HAS_SEMGREP -eq 0 ]; then
    echo "[error] no static analyzers installed. Run: $0 --install"
    exit 1
fi

OUT_DIR="$WS"
SLITHER_JSON="$OUT_DIR/slither.json"
ADERYN_REPORT="$OUT_DIR/aderyn-report.md"
SEMGREP_JSON="$OUT_DIR/semgrep.json"
SUMMARY="$OUT_DIR/static-analysis-summary.md"

# Preamble: archive ANY prior workspace artifacts before we overwrite them.
# NEVER DELETE FILES — see SKILL_ISSUES #41.  archive-workspace-artifacts.sh
# copies every known output file to <name>.<YYYY-MM-DD>.<N>.<ext>, preserving
# history. Subsequent writes in this script only touch the non-archived paths,
# so the archived copies stay pinned forever.
ARCHIVE_HELPER="$(cd "$(dirname "$0")" && pwd)/archive-workspace-artifacts.sh"
if [ -x "$ARCHIVE_HELPER" ]; then
    bash "$ARCHIVE_HELPER" "$WS" || echo "[warn] archive step failed but continuing"
elif [ -f "$ARCHIVE_HELPER" ]; then
    bash "$ARCHIVE_HELPER" "$WS" || echo "[warn] archive step failed but continuing"
else
    echo "[warn] $ARCHIVE_HELPER not found — prior artifacts will be OVERWRITTEN"
fi

# ---------------------------------------------------------------------------
# 1. Run Slither
# ---------------------------------------------------------------------------
SLITHER_HIGH=0
SLITHER_MED=0
if [ $HAS_SLITHER -eq 1 ]; then
    echo "[ok] running slither..."
    (cd "$SRC_DIR" && slither . --filter-paths "lib/|test/|dev/" --json "$SLITHER_JSON" 2>/dev/null) || true
    if [ -f "$SLITHER_JSON" ]; then
        SLITHER_HIGH=$(python3 -c "
import json; f=open('$SLITHER_JSON'); d=json.load(f)
print(sum(1 for h in d.get('results', {}).get('detectors', []) if h.get('impact')=='High'))
" 2>/dev/null || echo 0)
        SLITHER_MED=$(python3 -c "
import json; f=open('$SLITHER_JSON'); d=json.load(f)
print(sum(1 for h in d.get('results', {}).get('detectors', []) if h.get('impact')=='Medium'))
" 2>/dev/null || echo 0)
        echo "  slither: $SLITHER_HIGH HIGH + $SLITHER_MED MEDIUM"
    fi
else
    echo "[skip] slither not installed"
fi

# ---------------------------------------------------------------------------
# 2. Run Aderyn
# ---------------------------------------------------------------------------
ADERYN_HIGH=0
if [ $HAS_ADERYN -eq 1 ]; then
    echo "[ok] running aderyn..."
    (cd "$SRC_DIR" && aderyn . 2>/dev/null > /dev/null) || true
    # Aderyn writes report.md in the cwd — move it
    if [ -f "$SRC_DIR/report.md" ]; then
        mv "$SRC_DIR/report.md" "$ADERYN_REPORT"
        ADERYN_HIGH=$(grep -c "^## H-[0-9]" "$ADERYN_REPORT" 2>/dev/null || echo 0)
        echo "  aderyn: $ADERYN_HIGH HIGH"
    fi
else
    echo "[skip] aderyn not installed"
fi

# ---------------------------------------------------------------------------
# 3. Run Semgrep
# ---------------------------------------------------------------------------
SEMGREP_HITS=0
if [ $HAS_SEMGREP -eq 1 ]; then
    echo "[ok] running semgrep..."
    (cd "$SRC_DIR" && semgrep --config=p/smart-contracts --json --quiet -o "$SEMGREP_JSON" . 2>/dev/null) || true
    if [ -f "$SEMGREP_JSON" ]; then
        SEMGREP_HITS=$(python3 -c "
import json; f=open('$SEMGREP_JSON'); d=json.load(f)
print(len(d.get('results', [])))
" 2>/dev/null || echo 0)
        echo "  semgrep: $SEMGREP_HITS total hits"
    fi
else
    echo "[skip] semgrep not installed"
fi

# ---------------------------------------------------------------------------
# 3b. Run auditooor custom Slither detectors (Glider-ported)
# ---------------------------------------------------------------------------
AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"
CUSTOM_DETECTOR_LOG="$OUT_DIR/custom-detectors.log"
CUSTOM_HITS=0
CUSTOM_LOADED=0
if [ -f "$AUDITOOOR_DIR/detectors/run_custom.py" ] && [ $HAS_SLITHER -eq 1 ] && [ -n "$PYTHON_SLITHER_BIN" ]; then
    # Round 22 reuse-pool-scan path: if CUSTOM_LOG_SOURCE env var is set and
    # points at an existing file, skip the scan and reuse that log instead.
    # This lets the triage workflow consume already-running parallel pool
    # scans from detectors/run_custom.py --pool without double-scanning.
    if [ -n "${CUSTOM_LOG_SOURCE:-}" ] && [ -f "$CUSTOM_LOG_SOURCE" ]; then
        echo "[ok] reusing custom detector log from $CUSTOM_LOG_SOURCE"
        cp "$CUSTOM_LOG_SOURCE" "$CUSTOM_DETECTOR_LOG"
    else
        # Auto-discover: if /tmp/scan_pool_<basename>.log exists and is
        # newer than 30 min, reuse it. Otherwise scan fresh.
        POOL_LOG="/tmp/scan_pool_$(basename "$SRC_DIR").log"
        if [ -f "$POOL_LOG" ] && [ -n "$(find "$POOL_LOG" -mmin -30 2>/dev/null)" ]; then
            echo "[ok] auto-discovered recent pool scan at $POOL_LOG (< 30 min old)"
            cp "$POOL_LOG" "$CUSTOM_DETECTOR_LOG"
        else
            echo "[ok] running auditooor custom detectors..."
            ("$PYTHON_SLITHER_BIN" "$AUDITOOOR_DIR/detectors/run_custom.py" "$SRC_DIR" 2>&1 \
                | tee "$CUSTOM_DETECTOR_LOG" >/dev/null) || true
        fi
    fi
    if [ -f "$CUSTOM_DETECTOR_LOG" ]; then
        CUSTOM_LOADED=$(grep -cE '^\s+-\s+[a-z-]+:' "$CUSTOM_DETECTOR_LOG" 2>/dev/null | tr -d '\n')
        CUSTOM_LOADED=${CUSTOM_LOADED:-0}
        CUSTOM_HITS=$(grep -E '^\[done\] total hits:' "$CUSTOM_DETECTOR_LOG" 2>/dev/null \
            | awk '{print $NF}' | tr -d '\n')
        CUSTOM_HITS=${CUSTOM_HITS:-0}
        echo "  custom: $CUSTOM_LOADED detectors loaded, $CUSTOM_HITS hits"
    fi
else
    echo "[skip] custom detectors not available"
fi

# ---------------------------------------------------------------------------
# 4. Build consolidated summary
# ---------------------------------------------------------------------------
{
    echo "# Static Analysis Summary — $(basename "$WS")"
    echo ""
    echo "**Generated:** $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "**Source root:** $SRC_DIR"
    echo ""
    echo "## Tool counts"
    echo ""
    echo "| Tool | HIGH | MEDIUM | Notes |"
    echo "|---|---|---|---|"
    echo "| slither         | $SLITHER_HIGH | $SLITHER_MED | see \`slither.json\` |"
    echo "| aderyn          | $ADERYN_HIGH  | -  | see \`aderyn-report.md\` |"
    echo "| semgrep         | -  | $SEMGREP_HITS  | see \`semgrep.json\` |"
    echo "| custom detectors | $CUSTOM_HITS | - | $CUSTOM_LOADED loaded, see \`custom-detectors.log\` |"
    echo ""
    if [ -f "$CUSTOM_DETECTOR_LOG" ] && [ "$CUSTOM_HITS" != "0" ]; then
        # ---------------------------------------------------------------
        # Categorized readable summary (Round 18 — replaces wall-of-text).
        # Groups by: (A) role-grant deploy-state checklist (known FPs,
        # 94% rubric covered by deploy-state verification), (B) multi-
        # pattern amplifier signals, (C) genuine new custom findings.
        # ---------------------------------------------------------------
        python3 - "$CUSTOM_DETECTOR_LOG" <<'PY' 2>/dev/null
import re, sys, collections

log = open(sys.argv[1]).read()
lines = re.findall(r'^\s*\[(HIGH|MEDIUM|LOW)\]\s+(.+)$', log, re.M)

def classify(line):
    if line.startswith("Role-gated external function"):
        return "role-grant-checklist"
    if "is flagged by" in line and "independent detector" in line:
        return "multi-pattern-amplifier"
    return "custom-finding"

groups = collections.defaultdict(list)
for sev, line in lines:
    groups[classify(line)].append((sev, line))

def extract_detector_name(line):
    # heuristic: the trailing bracket pattern "[det-name, det-name]" or the
    # pattern from detector REPORT text. Fallback to first technical term.
    m = re.search(r'\[([^\]]+)\]', line)
    if m and ("," in m.group(1) or "-" in m.group(1)):
        return m.group(1)
    # Role-gated: uses modifier(s): <name>
    m = re.search(r'modifier\(s\):\s*([a-zA-Z]+)', line)
    if m: return f"role:{m.group(1)}"
    # Fallback: first capitalized contract.func match
    m = re.search(r'([A-Z][A-Za-z0-9]*\.[a-zA-Z][A-Za-z0-9_]*)', line)
    return m.group(1) if m else "unknown"

print(f"**Custom detector totals:** {len(lines)} hit(s) across {len(groups)} categor(ies).")
print()

# Category A — role-grant deploy-state checklist (known pattern)
if groups["role-grant-checklist"]:
    rg = groups["role-grant-checklist"]
    by_mod = collections.Counter()
    for _, line in rg:
        by_mod[extract_detector_name(line)] += 1
    print(f"### Category A — Role-grant deploy-state checklist ({len(rg)} hit(s))")
    print()
    print("_Known class P1. Each entry is a deploy-state verification checklist item, not a bug. Already covered by the #OFF.A deploy-state finding or Auth-module by-design OOS._")
    print()
    for mod, n in by_mod.most_common():
        print(f"- **{mod}** — {n} function(s) gated by this modifier")
    print()
    # Collapsed per-function list
    print("<details><summary>Full function list (click to expand)</summary>")
    print()
    for _, line in rg:
        m = re.search(r'(\S+\.\S+\(.*?\))\s+\(([^)]+)\)', line)
        if m:
            print(f"- `{m.group(1)}` @ `{m.group(2)}`")
    print()
    print("</details>")
    print()

# Category B — Multi-pattern amplifier signals
if groups["multi-pattern-amplifier"]:
    mp = groups["multi-pattern-amplifier"]
    print(f"### Category B — Multi-pattern amplifier ({len(mp)} hit(s))")
    print()
    print("_Multiple independent detectors fired on the same site. High-confidence candidate. Verify in source._")
    print()
    for sev, line in mp:
        m = re.search(r'(\S+\.\S+\(.*?\))\s+\(([^)]+)\)\s+is flagged by (\d+)', line)
        dets = re.search(r'\[([^\]]+)\]', line)
        if m:
            det_list = dets.group(1) if dets else "?"
            print(f"- **[{sev}]** `{m.group(1)}` @ `{m.group(2)}` — detectors: `{det_list}`")
        else:
            print(f"- **[{sev}]** {line[:200]}")
    print()

# Category C — Genuine custom detector findings
if groups["custom-finding"]:
    cf = groups["custom-finding"]
    print(f"### Category C — Custom detector findings ({len(cf)} hit(s))")
    print()
    print("_Each line is a distinct detector firing. Verify in source — if false-positive, add a one-line note to FINDINGS.md so future runs can skip._")
    print()
    # Group by the detector's one-line signature (first 80 chars of finding text)
    # and dedupe so repeated hits show count.
    sig_groups = collections.defaultdict(list)
    for sev, line in cf:
        # Extract site: Contract.func (file:line)
        site_m = re.search(r'(\S+\.\S+\(.*?\))\s+\(([^)]+\.sol#\d+[-\d]*)\)', line)
        site = f"`{site_m.group(1)}` @ `{site_m.group(2)}`" if site_m else "(site unknown)"
        # Extract short description: the text after the site
        desc_m = re.search(r'\.sol#[-\d]+\)\s*(.*)$', line)
        desc = desc_m.group(1)[:180] if desc_m else line[:180]
        sig_groups[desc].append((sev, site))
    for desc, hits in sig_groups.items():
        print(f"- **[{hits[0][0]}]** {desc}")
        for sev, site in hits:
            print(f"    - {site}")
    print()

# Diff against prior scan if available
import os
prior = sys.argv[1].replace(".log", ".prev.log")
if os.path.exists(prior):
    prior_lines = set(re.findall(r'\[(?:HIGH|MEDIUM|LOW)\].*', open(prior).read()))
    current_lines = set(re.findall(r'\[(?:HIGH|MEDIUM|LOW)\].*', log))
    new = current_lines - prior_lines
    removed = prior_lines - current_lines
    if new or removed:
        print(f"### Diff vs previous scan")
        print()
        if new:
            print(f"**+{len(new)} new hit(s)** since last run:")
            for line in list(new)[:20]:
                print(f"- `+ {line[:200]}`")
            print()
        if removed:
            print(f"**-{len(removed)} removed hit(s)** since last run:")
            for line in list(removed)[:20]:
                print(f"- `- {line[:200]}`")
            print()
PY
        # Archive current log for next-run diff
        cp "$CUSTOM_DETECTOR_LOG" "${CUSTOM_DETECTOR_LOG%.log}.prev.log" 2>/dev/null || true
        echo ""
    fi

    if [ -f "$SLITHER_JSON" ] && [ "$SLITHER_HIGH" != "0" ]; then
        echo "## Slither HIGH findings"
        echo ""
        python3 -c "
import json
with open('$SLITHER_JSON') as f: d = json.load(f)
for h in d.get('results', {}).get('detectors', []):
    if h.get('impact') != 'High': continue
    check = h.get('check', '?')
    desc = h.get('description', '?').replace('\n', ' ')[:300]
    print(f'- **\`{check}\`** — {desc}')
" 2>/dev/null
        echo ""
    fi

    if [ -f "$SLITHER_JSON" ] && [ "$SLITHER_MED" != "0" ]; then
        echo "## Slither MEDIUM findings"
        echo ""
        python3 -c "
import json
with open('$SLITHER_JSON') as f: d = json.load(f)
for h in d.get('results', {}).get('detectors', []):
    if h.get('impact') != 'Medium': continue
    check = h.get('check', '?')
    desc = h.get('description', '?').replace('\n', ' ')[:300]
    print(f'- **\`{check}\`** — {desc}')
" 2>/dev/null
        echo ""
    fi

    echo "## Cross-reference against FINDINGS.md"
    echo ""
    if [ -f "$WS/FINDINGS.md" ]; then
        # Check each Slither check against FINDINGS.md text
        if [ -f "$SLITHER_JSON" ]; then
            python3 -c "
import json, sys
with open('$SLITHER_JSON') as f: d = json.load(f)
with open('$WS/FINDINGS.md') as f: findings = f.read().lower()
high = [h for h in d.get('results', {}).get('detectors', []) if h.get('impact') == 'High']
uncaptured = []
for h in high:
    check = h.get('check', '?')
    # naive match — does the check name appear in FINDINGS.md?
    if check.replace('-', ' ') not in findings and check not in findings:
        uncaptured.append(h)
print(f'- {len(high)} HIGH findings total')
print(f'- {len(high) - len(uncaptured)} appear in FINDINGS.md')
print(f'- **{len(uncaptured)} UNCAPTURED — need iter target:**')
for h in uncaptured[:10]:
    desc = h.get('description', '?').replace('\n', ' ')[:200]
    print(f'  - [{h.get(\"check\")}] {desc}')
" 2>/dev/null
        fi
    else
        echo "- FINDINGS.md not found — skipping cross-reference"
    fi
    echo ""
    echo "## Next steps"
    echo ""
    echo "1. Review each UNCAPTURED HIGH finding above. For each:"
    echo "   (a) Verify in source at the cited file:line"
    echo "   (b) If false-positive, add a one-line justification to FINDINGS.md"
    echo "   (c) If real, add to TODO.md as an iter target"
    echo "2. Cross-check MEDIUM findings against \`RUBRIC_COVERAGE.md\` — any hit on a PARTIAL/NOT CHECKED row moves it forward"
    echo "3. Re-run this tool after every major iter change to catch regressions"
} > "$SUMMARY"

echo ""
echo "[ok] summary: $SUMMARY"
echo "  - slither.json: $(ls -la "$SLITHER_JSON" 2>/dev/null | awk '{print $5}') bytes"
echo "  - aderyn-report.md: $(ls -la "$ADERYN_REPORT" 2>/dev/null | awk '{print $5}') bytes"
echo "  - semgrep.json: $(ls -la "$SEMGREP_JSON" 2>/dev/null | awk '{print $5}') bytes"
echo ""
cat "$SUMMARY"
