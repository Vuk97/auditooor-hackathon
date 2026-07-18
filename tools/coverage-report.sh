#!/usr/bin/env bash
# coverage-report.sh — generate a one-page audit coverage snapshot
#
# Usage:
#   ./tools/coverage-report.sh <workspace-dir>
#
# Parses STATUS.md, SESSION_LOG.md, FINDINGS.md, and HEXENS_COVERAGE.md
# from the given audit workspace and prints a summary.
#
# Fixes Issues 8, 16, 17 from SKILL_ISSUES.md:
#   #8  — exists as a coverage snapshot tool
#   #16 — shares regex constants with finding-stats.sh via lib/finding-patterns.sh
#         so both tools report the same counts
#   #17 — fixed `|| echo 0` pattern that produced a stray bare "0" line when
#         grep -c exited 1 (count was captured from grep's own "0" output,
#         then `echo 0` appended ANOTHER "0", giving `$var = "0\n0"`)

set -uo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <workspace-dir>"
    exit 1
fi

WS="$1"
if [ ! -d "$WS" ]; then
    echo "Error: $WS is not a directory"
    exit 1
fi

# Load shared finding-patterns library
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=lib/finding-patterns.sh
source "$SCRIPT_DIR/lib/finding-patterns.sh"

echo "============================================"
echo "Audit coverage snapshot: $(basename "$WS")"
echo "============================================"
echo

# 1. Findings count by status (unified regex source with finding-stats.sh)
if [ -f "$WS/FINDINGS.md" ]; then
    echo "## Findings"
    submitted=$(finding_count "$WS/FINDINGS.md" SUBMITTED)
    ready=$(finding_count "$WS/FINDINGS.md" READY)
    closed=$(finding_count "$WS/FINDINGS.md" CLOSED)
    draft=$(finding_count "$WS/FINDINGS.md" INVESTIGATING)
    total=$(finding_count "$WS/FINDINGS.md" ANCHOR)
    echo "  Total anchors: $total"
    echo "  Submitted:     $submitted"
    echo "  Ready:         $ready"
    echo "  Investigating: $draft"
    echo "  Closed:        $closed"
    echo
fi

# 2. PoC tests (look for .t.sol files)
if [ -d "$WS/poc-tests" ]; then
    poc_count=$(ls "$WS/poc-tests"/*.t.sol 2>/dev/null | wc -l | tr -d ' ')
    echo "## PoC test files"
    echo "  Count: $poc_count"
    if [ "$poc_count" -gt 0 ]; then
        for f in "$WS/poc-tests"/*.t.sol; do
            basename "$f" | sed 's/^/    /'
        done
    fi
    echo
fi

# Helper: safe grep -c that never produces the "0\n0" double-count artifact
# that plain `$(grep -c ... || echo 0)` caused. Grep always prints a count
# on stdout even when matches==0 (and exits 1); `|| true` suppresses the
# non-zero exit; `${x:-0}` defaults the variable if grep failed entirely
# (file missing / IO error).
safe_count() {
    local result
    result=$(grep -cE "$1" "$2" 2>/dev/null || true)
    echo "${result:-0}"
}

# 3. Session iteration count
if [ -f "$WS/SESSION_LOG.md" ]; then
    echo "## Iterations"
    iter_count=$(safe_count '^\| +[0-9]+ +\|' "$WS/SESSION_LOG.md")
    echo "  Total: $iter_count"
    echo
    echo "  Last 3 iterations:"
    grep -E '^\| +[0-9]+ +\|' "$WS/SESSION_LOG.md" | tail -3 | head -c 1500 | sed 's/^/    /'
    echo
    echo
fi

# 4. Cleared surfaces (from STATUS.md)
if [ -f "$WS/STATUS.md" ]; then
    echo "## Cleared attack surfaces"
    cleared=$(safe_count '✅ CLEARED|CLEARED' "$WS/STATUS.md")
    echo "  Count: $cleared"
    echo
fi

# 4a. Contradiction summary (staging pro-bug vs final-clear / no-bug signals).
# Read-only reporting only: this does not fail the script or block any workflow.
if [ -d "$WS/submissions/staging" ]; then
    python3 - "$WS" <<'PY'
import re
import sys
from pathlib import Path

ws = Path(sys.argv[1])
staging = ws / "submissions" / "staging"
if not staging.exists():
    raise SystemExit(0)

def extract_title(path: Path) -> str:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("# "):
                return line[2:].strip()
    except Exception:
        pass
    return path.stem

def is_pro_bug(text: str) -> bool:
    return bool(re.search(
        r"\b(Critical|High|Medium|Impact|Likelihood|PoC|exploit|revert|reverts|brick|bricks|permanent|drain|loss|vulnerable|novel)\b",
        text,
        flags=re.IGNORECASE,
    ))

def surface_key(title: str, fallback: str) -> str:
    camel = re.findall(r"\b(?:[A-Z][a-z0-9]+){2,}\b", title)
    if camel:
        return max(camel, key=len)
    words = [w for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", title) if len(w) >= 4]
    if words:
        return max(words, key=len)
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", fallback) if len(p) >= 4]
    return max(parts, key=len) if parts else fallback

def negative_hit(text: str) -> bool:
    return bool(re.search(
        r"\b(no bug|not a bug|not exploitable|false positive|deployment-only|deployment only|cleared|clear|no new bug|no vulnerability|not a vuln|investigated)\b",
        text,
        flags=re.IGNORECASE,
    ))

drafts = []
for path in sorted(staging.glob("*.md")):
    if path.name.endswith(".block.md"):
        continue
    if re.match(r"R\d+-[A-Z]", path.stem):
        continue
    text = path.read_text()
    if not is_pro_bug(text):
        continue
    drafts.append((path, extract_title(path), text))

targets = [ws / "STATUS.md", ws / "FINAL_REPORT.md"]
notes_dir = ws / "notes"
if notes_dir.exists():
    targets.extend(sorted(notes_dir.glob("*verdict*.md")))

hits = []
for path, title, draft_text in drafts:
    key = surface_key(title, path.stem)
    for target in targets:
        if not target.exists():
            continue
        try:
            lines = target.read_text().splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, 1):
            if key.lower() not in line.lower():
                continue
            if not negative_hit(line):
                continue
            hits.append((path, key, target, lineno, line.strip()))
            break

if hits:
    print("## Contradiction summary")
    print(f"  Potential staging-vs-final contradictions: {len(hits)}")
    for draft, key, target, lineno, line in hits[:10]:
        print(f"  - {key} ({draft.relative_to(ws)}) vs {target.relative_to(ws)}:{lineno}")
        print(f"    {line}")
    if len(hits) > 10:
        print(f"  ... ({len(hits) - 10} more)")
    print()
PY
fi

# 4b. Rubric-example coverage (fixes SKILL_ISSUES.md #24).
# Row-scoped classification via awk — only counts table rows matching the
# `| <id> | <example> | <verdict> |` shape, ignoring legend / summary prose.
if [ -f "$WS/RUBRIC_COVERAGE.md" ]; then
    echo "## Rubric coverage"
    counts=$(awk '
        /^\| [CHML][0-9]+ \|/ {
            total++
            if ($0 ~ /NOT CHECKED/) unchecked++
            else if ($0 ~ /PARTIAL/) partial++
            else if ($0 ~ /PASS/) pass++
            else if ($0 ~ /SUBMITTED/) submitted++
            else if ($0 ~ /OOS/) oos++
            else if ($0 ~ /N\/A/) na++
        }
        END {
            resolved = pass + submitted + oos + na
            unresolved = unchecked + partial
            printf "%d %d %d %d %d %d %d\n", total, resolved, unresolved, pass, submitted, partial, unchecked
        }
    ' "$WS/RUBRIC_COVERAGE.md")
    read -r total_rows resolved unresolved pass submitted partial unchecked <<< "$counts"
    if [ "$total_rows" -gt 0 ] 2>/dev/null; then
        pct=$((resolved * 100 / total_rows))
    else
        pct=0
    fi
    echo "  Total rubric rows:   $total_rows"
    echo "  ✅ PASS:             $pass"
    echo "  🚀 SUBMITTED:        $submitted"
    echo "  ⚠️  PARTIAL:          $partial"
    echo "  📋 NOT CHECKED:      $unchecked"
    echo "  ──────────────────"
    echo "  Resolved:            $resolved / $total_rows ($pct%)"
    if [ "$pct" -lt 90 ] 2>/dev/null; then
        echo "  ⚠️  Graceful termination BLOCKED (requires ≥90%)"
    else
        echo "  ✅ Graceful termination eligible"
    fi
    echo
fi

# 5. Hexens query coverage (if initialized)
if [ -f "$WS/HEXENS_COVERAGE.md" ]; then
    echo "## Hexens query coverage (152 total)"
    unchecked=$(safe_count '⬜ UNCHECKED' "$WS/HEXENS_COVERAGE.md")
    passed=$(safe_count '✅ PASS' "$WS/HEXENS_COVERAGE.md")
    na=$(safe_count '🚫 N/A' "$WS/HEXENS_COVERAGE.md")
    hits=$(safe_count '⚠️ HITS' "$WS/HEXENS_COVERAGE.md")
    findings=$(safe_count '🎯 FINDING' "$WS/HEXENS_COVERAGE.md")
    reexam=$(safe_count '📋 RE-EXAMINE' "$WS/HEXENS_COVERAGE.md")
    echo "  ⬜ UNCHECKED:  $unchecked"
    echo "  ✅ PASS:       $passed"
    echo "  🚫 N/A:        $na"
    echo "  ⚠️  HITS:       $hits"
    echo "  🎯 FINDING:    $findings"
    echo "  📋 RE-EXAMINE: $reexam"
    echo
else
    echo "## Hexens query coverage"
    echo "  Not initialized. Run: ./tools/hexens-coverage-init.sh $WS"
    echo
fi

# 6. TODO stats
if [ -f "$WS/TODO.md" ]; then
    echo "## TODO"
    open=$(safe_count '^- \[ \]' "$WS/TODO.md")
    done_count=$(safe_count '^- \[x\]' "$WS/TODO.md")
    echo "  Open:  $open"
    echo "  Done:  $done_count"
    echo
fi

echo "============================================"
echo "Done."
