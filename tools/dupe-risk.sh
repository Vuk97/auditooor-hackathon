#!/usr/bin/env bash
# dupe-risk.sh — predict whether a finding will be triage'd as duplicate (Issue #79)
#
# The Morpho #I2.A lesson: originality-grep is lexical, but triagers reason
# in (contract, function, outcome-class) tuples. "Different code path, same
# constructor, same outcome" = DUPE in triager's eyes regardless of mechanism
# novelty.
#
# This tool extracts (contract, function, outcome-class) from a finding draft,
# then greps prior audit corpora + DUPE_CAUSES.md for any finding where
# (contract==X OR function==Y) AND outcome-class overlaps.
#
# Usage:
#   ./tools/dupe-risk.sh <finding-draft.md>
#   ./tools/dupe-risk.sh <finding-draft.md> --corpus-dir </path/to/audits>
#
# Exit codes:
#   0 — low risk (0 hits)
#   1 — HIGH risk (≥1 hit, submission should cite reframing)
#   2 — needs-review risk (partial match, human triage required)

set -uo pipefail

AUDITOOOR_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ $# -lt 1 ]; then
    sed -n '2,20p' "$0" | sed 's/^# //; s/^#//'
    exit 2
fi

DRAFT="$1"
CORPUS_DIR="$AUDITOOOR_DIR/reference/corpus_txt"

while [ $# -gt 0 ]; do
    case "$1" in
        --corpus-dir) CORPUS_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

if [ ! -f "$DRAFT" ]; then
    echo "[error] draft file not found: $DRAFT" >&2
    exit 2
fi

DUPE_CAUSES="$AUDITOOOR_DIR/reference/DUPE_CAUSES.md"

python3 - "$DRAFT" "$CORPUS_DIR" "$DUPE_CAUSES" "$AUDITOOOR_DIR" <<'PY'
import sys, re
from pathlib import Path

draft_path = Path(sys.argv[1])
corpus_dir = Path(sys.argv[2])
dupe_causes_path = Path(sys.argv[3])
auditooor_dir = Path(sys.argv[4])

text = draft_path.read_text(errors="ignore")

# --- Extract (contract, function, outcome) tuple ---
# Heuristics, since finding drafts don't have a strict schema:

# 1. Contract name: look for "Contract: <Name>" / "Target: .../<Name>.sol" / "### <Name>"
contract = None
m = re.search(r'(?:contract|target)\s*[:=]\s*([A-Z][A-Za-z0-9_]*)', text, re.IGNORECASE)
if m:
    contract = m.group(1)
else:
    m = re.search(r'([A-Z][A-Za-z0-9_]*)\.sol', text)
    if m:
        contract = m.group(1)

# 2. Function name: look for .<function>() / function <name>( / `function`
function = None
m = re.search(r'\.([a-z][A-Za-z0-9_]*)\s*\(', text)
if m:
    function = m.group(1)
else:
    m = re.search(r'function\s+([a-z][A-Za-z0-9_]*)\s*\(', text)
    if m:
        function = m.group(1)

# 3. Outcome-class keywords — short phrases we look for in prior findings
OUTCOME_CLASSES = {
    "loss-of-funds": ["steal", "drain", "loss of funds", "fund loss", "lose funds", "extract funds"],
    "dos": ["DoS", "denial of service", "revert", "brick", "permanent", "stuck funds", "freeze"],
    "broken-oracle": ["oracle", "scale factor", "stale price", "price manipulation", "feed"],
    "reentrancy": ["reentrancy", "reentrant", "callback"],
    "access-control": ["missing role", "missing modifier", "unauthorized", "access control", "privilege escalation"],
    "signature-replay": ["replay", "nonce", "signature verif", "EIP-712"],
    "overflow": ["overflow", "underflow", "Panic", "cast"],
    "rounding": ["rounding", "precision", "dust", "residue"],
    "init-missing": ["uninitialized", "missing initializer", "init "],
}
outcome_classes = []
text_low = text.lower()
for cls, kws in OUTCOME_CLASSES.items():
    for kw in kws:
        if kw.lower() in text_low:
            outcome_classes.append(cls)
            break

# --- Search prior corpora ---
print(f"=" * 76)
print(f"  dupe-risk — {draft_path.name}")
print(f"=" * 76)
print(f"  Extracted tuple:")
print(f"    Contract:    {contract or '(could not extract — supply manually)'}")
print(f"    Function:    {function or '(could not extract — supply manually)'}")
print(f"    Outcomes:    {', '.join(outcome_classes) or '(none matched)'}")
print()

hits = []  # list of (source_file, line_number, line_text, match_type)

# Search corpus_txt/ for (contract OR function) + any outcome-class keyword
if contract or function:
    corpora_files = []
    if corpus_dir.exists():
        corpora_files = list(corpus_dir.rglob("*.txt"))
    for cf in corpora_files:
        try:
            lines = cf.read_text(errors="ignore").split("\n")
        except Exception:
            continue
        for i, line in enumerate(lines, 1):
            low = line.lower()
            # Identifier match?
            id_match = False
            if contract and contract.lower() in low:
                id_match = "contract"
            elif function and f".{function.lower()}" in low or function and f" {function.lower()}(" in low:
                id_match = "function"
            if not id_match:
                continue
            # Outcome-class overlap?
            for cls, kws in OUTCOME_CLASSES.items():
                if cls not in outcome_classes:
                    continue
                for kw in kws:
                    if kw.lower() in low:
                        # Expand context: include 2 lines around
                        ctx_start = max(0, i - 2)
                        ctx_end = min(len(lines), i + 2)
                        snippet = "\n        ".join(lines[ctx_start:ctx_end])
                        hits.append({
                            "source": cf.name,
                            "line": i,
                            "id_match": id_match,
                            "outcome_class": cls,
                            "keyword": kw,
                            "snippet": snippet[:400],
                        })
                        break

# Search DUPE_CAUSES.md for prior learned rules
dupe_cause_hits = []
if dupe_causes_path.exists():
    lines = dupe_causes_path.read_text(errors="ignore").split("\n")
    for i, line in enumerate(lines, 1):
        low = line.lower()
        if contract and contract.lower() in low:
            dupe_cause_hits.append(f"{dupe_causes_path.name}:{i}: {line.strip()[:200]}")
        elif function and function.lower() in low:
            dupe_cause_hits.append(f"{dupe_causes_path.name}:{i}: {line.strip()[:200]}")

# --- Verdict ---
print(f"  Prior-audit corpora searched: {len(corpora_files) if (contract or function) else 0} files")
print(f"  Matches found:                {len(hits)} (identifier ∩ outcome-class)")
print(f"  DUPE_CAUSES.md rules matched: {len(dupe_cause_hits)}")
print()

if hits:
    print(f"  🔴 HIGH DUPE RISK — {len(hits)} prior findings match (contract OR function) AND outcome-class")
    print()
    for h in hits[:10]:
        print(f"  📄 {h['source']}:{h['line']}")
        print(f"     matched on: {h['id_match']} + outcome-class={h['outcome_class']} (kw=\"{h['keyword']}\")")
        print(f"     context:")
        for ln in h["snippet"].split("\n"):
            print(f"        {ln[:120]}")
        print()
    if len(hits) > 10:
        print(f"  ... ({len(hits) - 10} more hits)")
        print()
    print("  REFRAMING CHECKLIST (Morpho #I2.A lesson):")
    print("    1. Is (contract, function, outcome-class) the SAME as a prior finding?")
    print("       → If yes: HIGH DUPE RISK regardless of code-path novelty.")
    print("    2. Did the prior finding's fix land on this exact code path?")
    print("       → If not, you may argue 'incomplete fix' — but triagers often dedupe anyway.")
    print("    3. Is your attack vector class distinct from the prior one?")
    print("       → If yes, cite it EXPLICITLY in the submission's 'Distinction' section.")
    print("    4. Does the bounty rubric cite the prior finding as 'Acknowledged' or 'Partial Fix'?")
    print("       → If yes: the bar for novelty is higher; submit only with strong reframing.")
    print()
    sys.exit(1)

if dupe_cause_hits:
    print(f"  🟡 NEEDS REVIEW — {len(dupe_cause_hits)} prior DUPE_CAUSES.md rules match")
    for h in dupe_cause_hits[:5]:
        print(f"    {h}")
    sys.exit(2)

print(f"  🟢 LOW DUPE RISK — no prior findings match (contract OR function) AND outcome-class overlap.")
print()
print("  (Still recommended: run tools/originality-grep.sh for lexical keyword check.)")
sys.exit(0)
PY
