#!/usr/bin/env bash
# port-glider-query.sh — scaffold a new Slither detector from a Glider query file
#
# Usage:
#   ./tools/port-glider-query.sh <query-filename> [<wave>]
#
# Arguments:
#   query-filename  Filename (with or without path) from external/glider-query-db/queries/
#   wave            Target wave number (default: 3)
#
# What it does:
#   1. Reads the Glider query docstring (title, description, tags, impact)
#   2. Derives a Python-safe slug from the query filename
#   3. Copies detectors/_template.py → detectors/wave<N>/<slug>.py with pre-filled metadata
#   4. Creates stub fixtures test_fixtures/<slug>_vulnerable.sol and _clean.sol
#   5. Appends run_test lines to test_fixtures/run_tests.sh (with # TODO annotation)
#   6. Appends a row to detectors/_taxonomy.md Wave <N> table
#   7. Prints next steps
#
# Example:
#   ./tools/port-glider-query.sh missing-signature-nonce-storage.py 3
#   ./tools/port-glider-query.sh batch-signature-reuse-exploits.py

set -euo pipefail

# ── locate project root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── argument parsing ───────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <query-filename> [<wave>]"
    echo "Example: $0 missing-signature-nonce-storage.py 3"
    exit 1
fi

QUERY_FILE="$1"
WAVE="${2:-3}"

# Strip path prefix if user passed a full path
QUERY_BASENAME="$(basename "$QUERY_FILE")"

QUERY_PATH="$PROJECT_ROOT/external/glider-query-db/queries/$QUERY_BASENAME"
if [[ ! -f "$QUERY_PATH" ]]; then
    echo "ERROR: query file not found: $QUERY_PATH"
    echo "Available queries:"
    ls "$PROJECT_ROOT/external/glider-query-db/queries/" | head -20
    exit 1
fi

# ── derive slug from filename ─────────────────────────────────────────────────
# Strip .py, replace hyphens with underscores, truncate at 40 chars
RAW_SLUG="${QUERY_BASENAME%.py}"
SLUG="${RAW_SLUG//-/_}"
# Truncate long slugs at word boundary (keep first 40 chars, no trailing underscore)
SLUG="${SLUG:0:40}"
SLUG="${SLUG%_}"

# kebab-case ARGUMENT for Slither
ARGUMENT="${RAW_SLUG:0:40}"
ARGUMENT="${ARGUMENT%%-}"

# ── extract docstring fields ──────────────────────────────────────────────────
# Use Python to extract title, description, tags from the query file
EXTRACTED="$(python3 - "$QUERY_PATH" <<'PYEOF'
import sys, ast, re

fpath = sys.argv[1]
with open(fpath) as fh:
    src = fh.read()

title = ""
description = ""
tags = ""
impact = "MEDIUM"

try:
    tree = ast.parse(src)
    ds = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "query":
            ds = ast.get_docstring(node)
            break
    if not ds:
        ds = ast.get_docstring(tree)
    if ds:
        for line in ds.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("@title") or stripped.lower().startswith("title:"):
                title = re.sub(r'^@title[\s:]*', '', stripped, flags=re.IGNORECASE).strip()
            elif stripped.lower().startswith("@description") or stripped.lower().startswith("description:"):
                description = re.sub(r'^@description[\s:]*', '', stripped, flags=re.IGNORECASE).strip()
            elif stripped.lower().startswith("@tags"):
                tags = re.sub(r'^@tags[\s:]*', '', stripped, flags=re.IGNORECASE).strip()
            elif stripped.lower().startswith("@severity"):
                sev = re.sub(r'^@severity[\s:]*', '', stripped, flags=re.IGNORECASE).strip().upper()
                if sev in ("HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                    impact = sev
        # If description is still empty, use first non-tag line
        if not description and ds:
            for line in ds.splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("@") and not stripped.lower().startswith("title:"):
                    description = stripped[:200]
                    break
except Exception as e:
    pass

# Fallback: derive title from filename
if not title:
    import os
    base = os.path.basename(fpath).replace(".py", "").replace("-", " ").replace("_", " ")
    title = base.title()

# Sanitize for shell output — remove special chars that break heredoc
title = title.replace('"', "'").replace('\\', '').replace('`', '')[:120]
description = description.replace('"', "'").replace('\\', '').replace('`', '')[:300]
tags = tags.replace('"', "'").replace('\\', '').replace('`', '')[:120]

print(f"TITLE={repr(title)}")
print(f"DESCRIPTION={repr(description)}")
print(f"TAGS={repr(tags)}")
print(f"IMPACT={repr(impact)}")
PYEOF
)"

# Evaluate the extracted fields
eval "$EXTRACTED"

# ── paths ──────────────────────────────────────────────────────────────────────
WAVE_DIR="$PROJECT_ROOT/detectors/wave${WAVE}"
DETECTOR_FILE="$WAVE_DIR/${SLUG}.py"
FIXTURE_DIR="$PROJECT_ROOT/detectors/test_fixtures"
VULN_FIXTURE="$FIXTURE_DIR/${SLUG}_vulnerable.sol"
CLEAN_FIXTURE="$FIXTURE_DIR/${SLUG}_clean.sol"
RUN_TESTS="$FIXTURE_DIR/run_tests.sh"
TAXONOMY="$PROJECT_ROOT/detectors/_taxonomy.md"
TEMPLATE="$PROJECT_ROOT/detectors/_template.py"

# ── create wave directory if needed ───────────────────────────────────────────
mkdir -p "$WAVE_DIR"

# ── check for collisions ───────────────────────────────────────────────────────
if [[ -f "$DETECTOR_FILE" ]]; then
    echo "WARNING: $DETECTOR_FILE already exists. Skipping detector file creation."
else

# ── write detector file ────────────────────────────────────────────────────────
# Build class name: CamelCase from slug
CLASS_NAME="$(echo "$SLUG" | sed 's/_\([a-z]\)/\U\1/g; s/^\([a-z]\)/\U\1/')"

cat > "$DETECTOR_FILE" <<PYEOF
"""
${SLUG}.py — Custom Slither detector.

Ported from: external/glider-query-db/queries/${QUERY_BASENAME}

Title: ${TITLE}
Tags: ${TAGS}

Source query body: see ${QUERY_BASENAME} for the original Glider implementation.
Approximation notes: TODO — document any deviations from the Glider query logic.
"""

from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
# Uncomment imports as needed:
# from slither.core.declarations import Contract, Function, SolidityFunction
# from slither.core.declarations import SolidityVariableComposed
# from slither.core.variables.state_variable import StateVariable
# from slither.slithir.operations import (
#     HighLevelCall, LowLevelCall, SolidityCall, InternalCall,
#     Binary, BinaryType, TypeConversion, LibraryCall,
# )
# from slither.slithir.variables import Constant, TemporaryVariable
# from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.utils.output import Output


SKIP_KEYWORDS = ("test", "mock", "setup", "fixture", "helper", "deploy", "script")


class ${CLASS_NAME}(AbstractDetector):
    """${TITLE}"""

    ARGUMENT = "${ARGUMENT}"
    HELP = "${TITLE}"
    IMPACT = DetectorClassification.${IMPACT}
    CONFIDENCE = DetectorClassification.MEDIUM  # adjust after testing

    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/bug_patterns_observed.md"
    WIKI_TITLE = "${TITLE}"
    WIKI_DESCRIPTION = (
        # TODO: expand this based on the source query description
        "${DESCRIPTION}"
    )
    WIKI_EXPLOIT_SCENARIO = """
\`\`\`solidity
// TODO: paste minimal vulnerable Solidity snippet here
\`\`\`
TODO: Step-by-step exploitation scenario."""
    WIKI_RECOMMENDATION = (
        "TODO: add actionable recommendation. Reference OpenZeppelin or EIP as relevant."
    )

    def _detect(self) -> list[Output]:
        """
        TODO: implement detection logic.

        Source query: external/glider-query-db/queries/${QUERY_BASENAME}
        IR inspection: run the one-liner from reference/slither_detector_authoring.md
        before writing the match — do not guess the IR structure.

        Pattern to match:
        ${DESCRIPTION}
        """
        results: list[Output] = []

        for contract in self.compilation_unit.contracts_derived:
            if any(k in contract.name.lower() for k in SKIP_KEYWORDS):
                continue
            for function in contract.functions_and_modifiers_declared:
                # TODO: implement detection
                # Example skeleton:
                # for node in function.nodes:
                #     for ir in node.irs:
                #         if <your match condition>:
                #             info: DETECTOR_INFO = [
                #                 function, " description of finding: ", node, "\\n",
                #             ]
                #             results.append(self.generate_result(info))
                pass

        return results
PYEOF

echo "  Created: $DETECTOR_FILE"
fi  # end collision check

# ── write vulnerable fixture ───────────────────────────────────────────────────
if [[ -f "$VULN_FIXTURE" ]]; then
    echo "  SKIP (exists): $VULN_FIXTURE"
else
cat > "$VULN_FIXTURE" <<SOLEOF
// SPDX-License-Identifier: UNLICENSED
// ${SLUG}_vulnerable.sol — test fixture for ${ARGUMENT} detector
// TODO: implement a minimal vulnerable contract
// Rules:
//   - pragma solidity ^0.8.20;
//   - 1 contract, 1 function, 1 bug
//   - No imports — inline any interfaces needed
//   - The bug must be naked and obvious
//
// Ported from: external/glider-query-db/queries/${QUERY_BASENAME}
// Title: ${TITLE}
pragma solidity ^0.8.20;

contract Vulnerable${CLASS_NAME} {
    // TODO: add state variables

    // TODO: implement vulnerable function
    // function vulnerable() external {
    //     // BUG: <describe the vulnerable pattern here>
    // }
}
SOLEOF
echo "  Created: $VULN_FIXTURE"
fi

# ── write clean fixture ────────────────────────────────────────────────────────
if [[ -f "$CLEAN_FIXTURE" ]]; then
    echo "  SKIP (exists): $CLEAN_FIXTURE"
else
cat > "$CLEAN_FIXTURE" <<SOLEOF
// SPDX-License-Identifier: UNLICENSED
// ${SLUG}_clean.sol — clean (non-vulnerable) fixture for ${ARGUMENT} detector
// TODO: implement the fixed version of the vulnerable contract
// Must produce 0 detector hits.
//
// Ported from: external/glider-query-db/queries/${QUERY_BASENAME}
pragma solidity ^0.8.20;

contract Clean${CLASS_NAME} {
    // TODO: add state variables (same as vulnerable but fixed)

    // TODO: implement fixed function
    // function fixed() external {
    //     // FIX: <describe what was added to eliminate the vulnerability>
    // }
}
SOLEOF
echo "  Created: $CLEAN_FIXTURE"
fi

# ── append to run_tests.sh ─────────────────────────────────────────────────────
if grep -q "\"${ARGUMENT}\"" "$RUN_TESTS" 2>/dev/null; then
    echo "  SKIP (exists): run_tests.sh entry for ${ARGUMENT}"
else
cat >> "$RUN_TESTS" <<TESTEOF

# ${ARGUMENT}: ${TITLE}  [SCAFFOLDED — TODO: fill fixtures before enabling]
# run_test "${ARGUMENT}" "${SLUG}_vulnerable.sol" "${ARGUMENT}"
# run_clean_test "${ARGUMENT}" "${SLUG}_clean.sol" "${ARGUMENT}"
TESTEOF
echo "  Appended (commented): run_tests.sh entry for ${ARGUMENT}"
fi

# ── append to _taxonomy.md ────────────────────────────────────────────────────
if grep -q "${SLUG}" "$TAXONOMY" 2>/dev/null; then
    echo "  SKIP (exists): _taxonomy.md entry for ${SLUG}"
else
# Find the Wave N table header and append after the last row
WAVE_HEADER="## Wave ${WAVE}"
if grep -q "${WAVE_HEADER}" "$TAXONOMY" 2>/dev/null; then
    # Append a new row before the next --- separator after the wave header
    python3 - "$TAXONOMY" "$WAVE_HEADER" "$SLUG" "$ARGUMENT" "$QUERY_BASENAME" "$TITLE" "$IMPACT" <<'PYEOF2'
import sys, re

taxonomy_path = sys.argv[1]
wave_header = sys.argv[2]
slug = sys.argv[3]
argument = sys.argv[4]
query_basename = sys.argv[5]
title = sys.argv[6]
impact = sys.argv[7]

with open(taxonomy_path) as fh:
    content = fh.read()

new_row = f"| {len([l for l in content.splitlines() if '| ' in l and slug[:8] not in l]) + 10} | `{slug}` | `{argument}` | `queries/{query_basename}` | {impact} | SCAFFOLDED — needs fixtures |\n"

# Find the wave header, then find the table (if any), then append
idx = content.find(wave_header)
if idx == -1:
    # No matching wave header — append a new section at the end
    appendage = f"\n\n{wave_header} — scaffolded detectors\n\n| # | Detector | ARGUMENT | Source | Impact | Status |\n|---|---|---|---|---|---|\n{new_row}"
    content = content.rstrip() + appendage + "\n"
else:
    # Find the next table row area after the wave header
    # Look for the table block ending (next ---) and insert before it
    after_header = content[idx:]
    sep_match = re.search(r'\n---\n', after_header)
    if sep_match:
        insert_pos = idx + sep_match.start()
        content = content[:insert_pos] + "\n" + new_row.rstrip() + content[insert_pos:]
    else:
        content = content.rstrip() + "\n" + new_row

with open(taxonomy_path, "w") as fh:
    fh.write(content)
print("  Appended: _taxonomy.md row")
PYEOF2
else
    echo "  NOTE: Wave ${WAVE} header not found in _taxonomy.md — appending new section"
    cat >> "$TAXONOMY" <<TAXEOF


## Wave ${WAVE} — scaffolded detectors

| # | Detector | ARGUMENT | Source | Impact | Status |
|---|---|---|---|---|---|
| — | \`${SLUG}\` | \`${ARGUMENT}\` | \`queries/${QUERY_BASENAME}\` | ${IMPACT} | SCAFFOLDED — needs fixtures |
TAXEOF
fi
fi

# ── print next steps ──────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════════════"
echo " Scaffolded: ${ARGUMENT}"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "  Detector:         detectors/wave${WAVE}/${SLUG}.py"
echo "  Vuln fixture:     detectors/test_fixtures/${SLUG}_vulnerable.sol"
echo "  Clean fixture:    detectors/test_fixtures/${SLUG}_clean.sol"
echo "  Source query:     external/glider-query-db/queries/${QUERY_BASENAME}"
echo ""
echo "Next steps:"
echo "  1. Fill the vulnerable fixture — 1 contract, 1 function, 1 naked bug"
echo "  2. Inspect IR to learn what Slither actually generates:"
echo "       python3 -c \""
echo "         from slither import Slither"
echo "         s = Slither('detectors/test_fixtures/${SLUG}_vulnerable.sol')"
echo "         f = s.contracts[0].functions[0]"
echo "         [print(type(ir).__name__, ir) for n in f.nodes for ir in n.irs]"
echo "       \""
echo "  3. Write _detect() in detectors/wave${WAVE}/${SLUG}.py"
echo "  4. Uncomment run_test lines in detectors/test_fixtures/run_tests.sh"
echo "  5. Run: cd detectors && make test"
echo "  6. Update _taxonomy.md row status from SCAFFOLDED to PASS"
echo ""
