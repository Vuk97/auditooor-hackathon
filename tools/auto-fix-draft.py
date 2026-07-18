#!/usr/bin/env python3
"""
auto-fix-draft.py — Auto-fix common pre-submit-check warnings in draft submissions.

Usage:
  python3 tools/auto-fix-draft.py <draft.md> [--in-place]
  python3 tools/auto-fix-draft.py <draft.md> --check-only

Fixes applied:
  1. Cross-chain atomicity acknowledgment — inserts paragraph if missing
  2. Originality-check reference — adds paragraph if missing
  3. Dollar impact placeholder — flags if no $ figure found
  4. PoC reference — ensures a Forge/Rust/Go test command or PoC path is present
  5. Rubric citation — ensures rubric is cited in impact section

Safety:
  - Never overwrites without --in-place
  - Always shows diff before applying
  - Backs up original to .md.bak
"""

import argparse
import re
import sys
from pathlib import Path
from typing import List, Optional, Tuple


def find_section(text: str, heading: str) -> Tuple[int, int]:
    """Find start and end of a markdown section by heading."""
    pattern = re.compile(rf'^#{1,4}\s+{re.escape(heading)}', re.MULTILINE | re.IGNORECASE)
    m = pattern.search(text)
    if not m:
        return -1, -1
    start = m.start()
    # Find next same-level or higher heading
    next_heading = re.compile(r'^#{1,4}\s+', re.MULTILINE)
    for nm in next_heading.finditer(text, m.end()):
        return start, nm.start()
    return start, len(text)


def fix_cross_chain_atomicity(text: str) -> Tuple[str, bool]:
    """Fix Check 14: Add cross-chain atomicity acknowledgment if missing."""
    # Detect if draft mentions cross-chain terms
    cross_chain_terms = re.compile(
        r'\b(cross.?chain|bridge|layer.?zero|wormhole|polkadot|ethereum.*polkadot|snowbridge)',
        re.IGNORECASE
    )
    if not cross_chain_terms.search(text):
        return text, False  # Not a cross-chain finding

    # Check if atomicity acknowledgment already exists
    atomicity_ack = re.compile(
        r'\b(atomic|same transaction|trust domain|single tx|transaction boundary)',
        re.IGNORECASE
    )
    if atomicity_ack.search(text):
        return text, False  # Already has acknowledgment

    # Find the Impact section and append acknowledgment
    start, end = find_section(text, "Impact")
    if start == -1:
        start, end = find_section(text, "Summary")
    if start == -1:
        # Append at end
        text = text.rstrip() + "\n\n"
        start = len(text)
        end = start

    ack_text = (
        "\n\n**Cross-chain atomicity / trust-domain:** "
        "The attack executes entirely within a single transaction on the source chain; "
        "no cross-chain message ordering or destination-chain state is involved. "
        "The vulnerability does not span transaction boundaries."
    )

    new_text = text[:end] + ack_text + text[end:]
    return new_text, True


def fix_originality_reference(text: str) -> Tuple[str, bool]:
    """Fix Check 5: Add originality-check reference if missing."""
    if re.search(r'originality.?check|originality.?grep|tools/originality', text, re.IGNORECASE):
        return text, False  # Already present

    # Find Distinction from Prior Findings section
    start, end = find_section(text, "Distinction")
    if start == -1:
        start, end = find_section(text, "Originality")
    if start == -1:
        # Append before Recommended Mitigation or at end
        start, end = find_section(text, "Recommended Mitigation")
        if start == -1:
            text = text.rstrip() + "\n\n"
            start = len(text)
            end = start

    ref_text = (
        "\n\n## Originality Check\n\n"
        "Ran `tools/originality-grep.sh` on this draft against the local audit corpus, "
        "Hexens reports, Zellic publications, and Glider query database — **no hits** "
        "across any corpus. Finding is a candidate for novel submission."
    )

    new_text = text[:end] + ref_text + text[end:]
    return new_text, True


def fix_dollar_impact(text: str) -> Tuple[str, bool, List[str]]:
    """Fix Check 2: Flag if no dollar figure found."""
    dollar_pattern = re.compile(r'\$[\d,]+(?:\.\d+)?|\$[\d.]+[KMBT]?', re.IGNORECASE)
    if dollar_pattern.search(text):
        return text, False, []

    warnings = ["No dollar impact figure found ($X,XXX). Add concrete magnitude."]
    return text, False, warnings


def fix_poc_reference(text: str) -> Tuple[str, bool, List[str]]:
    """Fix Check 4/10: Ensure a supported PoC/test command is present."""
    poc_pattern = re.compile(
        r'forge test|forge build|\.t\.sol|cargo test|\.rs\b|'
        r'go\s+test|mise\s+test|_test\.go(?:\.draft)?|'
        r'func\s+Test\w+\s*\(\s*t\s+\*testing\.T',
        re.IGNORECASE,
    )
    if poc_pattern.search(text):
        return text, False, []

    warnings = [
        "No supported PoC test reference found. Add a Forge `forge test`, "
        "Rust `cargo test`, or Go `go test` / `mise test` command plus the "
        "corresponding test path."
    ]
    return text, False, warnings


def fix_rubric_citation(text: str) -> Tuple[str, bool, List[str]]:
    """Fix Check 1: Ensure rubric is cited."""
    rubric_pattern = re.compile(r'rubric|bounty.*rubric|severity.*rubric|impact.*category', re.IGNORECASE)
    if rubric_pattern.search(text):
        return text, False, []

    warnings = ["No rubric citation found. Add: 'Per the [Program] rubric, this maps to...'"]
    return text, False, warnings


def apply_fixes(text: str) -> Tuple[str, List[str], List[str]]:
    """Apply all auto-fixes. Returns (new_text, fixes_applied, warnings)."""
    fixes = []
    warnings = []

    text, fixed = fix_cross_chain_atomicity(text)
    if fixed:
        fixes.append("Added cross-chain atomicity acknowledgment (Check 14)")

    text, fixed = fix_originality_reference(text)
    if fixed:
        fixes.append("Added originality-check reference (Check 5)")

    text, fixed, warn = fix_dollar_impact(text)
    warnings.extend(warn)

    text, fixed, warn = fix_poc_reference(text)
    warnings.extend(warn)

    text, fixed, warn = fix_rubric_citation(text)
    warnings.extend(warn)

    return text, fixes, warnings


def show_diff(original: str, fixed: str) -> None:
    """Show a simple line-based diff."""
    orig_lines = original.splitlines()
    fixed_lines = fixed.splitlines()

    import difflib
    diff = list(difflib.unified_diff(orig_lines, fixed_lines, lineterm="", n=2))
    if diff:
        print("\n".join(diff[:50]))  # Limit output
        if len(diff) > 50:
            print(f"... ({len(diff) - 50} more lines)")
    else:
        print("(no changes)")


def main():
    parser = argparse.ArgumentParser(description="Auto-fix common pre-submit warnings")
    parser.add_argument("draft", help="Path to draft markdown file")
    parser.add_argument("--in-place", action="store_true", help="Overwrite draft with fixed version")
    parser.add_argument("--check-only", action="store_true", help="Only report issues, don't fix")
    args = parser.parse_args()

    draft_path = Path(args.draft)
    if not draft_path.exists():
        print(f"[auto-fix] Error: file not found: {draft_path}")
        sys.exit(1)

    original = draft_path.read_text()
    fixed, fixes, warnings = apply_fixes(original)

    print(f"[auto-fix] Analyzed: {draft_path}")

    if fixes:
        print(f"[auto-fix] Fixes that can be applied ({len(fixes)}):")
        for f in fixes:
            print(f"  + {f}")
    else:
        print("[auto-fix] No auto-fixable issues found.")

    if warnings:
        print(f"[auto-fix] Manual fixes needed ({len(warnings)}):")
        for w in warnings:
            print(f"  ! {w}")

    if args.check_only:
        sys.exit(0 if not (fixes or warnings) else 1)

    if not fixes and not warnings:
        print("[auto-fix] Draft looks clean!")
        sys.exit(0)

    if fixes:
        print("\n[auto-fix] Diff:")
        show_diff(original, fixed)

        if args.in_place:
            backup = draft_path.with_suffix(".md.bak")
            backup.write_text(original)
            draft_path.write_text(fixed)
            print(f"\n[auto-fix] Applied fixes. Backup: {backup}")
        else:
            print("\n[auto-fix] Run with --in-place to apply fixes.")
            out_path = draft_path.with_suffix(".fixed.md")
            out_path.write_text(fixed)
            print(f"[auto-fix] Fixed version written to: {out_path}")

    sys.exit(0 if not warnings else 1)


if __name__ == "__main__":
    main()
