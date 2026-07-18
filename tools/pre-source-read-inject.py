#!/usr/bin/env python3
"""pre-source-read-inject.py — Lane 4 PreToolUse shim for CASE_STUDIES_AND_PATTERNS_INDEX recall.

Per L29-Disc-5 (codified 2026-05-08), every worker brief MUST include recall
against docs/CASE_STUDIES_AND_PATTERNS_INDEX.md BEFORE any source read.
This tool automates that injection: given a source-file path it scans the
index and emits a markdown injection block to stdout.

Usage:
    python3 tools/pre-source-read-inject.py --source-path <path> [--workspace <ws>]
    python3 tools/pre-source-read-inject.py --source-path <path> --json
    python3 tools/pre-source-read-inject.py --source-path <path> --quiet  # exit-code only

Exit codes:
    0  — success (may be empty output if no match)
    1  — bad arguments or index not found

Match heuristics (applied in order, all non-exclusive — all matches emitted):
    1. File extension → language tag (.sol → Solidity, .go → Go, .rs → Rust,
       .py → Python, .ts/.tsx → TypeScript, .cairo → Cairo, .move → Move)
    2. Path basename (without extension) → component-slug substring match
       against index row File paths and Notes columns
    3. Path parent directory name → component-slug substring match

L29-Disc-5 mandate text is ALWAYS included verbatim in any non-empty output block.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO = pathlib.Path(__file__).resolve().parent.parent
INDEX_REL = "docs/CASE_STUDIES_AND_PATTERNS_INDEX.md"

# L29-Disc-5 mandate verbatim (from docs/CODIFIED_DISCIPLINE_RULES_2026-05-08.md)
L29_DISC_5_MANDATE = (
    "**L29-Disc-5 mandate**: every worker brief on an audit/hunt task MUST include "
    "case-study and known-patterns recall as a mandatory step BEFORE any source read. "
    "Consult `docs/CASE_STUDIES_AND_PATTERNS_INDEX.md` (canonical roll-up), drill into "
    "the matching category for the engagement's bug class, then read "
    "`reference/triager_patterns.md` + `reference/anti_patterns.md`. "
    "Skipping any of these is an L28-B violation (documentation != enforcement)."
)

# Extension → language tag
EXT_LANG: dict[str, str] = {
    ".sol": "Solidity",
    ".go": "Go",
    ".rs": "Rust",
    ".py": "Python",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".cairo": "Cairo",
    ".move": "Move",
}

# Language tag → keywords that signal a match in index rows
LANG_KEYWORDS: dict[str, list[str]] = {
    "Solidity": ["sol", "solidity", "erc", "amm", "defi", "swap", "vault", "erc20",
                 "erc4626", "erc7540", "exchange", "lending", "perp", "prediction",
                 "clob", "ctf", "dispute", "bridge", "invariant", "template",
                 "polymarket", "centrifuge", "morpho", "slither", "glider"],
    "Go": ["go", "cosmos", "tendermint", "cometbft", "dydx", "op-stack", "geth",
           "spark", "litecoin", "lightspark", "engine-api", "lz", "oft"],
    "Rust": ["rust", "rs", "solana", "near", "substrate", "cosmos-sdk", "tonic"],
    "Python": ["python", "py", "tools", "detector", "harness", "script"],
    "TypeScript": ["typescript", "ts", "frontend", "sdk", "web3", "ethers"],
    "Cairo": ["cairo", "starknet", "stark"],
    "Move": ["move", "aptos", "sui"],
}


# ---------------------------------------------------------------------------
# Index parsing
# ---------------------------------------------------------------------------

def _parse_index_rows(index_path: pathlib.Path) -> list[dict]:
    """Parse markdown tables in the index, returning list of row dicts."""
    rows: list[dict] = []
    current_section = ""
    in_table = False
    headers: list[str] = []

    for line in index_path.read_text(encoding="utf-8").splitlines():
        # Track section headings (## N. Title)
        heading_m = re.match(r"^#{1,3}\s+(.+)", line)
        if heading_m:
            current_section = heading_m.group(1).strip()
            in_table = False
            headers = []
            continue

        # Table header row
        if re.match(r"^\|", line) and not in_table:
            stripped = line.strip().strip("|")
            headers = [h.strip() for h in stripped.split("|")]
            in_table = True
            continue

        # Table separator row (---|---|---)
        if in_table and re.match(r"^\|[\s\-|]+\|", line):
            continue

        # Table data row
        if in_table and re.match(r"^\|", line):
            stripped = line.strip().strip("|")
            cells = [c.strip() for c in stripped.split("|")]
            if len(cells) >= 1 and cells[0]:
                row = {"section": current_section}
                for i, h in enumerate(headers):
                    row[h] = cells[i] if i < len(cells) else ""
                rows.append(row)
            continue

        # Blank line ends table
        if in_table and not line.strip():
            in_table = False

    return rows


# ---------------------------------------------------------------------------
# Match logic
# ---------------------------------------------------------------------------

def _row_text(row: dict) -> str:
    """Flatten all row values to a single searchable string."""
    return " ".join(str(v) for v in row.values()).lower()


def _match_rows(rows: list[dict], source_path: pathlib.Path,
                lang: Optional[str]) -> list[dict]:
    """Return rows that match the source path by language, slug, or component."""
    matched: list[dict] = []
    seen: set[int] = set()

    basename = source_path.stem.lower()          # e.g. "keeper"
    parent = source_path.parent.name.lower()      # e.g. "cosmos"

    # Slugify: replace underscores/hyphens with space for broader matching
    basename_slug = re.sub(r"[-_]", " ", basename)
    parent_slug = re.sub(r"[-_]", " ", parent)

    # Collect candidate keywords
    lang_kws: list[str] = []
    if lang and lang in LANG_KEYWORDS:
        lang_kws = LANG_KEYWORDS[lang]

    for i, row in enumerate(rows):
        if i in seen:
            continue
        text = _row_text(row)

        match = False

        # 1. Language tag match
        if lang_kws:
            for kw in lang_kws:
                if kw in text:
                    match = True
                    break

        # 2. Component-slug match on basename
        if not match and len(basename) >= 3:
            if basename in text or any(tok in text for tok in basename_slug.split() if len(tok) >= 3):
                match = True

        # 3. Parent directory slug match
        if not match and len(parent) >= 3:
            if parent in text or any(tok in text for tok in parent_slug.split() if len(tok) >= 3):
                match = True

        if match:
            seen.add(i)
            matched.append(row)

    return matched


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def _format_injection(matched: list[dict], source_path: pathlib.Path,
                      lang: Optional[str]) -> str:
    """Render the markdown injection block."""
    lines: list[str] = [
        "---",
        "## Pre-source-read index injection (L29-Disc-5 auto-inject)",
        "",
        f"**Source file**: `{source_path}`",
        f"**Language tag**: {lang or 'unknown'}",
        "",
        L29_DISC_5_MANDATE,
        "",
        f"**Matching rows from `{INDEX_REL}`** ({len(matched)} match{'es' if len(matched) != 1 else ''}):",
        "",
    ]

    # Group by section
    sections: dict[str, list[dict]] = {}
    for row in matched:
        sec = row.get("section", "Uncategorized")
        sections.setdefault(sec, []).append(row)

    for sec, sec_rows in sections.items():
        lines.append(f"### {sec}")
        lines.append("")
        for row in sec_rows:
            # Find the primary "File" or first non-section key
            file_val = row.get("File", row.get("file", row.get("Kit", "")))
            notes_val = (row.get("Notes", row.get("notes", row.get("Use when", "")))
                         or row.get("Key lesson", row.get("Engagement class",
                                    row.get("Source", row.get("Platform", "")))))
            if file_val:
                lines.append(f"- **{file_val}** — {notes_val}")
            else:
                # Fallback: print all non-section fields
                parts = [f"{k}={v}" for k, v in row.items() if k != "section" and v]
                lines.append(f"- {' | '.join(parts)}")
        lines.append("")

    lines += [
        "**Required action before proceeding**:",
        "1. Read the matching files listed above in full.",
        "2. Map each pattern to a specific source-code path in the target.",
        "3. Document the mapping in your worker reply (or 'no case-study match found' if none).",
        "---",
    ]
    return "\n".join(lines)


def _format_json(matched: list[dict], source_path: pathlib.Path,
                 lang: Optional[str]) -> str:
    payload = {
        "source_path": str(source_path),
        "language_tag": lang,
        "l29_disc_5_mandate": L29_DISC_5_MANDATE,
        "matched_rows": matched,
        "match_count": len(matched),
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Emit L29-Disc-5 pre-source-read injection block for a source file."
    )
    parser.add_argument("--source-path", required=True,
                        help="Path to the source file about to be read")
    parser.add_argument("--workspace", default=str(REPO),
                        help="Auditooor repo root (default: auto-detected from script location)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit structured JSON instead of markdown")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress stdout; use exit code only (0=ok, non-zero=error)")
    args = parser.parse_args(argv)

    workspace = pathlib.Path(args.workspace).resolve()
    index_path = workspace / INDEX_REL

    if not index_path.exists():
        if not args.quiet:
            print(f"ERROR: index not found at {index_path}", file=sys.stderr)
        return 1

    source_path = pathlib.Path(args.source_path)
    ext = source_path.suffix.lower()
    lang = EXT_LANG.get(ext)

    rows = _parse_index_rows(index_path)
    matched = _match_rows(rows, source_path, lang)

    if not matched:
        # Empty output, exit 0
        return 0

    if args.quiet:
        return 0

    if args.as_json:
        print(_format_json(matched, source_path, lang))
    else:
        print(_format_injection(matched, source_path, lang))

    return 0


if __name__ == "__main__":
    sys.exit(main())
