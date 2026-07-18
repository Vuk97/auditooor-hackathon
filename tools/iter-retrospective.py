#!/usr/bin/env python3
"""iter-retrospective.py — Auto-generate the iter-by-iter retrospective table.

Iter4 T6 (commit `df3dd79f`) added an "Iter-by-iter retrospective" section
to `docs/ROADMAP_10_OF_10_V2.md` and hand-maintained a row per overnight-loop
iteration (tests green / pending ledger rows / forced findings / notable
events). This tool automates that table by parsing the real
`docs/LOOP_ITER_NNN_RESULTS.md` dossiers.

Scope
-----

The iter-results-doc markdown files remain the canonical source. This tool
is derived-only: parse numbers out of them, emit a markdown table (default)
or JSON (`--json`). The tool NEVER writes to `docs/LOOP_ITER_*`.

Parsing robustness
------------------

Fail-closed: if a field cannot be extracted with confidence, the cell is
emitted as `?` and a line is logged to stderr citing the doc and missing
field. No field is ever fabricated. No number is ever guessed from context.

Pending-rows backfill (iter10 T5)
---------------------------------

The "Pending ledger rows" totals-table row entered the results-doc format
at iter3. For iter1 and iter2 the primary parser returns `?` (honest, not
fabricated). Iter10 T5 adds a SECONDARY parse path that scans the doc body
for explicit zero-statements such as:

  - `0 pending ledger rows`
  - `no ledger rows this iter`
  - `Ledger rows added | 0 |` (totals-table delta row, iter2 format)
  - `0 ledger rows` (bare mention, e.g. iter2 commit-log line)

If the primary parser returns `?` AND the secondary parser finds an explicit
match, the secondary value is used and the match string is cited on stderr.
If both fail, `?` remains. The secondary parser NEVER returns a non-zero
value it cannot cite verbatim: it is restricted to explicit-zero phrases.
Inferring 0 from calendar position or the absence of a table row is
fabrication per doctrine and is not done here.

Docs that currently cannot be backfilled:

  - `LOOP_ITER_001_RESULTS.md` — no prose statement of ledger-row count.
    (Manual Submission Ledger tooling LANDED in iter1, but the doc does
    not enumerate rows written.) `?` remains the honest answer.

Truth-audit
-----------

  1. Overclaim risk: "retrospective table = authoritative metric source".
     Guard: iter-results-doc is the canonical source. Any parse failure
     falls back to `?`, not a guessed number.
  2. Read-only: tool never writes to any `docs/LOOP_ITER_*_RESULTS.md`.
     Only write path is its own stdout or `--out` file.
  3. Status vocabulary: this tool does not emit or depend on any
     playbook §5 status string. It only counts structural markers.
  4. Secondary-parse-fabrication risk: secondary regexes match ONLY
     explicit zero-valued statements. Silence/absence is never a match.

Usage
-----

    python3 tools/iter-retrospective.py
    python3 tools/iter-retrospective.py --results-dir docs/ --out retro.md
    python3 tools/iter-retrospective.py --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


ITER_FILENAME_RE = re.compile(r"LOOP_ITER_(\d{3})_RESULTS\.md$")

# Matches a markdown table row cell containing a possibly-bolded integer,
# optionally followed by non-numeric suffix (e.g. "**197**" or "197" or
# "**225** (2 pending)").
BOLD_NUM_RE = re.compile(r"\*\*(\d+)\*\*")
PLAIN_NUM_RE = re.compile(r"\b(\d+)\b")


# ---------------------------------------------------------------------------
# Parsing primitives
# ---------------------------------------------------------------------------


def _iter_number_from_filename(path: Path) -> Optional[int]:
    m = ITER_FILENAME_RE.search(path.name)
    if not m:
        return None
    return int(m.group(1))


def _find_table_row(lines: List[str], label_substrs: List[str]) -> Optional[str]:
    """Return first markdown-table row whose first cell contains ALL
    substrs (case-insensitive). Returns the raw line or None."""
    for line in lines:
        if not line.lstrip().startswith("|"):
            continue
        # Split by | and take first non-empty cell
        parts = [p.strip() for p in line.strip().strip("|").split("|")]
        if not parts:
            continue
        label = parts[0].lower()
        if all(s.lower() in label for s in label_substrs):
            return line
    return None


def _find_totals_iter_column(lines: List[str], iter_num: int) -> Optional[int]:
    """Scan for a markdown table header row that contains a cell named
    like `Iter<N>` matching iter_num. Return the 0-indexed position of
    the value cell (i.e. column index into `cells[1:]`).

    Returns None if no matching header row is found.
    """
    header_iter_re = re.compile(r"^\s*iter\s*(\d+)\s*$", re.IGNORECASE)
    for line in lines:
        if not line.lstrip().startswith("|"):
            continue
        cells = [p.strip() for p in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        value_cells = cells[1:]
        for idx, c in enumerate(value_cells):
            m = header_iter_re.match(c)
            if m and int(m.group(1)) == iter_num:
                return idx
    return None


def _extract_cell_by_column(
    row: str, col_idx: int
) -> Optional[str]:
    """Return the raw content of value-column col_idx from a table row,
    or None if out of range."""
    cells = [p.strip() for p in row.strip().strip("|").split("|")]
    if len(cells) < 2:
        return None
    value_cells = cells[1:]
    if col_idx >= len(value_cells):
        return None
    return value_cells[col_idx]


def _int_from_cell(cell: str) -> Optional[str]:
    """Extract the first integer (bold-first, then plain) from a cell.
    Return it as a string, or None."""
    bm = BOLD_NUM_RE.search(cell)
    if bm:
        return bm.group(1)
    pm = PLAIN_NUM_RE.search(cell)
    if pm:
        return pm.group(1)
    return None


def _extract_iter_specific_number(
    row: str,
    iter_num: int,
    warnings: List[str],
    doc: str,
    field: str,
    iter_col: Optional[int],
) -> str:
    """Given a totals-table row, extract the number for `iter_num`.

    Strategy, in order:
      1. If we located a header column for this iter, use that exact cell.
      2. Else, if the row has exactly one bolded integer, trust it.
      3. Else, for single-value-column tables (iter1 style), take the
         single numeric value.
      4. Else, fall back to `?`.
    """
    if iter_col is not None:
        cell = _extract_cell_by_column(row, iter_col)
        if cell is not None:
            val = _int_from_cell(cell)
            if val is not None:
                return val
            warnings.append(
                f"{doc}: {field}: header-located column '{cell}' had no integer"
            )
            return "?"

    cells = [p.strip() for p in row.strip().strip("|").split("|")]
    if len(cells) < 2:
        warnings.append(f"{doc}: {field}: malformed row (no value cells)")
        return "?"
    value_cells = cells[1:]

    bold_matches: List[Tuple[int, str]] = []
    for idx, c in enumerate(value_cells):
        bm = BOLD_NUM_RE.search(c)
        if bm:
            bold_matches.append((idx, bm.group(1)))

    if len(bold_matches) == 1:
        return bold_matches[0][1]

    # iter1-style single "Value" column (no bolded-number convention).
    if len(value_cells) == 1:
        pm = PLAIN_NUM_RE.search(value_cells[0])
        if pm:
            return pm.group(1)
        warnings.append(f"{doc}: {field}: no integer in single value cell")
        return "?"

    if len(bold_matches) > 1:
        warnings.append(
            f"{doc}: {field}: multiple bolded integers, ambiguous "
            f"({[m[1] for m in bold_matches]})"
        )
    else:
        warnings.append(f"{doc}: {field}: no bolded integer in multi-col row")
    return "?"


def _extract_tests_green(
    lines: List[str],
    iter_num: int,
    warnings: List[str],
    doc: str,
    iter_col: Optional[int],
) -> str:
    # iter1 uses "Offline test suite" label with embedded "N tests".
    # iter2+ uses "Offline tests".
    row = _find_table_row(lines, ["offline test"])
    if row is None:
        warnings.append(f"{doc}: tests_green: no 'Offline test' row found")
        return "?"
    # iter1 format has "**171 tests / 0 failures / 1 skipped**". Prefer the
    # "N tests" pattern if present; else fall through to generic extraction.
    m = re.search(r"\*\*(\d+)\s+tests", row)
    if m:
        return m.group(1)
    return _extract_iter_specific_number(
        row, iter_num, warnings, doc, "tests_green", iter_col
    )


# ---------------------------------------------------------------------------
# Pending-rows secondary parser (iter10 T5)
# ---------------------------------------------------------------------------
#
# Each entry is (compiled regex, human description). A match extracts value
# "0" (all patterns are explicit-zero matchers). The description is cited
# on stderr so the operator can verify the backfill was not fabricated.
#
# Hard rule: no pattern here may return a non-zero value from doc silence.
# Every pattern must match a literal token that encodes `0` verbatim in
# the doc text.

PENDING_ROWS_SECONDARY_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"(?i)\b0\s+pending\s+ledger\s+rows?\b"),
        "'0 pending ledger rows' prose mention",
    ),
    (
        re.compile(r"(?i)no\s+(?:new\s+)?ledger\s+rows?\s+(?:this\s+iter|added|landed|written)"),
        "'no ledger rows this iter/added/landed/written' prose mention",
    ),
    (
        re.compile(r"(?i)ledger[_\s]row[_\s]count\s*[:=]\s*0\b"),
        "'ledger row count: 0' explicit key-value",
    ),
    (
        re.compile(r"(?i)pending[_\s]ledger[_\s]rows?\s*[:=]\s*0\b"),
        "'pending_ledger_rows: 0' explicit key-value",
    ),
    # iter2's Totals table carries a "Ledger rows added" delta row with
    # `| 0 | 0 | ...`. Match a markdown-table row whose first cell mentions
    # "ledger rows added" and whose second cell is exactly "0".
    (
        re.compile(
            r"(?im)^\s*\|\s*ledger\s+rows?\s+added\s*\|\s*0\s*\|\s*0\s*\|",
        ),
        "'| Ledger rows added | 0 | 0 |' totals-table delta row",
    ),
    # iter2 commit-log line: `84602445  Iter2 T1 status: 2 bundles produced (READY), 0 ledger rows`.
    (
        re.compile(r"(?i)\b0\s+ledger\s+rows?\b"),
        "'0 ledger rows' bare prose mention",
    ),
]


def _secondary_pending_rows(
    text: str, warnings: List[str], doc: str
) -> Optional[str]:
    """Scan the full doc text for explicit-zero ledger-row statements.

    Returns "0" if any pattern matches (with a stderr citation of the
    match), or None if no pattern matches. Never returns a non-zero value.
    """
    for pat, desc in PENDING_ROWS_SECONDARY_PATTERNS:
        m = pat.search(text)
        if m:
            snippet = m.group(0).strip()
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            warnings.append(
                f"{doc}: pending_rows: secondary parse matched "
                f"{desc}: {snippet!r} -> 0"
            )
            return "0"
    return None


def _extract_pending_rows(
    lines: List[str],
    iter_num: int,
    warnings: List[str],
    doc: str,
    iter_col: Optional[int],
    full_text: str = "",
) -> str:
    row = _find_table_row(lines, ["pending", "ledger"])
    if row is not None:
        return _extract_iter_specific_number(
            row, iter_num, warnings, doc, "pending_rows", iter_col
        )

    # Primary parse failed: try secondary explicit-zero scan.
    if full_text:
        val = _secondary_pending_rows(full_text, warnings, doc)
        if val is not None:
            return val

    # Both failed — honest `?`.
    warnings.append(
        f"{doc}: pending_rows: no 'pending ledger' row AND no "
        f"secondary-parse match; leaving as `?`"
    )
    return "?"


def _extract_forced_findings(
    lines: List[str],
    iter_num: int,
    warnings: List[str],
    doc: str,
    iter_col: Optional[int],
) -> str:
    row = _find_table_row(lines, ["forced"])
    if row is None:
        warnings.append(f"{doc}: forced_findings: no 'Forced' row found")
        return "?"
    val = _extract_iter_specific_number(
        row, iter_num, warnings, doc, "forced_findings", iter_col
    )
    if val != "?":
        return val
    # Fallback: scan the entire row for any integer — if they're all zero,
    # report 0 with high confidence. This preserves "?" for any row that
    # doesn't agree.
    nums = PLAIN_NUM_RE.findall(row)
    if nums and all(n == "0" for n in nums):
        if warnings and warnings[-1].startswith(f"{doc}: forced_findings:"):
            warnings.pop()
        return "0"
    return "?"


# Headers we will accept as a "notable events" source, in priority order.
# More-specific headlines (Headline / Landmark / 🎯) outrank the generic
# "What landed" heading that every iter carries.
HEADLINE_HEADER_PRIORITIES = (
    "## 🎯",
    "## Landmark",
    "## Headline",  # covers "Headline" + "Headlines"
    "## What landed",
)


def _extract_notable_event(
    lines: List[str], warnings: List[str], doc: str
) -> str:
    # Find first header matching each prefix in priority order.
    best_idx: Optional[int] = None
    for prefix in HEADLINE_HEADER_PRIORITIES:
        for i, line in enumerate(lines):
            if line.rstrip().startswith(prefix):
                best_idx = i
                break
        if best_idx is not None:
            break
    if best_idx is None:
        warnings.append(f"{doc}: notable: no headline-style section found")
        return "?"
    header = lines[best_idx].strip()
    header_clean = re.sub(r"^#+\s*", "", header).rstrip().rstrip(":")
    header_clean = re.sub(r"\s+", " ", header_clean)

    # If the header text alone is generic ("Headlines", "What landed...") —
    # i.e. contains no real content beyond a section label — drill down to
    # the first non-empty content line after it and prefer that.
    generic_patterns = (
        r"^headlines?$",
        r"^what landed.*",
        r"^landmark$",
    )
    is_generic = any(
        re.match(p, header_clean, re.IGNORECASE) for p in generic_patterns
    )
    if is_generic:
        in_code_fence = False
        for follow in lines[best_idx + 1 :]:
            s = follow.strip()
            if s.startswith("```"):
                in_code_fence = not in_code_fence
                continue
            if in_code_fence or not s:
                continue
            if s.startswith("#"):
                break  # next section — stop looking
            # Strip leading list / bold markers for a cleaner summary.
            stripped = re.sub(r"^[-*+]\s*", "", s)
            stripped = re.sub(r"\*\*(.+?)\*\*", r"\1", stripped)
            stripped = re.sub(r"`([^`]+)`", r"\1", stripped)
            stripped = re.sub(r"\s+", " ", stripped)
            if len(stripped) > 120:
                stripped = stripped[:117] + "..."
            return stripped

    if len(header_clean) > 120:
        header_clean = header_clean[:117] + "..."
    return header_clean


# ---------------------------------------------------------------------------
# Per-iter extraction
# ---------------------------------------------------------------------------


def parse_iter_doc(path: Path, warnings: List[str]) -> Optional[Dict[str, Any]]:
    iter_num = _iter_number_from_filename(path)
    if iter_num is None:
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        warnings.append(f"{path.name}: read error: {exc}")
        return None
    lines = text.splitlines()
    doc = path.name
    iter_col = _find_totals_iter_column(lines, iter_num)
    return {
        "iter": iter_num,
        "tests_green": _extract_tests_green(lines, iter_num, warnings, doc, iter_col),
        "pending_rows": _extract_pending_rows(
            lines, iter_num, warnings, doc, iter_col, full_text=text
        ),
        "forced_findings": _extract_forced_findings(
            lines, iter_num, warnings, doc, iter_col
        ),
        "notable": _extract_notable_event(lines, warnings, doc),
        "source": doc,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def render_markdown(rows: List[Dict[str, Any]]) -> str:
    out = []
    out.append(
        "| Iter | Tests green | Pending ledger rows | Forced findings | Notable events |"
    )
    out.append("|---:|---:|---:|---:|---|")
    if not rows:
        return "\n".join(out) + "\n"
    for r in rows:
        out.append(
            f"| {r['iter']} | {r['tests_green']} | {r['pending_rows']} | "
            f"{r['forced_findings']} | {r['notable']} |"
        )
    return "\n".join(out) + "\n"


def render_json(rows: List[Dict[str, Any]]) -> str:
    return json.dumps({"iterations": rows}, indent=2, sort_keys=True) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Generate the iter-by-iter retrospective table from "
            "docs/LOOP_ITER_NNN_RESULTS.md dossiers."
        )
    )
    ap.add_argument(
        "--results-dir",
        default="docs",
        help="Directory to scan for LOOP_ITER_*_RESULTS.md files (default: docs/)",
    )
    ap.add_argument(
        "--pattern",
        default="LOOP_ITER_*_RESULTS.md",
        help="Glob pattern to match (default: LOOP_ITER_*_RESULTS.md)",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Output file (default: stdout)",
    )
    fmt = ap.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit JSON instead of markdown")
    fmt.add_argument(
        "--md-table",
        action="store_true",
        help="Emit markdown table (default)",
    )
    args = ap.parse_args(argv)

    results_dir = Path(args.results_dir)
    if not results_dir.is_dir():
        print(
            f"[iter-retrospective] warning: results-dir does not exist: {results_dir}",
            file=sys.stderr,
        )
        matches: List[Path] = []
    else:
        matches = sorted(results_dir.glob(args.pattern))

    if not matches:
        print(
            f"[iter-retrospective] warning: no files matched "
            f"{results_dir}/{args.pattern}",
            file=sys.stderr,
        )

    warnings: List[str] = []
    rows: List[Dict[str, Any]] = []
    for p in matches:
        parsed = parse_iter_doc(p, warnings)
        if parsed is not None:
            rows.append(parsed)
    rows.sort(key=lambda r: r["iter"])

    for w in warnings:
        print(f"[iter-retrospective] {w}", file=sys.stderr)

    if args.json:
        output = render_json(rows)
    else:
        output = render_markdown(rows)

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
