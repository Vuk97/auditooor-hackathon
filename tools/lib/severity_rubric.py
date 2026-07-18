#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""tools/lib/severity_rubric.py - single source of truth for SEVERITY.md
discovery + tier-row parsing.

r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[].

# G13: this module emits no corpus record.

Factored out (G13, 2026-05-28) so BOTH
``tools/rubric-row-coverage-check.py`` (R52) and
``tools/dispatch-agent-with-prebriefing.py`` (G13.1 full-rubric injection)
share ONE implementation of:

  - ``find_severity_md(workspace)`` -> Path | None
  - ``parse_tier_rows(text)``       -> list[TierRow]

``parse_tier_rows`` is format-tolerant: it recognises the three live
SEVERITY.md shapes observed across the workspaces -

  1. dydx  : ``### Critical - **USD 150,000 to 1,000,000**`` then bullets.
  2. spark : ``### Critical (Blockchain/DLT)`` then a markdown table whose
             rows are ``| CRIT-1 | Direct loss of funds | USD ... |``,
             plus inline ``- Direct loss of funds`` bullets.
  3. hyperbridge : ``## Critical`` then a ``Reward: 30,000 USD to 50,000 USD.``
             line then a descriptive paragraph.

Each returned TierRow carries:
  tier      - canonical lowercase tier name (critical/high/medium/low)
  rubric_id - explicit ID if present (e.g. CRIT-1, HIGH-1) else ""
  sentence  - the verbatim listed-impact sentence (best-effort first line)
  payout    - the payout / reward text if discoverable else ""

The parser is intentionally permissive: a workspace with a non-standard
rubric still yields one TierRow per recognised tier heading so the
full-tier directive can enumerate every fileable tier.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


SEVERITY_FILE_NAMES = ("SEVERITY.md", "severity.md", "Severity.md")

# Canonical tier ordering (low -> critical). Used by callers to sort.
TIER_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Heading line that names a severity tier. Captures the tier word and any
# trailing payout-ish text on the same heading line (dydx em-dash form).
_TIER_HEADING_RE = re.compile(
    r"(?im)^\s{0,3}#{2,6}\s*(Critical|High|Medium|Low)\b\s*(.*)$"
)

# A payout / reward line that follows a heading (hyperbridge form).
_REWARD_LINE_RE = re.compile(
    r"(?im)^\s*(?:\*\*)?Reward(?:\*\*)?\s*[:\-]\s*(.+?)\s*$"
)

# Payout fragment embedded in a heading or table row (USD ranges, $ figures).
_PAYOUT_FRAGMENT_RE = re.compile(
    r"(USD\s*[\d,]+(?:\s*(?:to|-|–|—)\s*[\d,]+)?"
    r"|\$\s*[\d,]+(?:\s*(?:to|-|–|—)\s*\$?\s*[\d,]+)?"
    r"|[\d,]+\s*USD(?:\s*(?:to|-|–|—)\s*[\d,]+\s*USD)?)",
    re.IGNORECASE,
)

# Explicit rubric ID token (CRIT-1, HIGH-1, MED-2, LOW-3, C1, H2 ...).
_RUBRIC_ID_RE = re.compile(
    r"\b((?:CRIT|HIGH|MED|MEDIUM|LOW|C|H|M|L)-?\d+)\b"
)


@dataclass
class TierRow:
    tier: str           # canonical lowercase tier name
    rubric_id: str      # explicit ID if present else ""
    sentence: str       # verbatim listed-impact sentence (best-effort)
    payout: str         # payout / reward text if discoverable else ""

    def as_dict(self) -> dict:
        return {
            "tier": self.tier,
            "rubric_id": self.rubric_id,
            "sentence": self.sentence,
            "payout": self.payout,
        }


def find_severity_md(workspace: Optional[Path]) -> Optional[Path]:
    """Return the workspace SEVERITY.md Path, or None.

    Mirrors ``rubric-row-coverage-check.py:_find_severity_md`` but takes
    only the workspace root (the dispatch caller has no draft to walk up
    from). Honours the ``AUDITOOOR_R52_SEVERITY_MD_PATH`` env override used
    by the R52 gate so both callers agree.
    """
    import os

    override = os.environ.get("AUDITOOOR_R52_SEVERITY_MD_PATH", "").strip()
    if override:
        p = Path(override)
        if p.is_file():
            return p

    if workspace is None:
        return None
    root = Path(workspace).resolve()

    # Direct hit at workspace root.
    for name in SEVERITY_FILE_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate

    # Walk up from the workspace root (cheap; handles nested workspaces).
    for parent in [root, *root.parents]:
        for name in SEVERITY_FILE_NAMES:
            candidate = parent / name
            if candidate.is_file():
                return candidate
    return None


def _clean_sentence(raw: str) -> str:
    s = raw.strip()
    # Strip leading list markers / table pipes / bold.
    s = re.sub(r"^[\s|*\-]+", "", s)
    s = re.sub(r"[\s|*]+$", "", s)
    # Collapse whitespace.
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _extract_payout(text: str) -> str:
    m = _PAYOUT_FRAGMENT_RE.search(text)
    if m:
        return _clean_sentence(m.group(1))
    return ""


def _section_text(full_text: str, start: int) -> str:
    """Return the text from ``start`` up to the next heading (any level
    that introduces a new section), or end of file."""
    rest = full_text[start:]
    nxt = re.search(r"(?m)^\s{0,3}#{2,6}\s", rest)
    if nxt:
        return rest[: nxt.start()]
    return rest


def parse_tier_rows(text: str) -> List[TierRow]:
    """Parse all severity tier rows from a SEVERITY.md body.

    Format-tolerant across the dydx / spark / hyperbridge shapes. Returns
    one or more TierRow per recognised tier. A tier heading always yields
    at least one TierRow even when no sentence/payout can be extracted, so
    the full-tier directive can enumerate every fileable tier.
    """
    rows: List[TierRow] = []
    seen_keys: set = set()

    for m in _TIER_HEADING_RE.finditer(text):
        tier = m.group(1).strip().lower()
        heading_tail = (m.group(2) or "").strip()
        section = _section_text(text, m.end())

        # Payout: prefer a payout fragment inline in the heading (dydx),
        # else a "Reward:" line in the section (hyperbridge), else any
        # payout fragment in the section.
        payout = _extract_payout(heading_tail)
        if not payout:
            rm = _REWARD_LINE_RE.search(section)
            if rm:
                payout = _clean_sentence(rm.group(1))
        if not payout:
            payout = _extract_payout(section)

        # Sentence candidates inside the section:
        #  (a) markdown table rows | ID | sentence | reward | (spark)
        #  (b) bullet lines "- Direct loss of funds" (dydx / spark)
        #  (c) first non-empty descriptive paragraph (hyperbridge)
        sentence_rows: List[TierRow] = []

        # (a) table rows
        for tr in re.finditer(r"(?m)^\s*\|(.+)\|\s*$", section):
            cells = [c.strip() for c in tr.group(1).split("|")]
            cells = [c for c in cells if c != ""]
            if not cells:
                continue
            # Skip table header / separator rows.
            joined = " ".join(cells).lower()
            if set(joined) <= set("-| :") or "listed-impact" in joined or (
                "id" in cells[0].lower() and "reward" in joined
            ):
                continue
            rid = ""
            sent = ""
            row_payout = payout
            idm = _RUBRIC_ID_RE.search(cells[0])
            if idm and len(cells) >= 2:
                rid = idm.group(1)
                sent = _clean_sentence(cells[1])
                if len(cells) >= 3:
                    rp = _extract_payout(cells[2]) or _clean_sentence(cells[2])
                    if rp:
                        row_payout = rp
            else:
                # No ID column; treat first cell as the sentence.
                sent = _clean_sentence(cells[0])
            if sent and len(sent) > 3 and not _PAYOUT_FRAGMENT_RE.fullmatch(sent):
                sentence_rows.append(TierRow(tier, rid, sent, row_payout))

        # (b) bullet lines (only if no table rows captured for this tier).
        if not sentence_rows:
            for bm in re.finditer(r"(?m)^\s*[-*]\s+(.+?)\s*$", section):
                sent = _clean_sentence(bm.group(1))
                # Skip bullets that are pure payout/meta lines.
                if not sent or len(sent) <= 3:
                    continue
                low = sent.lower()
                if low.startswith(("floor", "extraordinary", "reward", "source")):
                    continue
                rid = ""
                idm = _RUBRIC_ID_RE.search(sent)
                if idm:
                    rid = idm.group(1)
                sentence_rows.append(TierRow(tier, rid, sent, payout))

        # (c) fallback: first descriptive paragraph.
        if not sentence_rows:
            for line in section.splitlines():
                cand = _clean_sentence(line)
                if not cand or len(cand) < 8:
                    continue
                low = cand.lower()
                if low.startswith(("reward", "source", "|", "id ")):
                    continue
                if _PAYOUT_FRAGMENT_RE.fullmatch(cand):
                    continue
                sentence_rows.append(TierRow(tier, "", cand, payout))
                break

        # Guarantee at least one row per tier heading.
        if not sentence_rows:
            sentence_rows.append(TierRow(tier, "", "", payout))

        for row in sentence_rows:
            key = (row.tier, row.rubric_id, row.sentence[:120])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            rows.append(row)

    # 4th format: Immunefi-standard "tier-in-first-column" table. Rows shaped
    # ``| Critical | Direct theft of any user funds ... |`` live under CATEGORY
    # headings (## Smart Contract / ## Blockchain), not tier-named headings, so the
    # tier-heading loop above misses them entirely (0 rows -> R52 unsatisfiable for
    # every finding). Scan every table row whose FIRST cell is a bare tier name.
    for tr in re.finditer(r"(?m)^\s*\|(.+)\|\s*$", text):
        cells = [c.strip() for c in tr.group(1).split("|")]
        cells = [c for c in cells if c != ""]
        if len(cells) < 2:
            continue
        tname = cells[0].strip().lower()
        if tname not in TIER_ORDER:  # col-1 must be exactly Critical/High/Medium/Low
            continue
        sent = _clean_sentence(cells[1])
        if not sent or len(sent) <= 3 or _PAYOUT_FRAGMENT_RE.fullmatch(sent):
            continue
        rid = ""
        idm = _RUBRIC_ID_RE.search(" ".join(cells[1:]))
        if idm:
            rid = idm.group(1)
        row_payout = _extract_payout(" ".join(cells[2:])) if len(cells) >= 3 else ""
        key = (tname, rid, sent[:120])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        rows.append(TierRow(tname, rid, sent, row_payout))

    return rows


def tier_set(rows: List[TierRow]) -> set:
    """Return the set of canonical tier names present in the rows."""
    return {r.tier for r in rows if r.tier}


if __name__ == "__main__":  # pragma: no cover - manual smoke
    import json
    import sys

    if len(sys.argv) < 2:
        print("usage: severity_rubric.py <workspace-or-SEVERITY.md>", file=sys.stderr)
        sys.exit(2)
    arg = Path(sys.argv[1])
    sev = arg if arg.is_file() else find_severity_md(arg)
    if sev is None:
        print(json.dumps({"error": "no SEVERITY.md", "arg": str(arg)}))
        sys.exit(1)
    rows = parse_tier_rows(sev.read_text(encoding="utf-8", errors="replace"))
    print(json.dumps(
        {"severity_md": str(sev), "tiers": sorted(tier_set(rows)),
         "rows": [r.as_dict() for r in rows]},
        indent=2,
    ))
