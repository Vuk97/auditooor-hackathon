#!/usr/bin/env python3
"""
engagement-retro.py — Automated engagement retrospective

Reads a workspace's submission tracking, extracts outcomes (paid/dupe/rejected),
and auto-updates the knowledge base:
  - docs/archive/LESSONS_LEARNED.md        — new rejection/acceptance lessons
  - reference/triager_patterns.md  — new rejection patterns for pre-submit check
  - workspace-state.json           — bumps findings/submissions counts

Usage:
    engagement-retro.py <workspace-dir> [--dry-run]
    engagement-retro.py ~/audits/polymarket
    engagement-retro.py ~/audits/polymarket --dry-run   # preview only

Exit codes:
    0 — retro completed, knowledge base updated
    1 — workspace not found or no submissions to process
"""

import argparse
import hashlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _stable_pattern_id(title: str) -> str:
    """Return a deterministic 4-digit pattern id derived from ``title``.

    Earlier versions used ``hash(title) % 10000``; Python's builtin ``hash``
    is randomised per-process (PEP 456 / SipHash) unless ``PYTHONHASHSEED`` is
    pinned, so the same title produced a different id on every run and the
    retro tool silently appended duplicates of the same conceptual pattern.
    sha1 is used purely as a fast deterministic digest (not for security) and
    truncated to 4 hex chars so the existing ``auto-XXXX`` shape is preserved.
    """
    digest = hashlib.sha1(title.encode("utf-8")).hexdigest()
    return f"auto-{digest[:4]}"

AUDITOOOR_DIR = Path(__file__).parent.parent
LESSONS_FILE = AUDITOOOR_DIR / "docs" / "LESSONS_LEARNED.md"
PATTERNS_FILE = AUDITOOOR_DIR / "reference" / "triager_patterns.md"
STATE_TOOL = AUDITOOOR_DIR / "tools" / "workspace-state.py"


def parse_submissions_table(text: str) -> List[Dict[str, Any]]:
    """Parse a markdown table from SUBMISSIONS.md.

    This is the original Polymarket layout: a markdown table with a
    standalone ``Status`` column and a ``Title`` column.
    """
    findings = []
    # Look for a table with Status column
    lines = text.splitlines()
    in_table = False
    headers = []
    for line in lines:
        # Header detection: must be a table row with a standalone 'Status' column
        if line.startswith("|") and re.search(r'\|\s*Status\s*\|', line):
            headers = [h.strip().lower() for h in line.split("|") if h.strip()]
            in_table = True
            continue
        if in_table and line.startswith("|") and "---" not in line:
            cells = [c.strip() for c in line.split("|")]
            # Strip leading/trailing empty cells from markdown table split
            while cells and not cells[0]:
                cells.pop(0)
            while cells and not cells[-1]:
                cells.pop()
            # Pad cells to match headers
            while len(cells) < len(headers):
                cells.append("")
            row = dict(zip(headers, cells))
            if row.get("status") and row.get("title"):
                findings.append(row)
        elif in_table and not line.startswith("|"):
            in_table = False
    return findings


def parse_submissions_line_item(text: str) -> List[Dict[str, Any]]:
    """Parse the Centrifuge-style ``S-001 / #<id>`` line-item layout.

    Each finding is a section opened by ``## S-NNN — title`` or
    ``## #NNN — title`` and contains bullet pairs of the form::

        - **Status**
          SUBMITTED
        - **Outcome**
          PENDING

    The parser collects ``status``, ``outcome``, ``severity`` and ``title``
    per section. ``status`` is normalised to whichever of ``Status`` or
    ``Outcome`` better describes the triage state — i.e. when ``Outcome``
    is set to a non-pending value (e.g. ``PAID``, ``REJECTED``, ``DUPE``)
    we promote it into the ``status`` field so :func:`extract_outcome_class`
    can read a single string. This mirrors the operator's mental model:
    "Outcome trumps Status once triaged."
    """
    findings: List[Dict[str, Any]] = []
    # Section header: "## S-NNN — title" or "## #NNN — title"
    section_re = re.compile(r"^##\s+(?:S-\d+|#\d+)\s+—\s+(.+?)\s*$")
    bullet_key_re = re.compile(r"^-\s+\*\*([A-Za-z][A-Za-z _]*)\*\*\s*$")
    lines = text.splitlines()
    i = 0
    n = len(lines)
    current: Optional[Dict[str, str]] = None
    while i < n:
        line = lines[i]
        m = section_re.match(line)
        if m:
            if current and current.get("title"):
                _promote_outcome_to_status(current)
                findings.append(current)
            current = {"title": m.group(1).strip()}
            i += 1
            continue
        if current is not None:
            mb = bullet_key_re.match(line)
            if mb:
                key = mb.group(1).strip().lower()
                # Value is on the indented line that follows.
                if i + 1 < n:
                    val = lines[i + 1].strip()
                    if val:
                        current[key] = val
                        i += 2
                        continue
        i += 1
    if current and current.get("title"):
        _promote_outcome_to_status(current)
        findings.append(current)
    # Only keep entries that actually carry a status — avoids matching
    # the bullet legend at the top of the file.
    return [f for f in findings if f.get("status")]


def _promote_outcome_to_status(row: Dict[str, str]) -> None:
    """If the ``outcome`` cell is more informative than ``status``, copy
    it onto ``status`` so :func:`extract_outcome_class` can classify the
    finding. ``PENDING`` outcomes do not override (they are weaker than
    e.g. ``SUBMITTED`` status).
    """
    outcome = (row.get("outcome") or "").strip().lower()
    if not outcome:
        return
    if outcome == "pending":
        return
    if extract_outcome_class(outcome) in ("PAID", "DUPE", "REJECTED"):
        row["status"] = row["outcome"]


def parse_submissions_section_header(text: str) -> List[Dict[str, Any]]:
    """Parse the Morpho ``# 🚀 Submission N — title — severity`` layout.

    Each section opens with a ``# Submission N`` header (optionally
    decorated with the rocket emoji) and is followed by a ``**Status:**``
    line. Severity is parsed out of the header.
    """
    findings: List[Dict[str, Any]] = []
    # Header e.g. "# 🚀 Submission 1 — #I2.B — Medium"
    section_re = re.compile(
        r"^#\s+(?:[^\w\s]+\s+)?Submission\s+\d+\s+—\s+(?P<title>.+?)\s+—\s+(?P<sev>Critical|High|Medium|Low|Info)\s*$",
        re.IGNORECASE,
    )
    status_re = re.compile(r"^\*\*Status:\*\*\s*(?P<val>.+?)\s*$")
    lines = text.splitlines()
    i = 0
    n = len(lines)
    current: Optional[Dict[str, str]] = None
    while i < n:
        line = lines[i]
        m = section_re.match(line)
        if m:
            if current and current.get("status"):
                findings.append(current)
            current = {
                "title": m.group("title").strip(),
                "severity": m.group("sev").strip(),
            }
            i += 1
            continue
        if current is not None and "status" not in current:
            ms = status_re.match(line)
            if ms:
                current["status"] = ms.group("val").strip()
        i += 1
    if current and current.get("status"):
        findings.append(current)
    return findings


def parse_submissions(text: str) -> Tuple[List[Dict[str, Any]], str]:
    """Try every known layout and return the first one that produces a
    non-empty result, alongside the layout name. Layouts tried (in order):

      1. ``table``               — Polymarket markdown table
      2. ``line_item``           — Centrifuge ``S-NNN`` / ``#NNN`` bullets
      3. ``section_header``      — Morpho ``# Submission N`` headers

    Returns ``([], "none")`` when nothing matches.
    """
    rows = parse_submissions_table(text)
    if rows:
        return rows, "table"
    rows = parse_submissions_line_item(text)
    if rows:
        return rows, "line_item"
    rows = parse_submissions_section_header(text)
    if rows:
        return rows, "section_header"
    return [], "none"


def extract_outcome_class(status: str) -> str:
    """Normalize status string to outcome class."""
    s = status.lower()
    if "paid" in s or "accept" in s or "confirmed" in s:
        return "PAID"
    if "dupe" in s or "duplicate" in s:
        return "DUPE"
    if "reject" in s or "invalid" in s or "oos" in s:
        return "REJECTED"
    if "pending" in s or "in review" in s or "review" in s:
        return "PENDING"
    return "UNKNOWN"


def extract_severity(status_cell: str, title: str) -> str:
    """Try to infer severity from the row."""
    # Often severity is in its own column
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev.lower() in status_cell.lower() or sev.lower() in title.lower():
            return sev
    return "Unknown"


def generate_lesson(finding: Dict) -> Optional[str]:
    """Generate a markdown lesson entry from a finding row."""
    outcome = extract_outcome_class(finding.get("status", ""))
    title = finding.get("title", "")
    severity = finding.get("severity", extract_severity(finding.get("status", ""), title))
    # Build a concise lesson
    if outcome == "REJECTED":
        return f"""### Auto-extracted: {title[:60]}
**Outcome:** Rejected  
**Severity claimed:** {severity}  
**Rule:** Submission was rejected. Review rejection reason and add to triager_patterns.md.
"""
    elif outcome == "PAID":
        return f"""### Auto-extracted: {title[:60]}
**Outcome:** Paid  
**Severity:** {severity}  
**Rule:** This pattern was accepted. Consider filing similar patterns in future engagements.
"""
    elif outcome == "DUPE":
        return f"""### Auto-extracted: {title[:60]}
**Outcome:** Duplicate  
**Severity claimed:** {severity}  
**Rule:** This pattern was marked duplicate. Check if a stronger vector or different contract surface exists.
"""
    return None


def generate_triager_pattern(finding: Dict) -> Optional[Dict]:
    """Generate a triager pattern entry from a rejected finding."""
    outcome = extract_outcome_class(finding.get("status", ""))
    if outcome != "REJECTED":
        return None
    title = finding.get("title", "").lower()
    # Heuristic: classify rejection type from title
    if "event" in title or "emit" in title or "topic" in title:
        return {
            "id": _stable_pattern_id(title),
            "name": "Event-only finding",
            "keywords": ["event", "emit", "topic", "indexed"],
            "severity": "block",
            "reason": "Event-only findings are rejected unless they cause downstream functional failure.",
            "lesson_ref": "LESSONS #1",
        }
    if any(x in title for x in ["overflow", "uint", "2^", "max"]):
        return {
            "id": _stable_pattern_id(title),
            "name": "Extreme value theoretical",
            "keywords": ["overflow", "uint248", "uint256", "2^", "type(uint"],
            "severity": "block",
            "reason": "Extreme value triggers without realistic supply path are rejected.",
            "lesson_ref": "LESSONS #2",
        }
    if "reentrancy" in title or "callback" in title or "ghost" in title:
        return {
            "id": _stable_pattern_id(title),
            "name": "Reentrancy without value extraction",
            "keywords": ["reentrancy", "callback", "ghost"],
            "severity": "warn",
            "reason": "Reentrancy findings are weak without concrete value extraction in one tx.",
            "lesson_ref": "LESSONS #2-acceptance",
        }
    return {
        "id": _stable_pattern_id(title),
        "name": f"Rejected: {title[:40]}",
        "keywords": [],
        "severity": "warn",
        "reason": "Finding was rejected — review triager feedback for specific reason.",
        "lesson_ref": "",
    }


def append_lessons(new_entries: List[str], dry_run: bool = False) -> None:
    """Append new lesson entries to LESSONS_LEARNED.md."""
    if not new_entries:
        return
    if dry_run:
        print("[retro] Would append to LESSONS_LEARNED.md:")
        for e in new_entries:
            print(e[:200] + "...")
        return

    if not LESSONS_FILE.exists():
        LESSONS_FILE.write_text("# Lessons Learned — Auditooor Engagement History\n\n")

    content = LESSONS_FILE.read_text()
    # Insert before "## Meta-Lessons" or append at end
    insert_marker = "## Meta-Lessons"
    block = "\n## Auto-Extracted Lessons (" + datetime.now(timezone.utc).strftime("%Y-%m-%d") + ")\n\n"
    block += "\n\n".join(new_entries)
    block += "\n\n"

    if insert_marker in content:
        content = content.replace(insert_marker, block + insert_marker)
    else:
        content += "\n" + block

    LESSONS_FILE.write_text(content)
    print(f"[retro] Appended {len(new_entries)} lesson(s) to {LESSONS_FILE}")


def append_triager_patterns(patterns: List[Dict], dry_run: bool = False) -> None:
    """Append new patterns to triager_patterns.md."""
    if not patterns:
        return
    if dry_run:
        print(f"[retro] Would append {len(patterns)} pattern(s) to triager_patterns.md")
        return

    if not PATTERNS_FILE.exists():
        PATTERNS_FILE.write_text("# Triager Rejection / Warning Patterns\n\n")

    lines = PATTERNS_FILE.read_text().splitlines()
    new_lines = []
    for p in patterns:
        new_lines.append(f"\n## {p['id']}: {p['name']} ({p['severity'].upper()})")
        new_lines.append(f"- **Keywords:** {', '.join(p['keywords']) if p['keywords'] else 'N/A'}")
        new_lines.append(f"- **Reason:** {p['reason']}")
        if p.get("lesson_ref"):
            new_lines.append(f"- **Lesson ref:** {p['lesson_ref']}")
        new_lines.append("")

    PATTERNS_FILE.write_text("\n".join(lines + new_lines))
    print(f"[retro] Appended {len(patterns)} pattern(s) to {PATTERNS_FILE}")


def bump_workspace_state(ws: str, findings: int, submissions: int, dry_run: bool = False) -> None:
    """Bump workspace state counters.

    Runs ``workspace-state.py bump`` via ``subprocess.run`` with an argument
    list (no shell), so paths with spaces or shell metacharacters are passed
    safely and a non-zero exit no longer fails silently. Earlier versions
    used ``os.system(... >/dev/null 2>&1)`` which both swallowed errors and
    interpolated ``ws`` into a shell string without escaping.
    """
    if dry_run:
        print(f"[retro] Would bump workspace-state: +{findings} findings, +{submissions} submissions")
        return
    if not STATE_TOOL.exists():
        return
    cmd = [
        sys.executable,
        str(STATE_TOOL),
        "bump",
        ws,
        "--findings",
        str(findings),
        "--submissions",
        str(submissions),
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        print(
            f"[retro] workspace-state bump failed (exit {e.returncode}): "
            f"{(e.stderr or e.stdout or '').strip()}",
            file=sys.stderr,
        )
        raise
    print(f"[retro] Bumped workspace-state: +{findings} findings, +{submissions} submissions")


def main() -> None:
    parser = argparse.ArgumentParser(description="Engagement retrospective automation")
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[retro] Error: workspace not found: {ws}")
        sys.exit(1)

    # Find submissions tracking file
    sub_file = ws / "SUBMISSIONS.md"
    if not sub_file.exists():
        sub_file = ws / "submissions" / "SUBMISSIONS.md"
    if not sub_file.exists():
        # Try to infer from individual submission files
        sub_files = list((ws / "submissions").glob("*.md")) if (ws / "submissions").exists() else []
        if not sub_files:
            print(f"[retro] No SUBMISSIONS.md or submission files found in {ws}")
            sys.exit(1)
        print(f"[retro] No SUBMISSIONS.md — found {len(sub_files)} individual submission files")
        print(f"[retro] Hint: create a SUBMISSIONS.md tracking table for full retro automation")
        sys.exit(0)

    text = sub_file.read_text()
    findings, layout = parse_submissions(text)
    if not findings:
        print(f"[retro] No findings parsed from {sub_file}")
        sys.exit(1)

    print(f"[retro] Parsed {len(findings)} finding(s) from {sub_file} (layout={layout})")

    # Categorize
    paid = [f for f in findings if extract_outcome_class(f.get("status", "")) == "PAID"]
    dupes = [f for f in findings if extract_outcome_class(f.get("status", "")) == "DUPE"]
    rejected = [f for f in findings if extract_outcome_class(f.get("status", "")) == "REJECTED"]
    pending = [f for f in findings if extract_outcome_class(f.get("status", "")) == "PENDING"]

    print(f"  Paid: {len(paid)} | Dupe: {len(dupes)} | Rejected: {len(rejected)} | Pending: {len(pending)}")

    # Generate lessons
    lessons = []
    for f in rejected:
        lesson = generate_lesson(f)
        if lesson:
            lessons.append(lesson)
    for f in paid:
        lesson = generate_lesson(f)
        if lesson:
            lessons.append(lesson)

    # Generate triager patterns from rejections
    patterns = []
    for f in rejected:
        pat = generate_triager_pattern(f)
        if pat:
            patterns.append(pat)

    # Apply updates
    append_lessons(lessons, args.dry_run)
    append_triager_patterns(patterns, args.dry_run)
    bump_workspace_state(str(ws), len(findings), len(findings), args.dry_run)

    print("[retro] Done.")


if __name__ == "__main__":
    main()
