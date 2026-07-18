#!/usr/bin/env python3
"""
submissions-tracker.py — Safely manage a draft tracker section in SUBMISSIONS.md

Scans submissions/staging/ for draft files and maintains a managed draft-tracker
table when the workspace opts in. It can:
  - Detect new drafts not yet tracked
  - Remove draft rows for deleted files
  - Create a minimal managed tracker file when none exists

It deliberately does NOT rewrite richly curated submission ledgers by default.
If a workspace uses a hand-maintained or narrative SUBMISSIONS.md, this tool
will report that the tracker is manual and leave it untouched.

Usage:
    submissions-tracker.py <workspace> [--sync] [--dry-run]
    submissions-tracker.py ~/audits/<project> --sync
    submissions-tracker.py ~/audits/<project> --dry-run   # preview changes

Exit codes:
    0 — success (up to date, changed, or intentionally skipped)
    1 — hard failure
"""

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from submission_counts import summarize_workspace

MANAGED_START = "<!-- AUDITOOOR_TRACKER_MANAGED_START -->"
MANAGED_END = "<!-- AUDITOOOR_TRACKER_MANAGED_END -->"


def _default_managed_tracker_header(workspace_name: str) -> str:
    return (
        f"# {workspace_name} — Submissions\n\n"
        "This tracker contains an auditooor-managed draft table sourced from\n"
        "`submissions/staging/`. Curated submitted-history sections may be added\n"
        "outside the managed block.\n\n"
        f"{MANAGED_START}\n"
        "| Cantina # | Date | Severity | Status | Title |\n"
        "|---:|---|---|---|---|\n"
        f"{MANAGED_END}\n"
    )


def _split_managed_block(text: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if MANAGED_START not in text or MANAGED_END not in text:
        return None, None, None
    start = text.index(MANAGED_START)
    end = text.index(MANAGED_END) + len(MANAGED_END)
    return text[:start], text[start:end], text[end:]


def extract_title_from_draft(filepath: Path) -> Optional[str]:
    """Extract title from draft markdown file. Skip investigation notes."""
    try:
        text = filepath.read_text()
        # Skip investigation notes (agent outputs marked as investigated/FP)
        first_lines = "\n".join(text.splitlines()[:10])
        if re.search(r'INVESTIGATED|FALSE\s+POSITIVE|not\s+a\s+bug|not\s+exploitable', first_lines, re.I):
            return None
        for line in text.splitlines()[:20]:
            if line.startswith("# "):
                title = line.lstrip("# ").strip()
                # Skip titles that are clearly investigation notes
                if re.search(r'^R\d+-[A-Z]', title) and "INVESTIGATED" in title:
                    return None
                return title
    except Exception:
        pass
    return None


def extract_severity_from_draft(filepath: Path) -> str:
    """Extract severity from draft."""
    try:
        text = filepath.read_text()
        for line in text.splitlines()[:30]:
            if "severity" in line.lower():
                m = re.search(r'(Critical|High|Medium|Low|Info)', line, re.I)
                if m:
                    return m.group(1).capitalize()
    except Exception:
        pass
    return "Medium"


def parse_submissions_table(text: str) -> List[Dict]:
    """Parse the first tracker table block into entries."""
    lines = text.splitlines()

    table_start = -1
    table_end = -1
    for i, line in enumerate(lines):
        if line.startswith("|") and "Status" in line:
            table_start = i
        elif table_start >= 0 and not line.startswith("|") and line.strip():
            table_end = i
            break

    if table_start == -1:
        return []
    if table_end == -1:
        table_end = len(lines)

    entries = []
    for line in lines[table_start:table_end]:
        if line.startswith("|") and "---" not in line and "Cantina #" not in line:
            cells = [c.strip() for c in line.split("|")]
            while cells and not cells[0]:
                cells.pop(0)
            while cells and not cells[-1]:
                cells.pop()
            if len(cells) >= 5:
                entries.append({
                    "cantina_num": cells[0],
                    "date": cells[1],
                    "severity": cells[2],
                    "status": cells[3],
                    "title": cells[4],
                    "raw": line,
                })

    return entries


def find_staging_drafts(ws: Path) -> List[Path]:
    """Find all draft files in submissions/staging/. Skip investigation notes."""
    staging = ws / "submissions" / "staging"
    if not staging.exists():
        return []
    drafts = []
    for f in staging.glob("*.md"):
        if f.name.endswith(".block.md"):
            continue
        # Skip investigation notes (R83-A, R84-F, etc.)
        if re.match(r'R\d+-[A-Z]', f.stem):
            continue
        drafts.append(f)
    return sorted(drafts)


def build_table(entries: List[Dict]) -> str:
    """Build markdown table from entries."""
    lines = [
        "| Cantina # | Date | Severity | Status | Title |",
        "|---:|---|---|---|---|",
    ]
    for e in entries:
        lines.append(f"| {e['cantina_num']} | {e['date']} | {e['severity']} | {e['status']} | {e['title']} |")
    return "\n".join(lines)


def _is_manual_tracker(text: str, ws: Path) -> bool:
    if MANAGED_START in text and MANAGED_END in text:
        return False
    summary = summarize_workspace(ws)
    if summary["submitted"] > 0:
        return True
    # Narrative tracker sections or multiple headings generally indicate a hand-maintained file.
    headings = len(re.findall(r"^##+\s", text, flags=re.MULTILINE))
    return headings > 1


def sync_submissions(ws: Path, dry_run: bool = False) -> bool:
    """Sync a managed draft section with staging directory. Returns True if changes made."""
    sub_file = ws / "submissions" / "SUBMISSIONS.md"

    if sub_file.exists():
        text = sub_file.read_text()
        if _is_manual_tracker(text, ws):
            print("[tracker] Manual or curated SUBMISSIONS.md detected — no changes applied")
            print(f"[tracker] To use the auto-tracker, add a managed block with {MANAGED_START} / {MANAGED_END}")
            return False
        if MANAGED_START in text and MANAGED_END in text:
            before, managed_block, after = _split_managed_block(text)
            assert before is not None and managed_block is not None and after is not None
            managed_entries = parse_submissions_table(managed_block)
        else:
            before = ""
            after = ""
            managed_entries = []
    else:
        text = _default_managed_tracker_header(ws.name)
        before, managed_block, after = _split_managed_block(text)
        assert before is not None and managed_block is not None and after is not None
        managed_entries = []

    # Find current drafts
    drafts = find_staging_drafts(ws)

    # Build lookup by title
    existing_by_title = {}
    for e in managed_entries:
        existing_by_title[e["title"]] = e

    changes = []

    # Add new drafts
    for draft in drafts:
        title = extract_title_from_draft(draft)
        if not title:
            title = draft.stem

        if title not in existing_by_title:
            severity = extract_severity_from_draft(draft)
            new_entry = {
                "cantina_num": "—",
                "date": "TBD",
                "severity": severity,
                "status": "Draft",
                "title": title,
                "raw": "",
            }
            managed_entries.append(new_entry)
            changes.append(f"+ ADD: {title}")

    # Remove entries for deleted drafts (only if status is Draft)
    draft_titles = set()
    for draft in drafts:
        title = extract_title_from_draft(draft)
        if title:
            draft_titles.add(title)
        else:
            draft_titles.add(draft.stem)

    for e in managed_entries[:]:
        if e["status"] == "Draft" and e["title"] not in draft_titles:
            managed_entries.remove(e)
            changes.append(f"- REMOVE: {e['title']}")

    if not changes:
        print("[tracker] SUBMISSIONS.md is up to date")
        return False

    print(f"[tracker] Changes detected ({len(changes)}):")
    for c in changes:
        print(f"  {c}")

    if dry_run:
        print("[tracker] Dry-run — no changes written")
        return True

    table = build_table(managed_entries)
    new_text = before + MANAGED_START + "\n" + table + "\n" + MANAGED_END + after
    sub_file.write_text(new_text)
    print(f"[tracker] Updated: {sub_file}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Manage only the auditooor-managed draft block inside nested "
            "submissions/SUBMISSIONS.md trackers. Curated nested ledgers and "
            "root-level manual ledgers are skipped safely."
        )
    )
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("--sync", action="store_true", help="Apply updates to the managed nested tracker block")
    parser.add_argument("--dry-run", action="store_true", help="Preview managed-block updates without writing")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.exists():
        print(f"[tracker] Workspace not found: {ws}")
        sys.exit(1)

    sync_submissions(ws, dry_run=(args.dry_run or not args.sync))
    sys.exit(0)


if __name__ == "__main__":
    main()
