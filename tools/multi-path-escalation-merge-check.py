#!/usr/bin/env python3
"""Rule 28 Multi-path escalation merge preflight check.

# Rule 28: this tool emits no corpus record.

When >=2 in-flight harness / escalation paths target the same filed Cantina
submission ID, DO NOT paste any single one into Cantina. Wait for ALL paths to
land, MERGE into a single unified triager response, paste once.

Trigger: HIGH+ drafts that reference a filed Cantina submission ID (e.g. #192,
cantina-192, cantina/#192, submission #192) where TWO OR MORE drafts targeting
the same submission ID exist across submissions/staging/, submissions/paste_ready/,
submissions/held/, submissions/superseded/ in the workspace.

Exit codes:
  0 - pass (out-of-scope, no cantina ID, single path, merged, or ok-rebuttal)
  1 - Rule 28 violation (multiple unmerged in-flight paths)
  2 - input error

Schema: auditooor.r28_multi_path_escalation_merge.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r28_multi_path_escalation_merge.v1"
GATE = "R28-MULTI-PATH-ESCALATION-MERGE"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Status directories to scan for sibling drafts.
_DEFAULT_STATUS_DIRS = [
    "submissions/staging",
    "submissions/paste_ready",
    "submissions/held",
    "submissions/superseded",
    "submissions/ready",
    "submissions/filed",
]

# Patterns that recognise a Cantina submission ID citation inside a draft.
# Matches: #192, cantina-192, cantina/#192, cantina/192, Submission #192,
#          cantina submission 192, cantina id 192 (case-insensitive).
_CANTINA_ID_RE = re.compile(
    r"""
    (?:
        (?:cantina[-/\s](?:submission\s*)?(?:[#]?)(\d{2,5}))  # cantina-NNN / cantina/#NNN / cantina/NNN
      | (?:submission\s*[#](\d{2,5}))                          # submission #NNN
      | (?:cantina\s+id\s*[#]?(\d{2,5}))                      # cantina id NNN
      | (?:^|\s|[/(])#(\d{2,5})(?:\s|[,;)\]]|$)               # bare #NNN (with word boundary guards)
    )
    """,
    re.VERBOSE | re.IGNORECASE | re.MULTILINE,
)

# Signals that a draft is a MERGED / unified response (passes the rule).
_MERGED_SIGNAL_RE = re.compile(
    r"merged.{0,60}(?:unified|response|triager|path)|"
    r"unified.{0,60}(?:response|triager|merge)|"
    r"(?:all paths? merged|single unified response|merged from \w+ paths?)",
    re.IGNORECASE,
)

# Rebuttal pattern.
_REBUTTAL_RE = re.compile(
    r"(?:<!-{2,}\s*r28-rebuttal\s*:\s*(?P<reason>[^\-]{1,200}?)\s*-{2,}>|"
    r"r28-rebuttal\s*:\s*(?P<reason2>[^\n]{1,200}))",
    re.IGNORECASE,
)


def _severity_rank(text: str) -> int:
    return SEVERITY_RANK.get(text.strip().lower(), 0)


def _resolve_severity(draft_path: Path, override: str | None) -> tuple[str, str]:
    """Return (normalised_severity, source)."""
    if override:
        return override.strip().capitalize(), "cli"
    text = draft_path.read_text(encoding="utf-8", errors="replace")
    m = re.search(r"^-?\s*Severity\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
    if m:
        return m.group(1).strip().capitalize(), "draft"
    return "Unknown", "unknown"


def _extract_cantina_ids(text: str) -> set[str]:
    """Return set of normalised Cantina IDs found in text (e.g. '192')."""
    ids: set[str] = set()
    for m in _CANTINA_ID_RE.finditer(text):
        for g in m.groups():
            if g:
                ids.add(g)
    return ids


def _find_workspace(draft_path: Path, ws_hint: Path | None) -> Path | None:
    """Walk up from draft_path looking for a submissions/ directory."""
    if ws_hint and ws_hint.is_dir():
        return ws_hint
    candidate = draft_path.parent
    for _ in range(8):
        if (candidate / "submissions").is_dir():
            return candidate
        candidate = candidate.parent
    return None


def _scan_workspace_for_id(
    workspace: Path,
    cantina_id: str,
    current_draft: Path,
) -> list[dict[str, Any]]:
    """Return list of {path, is_merged} for drafts citing the given ID, excluding current."""
    matches: list[dict[str, Any]] = []
    _env_dirs = os.environ.get("AUDITOOOR_R28_STATUS_DIRS", "")
    dirs = [d for d in _env_dirs.split(":") if d] if _env_dirs else _DEFAULT_STATUS_DIRS

    for rel in dirs:
        sdir = workspace / rel
        if not sdir.is_dir():
            continue
        for md in sdir.rglob("*.md"):
            if md.resolve() == current_draft.resolve():
                continue
            try:
                text = md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            ids = _extract_cantina_ids(text)
            if cantina_id in ids:
                is_merged = bool(_MERGED_SIGNAL_RE.search(text))
                matches.append({
                    "path": str(md),
                    "relative": str(md.relative_to(workspace)),
                    "is_merged": is_merged,
                })
    return matches


def run(
    draft_path: Path,
    *,
    workspace: Path | None = None,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Main check entry point. Returns (exit_code, payload)."""
    try:
        text = draft_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return 2, {"schema": SCHEMA_VERSION, "gate": GATE, "verdict": "error",
                   "reason": f"cannot read draft: {exc}"}

    severity, severity_source = _resolve_severity(draft_path, severity_override)
    rank = _severity_rank(severity)

    if rank < SEVERITY_RANK["high"]:
        return 0, {
            "schema": SCHEMA_VERSION, "gate": GATE,
            "verdict": "pass-out-of-scope",
            "reason": f"severity={severity} below HIGH; R28 not triggered",
            "severity": severity, "severity_source": severity_source,
        }

    # Check for rebuttal override.
    rebuttal_m = _REBUTTAL_RE.search(text)
    rebuttal_reason = ""
    if rebuttal_m:
        rebuttal_reason = (rebuttal_m.group("reason") or rebuttal_m.group("reason2") or "").strip()
        if rebuttal_reason:
            return 0, {
                "schema": SCHEMA_VERSION, "gate": GATE,
                "verdict": "ok-rebuttal",
                "reason": f"r28-rebuttal accepted: {rebuttal_reason[:200]}",
                "severity": severity, "severity_source": severity_source,
            }

    # Extract Cantina IDs from the draft.
    ids = _extract_cantina_ids(text)
    if not ids:
        return 0, {
            "schema": SCHEMA_VERSION, "gate": GATE,
            "verdict": "pass-no-cantina-id-cited",
            "reason": "no Cantina submission ID found in draft; R28 not triggered",
            "severity": severity, "severity_source": severity_source,
        }

    # Find the workspace.
    ws = _find_workspace(draft_path, workspace)
    if ws is None:
        # Cannot scan - treat as pass-out-of-scope with a warning.
        return 0, {
            "schema": SCHEMA_VERSION, "gate": GATE,
            "verdict": "pass-no-cantina-id-cited",
            "reason": "workspace not found; cannot scan for sibling paths",
            "severity": severity, "severity_source": severity_source,
            "hints": ["pass workspace with --workspace <ws> for accurate results"],
        }

    # For each found Cantina ID, scan for siblings.
    all_siblings: list[dict[str, Any]] = []
    triggering_id = ""
    for cid in sorted(ids):
        siblings = _scan_workspace_for_id(ws, cid, draft_path)
        if siblings:
            all_siblings.extend(siblings)
            triggering_id = cid

    if not all_siblings:
        return 0, {
            "schema": SCHEMA_VERSION, "gate": GATE,
            "verdict": "pass-only-one-path-in-flight",
            "reason": f"no other drafts cite the same Cantina ID(s) {sorted(ids)}",
            "cantina_ids": sorted(ids),
            "severity": severity, "severity_source": severity_source,
        }

    # Check if the current draft itself is marked as a merged response.
    current_is_merged = bool(_MERGED_SIGNAL_RE.search(text))
    if current_is_merged:
        return 0, {
            "schema": SCHEMA_VERSION, "gate": GATE,
            "verdict": "pass-merged-into-unified-response",
            "reason": "draft contains merged-unified-response signal; R28 satisfied",
            "cantina_ids": sorted(ids),
            "sibling_paths": [s["path"] for s in all_siblings],
            "severity": severity, "severity_source": severity_source,
        }

    # Multiple in-flight paths detected.
    sibling_paths = [s["path"] for s in all_siblings]
    hints = [
        f"Cantina ID #{triggering_id}: {len(all_siblings)} other draft(s) in-flight",
        "Merge all paths into one unified triager response before pasting",
        "Add 'merged unified response' signal to the merged draft to pass this gate",
        "Override: <!-- r28-rebuttal: <reason up to 200 chars> -->",
    ]

    return 1, {
        "schema": SCHEMA_VERSION, "gate": GATE,
        "verdict": "fail-multiple-paths-in-flight-unmerged",
        "reason": (
            f"R28 violation: {len(all_siblings) + 1} draft(s) reference "
            f"Cantina #{triggering_id} but none is marked as the merged unified "
            "response. Wait for all paths to land, merge into one, paste once."
        ),
        "cantina_ids": sorted(ids),
        "triggering_id": triggering_id,
        "sibling_paths": sibling_paths,
        "hints": hints,
        "severity": severity, "severity_source": severity_source,
    }




def _main() -> None:
    parser = argparse.ArgumentParser(
        description="R28 multi-path escalation merge check"
    )
    parser.add_argument("draft", type=Path, help="Path to the draft .md file")
    parser.add_argument("--workspace", type=Path, default=None,
                        help="Workspace root (auto-detected if not set)")
    parser.add_argument("--severity", default=None,
                        help="Override severity (High, Critical, etc.)")
    parser.add_argument("--strict", action="store_true",
                        help="Alias for --json; no effect, kept for CLI compat")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output")
    args = parser.parse_args()

    if not args.draft.exists():
        print(json.dumps({
            "schema": SCHEMA_VERSION, "gate": GATE,
            "verdict": "error", "reason": f"draft not found: {args.draft}"
        }), flush=True)
        sys.exit(2)

    rc, payload = run(
        args.draft,
        workspace=args.workspace,
        severity_override=args.severity,
        strict=args.strict,
    )

    print(json.dumps(payload, indent=2), flush=True)
    sys.exit(rc)


if __name__ == "__main__":
    _main()
