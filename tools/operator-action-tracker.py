#!/usr/bin/env python3
"""
operator-action-tracker.py - Weekly digest of all pending operator-action items.

Aggregates from five sources:
  1. reports/v3_blocker_ledger/blocker_ledger.json  external_state_required open rows
  2. /Users/wolf/audits/*/submissions/SUBMISSIONS.md  PENDING/IN_REVIEW rows
  3. ~/.claude.json mcpServers env  credentials present-or-empty check
  4. agent_outputs/**/*.md  files flagged "operator action required" in SUMMARY
  5. .auditooor/lesson_source_decisions.json  decision_required: true rows

CLI:
  python3 tools/operator-action-tracker.py [--workspace <ws>] [--since <date>]
                                            [--json | --markdown]
                                            [--audits-root <root>]

Rule 37: this tool emits no corpus records; reporting-only.

Context pack: auditooor.vault_context_pack.v1:resume:4b4c810b9c00d4a3
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Item class
# ---------------------------------------------------------------------------

ACTION_CLASSES = {
    "credentials": "credentials",
    "platform-outcome": "platform-outcome",
    "editorial": "editorial",
    "config": "config",
    "policy-promotion": "policy-promotion",
}

# ETA strings kept short; no em-dashes
ETA_MAP = {
    "credentials": "< 5 min (paste API key)",
    "platform-outcome": "5-10 min (check bounty platform)",
    "editorial": "15-30 min (draft response)",
    "config": "< 5 min (update config value)",
    "policy-promotion": "30-60 min (review and promote rule)",
}


class ActionItem:
    def __init__(
        self,
        source: str,
        item_id: str,
        description: str,
        action: str,
        action_class: str,
        created_at: str = "",
    ) -> None:
        self.source = source
        self.item_id = item_id
        self.description = description
        self.action = action
        self.action_class = action_class
        self.created_at = created_at

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "item_id": self.item_id,
            "description": self.description,
            "action": self.action,
            "action_class": self.action_class,
            "eta": ETA_MAP.get(self.action_class, "unknown"),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Source parsers
# ---------------------------------------------------------------------------

CLOSED_STATUSES = {
    "closed",
    "closed_by_bounded_live_delta",
    "closed_by_bounded_r3_snapshot",
    "closed_by_documented_external_dependency",
    "closed_for_strict_worker_packet_path",
    "closed_by_targeted_unittest_pass",
    "closed_by_restored_local_artifacts",
    "closed_reviewed_staged_only_no_canonical_promotion",
    "closed_by_reachable_bounds_lesson_and_rule_proposal",
    "closed_by_negative_lesson_and_enforcement_proposal",
    "resolved",
    "no_action",
}


def _classify_blocker(cat: str, status: str) -> str:
    if "credential" in status or "credential" in cat:
        return "credentials"
    if "platform" in cat or "disposition" in status or "filing_status" in status:
        return "platform-outcome"
    if "lesson" in cat or "writeback" in cat:
        return "policy-promotion"
    if "source_mining" in cat:
        return "config"
    return "editorial"


def parse_blocker_ledger(workspace: Path) -> list[ActionItem]:
    ledger_path = workspace / "reports" / "v3_blocker_ledger" / "blocker_ledger.json"
    if not ledger_path.exists():
        return []
    try:
        data = json.loads(ledger_path.read_text())
    except Exception:
        return []
    items: list[ActionItem] = []
    for b in data.get("blockers", []):
        if not b.get("external_state_required", False):
            continue
        status = b.get("status", "")
        if status.lower() in CLOSED_STATUSES:
            continue
        bid = b.get("blocker_id", "unknown")
        cat = b.get("category", "")
        action_raw = b.get("next_action", "Operator action required - see blocker ledger")
        # Truncate long action to 120 chars
        action = action_raw[:120].rstrip() + ("..." if len(action_raw) > 120 else "")
        ac = _classify_blocker(cat, status)
        items.append(
            ActionItem(
                source="blocker_ledger",
                item_id=bid,
                description=f"{cat} [{status}]",
                action=action,
                action_class=ac,
            )
        )
    return items


# Patterns for pending rows in SUBMISSIONS.md tables
_PENDING_RE = re.compile(
    r"\|\s*(?P<id>[^|]+?)\s*\|\s*(?P<date>[^|]+?)\s*\|\s*(?P<sev>[^|]+?)\s*\|"
    r"\s*(?P<status>[^|]+?)\s*\|\s*(?P<title>[^|]+?)\s*\|",
    re.IGNORECASE,
)

PENDING_STATUS_KEYWORDS = {
    "pending",
    "in_review",
    "in review",
    "filed (cantina # pending)",
    "filed (cantina#pending)",
    "awaiting",
    "v3 production-profile response current",
    "response current",
    "high rejection risk",
}


def _is_pending_status(status: str) -> bool:
    sl = status.lower().strip()
    for kw in PENDING_STATUS_KEYWORDS:
        if kw in sl:
            return True
    return False


def parse_submissions(audits_root: Path, since: _dt.date | None = None) -> list[ActionItem]:
    items: list[ActionItem] = []
    if not audits_root.exists():
        return items
    for subs_md in audits_root.glob("*/submissions/SUBMISSIONS.md"):
        workspace_name = subs_md.parts[-3]  # audits/<name>/submissions/SUBMISSIONS.md
        try:
            text = subs_md.read_text()
        except Exception:
            continue
        for m in _PENDING_RE.finditer(text):
            status = m.group("status").strip()
            if not _is_pending_status(status):
                continue
            date_str = m.group("date").strip()
            if since:
                try:
                    row_date = _dt.date.fromisoformat(date_str[:10])
                    if row_date < since:
                        continue
                except ValueError:
                    pass
            rid = m.group("id").strip()
            sev = m.group("sev").strip()
            title = m.group("title").strip()[:80]
            ac = "editorial" if "rejection risk" in status.lower() else "platform-outcome"
            items.append(
                ActionItem(
                    source=f"submissions/{workspace_name}",
                    item_id=rid,
                    description=f"[{sev}] {title}",
                    action=f"Check {workspace_name} platform for triage outcome of {rid}",
                    action_class=ac,
                    created_at=date_str,
                )
            )
        # Also scan the plain table at bottom (check-submission-tracker style)
        for m in re.finditer(
            r"\|\s*(?P<date>\d{4}-\d{2}-\d{2}[^|]*?)\s*\|\s*(?P<id>[^|]+?)\s*\|"
            r"[^|]+?\|[^|]+?\|[^|]+?\|[^|]+?\|\s*(?P<status>Pending|In Review)\s*\|",
            text,
            re.IGNORECASE,
        ):
            status = m.group("status").strip()
            if not _is_pending_status(status):
                continue
            rid = m.group("id").strip()
            date_str = m.group("date").strip()[:10]
            items.append(
                ActionItem(
                    source=f"submissions/{workspace_name}/tracker",
                    item_id=rid,
                    description=f"[{status}] finding {rid} in {workspace_name}",
                    action=f"Check {workspace_name} platform for triage outcome of finding {rid}",
                    action_class="platform-outcome",
                    created_at=date_str,
                )
            )
    return items


def parse_mcp_credentials() -> list[ActionItem]:
    """Check ~/.claude.json mcpServers for empty credential values."""
    claude_json = Path.home() / ".claude.json"
    if not claude_json.exists():
        return []
    try:
        data = json.loads(claude_json.read_text())
    except Exception:
        return []
    items: list[ActionItem] = []
    for server_name, cfg in data.get("mcpServers", {}).items():
        env = cfg.get("env", {})
        for key, val in env.items():
            if not val or not str(val).strip():
                items.append(
                    ActionItem(
                        source="mcp_credentials",
                        item_id=f"{server_name}.{key}",
                        description=f"MCP server '{server_name}' env var {key} is empty",
                        action=f"Set {key} in ~/.claude.json mcpServers.{server_name}.env",
                        action_class="credentials",
                    )
                )
    return items


_OPERATOR_ACTION_RE = re.compile(
    r"operator\s+action\s+required", re.IGNORECASE
)


def parse_lane_reports(workspace: Path) -> list[ActionItem]:
    """Scan agent_outputs lane SUMMARY sections for 'operator action required'."""
    agent_outputs = workspace / "agent_outputs"
    if not agent_outputs.exists():
        return []
    items: list[ActionItem] = []
    # Only check top-level .md files and one-level deep SUMMARY or index files
    candidates: list[Path] = list(agent_outputs.glob("*.md"))
    for subdir in agent_outputs.iterdir():
        if subdir.is_dir():
            for fname in ("SUMMARY.md", "index.md", "REPORT.md", "OUTCOME.md"):
                p = subdir / fname
                if p.exists():
                    candidates.append(p)
    for p in candidates:
        try:
            text = p.read_text()
        except Exception:
            continue
        if _OPERATOR_ACTION_RE.search(text):
            # Extract context line
            for line in text.splitlines():
                if _OPERATOR_ACTION_RE.search(line):
                    context = line.strip()[:100]
                    break
            else:
                context = "See file for details"
            rel = p.relative_to(workspace)
            items.append(
                ActionItem(
                    source="lane_report",
                    item_id=str(rel),
                    description=f"Lane report flagged operator action: {context}",
                    action=f"Read {rel} and clear the flagged action item",
                    action_class="editorial",
                )
            )
    return items


def parse_lesson_source_decisions(workspace: Path) -> list[ActionItem]:
    """Find decision_required: true rows in lesson_source_decisions.json."""
    lsd_path = workspace / ".auditooor" / "lesson_source_decisions.json"
    if not lsd_path.exists():
        return []
    try:
        data = json.loads(lsd_path.read_text())
    except Exception:
        return []
    items: list[ActionItem] = []
    decisions = data.get("decisions", [])
    for row in decisions:
        if not row.get("decision_required", False):
            continue
        did = row.get("decision_id", "unknown")
        reason = row.get("needs_human_reason", "")[:80]
        items.append(
            ActionItem(
                source="lesson_source_decisions",
                item_id=did,
                description=f"Lesson decision requires operator input: {reason or did}",
                action="Open .auditooor/lesson_source_decisions.json and resolve this decision_id",
                action_class="policy-promotion",
                created_at=row.get("generated_at_utc", ""),
            )
        )
    return items


# ---------------------------------------------------------------------------
# Delta detection
# ---------------------------------------------------------------------------

_STATE_FILE = ".auditooor/operator_action_tracker_state.json"


def _load_state(workspace: Path) -> dict:
    sp = workspace / _STATE_FILE
    if sp.exists():
        try:
            return json.loads(sp.read_text())
        except Exception:
            pass
    return {}


def _save_state(workspace: Path, item_ids: list[str]) -> None:
    sp = workspace / _STATE_FILE
    sp.parent.mkdir(parents=True, exist_ok=True)
    state = {
        "last_run": _dt.datetime.utcnow().isoformat() + "Z",
        "item_ids": sorted(item_ids),
    }
    sp.write_text(json.dumps(state, indent=2))


def _compute_delta(
    current_ids: set[str], prev_state: dict
) -> tuple[set[str], set[str]]:
    prev_ids = set(prev_state.get("item_ids", []))
    newly_added = current_ids - prev_ids
    newly_cleared = prev_ids - current_ids
    return newly_added, newly_cleared


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(
    items: list[ActionItem],
    newly_cleared: set[str],
    run_at: str,
) -> str:
    lines: list[str] = []
    lines.append(f"# Operator Action Digest")
    lines.append(f"Generated: {run_at}")
    lines.append("")

    if not items:
        lines.append("**No pending operator actions.**")
        if newly_cleared:
            lines.append("")
            lines.append(f"## Cleared since last run ({len(newly_cleared)})")
            for iid in sorted(newly_cleared):
                lines.append(f"- {iid}")
        return "\n".join(lines)

    # Counts by class
    class_counts: dict[str, int] = {}
    for it in items:
        class_counts[it.action_class] = class_counts.get(it.action_class, 0) + 1
    lines.append(f"**Total pending: {len(items)}**")
    lines.append("")
    lines.append("| Class | Count | Typical ETA |")
    lines.append("|---|---|---|")
    for ac, cnt in sorted(class_counts.items()):
        lines.append(f"| {ac} | {cnt} | {ETA_MAP.get(ac, '-')} |")
    lines.append("")

    # Per class groups
    grouped: dict[str, list[ActionItem]] = {}
    for it in items:
        grouped.setdefault(it.action_class, []).append(it)

    for ac in sorted(grouped.keys()):
        lines.append(f"## {ac.title()} ({len(grouped[ac])})")
        lines.append("")
        for it in grouped[ac]:
            lines.append(f"### {it.item_id}")
            lines.append(f"- **Source**: {it.source}")
            if it.created_at:
                lines.append(f"- **Date**: {it.created_at}")
            lines.append(f"- **Description**: {it.description}")
            lines.append(f"- **Action**: {it.action}")
            lines.append(f"- **ETA**: {ETA_MAP.get(it.action_class, 'unknown')}")
            lines.append("")

    if newly_cleared:
        lines.append(f"## Cleared since last run ({len(newly_cleared)})")
        for iid in sorted(newly_cleared):
            lines.append(f"- {iid}")
        lines.append("")

    return "\n".join(lines)


def render_json(
    items: list[ActionItem],
    newly_cleared: set[str],
    run_at: str,
) -> str:
    class_counts: dict[str, int] = {}
    for it in items:
        class_counts[it.action_class] = class_counts.get(it.action_class, 0) + 1
    out = {
        "schema": "auditooor.operator_action_tracker.v1",
        "generated_at_utc": run_at,
        "total_pending": len(items),
        "by_class": class_counts,
        "items": [it.to_dict() for it in items],
        "cleared_since_last_run": sorted(newly_cleared),
    }
    return json.dumps(out, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="operator-action-tracker: weekly digest of pending operator actions"
    )
    parser.add_argument(
        "--workspace",
        default=str(REPO_ROOT),
        help="Workspace root (default: repo root)",
    )
    parser.add_argument(
        "--audits-root",
        default=str(Path.home() / "audits"),
        help="Root of audit workspaces for SUBMISSIONS.md scan",
    )
    parser.add_argument(
        "--since",
        default=None,
        help="Filter SUBMISSIONS rows newer than YYYY-MM-DD",
    )
    parser.add_argument(
        "--json",
        dest="output_json",
        action="store_true",
        help="Output JSON instead of Markdown",
    )
    parser.add_argument(
        "--markdown",
        dest="output_markdown",
        action="store_true",
        help="Output Markdown (default)",
    )
    parser.add_argument(
        "--no-delta",
        action="store_true",
        help="Skip delta tracking (do not read/write state file)",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    audits_root = Path(args.audits_root).expanduser().resolve()
    since: _dt.date | None = None
    if args.since:
        try:
            since = _dt.date.fromisoformat(args.since)
        except ValueError:
            print(f"ERROR: --since must be YYYY-MM-DD, got: {args.since}", file=sys.stderr)
            return 1

    run_at = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Collect items
    items: list[ActionItem] = []
    items.extend(parse_blocker_ledger(workspace))
    items.extend(parse_submissions(audits_root, since))
    items.extend(parse_mcp_credentials())
    items.extend(parse_lane_reports(workspace))
    items.extend(parse_lesson_source_decisions(workspace))

    # Deduplicate by item_id
    seen: set[str] = set()
    deduped: list[ActionItem] = []
    for it in items:
        key = f"{it.source}:{it.item_id}"
        if key not in seen:
            seen.add(key)
            deduped.append(it)
    items = deduped

    # Delta
    current_ids = {f"{it.source}:{it.item_id}" for it in items}
    newly_cleared: set[str] = set()
    if not args.no_delta:
        prev_state = _load_state(workspace)
        _, newly_cleared = _compute_delta(current_ids, prev_state)
        _save_state(workspace, list(current_ids))

    # Render
    if args.output_json:
        print(render_json(items, newly_cleared, run_at))
    else:
        print(render_markdown(items, newly_cleared, run_at))

    return 0


if __name__ == "__main__":
    sys.exit(main())
