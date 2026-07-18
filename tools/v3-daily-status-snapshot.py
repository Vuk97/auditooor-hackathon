#!/usr/bin/env python3
"""
v3-daily-status-snapshot.py  --  single-command V3 state-at-a-glance tool.

Schema: auditooor.v3_daily_status_snapshot.v1

CLI:
    python3 tools/v3-daily-status-snapshot.py [--workspace <ws>]
        [--json | --markdown] [--since <YYYY-MM-DD>] [--write-snapshot]

Exit codes:
    0  success
    2  usage error
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _repo_root(workspace: str) -> Path:
    """Return the auditooor-mcp repo root (one directory up from tools/)."""
    p = Path(workspace).resolve()
    # if workspace is a sub-path, walk up to find pre-submit-check.sh
    for candidate in [p, p.parent, p.parent.parent]:
        if (candidate / "tools" / "pre-submit-check.sh").exists():
            return candidate
    return p


def _git_log(root: Path, n: int = 5) -> list:
    """Return last n commits as list of {sha, summary}."""
    try:
        out = subprocess.check_output(
            ["git", "-C", str(root), "log", f"-{n}", "--oneline"],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        entries = []
        for line in out.strip().splitlines():
            parts = line.split(" ", 1)
            if len(parts) == 2:
                entries.append({"sha": parts[0], "summary": parts[1]})
        return entries
    except Exception:
        return []


def _git_head(root: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return "unknown"


def _count_codified_rules(root: Path) -> dict:
    digest_path = root / "reference" / "codified_rules_digest.json"
    if not digest_path.exists():
        return {"rule_count": None, "do_not_count": None, "path": None}
    try:
        d = json.loads(digest_path.read_text())
        return {
            "rule_count": d.get("rule_count"),
            "do_not_count": d.get("do_not_count"),
            "path": str(digest_path.relative_to(root)),
        }
    except Exception:
        return {"rule_count": None, "do_not_count": None, "path": str(digest_path)}


def _count_operational_gates(root: Path) -> dict:
    """Count wired R-rule gates in pre-submit-check.sh via _RC variable pattern."""
    psc = root / "tools" / "pre-submit-check.sh"
    if not psc.exists():
        return {"gate_count": None, "highest_check": None}
    text = psc.read_text(errors="replace")
    # Each wired gate sets R<NN>_RC=... - collect unique rule numbers
    # Also collect explicit "Check #NN" references for highest-check display
    rule_nums = set()
    # gates set _R<NN>_RC or R<NN>_RC
    for m in re.finditer(r"_?R(\d+)_RC", text):
        n = int(m.group(1))
        if n < 1000:  # exclude stray large numbers
            rule_nums.add(n)
    # highest Check # referenced
    check_nums = set()
    for m in re.finditer(r"Check #(\d+)", text):
        check_nums.add(int(m.group(1)))
    return {
        "gate_count": len(rule_nums),
        "highest_check": max(check_nums) if check_nums else None,
        "rule_numbers": sorted(rule_nums),
    }


def _meta1_status(root: Path) -> dict:
    """META-1: thinking-prosthesis lane skeleton activation status."""
    augmenter = root / "tools" / "agent-prompt-hacker-augmenter.py"
    skeleton_dir = root / "tools" / "lane_skeleton_templates"
    shipped = augmenter.exists()
    skeletons = list(skeleton_dir.glob("*.md")) if skeleton_dir.exists() else []
    # look for 15a/15b activation markers
    activated = False
    if shipped:
        text = augmenter.read_text(errors="replace")
        activated = "15a" in text or "15b" in text or "section_15" in text.lower()
    return {
        "shipped": shipped,
        "activated": activated,
        "skeleton_count": len(skeletons),
        "verdict": (
            "SHIPPED + ACTIVATED"
            if (shipped and activated)
            else ("SHIPPED, activation unconfirmed" if shipped else "NOT FOUND")
        ),
        "note": "VVV iter12: shelfware per Lane QQQ assessment; section-15 path exists but fail-rate not re-measured",
    }


def _meta2_status(root: Path) -> dict:
    """META-2: operator-action-tracker."""
    tracker = root / "tools" / "operator-action-tracker.py"
    snapshot_dir = root / "reports" / "v3_operator_action_snapshots"
    snapshots = sorted(snapshot_dir.glob("snapshot_*.json")) if snapshot_dir.exists() else []
    latest_snapshot = None
    pending_count = None
    mcp_pack_id = None
    if snapshots:
        latest = snapshots[-1]
        latest_snapshot = str(latest.relative_to(root))
        try:
            d = json.loads(latest.read_text())
            pending_count = d.get("total_pending")
            mcp_pack_id = d.get("mcp_context_pack_id")
        except Exception:
            pass
    return {
        "shipped": tracker.exists(),
        "latest_snapshot": latest_snapshot,
        "pending_item_count": pending_count,
        "mcp_context_pack_id": mcp_pack_id,
        "verdict": (
            f"OPERATIONAL - latest snapshot: {latest_snapshot} ({pending_count} pending)"
            if latest_snapshot
            else "SHIPPED, no snapshot yet"
        ),
    }


def _burndown_status(root: Path) -> dict:
    """V3 burndown script status."""
    burndown = root / "tools" / "audit-question-burndown.py"
    close_sh = root / "tools" / "v3-tooling-burn-down-close.sh"
    return {
        "shipped": burndown.exists(),
        "close_script_shipped": close_sh.exists(),
        "verdict": (
            "READY - operator-runnable; pending operator decision on Lane XX redefinition"
            if burndown.exists()
            else "NOT FOUND"
        ),
    }


def _mining_dashboard_status(root: Path) -> dict:
    """Mining coverage dashboard freshness."""
    dashboard_json = root / ".auditooor" / "mining_coverage_dashboard.json"
    if not dashboard_json.exists():
        return {
            "fresh": None,
            "stale": None,
            "backlog": None,
            "queued": None,
            "verdict": "dashboard JSON not present - run make v3-roadmap-sidecars",
        }
    try:
        d = json.loads(dashboard_json.read_text())
        # schema v1 uses "summary" block + "rows" list; older schemas used "sources"
        summary = d.get("summary", {})
        if summary:
            fresh = summary.get("fresh", 0)
            stale = summary.get("stale", 0)
            queued = summary.get("queued", 0)
            backlog = summary.get("backlog", 0)
            total = summary.get("total_sources", 0)
        else:
            sources = d.get("rows", d.get("sources", []))
            by_status = {}
            for s in sources:
                st = s.get("status", "unknown")
                by_status[st] = by_status.get(st, 0) + 1
            fresh = by_status.get("fresh", 0)
            stale = by_status.get("stale", 0)
            queued = by_status.get("queued", 0)
            backlog = by_status.get("backlog", 0)
            total = len(sources)
        return {
            "fresh": fresh,
            "stale": stale,
            "backlog": backlog,
            "queued": queued,
            "total": total,
            "verdict": f"{fresh}/{total} fresh, {stale} stale, {backlog} backlog, {queued} queued",
        }
    except Exception as e:
        return {"verdict": f"parse error: {e}"}


def _top_operator_items(root: Path, n: int = 5) -> list:
    """Return top N operator action items from latest snapshot."""
    snapshot_dir = root / "reports" / "v3_operator_action_snapshots"
    snapshots = sorted(snapshot_dir.glob("snapshot_*.json")) if snapshot_dir.exists() else []
    if not snapshots:
        return []
    try:
        d = json.loads(snapshots[-1].read_text())
        top = d.get("top_priority_items", [])[:n]
        if not top:
            items = d.get("items", [])[:n]
            top = items
        return top
    except Exception:
        return []


def _three_pending_decisions(root: Path) -> list:
    """Return the 3 canonical pending operator decisions from V3 doctrine."""
    return [
        {
            "id": "LANE-XX-REDEF",
            "label": "Lane XX redefinition",
            "detail": "Decide whether to redefine the perpetual-loop as real-hunt-driven (QQQ iter11 verdict: AT-WALL-CONDITIONALLY pending this decision).",
        },
        {
            "id": "L34-PER-DRAFT-AUTH",
            "label": "L34 per-draft authorization",
            "detail": "L34 new-engagement authorization gate needs per-draft sign-off policy; blocked on operator config decision.",
        },
        {
            "id": "CREDENTIALS",
            "label": "Credentials: SOLODIT_API_KEY",
            "detail": "Export SOLODIT_API_KEY to unblock corpus freshness ingestion (17,573+ detector corpus primary source).",
        },
    ]


def _since_filter(commits: list, since: str) -> list:
    """Filter commits (no dates available from --oneline, so return all for now)."""
    # git oneline doesn't include dates; we just return all
    return commits


# ---------------------------------------------------------------------------
# main builder
# ---------------------------------------------------------------------------

def build_snapshot(workspace: str, since: str = None) -> dict:
    root = _repo_root(workspace)
    now_utc = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    commits = _git_log(root, 5)
    if since:
        # best-effort: can't filter without date info from --oneline
        pass

    rules = _count_codified_rules(root)
    gates = _count_operational_gates(root)
    meta1 = _meta1_status(root)
    meta2 = _meta2_status(root)
    burndown = _burndown_status(root)
    mining = _mining_dashboard_status(root)
    top_ops = _top_operator_items(root, 5)
    pending_decisions = _three_pending_decisions(root)

    # at-a-glance status banner
    gate_count = gates.get("gate_count") or 0
    pending = meta2.get("pending_item_count")
    if pending is not None and pending > 0:
        status_banner = (
            f"AT-WALL-CONDITIONALLY pending {pending} operator-action items "
            f"and Lane XX redefinition decision"
        )
    elif gate_count >= 9:
        status_banner = "TOOLING ACTIVE - gate stack operational, empirical roadmap open"
    else:
        status_banner = "TOOLING PARTIALLY ACTIVE - some gates not yet wired"

    head_sha = _git_head(root)
    head_summary = commits[0]["summary"] if commits else "unknown"

    return {
        "schema": "auditooor.v3_daily_status_snapshot.v1",
        "generated_at_utc": now_utc,
        "workspace": str(root),
        "status_banner": status_banner,
        "head_sha": head_sha[:12],
        "head_summary": head_summary,
        "codified_rules": rules,
        "r_rule_gates": gates,
        "meta1": meta1,
        "meta2": meta2,
        "burndown": burndown,
        "mining_dashboard": mining,
        "recent_commits": commits,
        "top_operator_items": top_ops,
        "pending_decisions": pending_decisions,
    }


# ---------------------------------------------------------------------------
# formatters
# ---------------------------------------------------------------------------

def render_markdown(snap: dict) -> str:
    lines = []
    lines.append("# V3 Daily Status Snapshot")
    lines.append(f"Generated: {snap['generated_at_utc']}")
    lines.append("")

    # --- Top: at-a-glance ---
    lines.append("## At-a-Glance")
    lines.append(f"- **Status**: {snap['status_banner']}")
    lines.append(f"- **HEAD**: `{snap['head_sha']}` {snap['head_summary']}")

    rules = snap.get("codified_rules", {})
    rule_count = rules.get("rule_count", "?")
    do_not_count = rules.get("do_not_count", "?")
    lines.append(f"- **Codified rules**: {rule_count} rules + {do_not_count} do-not items (source: `{rules.get('path','?')}`)")

    gates = snap.get("r_rule_gates", {})
    gc = gates.get("gate_count", "?")
    hc = gates.get("highest_check", "?")
    lines.append(f"- **R-rule gates**: {gc} wired in pre-submit-check.sh (highest: Check #{hc})")
    lines.append("")

    # --- Mid: what's working ---
    lines.append("## What's Working")

    m1 = snap.get("meta1", {})
    lines.append(f"### META-1 (thinking-prosthesis)")
    lines.append(f"- Verdict: {m1.get('verdict','?')}")
    lines.append(f"- Lane skeleton templates: {m1.get('skeleton_count', 0)}")
    lines.append(f"- Note: {m1.get('note','')}")
    lines.append("")

    m2 = snap.get("meta2", {})
    lines.append("### META-2 (operator-action-tracker)")
    lines.append(f"- Verdict: {m2.get('verdict','?')}")
    if m2.get("mcp_context_pack_id"):
        lines.append(f"- MCP context_pack_id at snapshot: `{m2['mcp_context_pack_id']}`")
    lines.append("")

    bd = snap.get("burndown", {})
    lines.append("### V3 Burndown Script")
    lines.append(f"- Verdict: {bd.get('verdict','?')}")
    lines.append("")

    md = snap.get("mining_dashboard", {})
    lines.append("### Mining Coverage Dashboard")
    lines.append(f"- {md.get('verdict','?')}")
    lines.append("")

    lines.append("### Last 5 Commits")
    for c in snap.get("recent_commits", []):
        lines.append(f"- `{c['sha']}` {c['summary']}")
    lines.append("")

    # --- Bottom: operator action queue ---
    lines.append("## Operator Action Queue")
    top = snap.get("top_operator_items", [])
    if top:
        lines.append("### Top 5 Leverage Items")
        for i, item in enumerate(top[:5], 1):
            cls = item.get("class", item.get("type", "?"))
            action = item.get("action", item.get("summary", str(item)))[:100]
            lines.append(f"{i}. **[{cls}]** {action}")
    else:
        lines.append("_No top items found - run `make v3-operator-actions` to refresh._")
    lines.append("")

    lines.append("### 3 Pending Operator Decisions")
    for pd in snap.get("pending_decisions", []):
        lines.append(f"- **{pd['label']}** ({pd['id']}): {pd['detail']}")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="V3 daily status snapshot - single-command V3 state summary."
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("WS", str(Path(__file__).resolve().parent.parent)),
        help="Path to auditooor-mcp repo root (default: parent of tools/)",
    )
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit JSON output")
    fmt.add_argument("--markdown", action="store_true", help="Emit markdown output (default)")
    parser.add_argument(
        "--since",
        default=None,
        metavar="YYYY-MM-DD",
        help="Filter commits since this date (advisory, --oneline has no dates)",
    )
    parser.add_argument(
        "--write-snapshot",
        action="store_true",
        help="Also write a timestamped copy to reports/v3_daily_status/",
    )
    args = parser.parse_args()

    snap = build_snapshot(args.workspace, since=args.since)

    if args.json:
        output = json.dumps(snap, indent=2)
    else:
        output = render_markdown(snap)

    print(output)

    if args.write_snapshot:
        root = Path(snap["workspace"])
        out_dir = root / "reports" / "v3_daily_status"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        if args.json:
            out_path = out_dir / f"snapshot_{ts}.json"
            out_path.write_text(output)
        else:
            out_path = out_dir / f"snapshot_{ts}.md"
            out_path.write_text(output)
        print(f"\n[v3-daily-status-snapshot] wrote {out_path}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
