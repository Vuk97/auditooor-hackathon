#!/usr/bin/env python3
"""
pattern-migration-alert.py — Alert on high-ROI pattern migrations

Scans all workspaces and alerts when an unmined workspace contains a CCIA
pattern that matches a PAID finding from another workspace. This tells you
exactly which bounty to mine next for highest expected ROI.

Usage:
    pattern-migration-alert.py [--audits-dir ~/audits] [--min-score 5]
    pattern-migration-alert.py [--audits-dir ~/audits] [--out report.md]
    pattern-migration-alert.py --json

Alert format:
  🚨 HIGH ROI: snowbridge has A-REENT (BeefyClient.invoke)
     Similar to PAID finding in polymarket #84 (Medium)
     Action: mine snowbridge for reentrancy in BeefyClient
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent


def discover_workspaces(audits_dir: Path) -> List[Path]:
    """Find all workspace directories."""
    if not audits_dir.exists():
        return []
    workspaces = []
    for entry in audits_dir.iterdir():
        if entry.is_dir() and not entry.name.startswith("."):
            if any((entry / marker).exists() for marker in ("src", "submissions", "AUDIT.md", "OOS_CHECKLIST.md")):
                if "test" not in entry.name.lower() and "dogfood" not in entry.name.lower():
                    workspaces.append(entry)
    return sorted(workspaces)


def load_ccia_angles(ws: Path) -> List[Dict]:
    """Load CCIA attack angles."""
    json_path = ws / "ccia_report.json"
    if json_path.exists():
        data = json.loads(json_path.read_text())
        if isinstance(data, list):
            return data
        return data.get("attack_angles", [])
    md_path = ws / "ccia_report.md"
    if md_path.exists():
        angles = []
        for line in md_path.read_text().splitlines():
            m = re.match(r'###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)', line)
            if m:
                angles.append({"id": m.group(1), "severity": m.group(2), "title": m.group(3)})
        return angles
    return []


def load_paid_findings(ws: Path) -> List[Dict]:
    """Load paid/accepted findings from a workspace."""
    paid = []
    sub_file = ws / "submissions" / "SUBMISSIONS.md"
    if not sub_file.exists():
        return paid
    
    text = sub_file.read_text()
    lines = text.splitlines()
    in_table = False
    headers = []
    for line in lines:
        if line.startswith("|") and "Status" in line:
            headers = [h.strip().lower() for h in line.split("|") if h.strip()]
            in_table = True
            continue
        if in_table and line.startswith("|") and "---" not in line:
            cells = [c.strip() for c in line.split("|")]
            while cells and not cells[0]:
                cells.pop(0)
            while cells and not cells[-1]:
                cells.pop()
            while len(cells) < len(headers):
                cells.append("")
            row = dict(zip(headers, cells))
            status = row.get("status", "").lower()
            if "paid" in status or "accept" in status or "confirmed" in status:
                paid.append({
                    "title": row.get("title", ""),
                    "severity": row.get("severity", "?"),
                    "status": row.get("status", ""),
                    "cantina_num": row.get("cantina #", "?"),
                })
        elif in_table and not line.startswith("|"):
            in_table = False
    return paid


def extract_keywords(text: str) -> set:
    """Extract searchable keywords from text."""
    keywords = set()
    text = text.lower()
    # Contract names
    for m in re.finditer(r'`([a-z_][a-z0-9_]*)`', text):
        keywords.add(m.group(1))
    for m in re.finditer(r'\b([a-z_][a-z0-9_]+)\.', text):
        keywords.add(m.group(1))
    # Bug class keywords
    for kw in ["reentrancy", "oracle", "timestamp", "delegatecall", "flash", "auth", "access", "race", "upgrade", "erc4626", "vault", "overflow", "selfdestruct"]:
        if kw in text:
            keywords.add(kw)
    return keywords


def score_migration(angle: Dict, paid_finding: Dict) -> Tuple[float, List[str]]:
    """Score how similar an angle is to a paid finding."""
    score = 0.0
    reasons = []
    
    angle_kw = extract_keywords(angle.get("title", ""))
    paid_kw = extract_keywords(paid_finding.get("title", ""))
    
    # Contract overlap
    overlap = angle_kw & paid_kw
    if overlap:
        contract_overlap = len(overlap) / max(len(angle_kw), len(paid_kw))
        score += contract_overlap * 50
        reasons.append(f"Shared keywords: {', '.join(overlap)}")
    
    # Same bug class
    angle_id = angle.get("id", "")
    bug_class_map = {
        "A-REENT": "reentrancy",
        "A-ORACLE": "oracle",
        "A-ERC4626": "erc4626",
        "A-FLASH": "flash",
        "A-TIMESTAMP": "timestamp",
        "A-DELEGATE": "delegatecall",
        "A-AUTH": "auth",
        "A-UPGRADE": "upgrade",
        "A-RACE": "race",
    }
    angle_bug = bug_class_map.get(angle_id, "")
    if angle_bug and angle_bug in paid_finding.get("title", "").lower():
        score += 30
        reasons.append(f"Same bug class: {angle_bug}")
    
    # Severity bonus
    angle_sev = angle.get("severity", "Medium")
    paid_sev = paid_finding.get("severity", "Medium")
    if angle_sev == paid_sev:
        score += 10
        reasons.append(f"Same severity: {angle_sev}")
    
    return score, reasons


def main() -> None:
    parser = argparse.ArgumentParser(description="Pattern migration alert")
    parser.add_argument("--audits-dir", type=Path, default=Path.home() / "audits")
    parser.add_argument("--min-score", type=float, default=25, help="Minimum alert score")
    parser.add_argument("--out", type=Path, help="Write report to file")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    workspaces = discover_workspaces(args.audits_dir)
    if not workspaces:
        print("[alert] No workspaces found")
        sys.exit(1)

    # Load all paid findings and all angles
    all_paid = {}  # ws_name -> [findings]
    all_angles = {}  # ws_name -> [angles]
    
    for ws in workspaces:
        paid = load_paid_findings(ws)
        angles = load_ccia_angles(ws)
        if paid:
            all_paid[ws.name] = paid
        if angles:
            all_angles[ws.name] = angles

    print(f"[alert] Analyzing {len(workspaces)} workspaces")
    print(f"[alert] Paid findings: {sum(len(v) for v in all_paid.values())}")
    print(f"[alert] CCIA angles: {sum(len(v) for v in all_angles.values())}")

    # Find migrations: unmined workspace angles that match paid findings in other workspaces
    alerts = []
    for ws_name, angles in all_angles.items():
        # Skip if this workspace already has paid findings (it's being mined)
        # Actually, we want to alert even on mined workspaces for new angles
        for angle in angles:
            for other_ws, paid_findings in all_paid.items():
                if other_ws == ws_name:
                    continue  # Same workspace
                for paid in paid_findings:
                    score, reasons = score_migration(angle, paid)
                    if score >= args.min_score:
                        alerts.append({
                            "target_ws": ws_name,
                            "angle": angle,
                            "source_ws": other_ws,
                            "paid_finding": paid,
                            "score": score,
                            "reasons": reasons,
                        })

    # Sort by score descending
    alerts.sort(key=lambda x: x["score"], reverse=True)

    if args.json:
        output = [
            {
                "target_ws": a["target_ws"],
                "angle_id": a["angle"]["id"],
                "angle_title": a["angle"]["title"],
                "source_ws": a["source_ws"],
                "paid_title": a["paid_finding"]["title"],
                "paid_severity": a["paid_finding"]["severity"],
                "score": a["score"],
                "reasons": a["reasons"],
            }
            for a in alerts[:20]
        ]
        print(json.dumps(output, indent=2))
    else:
        if not alerts:
            output = "\n".join([
                "[alert] No high-ROI pattern migrations detected.",
                "[alert] Run CCIA on more workspaces to find cross-bounty patterns.",
            ])
        else:
            lines = [f"[alert] {len(alerts)} high-ROI migration(s) detected:", ""]
            for i, a in enumerate(alerts[:15], 1):
                sev_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(a["angle"].get("severity", "Medium"), "⚪")
                lines.append(f"{i}. {sev_emoji} [{a['angle']['id']}] {a['angle']['title']}")
                lines.append(f"   📍 Target: {a['target_ws']} | 💰 Paid in: {a['source_ws']} #{a['paid_finding']['cantina_num']} ({a['paid_finding']['severity']})")
                lines.append(f"   📊 Score: {a['score']:.1f} | Reasons: {'; '.join(a['reasons'])}")
                lines.append(f"   🎯 Action: Mine {a['target_ws']} for {a['angle']['id']} — similar pattern was paid in {a['source_ws']}")
                lines.append("")
            output = "\n".join(lines).rstrip() + "\n"

    if args.out:
        args.out.write_text(output if isinstance(output, str) else json.dumps(output, indent=2))
        print(f"[alert] Report written to {args.out}")
    elif args.json:
        print(json.dumps(output, indent=2))
    else:
        print(output)
    sys.exit(0)


if __name__ == "__main__":
    main()
