#!/usr/bin/env python3
"""
cross-ws-pattern-mapper.py — Cross-workspace pattern migration tool

Maps attack patterns (from CCIA attack angles) across all audit workspaces
to identify which bug classes have been found where, and which workspaces
still have unmined surfaces.

Usage:
    cross-ws-pattern-mapper.py [--audits-dir ~/audits] [--generate-ccia]
    cross-ws-pattern-mapper.py --pattern A-ORACLE
    cross-ws-pattern-mapper.py --suggest

Output:
    - Pattern matrix: which workspaces have each attack angle
    - Suggestions: unmined workspaces ranked by pattern overlap with paid findings
    - Actionable briefs: "Mine <workspace> for <pattern> — similar to <paid_finding>"
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent
CCIA_TOOL = AUDITOOOR_DIR / "tools" / "ccia.py"
STATE_TOOL = AUDITOOOR_DIR / "tools" / "workspace-state.py"


def discover_workspaces(audits_dir: Path) -> List[Path]:
    """Find all workspace directories under ~/audits."""
    if not audits_dir.exists():
        return []
    workspaces = []
    for entry in audits_dir.iterdir():
        if entry.is_dir() and not entry.name.startswith("."):
            # Skip test/dogfood workspaces
            if "test" in entry.name.lower() or "dogfood" in entry.name.lower():
                continue
            # Heuristic: must have src/ or submissions/ or AUDIT.md
            if any((entry / marker).exists() for marker in ("src", "submissions", "AUDIT.md", "OOS_CHECKLIST.md")):
                workspaces.append(entry)
    return sorted(workspaces)


def get_workspace_state(ws: Path) -> Dict[str, Any]:
    """Read workspace phase/state from workspace-state.py."""
    try:
        out = subprocess.run(
            [sys.executable, str(STATE_TOOL), "get", str(ws)],
            capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            return json.loads(out.stdout)
    except Exception:
        pass
    return {"phase": 1, "phase_name": "orient", "findings_count": 0, "submissions_count": 0, "status": "active"}


def load_or_generate_ccia(ws: Path, generate: bool = False) -> Optional[List[Dict]]:
    """Load CCIA attack angles for a workspace. Generate if missing and requested."""
    # Check for existing JSON report
    json_report = ws / "ccia_report.json"
    md_report = ws / "ccia_report.md"

    if json_report.exists():
        try:
            data = json.loads(json_report.read_text())
            if isinstance(data, list):
                return data  # --attack-angles outputs a raw list
            return data.get("attack_angles", [])
        except Exception:
            pass

    if md_report.exists():
        # Try to extract attack angles from markdown
        return parse_attack_angles_from_md(md_report.read_text())

    if generate and CCIA_TOOL.exists():
        print(f"[mapper] Generating CCIA for {ws.name} ...")
        src_dir = ws / "src"
        if not src_dir.exists():
            src_dir = ws  # fallback
        try:
            subprocess.run(
                [sys.executable, str(CCIA_TOOL), str(ws), "--attack-angles", "--out", str(json_report)],
                capture_output=True, timeout=120
            )
            if json_report.exists():
                data = json.loads(json_report.read_text())
                return data.get("attack_angles", [])
        except Exception as e:
            print(f"[mapper] CCIA generation failed for {ws.name}: {e}")
            return None

    return None


def parse_attack_angles_from_md(text: str) -> List[Dict]:
    """Extract attack angles from a markdown CCIA report."""
    angles = []
    lines = text.splitlines()
    for line in lines:
        # Look for lines like "### A-ORACLE — MEDIUM — Oracle manipulation surface: Foo.getPrice"
        m = re.match(r'###\s+(A-[A-Z0-9]+)\s+—\s+(\w+)\s+—\s+(.+)', line)
        if m:
            angles.append({
                "id": m.group(1),
                "severity": m.group(2),
                "title": m.group(3),
            })
    return angles


def build_pattern_matrix(workspaces: List[Path], generate_ccia: bool = False) -> Dict[str, Any]:
    """Build a matrix of patterns × workspaces."""
    matrix = defaultdict(lambda: {"workspaces": [], "angles": []})
    workspace_patterns = {}

    for ws in workspaces:
        angles = load_or_generate_ccia(ws, generate_ccia)
        if angles is None:
            continue
        workspace_patterns[ws.name] = angles
        for angle in angles:
            pat_id = angle["id"]
            matrix[pat_id]["workspaces"].append(ws.name)
            matrix[pat_id]["angles"].append({
                "workspace": ws.name,
                "title": angle.get("title", ""),
                "severity": angle.get("severity", "MEDIUM"),
                "contracts": angle.get("contracts", []),
            })

    return dict(matrix), workspace_patterns


def suggest_next_mines(matrix: Dict, workspaces: List[Path]) -> List[Dict]:
    """Suggest which workspaces to mine next based on pattern overlap."""
    suggestions = []

    # Get state for each workspace
    ws_states = {ws.name: get_workspace_state(ws) for ws in workspaces}

    # For each pattern, find workspaces that HAVE the pattern but are not yet mined
    for pat_id, data in matrix.items():
        found_in = set(data["workspaces"])
        # Workspaces with this pattern that are early-phase (not yet synthesized)
        unmined = []
        for ws_name in found_in:
            state = ws_states.get(ws_name, {})
            phase = state.get("phase", 1)
            if phase < 6:  # Not yet synthesized/submitted
                unmined.append({
                    "workspace": ws_name,
                    "phase": phase,
                    "phase_name": state.get("phase_name", "?"),
                    "angles": [a for a in data["angles"] if a["workspace"] == ws_name],
                })

        if unmined:
            # Score by severity (HIGH = 3, MEDIUM = 2, LOW = 1)
            max_sev = max(
                {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "CRITICAL": 4}.get(a["severity"], 1)
                for a in data["angles"]
            )
            suggestions.append({
                "pattern": pat_id,
                "found_in": sorted(found_in),
                "unmined": unmined,
                "score": max_sev * len(unmined),
                "max_severity": max_sev,
            })

    # Sort by score descending
    suggestions.sort(key=lambda x: x["score"], reverse=True)
    return suggestions


def render_report(matrix: Dict, suggestions: List[Dict], workspace_patterns: Dict) -> str:
    """Render a markdown report."""
    lines = []
    lines.append("# Cross-Workspace Pattern Migration Report")
    lines.append("")
    lines.append(f"**Generated:** {__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat()}")
    lines.append(f"**Workspaces analyzed:** {len(workspace_patterns)}")
    lines.append(f"**Unique patterns:** {len(matrix)}")
    lines.append("")

    # Pattern matrix
    lines.append("## Pattern Matrix")
    lines.append("")
    lines.append("| Pattern | Severity | Workspaces | Count |")
    lines.append("|---|---|---|---|")
    for pat_id in sorted(matrix.keys()):
        data = matrix[pat_id]
        # Infer max severity
        sevs = [a["severity"] for a in data["angles"]]
        max_sev = max(sevs, key=lambda s: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(s, 0))
        ws_list = ", ".join(sorted(set(data["workspaces"])))
        lines.append(f"| {pat_id} | {max_sev} | {ws_list} | {len(data['workspaces'])} |")
    lines.append("")

    # Suggestions
    if suggestions:
        lines.append("## Suggested Next Mines")
        lines.append("")
        for sug in suggestions[:15]:
            lines.append(f"### {sug['pattern']} (score: {sug['score']})")
            lines.append(f"- **Found in:** {', '.join(sug['found_in'])}")
            lines.append(f"- **Unmined workspaces:**")
            for u in sug["unmined"]:
                lines.append(f"  - `{u['workspace']}` (phase {u['phase']}: {u['phase_name']})")
                for a in u["angles"][:3]:
                    lines.append(f"    - {a['severity']}: {a['title']}")
            lines.append("")

    # Workspace detail
    lines.append("## Per-Workspace Pattern Inventory")
    lines.append("")
    for ws_name in sorted(workspace_patterns.keys()):
        angles = workspace_patterns[ws_name]
        if not angles:
            continue
        lines.append(f"### {ws_name}")
        for angle in angles:
            lines.append(f"- **{angle['id']}** ({angle.get('severity', '?')}) — {angle.get('title', '')}")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Cross-workspace pattern migration mapper")
    parser.add_argument("--audits-dir", type=Path, default=Path.home() / "audits",
                        help="Directory containing audit workspaces (default: ~/audits)")
    parser.add_argument("--generate-ccia", action="store_true",
                        help="Generate CCIA reports for workspaces that lack them")
    parser.add_argument("--pattern", help="Filter to a specific pattern ID (e.g., A-ORACLE)")
    parser.add_argument("--suggest", action="store_true",
                        help="Only show suggestions (unmined workspaces)")
    parser.add_argument("--out", type=Path, help="Write report to file")
    parser.add_argument("--json", action="store_true", help="Output JSON instead of markdown")
    args = parser.parse_args()

    workspaces = discover_workspaces(args.audits_dir)
    if not workspaces:
        print(f"[mapper] No workspaces found in {args.audits_dir}")
        sys.exit(1)

    print(f"[mapper] Analyzing {len(workspaces)} workspace(s) ...")
    matrix, workspace_patterns = build_pattern_matrix(workspaces, args.generate_ccia)

    if args.pattern:
        if args.pattern not in matrix:
            print(f"[mapper] Pattern {args.pattern} not found in any workspace")
            sys.exit(1)
        data = matrix[args.pattern]
        print(f"Pattern {args.pattern} found in: {', '.join(sorted(set(data['workspaces'])))}")
        for a in data["angles"]:
            print(f"  {a['workspace']}: {a['severity']} — {a['title']}")
        sys.exit(0)

    suggestions = suggest_next_mines(matrix, workspaces)

    if args.json:
        output = json.dumps({
            "matrix": matrix,
            "suggestions": suggestions,
            "workspace_patterns": {k: [{"id": a["id"], "severity": a.get("severity"), "title": a.get("title")} for a in v]
                                 for k, v in workspace_patterns.items()},
        }, indent=2)
    else:
        output = render_report(matrix, suggestions, workspace_patterns)

    if args.out:
        args.out.write_text(output)
        print(f"[mapper] Report written to {args.out}")
    else:
        print(output)


if __name__ == "__main__":
    main()
