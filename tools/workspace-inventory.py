#!/usr/bin/env python3
"""Inventory local auditooor workspaces without committing private artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from submission_counts import summarize_workspace

STATE_FILE = Path.home() / ".auditooor" / "workspace_state.json"

ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("src", "src"),
    ("foundry", "foundry.toml"),
    ("engage", "engage_report.md"),
    ("ccia", "ccia_report.md"),
    ("skill", ".skill_state.yaml"),
    ("retro", "RETROSPECTIVE.md"),
    ("subs", "submissions/SUBMISSIONS.md"),
    ("clean", "submissions/clean"),
    ("eclean", "submissions/engage_candidates/clean"),
    ("packaged", "submissions/packaged"),
    ("staging", "submissions/staging"),
    ("pocs", "poc-tests"),
    ("agents", "agent_outputs"),
    ("swarm", "swarm"),
)


def _load_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text())
    except json.JSONDecodeError:
        return {}
    out: dict[str, Any] = {}
    for ws in data.get("workspaces", {}).values():
        path = ws.get("path")
        if path:
            out[str(Path(path).expanduser().resolve())] = ws
    return out


def _count_markdown(path: Path) -> int:
    if not path.is_dir():
        return 0
    return len([p for p in path.glob("*.md") if p.is_file()])


def _workspace_row(path: Path, state: dict[str, Any]) -> dict[str, Any]:
    resolved = path.resolve()
    state_row = state.get(str(resolved), {})
    submission_summary = summarize_workspace(resolved)
    artifacts: dict[str, bool | int] = {}
    for key, rel in ARTIFACTS:
        target = resolved / rel
        if key in {"clean", "eclean", "packaged", "staging", "pocs", "agents"}:
            artifacts[key] = _count_markdown(target) if key != "pocs" else len(list(target.glob("*.t.sol"))) if target.is_dir() else 0
        else:
            artifacts[key] = target.exists()

    submissions = submission_summary["submitted"]
    if submission_summary["source_kind"] == "missing":
        submissions = state_row.get("submissions_count", 0)

    return {
        "name": state_row.get("name") or resolved.name,
        "path": str(resolved),
        "phase": state_row.get("phase"),
        "phase_name": state_row.get("phase_name"),
        "findings": state_row.get("findings_count", 0),
        "submissions": submissions,
        "status": state_row.get("status"),
        "updated_at": state_row.get("updated_at"),
        "artifacts": artifacts,
        "submission_summary": submission_summary,
    }


def _discover(audits_dir: Path) -> list[Path]:
    if not audits_dir.is_dir():
        return []
    out: list[Path] = []
    for child in sorted(audits_dir.iterdir()):
        if child.name.startswith(".") or not child.is_dir():
            continue
        out.append(child)
    return out


def _flag(value: bool | int) -> str:
    if isinstance(value, bool):
        return "Y" if value else "-"
    return str(value) if value else "-"


def _looks_like_workspace(row: dict[str, Any]) -> bool:
    if row.get("phase") is not None:
        return True
    artifacts = row["artifacts"]
    return any(bool(value) for value in artifacts.values())


def _print_table(rows: list[dict[str, Any]], audits_dir: Path, skipped: int) -> None:
    print(f"Workspace inventory: {audits_dir.expanduser()}")
    if not rows:
        print("No workspace directories found.")
        if skipped:
            print(f"Skipped {skipped} direct child directories with no auditooor artifacts.")
        return

    headers = ["Workspace", "Phase", "Find", "Subs", "src", "engage", "ccia", "clean", "ec", "pkg", "pocs", "agents", "swarm"]
    widths = [22, 18, 5, 4, 3, 6, 4, 5, 2, 3, 4, 6, 5]
    print(" ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("-" * (sum(widths) + len(widths) - 1))
    for row in rows:
        artifacts = row["artifacts"]
        phase = "-"
        if row.get("phase") is not None:
            phase = f"{row['phase']}: {row.get('phase_name') or '?'}"
        cells = [
            row["name"][: widths[0]],
            phase[: widths[1]],
            str(row.get("findings", 0)),
            str(row.get("submissions", 0)),
            _flag(artifacts["src"]),
            _flag(artifacts["engage"]),
            _flag(artifacts["ccia"]),
            _flag(artifacts["clean"]),
            _flag(artifacts["eclean"]),
            _flag(artifacts["packaged"]),
            _flag(artifacts["pocs"]),
            _flag(artifacts["agents"]),
            _flag(artifacts["swarm"]),
        ]
        print(" ".join(c.ljust(w) for c, w in zip(cells, widths)))

    print(f"\nState file: {STATE_FILE}")
    print("Legend: Y=artifact exists, -=missing, counts=markdown/test files in directory.")
    if skipped:
        print(f"Skipped {skipped} direct child directories with no auditooor artifacts. Use --all to include them.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory local audit workspaces")
    parser.add_argument("--audits-dir", default="~/audits", help="Directory containing audit workspaces")
    parser.add_argument("--all", action="store_true", help="Include directories with no auditooor artifacts")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    audits_dir = Path(args.audits_dir).expanduser()
    state = _load_state()
    raw_rows = [_workspace_row(path, state) for path in _discover(audits_dir)]
    rows = raw_rows if args.all else [row for row in raw_rows if _looks_like_workspace(row)]
    skipped = len(raw_rows) - len(rows)

    if args.json:
        print(json.dumps({
            "audits_dir": str(audits_dir),
            "skipped_unrecognized": skipped,
            "workspaces": rows,
        }, indent=2))
    else:
        _print_table(rows, audits_dir, skipped)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
