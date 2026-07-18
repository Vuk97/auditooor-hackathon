#!/usr/bin/env python3
"""Inventory tracked documentation and stale-file cleanup candidates.

This tool is intentionally read-only. It gives cleanup work a repeatable
baseline before deletion PRs, so operators can review evidence instead of
guessing which files are historical, generated, or still live.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MD = ROOT / "docs" / "cleanup" / "STALE_FILE_INVENTORY_2026-04-28.md"
DEFAULT_JSON = ROOT / ".audit_logs" / "cleanup" / "stale_file_inventory_2026-04-28.json"

ITERATION_DOC_RE = re.compile(
    r"^(docs/)?("
    r"LOOP_ITER_|CAPABILITY_V3_ITER_|CAPV3_ITER|FIX[0-9]|FIX_CHECK|PR_[0-9]|"
    r"PACKAGER_.*ITER|WORKTREE_.*ITER|TOOLING_DEBT_.*ITER|TRIAGER_OUTCOMES_POST_ITER"
    r")"
)
PLAN_DOC_RE = re.compile(r"^(docs/)?(PLAN_|ROADMAP_|MEGAPLAN_|GIGAPLAN_)")
REPORT_DOC_RE = re.compile(r"(?:_REPORT|_AUDIT|_STATUS|_SUMMARY)\.md$")
GENERATED_LARGE_RE = re.compile(
    r"^(projects/.*/cica/(findings_raw\.jsonl|scan\.log|findings_triage\.md)|"
    r"agent_outputs/.*\.json|patterns/fixtures/auto/.*)"
)


def run_git(args: list[str]) -> str:
    proc = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def tracked_files() -> list[str]:
    return [line for line in run_git(["ls-files"]).splitlines() if line]


def file_size(path: str) -> int:
    try:
        return (ROOT / path).stat().st_size
    except OSError:
        return 0


def classify(path: str) -> set[str]:
    tags: set[str] = set()
    p = Path(path)
    if path.startswith("docs/archive/"):
        tags.add("archived-doc")
    if path.startswith("docs/") and p.suffix.lower() == ".md":
        tags.add("doc")
    if path.startswith("docs/") and ITERATION_DOC_RE.search(path.removeprefix("docs/")):
        tags.add("iteration-doc")
    if path.startswith("docs/") and PLAN_DOC_RE.search(path.removeprefix("docs/")):
        tags.add("plan-or-roadmap-doc")
    if path.startswith("docs/") and REPORT_DOC_RE.search(p.name):
        tags.add("report-status-doc")
    if path.startswith("docs/") and p.name in {"README.md", "WORKFLOW.md", "ENGAGE.md", "STAGE_REFERENCE.md", "TOOL_STATUS.md", "KNOWN_LIMITATIONS.md"}:
        tags.add("canonical-doc")
    if GENERATED_LARGE_RE.search(path):
        tags.add("generated-or-corpus-artifact")
    if p.suffix in {".pyc", ".pyo"} or "__pycache__" in p.parts:
        tags.add("cache")
    if file_size(path) >= 200_000:
        tags.add("large-tracked-file")
    return tags


def duplicate_archive_pairs(files: list[str]) -> list[dict[str, str]]:
    by_name: dict[str, list[str]] = defaultdict(list)
    for f in files:
        if f.startswith("docs/") and f.endswith(".md"):
            by_name[Path(f).name].append(f)
    pairs: list[dict[str, str]] = []
    for name, paths in sorted(by_name.items()):
        live = [p for p in paths if not p.startswith("docs/archive/")]
        archived = [p for p in paths if p.startswith("docs/archive/")]
        for l in live:
            for a in archived:
                pairs.append({"name": name, "live": l, "archive": a})
    return pairs


def build_inventory() -> dict[str, Any]:
    files = tracked_files()
    entries = []
    tag_counts: Counter[str] = Counter()
    dir_counts: Counter[str] = Counter()
    docs_by_family: Counter[str] = Counter()
    total_size = 0

    for path in files:
        size = file_size(path)
        tags = sorted(classify(path))
        total_size += size
        for tag in tags:
            tag_counts[tag] += 1
        dir_counts[path.split("/", 1)[0]] += 1
        if path.startswith("docs/") and path.endswith(".md"):
            if path.startswith("docs/archive/"):
                family = "archive"
            elif "ITER" in path or Path(path).name.startswith(("LOOP_ITER_", "CAPABILITY_V3_ITER_", "CAPV3_ITER")):
                family = "iteration-log"
            elif Path(path).name.startswith(("ROADMAP_", "PLAN_", "MEGAPLAN_", "GIGAPLAN_")):
                family = "plan-roadmap"
            elif Path(path).name.endswith(("_REPORT.md", "_STATUS.md", "_SUMMARY.md")):
                family = "report-status"
            else:
                family = "canonical-or-topic"
            docs_by_family[family] += 1
        if tags:
            entries.append({"path": path, "size": size, "tags": tags})

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": str(ROOT),
        "totals": {
            "tracked_files": len(files),
            "tracked_bytes": total_size,
            "tracked_docs": sum(1 for f in files if f.startswith("docs/") and f.endswith(".md")),
            "archived_docs": sum(1 for f in files if f.startswith("docs/archive/") and f.endswith(".md")),
        },
        "top_level_counts": dict(dir_counts.most_common()),
        "tag_counts": dict(tag_counts.most_common()),
        "docs_by_family": dict(docs_by_family.most_common()),
        "largest_tracked_files": sorted(
            ({"path": f, "size": file_size(f)} for f in files),
            key=lambda x: x["size"],
            reverse=True,
        )[:40],
        "duplicate_archive_pairs": duplicate_archive_pairs(files),
        "tagged_entries": sorted(entries, key=lambda x: (-x["size"], x["path"])),
    }


def human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.1f}{unit}" if unit != "B" else f"{size}B"
        size /= 1024
    return f"{size}B"


def table_rows(items: list[dict[str, Any]], columns: list[str], limit: int = 20) -> str:
    rows = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for item in items[:limit]:
        vals = []
        for col in columns:
            value = item.get(col, "")
            if col == "size":
                value = human_size(int(value))
            if isinstance(value, list):
                value = ", ".join(value)
            vals.append(str(value).replace("\n", " "))
        rows.append("| " + " | ".join(vals) + " |")
    return "\n".join(rows)


def render_markdown(inv: dict[str, Any]) -> str:
    totals = inv["totals"]
    dupes = inv["duplicate_archive_pairs"]
    tagged = inv["tagged_entries"]
    large_generated = [e for e in tagged if "generated-or-corpus-artifact" in e["tags"]]
    iteration_docs = [e for e in tagged if "iteration-doc" in e["tags"]]

    lines = [
        "# Stale File Inventory - 2026-04-28",
        "",
        "Read-only inventory generated by `tools/cleanup-inventory.py`. This report",
        "does not delete anything; it ranks cleanup surfaces so deletion PRs can be",
        "small, reviewable, and evidence-backed.",
        "",
        "## Summary",
        "",
        f"- Tracked files: `{totals['tracked_files']}`",
        f"- Tracked size: `{human_size(totals['tracked_bytes'])}`",
        f"- Tracked docs: `{totals['tracked_docs']}`",
        f"- Archived docs: `{totals['archived_docs']}`",
        f"- Duplicate live/archive doc basenames: `{len(dupes)}`",
        "",
        "## Top-Level File Counts",
        "",
    ]
    for name, count in list(inv["top_level_counts"].items())[:20]:
        lines.append(f"- `{name}`: `{count}`")
    lines += ["", "## Documentation Families", ""]
    for name, count in inv["docs_by_family"].items():
        lines.append(f"- `{name}`: `{count}`")
    lines += ["", "## Tagged Cleanup Surfaces", ""]
    for name, count in inv["tag_counts"].items():
        lines.append(f"- `{name}`: `{count}`")
    lines += [
        "",
        "## Largest Tracked Files",
        "",
        table_rows(inv["largest_tracked_files"], ["path", "size"], limit=25),
        "",
        "## Generated Or Corpus Artifacts",
        "",
        table_rows(large_generated, ["path", "size", "tags"], limit=25),
        "",
        "## Iteration / One-Off Docs",
        "",
        table_rows(iteration_docs, ["path", "size", "tags"], limit=40),
        "",
        "## Duplicate Live/Archive Doc Names",
        "",
    ]
    if dupes:
        lines.append(table_rows(dupes, ["name", "live", "archive"], limit=40))
    else:
        lines.append("_None detected._")
    lines += [
        "",
        "## First Safe Cleanup Decisions",
        "",
        "- Keep `/Users/wolf/audits/*` out of repo cleanup.",
        "- Treat `projects/*/cica/*.jsonl` and `patterns/fixtures/auto/*` as corpus",
        "  artifacts, not disposable cache, until the mining pipeline has an archive path.",
        "- Move or consolidate iteration logs only after their summaries are represented",
        "  in canonical docs such as `docs/LOOP_INDEX.md`, `docs/CURRENT_STATE.md`,",
        "  `docs/ROADMAP_10_OF_10_V*.md`, or `docs/KNOWN_LIMITATIONS.md`.",
        "- Machine-readable JSON is written under `.audit_logs/cleanup/` by default",
        "  so it can be compared locally without adding tracked repository bulk.",
        "- Deletion PRs should be narrow: one family at a time, with this inventory",
        "  regenerated before and after.",
        "",
    ]
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_MD)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    inv = build_inventory()
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(render_markdown(inv), encoding="utf-8")
    if args.print_json:
        print(json.dumps(inv["totals"], indent=2, sort_keys=True))
    else:
        print(f"wrote {args.out_md}")
        print(f"wrote {args.out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
