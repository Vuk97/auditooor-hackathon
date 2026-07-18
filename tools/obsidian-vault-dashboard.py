#!/usr/bin/env python3
"""obsidian-vault-dashboard.py — Generate obsidian-vault/DASHBOARD.md.

Reads the vault's .last_sync.json + canonical source stats to produce a
top-level, Dataview-rich dashboard that an agent can read in 30 seconds and
know the full state of the auditooor project.

Usage:
    python3 tools/obsidian-vault-dashboard.py [--vault-dir <path>]
    python3 tools/obsidian-vault-dashboard.py --dry-run  # print to stdout only
"""
from __future__ import annotations

import argparse
import datetime as _dt
import glob
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Repo layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
INVENTORY_DIR = Path("/private/tmp/auditooor-inventory")


def _now() -> str:
    return _dt.datetime.now(tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:%MZ")


def _read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Data gathering
# ---------------------------------------------------------------------------

def _gather_vault_sync(vault: Path) -> dict:
    """Read vault/.last_sync.json for note counts."""
    sync_path = vault / ".last_sync.json"
    d = _read_json(sync_path)
    if isinstance(d, dict):
        return d
    return {}


def _gather_pr_count() -> str:
    """Best-effort PR count from docs."""
    docs = REPO_ROOT / "docs"
    best = "unknown"
    # Look for highest PR number in any doc
    max_pr = 0
    for f in sorted(docs.glob("*.md"))[-20:]:  # only last 20 alphabetically
        text = _read_text(f)
        for m in re.finditer(r"PR #(\d{3,})", text):
            n = int(m.group(1))
            if n > max_pr:
                max_pr = n
    if max_pr > 0:
        best = f"≥{max_pr}"
    return best


def _gather_detector_count() -> dict:
    """Read detectors/_tier_registry.yaml for tier breakdown."""
    reg_path = REPO_ROOT / "detectors" / "_tier_registry.yaml"
    if not reg_path.exists():
        return {}
    try:
        import yaml
        raw = yaml.safe_load(reg_path.read_text(encoding="utf-8", errors="replace"))
        if not isinstance(raw, dict) or "tiers" not in raw:
            return {}
        tiers = raw["tiers"]
        counts: dict[str, int] = {}
        verified_count = 0
        for det_id, info in tiers.items():
            if not isinstance(info, dict):
                continue
            tier = str(info.get("tier", "?")).upper()
            counts[tier] = counts.get(tier, 0) + 1
            if info.get("verified"):
                verified_count += 1
        counts["_verified"] = verified_count
        counts["_total"] = len(tiers)
        return counts
    except Exception:
        return {}


def _gather_loop_progress() -> list[dict]:
    """Read all *.progress.json from INVENTORY_DIR."""
    if not INVENTORY_DIR.is_dir():
        return []
    results = []
    for pj in sorted(INVENTORY_DIR.glob("*.progress.json")):
        d = _read_json(pj)
        if not isinstance(d, dict):
            continue
        total = d.get("total", 0)
        done = d.get("done", 0)
        failed = d.get("failed", 0)
        skipped = d.get("skipped", 0)
        ts = str(d.get("ts", d.get("last_run", "")))
        pct = round(done / total * 100, 1) if total else 0.0
        status = "complete" if (total > 0 and done >= total) else ("in-progress" if done > 0 else "not-started")
        results.append({
            "name": pj.stem.replace(".progress", ""),
            "total": total,
            "done": done,
            "failed": failed,
            "skipped": skipped,
            "pct": pct,
            "status": status,
            "ts": ts,
        })
    return results


def _gather_stale_sources(vault: Path) -> list[str]:
    """
    Find sources whose mtime is newer than their vault note.
    Returns list of warning strings.
    """
    warnings: list[str] = []
    sync = _gather_vault_sync(vault)
    if not sync:
        return ["[!] No .last_sync.json - run make vault-refresh first."]

    generated_str = sync.get("generated", "")
    if not generated_str:
        return []
    try:
        generated_ts = _dt.datetime.strptime(generated_str, "%Y-%m-%dT%H:%MZ").replace(
            tzinfo=_dt.timezone.utc
        )
    except Exception:
        return []

    sources_to_check = [
        REPO_ROOT / "detectors" / "_tier_registry.yaml",
        REPO_ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json",
        REPO_ROOT / "docs" / "KNOWN_LIMITATIONS.md",
    ]
    for src in sources_to_check:
        if not src.exists():
            continue
        mtime = _dt.datetime.fromtimestamp(src.stat().st_mtime, tz=_dt.timezone.utc)
        if mtime > generated_ts:
            delta = mtime - generated_ts
            warnings.append(
                f"`{src.relative_to(REPO_ROOT)}` modified {int(delta.total_seconds() // 60)}m after last vault sync"
            )
    return warnings


def _gather_top_recent_notes(vault: Path, n: int = 10) -> list[tuple[str, str]]:
    """Return top N most recently modified vault notes as (relpath, mtime_str)."""
    if not vault.is_dir():
        return []
    results = []
    for md in vault.rglob("*.md"):
        if md.name.startswith("."):
            continue
        try:
            mtime = md.stat().st_mtime
            mtime_str = _dt.datetime.utcfromtimestamp(mtime).strftime("%Y-%m-%dT%H:%MZ")
            rel = str(md.relative_to(vault))
            results.append((rel, mtime_str, mtime))
        except Exception:
            pass
    results.sort(key=lambda x: x[2], reverse=True)
    return [(rel, mtime_str) for rel, mtime_str, _ in results[:n]]


def _gather_p0_p1_limitations() -> list[dict]:
    """Top open P0/P1 limitations from burndown JSON."""
    bp = REPO_ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
    d = _read_json(bp)
    if not isinstance(d, dict):
        return []
    rows = d.get("rows", [])
    open_rows = [
        r for r in rows
        if isinstance(r, dict) and not r.get("stop_condition_met", False)
        and r.get("priority_group", "") in ("current_priority", "p0", "p1", "priority-0", "priority-1")
    ]
    return open_rows[:5]


def _gather_pattern_count() -> int:
    """Count total DSL pattern YAMLs across all rounds."""
    ref = REPO_ROOT / "reference"
    total = 0
    for d in ref.iterdir():
        if d.is_dir() and d.name.startswith("patterns.dsl") and not d.name.endswith(".PROMOTED"):
            total += len(list(d.glob("*.yaml")))
    return total


# ---------------------------------------------------------------------------
# Dashboard generation
# ---------------------------------------------------------------------------

def build_dashboard(vault: Path, dry_run: bool = False) -> str:
    """Build DASHBOARD.md content and return it as a string."""
    now = _now()
    sync = _gather_vault_sync(vault)
    det_counts = _gather_detector_count()
    loops = _gather_loop_progress()
    stale = _gather_stale_sources(vault)
    recent_notes = _gather_top_recent_notes(vault, 10)
    open_lims = _gather_p0_p1_limitations()
    pr_count = _gather_pr_count()
    pattern_count = _gather_pattern_count()

    total_notes = sync.get("total_notes", sum(sync.get("stats", {}).values()))
    bytes_mb = round(sync.get("bytes_written", 0) / (1024 * 1024), 2)
    last_sync = sync.get("generated", "never")

    det_total = det_counts.get("_total", "?")
    det_verified = det_counts.get("_verified", "?")
    det_s = det_counts.get("S", 0)
    det_a = det_counts.get("A", 0)
    det_b = det_counts.get("B", 0)
    det_d = det_counts.get("D", 0)

    in_progress_loops = [l for l in loops if l["status"] == "in-progress"]
    complete_loops = [l for l in loops if l["status"] == "complete"]

    lines: list[str] = []

    # Frontmatter
    lines += [
        "---",
        f'title: "Auditooor Dashboard"',
        f'generated: "{now}"',
        f'total_notes: "{total_notes}"',
        f'vault_size_mb: "{bytes_mb}"',
        f'last_sync: "{last_sync}"',
        f'pr_count: "{pr_count}"',
        f'verified_detectors: "{det_verified}"',
        f'in_flight_loops: "{len(in_progress_loops)}"',
        "tags:",
        "  - dashboard",
        "  - index",
        "---",
        "",
        "# Auditooor Dashboard",
        "",
        f"_Generated: {now}  |  Last vault sync: {last_sync}_",
        "",
    ]

    # ----------------------------------------------------------------
    # Section 1: Project snapshot
    # ----------------------------------------------------------------
    lines += [
        "## Project Snapshot",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| PR cycle count | {pr_count} |",
        f"| Total detector rows | {det_total} |",
        f"| Verified detectors (A/B/S) | {det_verified} |",
        f"| Tier-S | {det_s} |",
        f"| Tier-A | {det_a} |",
        f"| Tier-B | {det_b} |",
        f"| Tier-D | {det_d} |",
        f"| Total DSL patterns | {pattern_count} |",
        f"| Vault notes | {total_notes} |",
        f"| Vault size | {bytes_mb} MB |",
        "",
    ]

    # ----------------------------------------------------------------
    # Section 2: In-flight overnight loops
    # ----------------------------------------------------------------
    lines += ["## In-Flight Overnight Loops", ""]
    if in_progress_loops:
        lines += [
            "| Loop | Done | Total | % | Failed | Last Run |",
            "|------|------|-------|---|--------|----------|",
        ]
        for lp in in_progress_loops:
            vault_link = f"[[mining/progress/{lp['name'].replace('_queue', '-queue')}]]"
            lines.append(
                f"| {vault_link} | {lp['done']} | {lp['total']} | {lp['pct']}% "
                f"| {lp['failed']} | {lp['ts']} |"
            )
        lines.append("")
    else:
        lines += ["> No in-progress loops. All complete or none running.", ""]

    if complete_loops:
        lines += [f"**Completed loops:** {len(complete_loops)} - see [[mining/INDEX]]", ""]

    # ----------------------------------------------------------------
    # Section 3: Top 10 most recently modified vault notes
    # ----------------------------------------------------------------
    lines += ["## Top 10 Recently Modified Notes", ""]
    if recent_notes:
        lines += [
            "| Note | Modified |",
            "|------|----------|",
        ]
        for rel, mtime_str in recent_notes:
            note_name = rel.replace(".md", "").replace("/", "/")
            lines.append(f"| [[{note_name}]] | {mtime_str} |")
        lines.append("")
    else:
        lines += ["> Vault not built yet - run `make vault-refresh` first.", ""]

    # ----------------------------------------------------------------
    # Section 4: Stale-source warnings
    # ----------------------------------------------------------------
    lines += ["## Stale-Source Warnings", ""]
    if stale:
        for w in stale:
            lines.append(f"> [!warning] {w}")
        lines.append("")
        lines += [
            "_Run `make vault-refresh` or `make vault-deepen` to update._",
            "",
        ]
    else:
        lines += ["> [!success] All tracked sources are up-to-date with the vault.", ""]

    # ----------------------------------------------------------------
    # Section 5: Top 5 open P0/P1 limitations
    # ----------------------------------------------------------------
    lines += ["## Top Open Limitations (P0/P1)", ""]
    if open_lims:
        for lim in open_lims:
            lim_id = lim.get("limitation_id", "?")
            title = lim.get("title", lim_id)
            priority = lim.get("priority_group", "?")
            stop = lim.get("stop_condition", "")[:120]
            lim_slug = re.sub(r"[^\w\s-]", "", (lim_id + "-" + title).lower())
            lim_slug = re.sub(r"[\s_]+", "-", lim_slug).strip("-")[:80]
            lines += [
                f"### {title}",
                "",
                f"**ID:** `{lim_id}`  |  **Priority:** {priority}",
            ]
            if stop:
                lines += [f"**Stop condition:** {stop}", ""]
            lines += [f"See: [[limitations/deep/{lim_slug}]]", ""]
    else:
        lines += ["> No open P0/P1 limitations found.", ""]

    # ----------------------------------------------------------------
    # Section 6: Navigation + Dataview queries
    # ----------------------------------------------------------------
    lines += [
        "## Navigation",
        "",
        "- [[INDEX_active]] - Live status entry-point (start here for cold onboarding)",
        "- [[INDEX]] - Vault top-level index",
        "- [[patterns/INDEX]] - All DSL patterns",
        "- [[detectors/INDEX]] - All detectors by wave",
        "- [[findings/INDEX]] - Per-workspace findings",
        "- [[r-rounds/INDEX]] - DSL round directories",
        "- [[mining/INDEX]] - Mining sources + progress",
        "- [[agent-runs/INDEX]] - Agent output dirs",
        "- [[limitations/INDEX]] - Known limitations",
        "- [[tasks/active/index]] - Active tasks",
        "- [[agent-memory/INDEX]] - Agent memory",
        "",
        "## Dataview Queries",
        "",
        "### Verified Tier-B+ detectors",
        "```dataview",
        "TABLE id, engine, wave",
        'FROM "detectors"',
        'WHERE verified = "true" AND (contains(tags, "tier/b") OR contains(tags, "tier/a") OR contains(tags, "tier/s"))',
        "SORT id ASC",
        "LIMIT 20",
        "```",
        "",
        "### In-progress mining loops",
        "```dataview",
        "TABLE loop_id, done, total, pct_done, last_run",
        'FROM "mining/progress"',
        'WHERE status = "in-progress"',
        "SORT pct_done DESC",
        "```",
        "",
        "### Open limitations",
        "```dataview",
        "TABLE title, priority_group, stop_condition_met",
        'FROM "limitations/deep"',
        'WHERE stop_condition_met = false',
        "SORT priority_group ASC",
        "```",
        "",
        "### Critical / High findings",
        "```dataview",
        "TABLE title, workspace",
        'FROM "findings"',
        'WHERE contains(tags, "severity/critical") OR contains(tags, "severity/high")',
        "```",
        "",
        "### R-rounds with most patterns",
        "```dataview",
        "TABLE round_num, class_part, yaml_count, is_promoted",
        'FROM "r-rounds"',
        "SORT yaml_count DESC",
        "LIMIT 15",
        "```",
        "",
    ]

    # ----------------------------------------------------------------
    # Footer
    # ----------------------------------------------------------------
    note_cats = sync.get("stats", {})
    if note_cats:
        lines += ["## Note Count by Category", "", "| Category | Count |", "|----------|-------|"]
        for cat, n in sorted(note_cats.items()):
            lines.append(f"| {cat} | {n} |")
        lines += [f"| **TOTAL** | **{total_notes}** |", ""]

    lines += [
        f"_Vault built from `{REPO_ROOT}` · `make vault-refresh` / `make vault-deepen` to rebuild_",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate obsidian-vault/DASHBOARD.md from vault state + canonical sources."
    )
    parser.add_argument(
        "--vault-dir",
        type=Path,
        default=VAULT_DEFAULT,
        help="Path to vault directory (default: obsidian-vault/ in repo root)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print dashboard to stdout instead of writing to vault",
    )
    args = parser.parse_args()

    vault = args.vault_dir.resolve()
    dashboard_content = build_dashboard(vault, args.dry_run)

    if args.dry_run:
        print(dashboard_content)
    else:
        vault.mkdir(parents=True, exist_ok=True)
        out = vault / "DASHBOARD.md"
        out.write_text(dashboard_content, encoding="utf-8")
        lines = dashboard_content.splitlines()
        print(f"[obsidian-vault-dashboard] Written to {out}")
        print(f"  Lines: {len(lines)}")
        print("\n--- Top 15 lines ---")
        for line in lines[:15]:
            print(line)


if __name__ == "__main__":
    main()
