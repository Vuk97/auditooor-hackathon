#!/usr/bin/env python3
"""memory-rollup-weekly.py — Layer L2 weekly rollup aggregator.

Aggregates 7 daily rollups into a weekly summary with trend lines.

Usage:
    python3 tools/memory-rollup-weekly.py [--week YYYY-W##] [--vault-dir <path>]
    python3 tools/memory-rollup-weekly.py --backfill 4   # last N weeks

Output:
    obsidian-vault/rollups/weekly/<YYYY-W##>.md

Sources read (all read-only):
    obsidian-vault/rollups/daily/<YYYY-MM-DD>.md  (7 daily rollups for the week)

Constraints:
    - No LLM calls — trends computed from frontmatter counts
    - Output capped at 200 KB
    - Idempotent: regenerating overwrites cleanly
    - If fewer than 7 daily rollups exist for the week, generates from available data
      and surfaces a coverage notice
"""
from __future__ import annotations

import argparse
import datetime as _dt
import re
import sys
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
OUTPUT_CAP_BYTES = 200 * 1024  # 200 KB


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _week_dates(iso_week: str) -> list[str]:
    """Return 7 ISO date strings for a given YYYY-W## week (Mon–Sun)."""
    year, wnum = iso_week.split("-W")
    # ISO week: week 1 is the week with the year's first Thursday
    # Monday of that week:
    monday = _dt.date.fromisocalendar(int(year), int(wnum), 1)
    return [(monday + _dt.timedelta(days=i)).isoformat() for i in range(7)]


def _current_week() -> str:
    """Return YYYY-W## for today's ISO week."""
    today = _dt.date.today()
    return f"{today.isocalendar()[0]}-W{today.isocalendar()[1]:02d}"


def _week_for_date(date_str: str) -> str:
    d = _dt.date.fromisoformat(date_str)
    iso = d.isocalendar()
    return f"{iso[0]}-W{iso[1]:02d}"


# ---------------------------------------------------------------------------
# Frontmatter parser
# ---------------------------------------------------------------------------

def _parse_frontmatter(text: str) -> dict[str, Any]:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end == -1:
        return {}
    fm_text = text[3:end].strip()
    try:
        return yaml.safe_load(fm_text) or {}
    except Exception:
        return {}


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Load daily rollups
# ---------------------------------------------------------------------------

def _load_daily_rollup(date_str: str, vault_dir: Path) -> dict[str, Any] | None:
    """Load a single daily rollup note and return its frontmatter + parsed data."""
    p = vault_dir / "rollups" / "daily" / f"{date_str}.md"
    if not p.exists():
        return None
    text = _read(p)
    fm = _parse_frontmatter(text)
    # Extract TL;DR bullets
    tldr_match = re.search(r"## TL;DR\n\n(.*?)(?=^##|\Z)", text, re.DOTALL | re.MULTILINE)
    tldr_bullets: list[str] = []
    if tldr_match:
        for line in tldr_match.group(1).splitlines():
            if line.startswith("- "):
                tldr_bullets.append(line[2:].strip())
    # Extract M14 incidents
    m14_match = re.search(r"## M14-Trap Incidents\n\n(.*?)(?=^##|\Z)", text, re.DOTALL | re.MULTILINE)
    m14_lines: list[str] = []
    if m14_match:
        for line in m14_match.group(1).splitlines():
            if line.startswith("- "):
                m14_lines.append(line[2:].strip())
    return {
        "date": date_str,
        "fm": fm,
        "path": p,
        "verified_count": int(fm.get("verified_detector_count", 0)),
        "commit_count": int(fm.get("commit_count", 0)),
        "pr_count": int(fm.get("pr_count", 0)),
        "error_source_count": int(fm.get("error_source_count", 0)),
        "agent_run_count": int(fm.get("agent_run_count", 0)),
        "tldr_bullets": tldr_bullets,
        "m14_lines": m14_lines,
    }


# ---------------------------------------------------------------------------
# Trend helpers
# ---------------------------------------------------------------------------

def _trend_arrow(values: list[int]) -> str:
    """Return ↑ / ↓ / → based on first-vs-last non-zero available values."""
    nz = [v for v in values if v is not None]
    if len(nz) < 2:
        return "→"
    diff = nz[-1] - nz[0]
    if diff > 0:
        return "↑"
    if diff < 0:
        return "↓"
    return "→"


def _sparkline(values: list[int | None]) -> str:
    """Build a simple ASCII sparkline from a list of values (None = missing day)."""
    chars = " ▁▂▃▄▅▆▇█"
    valid = [v for v in values if v is not None]
    if not valid:
        return "no data"
    max_v = max(valid) if max(valid) > 0 else 1
    result = []
    for v in values:
        if v is None:
            result.append("·")
        else:
            idx = min(int(v / max_v * (len(chars) - 1)), len(chars) - 1)
            result.append(chars[idx])
    return "".join(result)


# ---------------------------------------------------------------------------
# Render weekly rollup
# ---------------------------------------------------------------------------

def _render_weekly(
    iso_week: str,
    dates: list[str],
    dailies: list[dict[str, Any] | None],
    generated_at: str,
) -> str:
    present = [d for d in dailies if d is not None]
    missing_dates = [dates[i] for i, d in enumerate(dailies) if d is None]

    # Aggregate counts
    total_commits = sum(d["commit_count"] for d in present)
    total_prs = sum(d["pr_count"] for d in present)
    total_errors = sum(d["error_source_count"] for d in present)
    total_agents = sum(d["agent_run_count"] for d in present)
    all_m14 = [(d["date"], line) for d in present for line in d["m14_lines"]]

    # Verified count — use last available day
    verified_counts = [d["verified_count"] for d in present if d["verified_count"] > 0]
    final_verified = verified_counts[-1] if verified_counts else 0
    first_verified = verified_counts[0] if len(verified_counts) >= 2 else None
    verified_delta = (final_verified - first_verified) if first_verified is not None else None

    lines: list[str] = []

    # --- Frontmatter ---
    lines.append("---")
    lines.append(f"week: '{iso_week}'")
    lines.append(f"generated_at: '{generated_at}'")
    lines.append(f"days_covered: {len(present)}")
    lines.append(f"total_commits: {total_commits}")
    lines.append(f"total_prs: {total_prs}")
    lines.append(f"m14_incident_count: {len(all_m14)}")
    lines.append(f"final_verified_count: {final_verified}")
    lines.append("tags:")
    lines.append("  - rollup/weekly")
    lines.append(f"  - '#rollup/{iso_week}'")
    lines.append("---")
    lines.append("")

    # --- Title ---
    lines.append(f"# Weekly Rollup — {iso_week}")
    lines.append(f"*{dates[0]} → {dates[-1]} | {len(present)}/7 days covered*")
    lines.append("")
    lines.append(f"*Generated {generated_at} | auditooor memory-rollup-weekly.py*")
    lines.append("")

    if missing_dates:
        lines.append(f"> [!note] Missing daily rollups for: {', '.join(missing_dates)}. "
                     "Run `make memory-rollup-daily DATE=<date>` to fill gaps.")
        lines.append("")

    # --- Weekly TL;DR ---
    lines.append("## Weekly TL;DR")
    lines.append("")
    lines.append(f"- **{total_commits}** commits landed across {len(present)} active days.")
    lines.append(f"- **{total_prs}** PR events recorded (merged + active).")
    if verified_delta is not None:
        sign = "+" if verified_delta >= 0 else ""
        lines.append(
            f"- Detector registry grew from **{first_verified}** → **{final_verified}** "
            f"({sign}{verified_delta} net change)."
        )
    else:
        lines.append(f"- Final detector registry count: **{final_verified}**.")
    if all_m14:
        lines.append(f"- **{len(all_m14)} M14-trap incident(s)** detected this week — see §M14 below.")
    else:
        lines.append("- No M14-trap incidents detected this week.")
    lines.append(f"- **{total_errors}** error-source logs across the week.")
    lines.append("")

    # --- Day-by-day summary table ---
    lines.append("## Day-by-Day Summary")
    lines.append("")
    lines.append("| Date | Commits | PRs | Errors | Agent Runs | Verified Count |")
    lines.append("|---|---|---|---|---|---|")
    for date_str, daily in zip(dates, dailies):
        if daily is None:
            lines.append(f"| {date_str} | — | — | — | — | *(no rollup)* |")
        else:
            lines.append(
                f"| {date_str} | {daily['commit_count']} | {daily['pr_count']} "
                f"| {daily['error_source_count']} | {daily['agent_run_count']} "
                f"| {daily['verified_count']} |"
            )
    lines.append("")

    # --- Trend lines ---
    lines.append("## Trend Lines")
    lines.append("")

    commit_vals = [d["commit_count"] if d else None for d in dailies]
    pr_vals = [d["pr_count"] if d else None for d in dailies]
    verified_vals = [d["verified_count"] if d else None for d in dailies]
    error_vals = [d["error_source_count"] if d else None for d in dailies]

    lines.append("```")
    lines.append(f"Commits   [{_sparkline(commit_vals)}]  {_trend_arrow([v for v in commit_vals if v is not None])}")
    lines.append(f"PRs       [{_sparkline(pr_vals)}]  {_trend_arrow([v for v in pr_vals if v is not None])}")
    lines.append(f"Verified  [{_sparkline(verified_vals)}]  {_trend_arrow([v for v in verified_vals if v is not None])}")
    lines.append(f"Errors    [{_sparkline(error_vals)}]  {_trend_arrow([v for v in error_vals if v is not None])}")
    lines.append("```")
    lines.append("")
    lines.append("_(Sparkline: Mon → Sun; · = no data; █ = highest value in week)_")
    lines.append("")

    # --- Verified count growth ---
    lines.append("## Verified Detector Count Growth")
    lines.append("")
    if verified_delta is not None:
        sign = "+" if verified_delta >= 0 else ""
        lines.append(f"**Start of week:** {first_verified} | **End of week:** {final_verified} | **Net:** {sign}{verified_delta}")
    else:
        lines.append(f"**Latest available count:** {final_verified}")
    lines.append("")
    lines.append("| Date | Count |")
    lines.append("|---|---|")
    for date_str, daily in zip(dates, dailies):
        cnt = daily["verified_count"] if daily else "—"
        lines.append(f"| {date_str} | {cnt} |")
    lines.append("")

    # --- Error frequency ---
    lines.append("## Error Frequency")
    lines.append("")
    lines.append(f"Total error-source logs this week: **{total_errors}**")
    lines.append("")
    lines.append("| Date | Error Sources |")
    lines.append("|---|---|")
    for date_str, daily in zip(dates, dailies):
        cnt = daily["error_source_count"] if daily else "—"
        lines.append(f"| {date_str} | {cnt} |")
    lines.append("")

    # --- M14-trap incidents ---
    lines.append("## M14-Trap Incidents")
    lines.append("")
    if not all_m14:
        lines.append("_No M14-trap incidents recorded this week._")
    else:
        lines.append(f"**{len(all_m14)} incident(s):**")
        lines.append("")
        for date_str, line in all_m14:
            lines.append(f"- [{date_str}] {line[:150]}")
    lines.append("")

    # --- Routing changes ---
    lines.append("## Routing Observations")
    lines.append("")
    # Collect routing observations from daily TL;DR bullets
    routing_bullets: list[tuple[str, str]] = []
    for daily in present:
        for b in daily.get("tldr_bullets", []):
            if re.search(r'\b(provider|route|dispatch|claude|codex|kimi|opus|sonnet|minimax)\b', b, re.I):
                routing_bullets.append((daily["date"], b))
    if routing_bullets:
        lines.append("Provider/routing signals surfaced in daily TL;DRs:")
        lines.append("")
        for date_str, b in routing_bullets[:20]:
            lines.append(f"- [{date_str}] {b[:140]}")
    else:
        lines.append(
            "_No explicit provider/routing signals in daily TL;DR bullets this week. "
            "Check daily rollups or `obsidian-vault/agent-runs/` for dispatch metadata._"
        )
    lines.append("")

    # --- Daily TL;DRs quick-ref ---
    lines.append("## Daily TL;DRs (Quick Reference)")
    lines.append("")
    for daily in present:
        lines.append(f"### {daily['date']}")
        lines.append("")
        for b in daily["tldr_bullets"]:
            lines.append(f"- {b}")
        if not daily["tldr_bullets"]:
            lines.append("_(no bullets)_")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_weekly_rollup(iso_week: str, vault_dir: Path) -> Path:
    """Generate a weekly rollup. Returns output path."""
    generated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dates = _week_dates(iso_week)
    dailies = [_load_daily_rollup(d, vault_dir) for d in dates]
    present = [d for d in dailies if d is not None]

    content = _render_weekly(iso_week, dates, dailies, generated_at)

    # Cap at 200 KB
    if len(content.encode("utf-8")) > OUTPUT_CAP_BYTES:
        content = content[:OUTPUT_CAP_BYTES - 200]
        content += "\n\n> [!warning] Output truncated at 200 KB cap. See daily rollups for full detail.\n"

    out_dir = vault_dir / "rollups" / "weekly"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{iso_week}.md"
    out_path.write_text(content, encoding="utf-8")

    size_kb = len(content.encode("utf-8")) / 1024
    print(
        f"  [weekly-rollup] {iso_week} ({dates[0]}–{dates[-1]}) → "
        f"{out_path.relative_to(vault_dir.parent)} "
        f"({size_kb:.1f} KB) | {len(present)}/7 days covered"
    )
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="memory-rollup-weekly.py — generate weekly vault rollup"
    )
    parser.add_argument("--week", default=None,
                        help="ISO week (YYYY-W##). Defaults to current week.")
    parser.add_argument("--vault-dir", default=str(VAULT_DEFAULT),
                        help="Path to obsidian-vault directory.")
    parser.add_argument("--backfill", type=int, default=0, metavar="N",
                        help="Generate rollups for the last N weeks.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be generated without writing.")
    args = parser.parse_args()

    vault_dir = Path(args.vault_dir)
    if not vault_dir.exists():
        print(f"[weekly-rollup] WARNING: vault not found at {vault_dir}.")

    current_week = _current_week()

    if args.backfill > 0:
        today = _dt.date.today()
        weeks = []
        for i in range(args.backfill):
            d = today - _dt.timedelta(weeks=i)
            iso = d.isocalendar()
            w = f"{iso[0]}-W{iso[1]:02d}"
            if w not in weeks:
                weeks.append(w)
        weeks.reverse()  # oldest first
        print(f"[weekly-rollup] Backfilling {len(weeks)} weeks ({weeks[0]} → {weeks[-1]})")
        for w in weeks:
            if args.dry_run:
                print(f"  [dry-run] would generate {w}")
            else:
                generate_weekly_rollup(w, vault_dir)
        return

    week = args.week or current_week
    if args.dry_run:
        print(f"[weekly-rollup] dry-run: would generate {week}")
        return
    generate_weekly_rollup(week, vault_dir)


if __name__ == "__main__":
    main()
