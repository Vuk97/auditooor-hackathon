#!/usr/bin/env python3
"""memory-rollup-daily.py — Layer L2 daily rollup aggregator.

Reads vault notes for a given date and produces a single digestible summary
an agent can read in ~30 seconds.

Usage:
    python3 tools/memory-rollup-daily.py [--date YYYY-MM-DD] [--vault-dir <path>]
    python3 tools/memory-rollup-daily.py --backfill 30     # last N days

Output:
    obsidian-vault/rollups/daily/<YYYY-MM-DD>.md

Sources read (all read-only):
  - obsidian-vault/events/<date>/HOURLY-*.md    (ACT-17 event watcher, if present)
  - obsidian-vault/commits/<short-sha>.md       (any commit with date == <date>)
  - obsidian-vault/prs/<N>.md                   (PRs merged/opened on <date>)
  - obsidian-vault/errors/<source>-<date>.md    (errors emitted on <date>)
  - obsidian-vault/agent-runs/<id>.md           (agent dispatches touching <date>)
  - detectors/_tier_registry.yaml               (verified count delta vs yesterday)

Constraints:
  - No LLM calls — TL;DR is rule-based (top commits by subject keyword weight)
  - Output capped at 100 KB per rollup
  - Idempotent: regenerating overwrites cleanly
  - Honest staleness: surfaces data age when sources are older than 24h
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

import yaml

# ---------------------------------------------------------------------------
# Layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parents[1]
VAULT_DEFAULT = REPO_ROOT / "obsidian-vault"
TIER_REGISTRY = REPO_ROOT / "detectors" / "_tier_registry.yaml"
OUTPUT_CAP_BYTES = 100 * 1024   # 100 KB hard cap
MAX_ITEMS_PER_SECTION = 50      # summarize + link if exceeded

# ---------------------------------------------------------------------------
# YAML frontmatter parser (minimal, no PyYAML dep on the block delimiters)
# ---------------------------------------------------------------------------

def _parse_frontmatter(text: str) -> dict[str, Any]:
    """Extract YAML frontmatter from a --- ... --- block at top of file."""
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


def _parse_codeblock_meta(text: str) -> dict[str, str]:
    """Parse commit-style code-block metadata: key: value lines inside ```."""
    m = re.search(r"```\n(.*?)```", text, re.DOTALL)
    if not m:
        return {}
    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return meta


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Tier registry: count verified detectors
# ---------------------------------------------------------------------------

def _count_verified_detectors() -> int:
    """Return number of entries in _tier_registry.yaml."""
    if not TIER_REGISTRY.exists():
        return 0
    try:
        data = yaml.safe_load(TIER_REGISTRY.read_text()) or {}
        tiers = data.get("tiers", {})
        return len(tiers)
    except Exception:
        return 0


def _verified_count_for_date(date_str: str, vault_dir: Path) -> int:
    """
    Return verified detector count as recorded in yesterday's rollup (if it exists),
    so we can compute a delta. Returns -1 if no prior rollup found.
    """
    prev = (_dt.date.fromisoformat(date_str) - _dt.timedelta(days=1)).isoformat()
    prev_rollup = vault_dir / "rollups" / "daily" / f"{prev}.md"
    if not prev_rollup.exists():
        return -1
    text = _read(prev_rollup)
    m = re.search(r"verified_detector_count:\s*(\d+)", text)
    if m:
        return int(m.group(1))
    # Also try the section body
    m2 = re.search(r"\*\*Verified detector count\*\*[^\n]*?(\d+)", text)
    if m2:
        return int(m2.group(1))
    return -1


# ---------------------------------------------------------------------------
# Commit ingestion
# ---------------------------------------------------------------------------

def _load_commits_for_date(date_str: str, vault_dir: Path) -> list[dict[str, str]]:
    """Return list of commit dicts {sha, short_sha, subject, author, datetime} for date.

    Vault commit notes come in two formats:
    1. YAML frontmatter (newer format from memory-deep-crawler)
    2. Markdown code-block with `key: value` lines (legacy format)
    """
    commits_dir = vault_dir / "commits"
    if not commits_dir.exists():
        return []
    results = []
    for p in sorted(commits_dir.glob("*.md")):
        text = _read(p)
        fm = _parse_frontmatter(text)
        commit_date = str(fm.get("date", ""))[:10]

        # Fallback: parse code-block metadata (date: 2026-05-04T... inside ```)
        if not commit_date:
            cb = _parse_codeblock_meta(text)
            commit_date = str(cb.get("date", ""))[:10]
            if commit_date and not fm:
                # Reconstruct fm from code-block
                sha = cb.get("sha", "").strip()
                fm = {
                    "sha": sha,
                    "short_sha": sha[:8] if sha else p.stem,
                    "author": cb.get("author", "unknown").strip(),
                    "date": commit_date,
                    "datetime": cb.get("date", date_str).strip(),
                }

        if commit_date != date_str:
            continue

        # Subject is the H1 title in the body
        h1 = re.search(r"^# (.+)$", text, re.MULTILINE)
        subject = h1.group(1).strip() if h1 else str(fm.get("sha", p.stem))[:40]
        results.append({
            "sha": str(fm.get("sha", "")),
            "short_sha": str(fm.get("short_sha", p.stem)),
            "subject": subject,
            "author": str(fm.get("author", "unknown")),
            "datetime": str(fm.get("datetime", date_str)),
        })
    # Sort by datetime
    results.sort(key=lambda c: c["datetime"])
    return results


# ---------------------------------------------------------------------------
# PR ingestion
# ---------------------------------------------------------------------------

def _load_prs_for_date(date_str: str, vault_dir: Path) -> list[dict[str, Any]]:
    """Return PRs that were merged or had activity on date_str."""
    prs_dir = vault_dir / "prs"
    if not prs_dir.exists():
        return []
    results = []
    for p in sorted(prs_dir.glob("*.md")):
        text = _read(p)
        fm = _parse_frontmatter(text)
        merged_at = str(fm.get("merged_at", ""))[:10]
        last_synced = str(fm.get("last_synced", ""))[:10]
        # Include if merged on date or synced on date (proxy for "activity")
        if merged_at == date_str or last_synced == date_str:
            results.append({
                "number": fm.get("pr_number", p.stem),
                "title": str(fm.get("title", "untitled")),
                "state": str(fm.get("state", "unknown")),
                "merged_at": merged_at,
                "branch": str(fm.get("branch", "")),
                "activity_date": merged_at if merged_at == date_str else last_synced,
            })
    results.sort(key=lambda r: (r["activity_date"], str(r["number"])))
    return results


# ---------------------------------------------------------------------------
# Error ingestion
# ---------------------------------------------------------------------------

def _load_errors_for_date(date_str: str, vault_dir: Path) -> list[dict[str, Any]]:
    """Return error vault entries for date_str."""
    errors_dir = vault_dir / "errors"
    if not errors_dir.exists():
        return []
    results = []
    for p in sorted(errors_dir.glob(f"*-{date_str}.md")):
        text = _read(p)
        fm = _parse_frontmatter(text)
        source = str(fm.get("source", p.stem))
        error_count = int(fm.get("error_line_count", 0))
        total_count = int(fm.get("total_line_count", 0))
        log_file = str(fm.get("log_file", ""))
        # Extract exit-code frequency table
        freq: dict[str, int] = {}
        in_table = False
        for line in text.splitlines():
            if "| Exit Code | Count |" in line:
                in_table = True
                continue
            if in_table and line.startswith("|---"):
                continue
            if in_table and line.startswith("|"):
                parts = [x.strip() for x in line.split("|") if x.strip()]
                if len(parts) >= 2:
                    try:
                        freq[parts[0]] = int(parts[1])
                    except ValueError:
                        pass
            elif in_table and not line.startswith("|"):
                in_table = False
        results.append({
            "source": source,
            "log_file": log_file,
            "error_count": error_count,
            "total_count": total_count,
            "freq": freq,
        })
    # Sort by error_count desc
    results.sort(key=lambda r: r["error_count"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Agent-run ingestion
# ---------------------------------------------------------------------------

def _load_agent_runs_for_date(date_str: str, vault_dir: Path) -> list[dict[str, Any]]:
    """Return agent-run vault entries that touch date_str."""
    runs_dir = vault_dir / "agent-runs"
    if not runs_dir.exists():
        return []
    results = []
    for p in sorted(runs_dir.glob("*.md")):
        if p.name == "INDEX.md":
            continue
        text = _read(p)
        fm = _parse_frontmatter(text)
        # Use oldest_mtime or newest_mtime from frontmatter
        oldest = str(fm.get("oldest_mtime", ""))[:10]
        newest = str(fm.get("newest_mtime", ""))[:10]
        if oldest != date_str and newest != date_str:
            continue
        results.append({
            "id": p.stem,
            "file_count": fm.get("file_count", "?"),
            "total_size_kb": fm.get("total_size_kb", "?"),
            "oldest": oldest,
            "newest": newest,
            "path": str(fm.get("path", "")),
        })
    return results


# ---------------------------------------------------------------------------
# Hourly event ingestion (ACT-17)
# ---------------------------------------------------------------------------

def _load_hourly_events_for_date(date_str: str, vault_dir: Path) -> list[dict[str, Any]]:
    """Return hourly event summaries from events/<date>/HOURLY-*.md if they exist."""
    events_dir = vault_dir / "events" / date_str
    if not events_dir.exists():
        return []
    results = []
    for p in sorted(events_dir.glob("HOURLY-*.md")):
        text = _read(p)
        fm = _parse_frontmatter(text)
        # Extract first H2 section content as summary
        h2_match = re.search(r"^## (.+)$\n(.+?)(?=^##|\Z)", text, re.MULTILINE | re.DOTALL)
        snippet = h2_match.group(2).strip()[:200] if h2_match else ""
        results.append({
            "filename": p.name,
            "hour": str(fm.get("hour", p.stem)),
            "snippet": snippet,
        })
    return results


# ---------------------------------------------------------------------------
# TL;DR — rule-based, no LLM
# ---------------------------------------------------------------------------

# Keyword weights for surfacing "important" commits in TL;DR
_KEYWORD_WEIGHTS: list[tuple[re.Pattern[str], int]] = [
    (re.compile(r'\b(critical|security|vuln|exploit|cve|ban|breach)\b', re.I), 10),
    (re.compile(r'\b(feat|feature|add|new|introduce|implement)\b', re.I), 4),
    (re.compile(r'\b(fix|bugfix|hotfix|patch|repair|resolve)\b', re.I), 5),
    (re.compile(r'\b(merge|pr|pull.?request)\b', re.I), 2),
    (re.compile(r'\b(refactor|cleanup|clean|simplify)\b', re.I), 1),
    (re.compile(r'\b(doc|docs|readme|guide)\b', re.I), 1),
    (re.compile(r'\b(test|spec|assert|fixture|smoke)\b', re.I), 2),
    (re.compile(r'\b(detector|pattern|wave|tier|registry)\b', re.I), 3),
    (re.compile(r'\b(audit|finding|submission|vuln|reentr)\b', re.I), 5),
]


def _commit_score(subject: str) -> int:
    score = 0
    for pat, weight in _KEYWORD_WEIGHTS:
        if pat.search(subject):
            score += weight
    return score


def _build_tldr(
    date_str: str,
    commits: list[dict],
    prs: list[dict],
    errors: list[dict],
    agent_runs: list[dict],
    verified_count: int,
    yesterday_count: int,
) -> list[str]:
    """
    Return up to 5 bullet strings for the TL;DR section.
    Rule-based: no LLM. Deterministic.
    """
    bullets: list[str] = []

    # Bullet 1: detector count delta
    if yesterday_count >= 0:
        delta = verified_count - yesterday_count
        sign = "+" if delta >= 0 else ""
        bullets.append(
            f"Detector registry: **{verified_count}** verified entries "
            f"({sign}{delta} vs yesterday)."
        )
    else:
        bullets.append(f"Detector registry: **{verified_count}** verified entries (no prior rollup for delta).")

    # Bullet 2: commit summary — top-scored commit
    if commits:
        scored = sorted(commits, key=lambda c: _commit_score(c["subject"]), reverse=True)
        top = scored[0]
        bullets.append(
            f"Top commit: `{top['short_sha']}` — {top['subject'][:100]}"
            + (f" (+{len(commits)-1} others)" if len(commits) > 1 else "")
        )
    else:
        bullets.append("No commits recorded on this date in vault.")

    # Bullet 3: PR activity
    merged = [p for p in prs if p["state"] == "MERGED"]
    open_prs = [p for p in prs if p["state"] in ("OPEN", "open")]
    if merged or open_prs:
        parts = []
        if merged:
            # Show highest PR number (most recent)
            nums = sorted([int(str(p["number"])) for p in merged], reverse=True)
            parts.append(f"{len(merged)} merged (highest: #{nums[0]})")
        if open_prs:
            parts.append(f"{len(open_prs)} open/active")
        bullets.append("PRs: " + "; ".join(parts) + ".")
    else:
        bullets.append("No PR activity on this date.")

    # Bullet 4: errors / smoke fails
    if errors:
        total_errs = sum(e["error_count"] for e in errors)
        top_err = errors[0]  # already sorted by error_count desc
        bullets.append(
            f"Errors: **{total_errs}** error lines across {len(errors)} log(s); "
            f"worst: `{top_err['source']}` ({top_err['error_count']} errors)."
        )
    else:
        bullets.append("No error logs recorded on this date.")

    # Bullet 5: agent runs
    if agent_runs:
        bullets.append(f"Agent dispatches: {len(agent_runs)} run dir(s) touched.")
    elif commits and len(commits) >= 5:
        # Use the 5th bullet for a secondary commit insight
        subjects = [c["subject"] for c in commits]
        fix_count = sum(1 for s in subjects if re.search(r'\b(fix|patch|repair)\b', s, re.I))
        feat_count = sum(1 for s in subjects if re.search(r'\b(feat|add|new|introduce)\b', s, re.I))
        bullets.append(
            f"Commit breakdown: {feat_count} feature/add, {fix_count} fix/patch, "
            f"{len(commits) - feat_count - fix_count} other."
        )
    else:
        bullets.append("No agent-run directories recorded on this date.")

    return bullets[:5]


# ---------------------------------------------------------------------------
# Staleness check
# ---------------------------------------------------------------------------

def _staleness_notice(vault_dir: Path, date_str: str) -> str | None:
    """Return a notice string if the vault data appears stale (>24h old) for date."""
    sync_file = vault_dir / ".deep_sync.json"
    if not sync_file.exists():
        return "Vault sync state unknown — `.deep_sync.json` not found; data may be stale."
    try:
        state = json.loads(sync_file.read_text())
    except Exception:
        return "Vault sync state unreadable; data may be stale."
    # Find most recent sync timestamp across sections
    timestamps = []
    for v in state.values():
        try:
            timestamps.append(float(v))
        except (TypeError, ValueError):
            pass
    if not timestamps:
        return "No sync timestamps found; data may be stale."
    last_sync = _dt.datetime.fromtimestamp(max(timestamps), tz=_dt.timezone.utc)
    now = _dt.datetime.now(_dt.timezone.utc)
    age_h = (now - last_sync).total_seconds() / 3600
    if age_h > 24:
        return (
            f"**Staleness warning**: vault last synced {age_h:.1f}h ago "
            f"(at {last_sync.strftime('%Y-%m-%dT%H:%MZ')}). "
            "Run `make vault-sync` for fresher data."
        )
    return None


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------

def _render_rollup(
    date_str: str,
    commits: list[dict],
    prs: list[dict],
    errors: list[dict],
    agent_runs: list[dict],
    hourly_events: list[dict],
    verified_count: int,
    yesterday_count: int,
    stale_notice: str | None,
    generated_at: str,
) -> str:
    lines: list[str] = []

    tldr_bullets = _build_tldr(
        date_str, commits, prs, errors, agent_runs, verified_count, yesterday_count
    )

    # --- Frontmatter ---
    lines.append("---")
    lines.append(f"date: '{date_str}'")
    lines.append(f"generated_at: '{generated_at}'")
    lines.append(f"verified_detector_count: {verified_count}")
    lines.append(f"commit_count: {len(commits)}")
    lines.append(f"pr_count: {len(prs)}")
    lines.append(f"error_source_count: {len(errors)}")
    lines.append(f"agent_run_count: {len(agent_runs)}")
    lines.append("tags:")
    lines.append("  - rollup/daily")
    lines.append(f"  - '#rollup/{date_str}'")
    lines.append("---")
    lines.append("")

    # --- Title ---
    lines.append(f"# Daily Rollup — {date_str}")
    lines.append("")
    lines.append(f"*Generated {generated_at} | auditooor memory-rollup-daily.py*")
    lines.append("")

    if stale_notice:
        lines.append(f"> [!warning] {stale_notice}")
        lines.append("")

    # --- TL;DR ---
    lines.append("## TL;DR")
    lines.append("")
    for b in tldr_bullets:
        lines.append(f"- {b}")
    lines.append("")

    # --- Commits ---
    lines.append("## Commits")
    lines.append("")
    if not commits:
        lines.append("_No commits recorded in vault for this date._")
    elif len(commits) > MAX_ITEMS_PER_SECTION:
        lines.append(
            f"**{len(commits)} commits** — showing top {MAX_ITEMS_PER_SECTION} by score; "
            f"see `obsidian-vault/commits/` for full list."
        )
        lines.append("")
        scored = sorted(commits, key=lambda c: _commit_score(c["subject"]), reverse=True)
        for c in scored[:MAX_ITEMS_PER_SECTION]:
            lines.append(f"- `{c['short_sha']}` {c['subject'][:120]}")
    else:
        lines.append(f"**{len(commits)} commit(s)**")
        lines.append("")
        for c in commits:
            lines.append(f"- `{c['short_sha']}` {c['subject'][:120]}")
    lines.append("")

    # --- PRs ---
    lines.append("## PRs")
    lines.append("")
    if not prs:
        lines.append("_No PR activity recorded for this date._")
    elif len(prs) > MAX_ITEMS_PER_SECTION:
        merged_prs = [p for p in prs if p["state"] == "MERGED"]
        open_prs = [p for p in prs if p["state"] not in ("MERGED",)]
        lines.append(
            f"**{len(prs)} PRs** — {len(merged_prs)} merged, {len(open_prs)} other; "
            f"see `obsidian-vault/prs/` for full list."
        )
    else:
        merged_prs = [p for p in prs if p["state"] == "MERGED"]
        open_prs = [p for p in prs if p["state"] not in ("MERGED",)]
        if merged_prs:
            lines.append(f"**Merged ({len(merged_prs)}):**")
            for p in merged_prs:
                lines.append(f"- PR #{p['number']}: {p['title'][:100]}")
            lines.append("")
        if open_prs:
            lines.append(f"**Active ({len(open_prs)}):**")
            for p in open_prs:
                lines.append(f"- PR #{p['number']} [{p['state']}]: {p['title'][:100]}")
            lines.append("")
        if not merged_prs and not open_prs:
            lines.append("_No PR activity._")
    lines.append("")

    # --- Agent dispatches ---
    lines.append("## Agent Dispatches")
    lines.append("")
    if not agent_runs:
        lines.append("_No agent-run directories recorded for this date._")
    else:
        lines.append(f"**{len(agent_runs)} dispatch(es)**")
        lines.append("")
        for r in agent_runs[:MAX_ITEMS_PER_SECTION]:
            lines.append(
                f"- `{r['id']}` — {r['file_count']} file(s), {r['total_size_kb']} KB "
                f"(newest: {r['newest']})"
            )
        if len(agent_runs) > MAX_ITEMS_PER_SECTION:
            lines.append(f"- … {len(agent_runs) - MAX_ITEMS_PER_SECTION} more; see `obsidian-vault/agent-runs/`")
    lines.append("")

    # --- Errors ---
    lines.append("## Errors / Smoke Fails")
    lines.append("")
    if not errors:
        lines.append("_No error logs for this date._")
    else:
        total_errs = sum(e["error_count"] for e in errors)
        lines.append(f"**{total_errs} total error lines** across **{len(errors)} source(s)** (top 5 by frequency):")
        lines.append("")
        lines.append("| Source | Error Lines | Total Lines |")
        lines.append("|---|---|---|")
        for e in errors[:5]:
            lines.append(f"| `{e['source']}` | {e['error_count']} | {e['total_count']} |")
        if len(errors) > 5:
            lines.append(f"| *(+{len(errors)-5} more)* | — | — |")
    lines.append("")

    # --- Verified detector count ---
    lines.append("## Verified Detector Count")
    lines.append("")
    if yesterday_count >= 0:
        delta = verified_count - yesterday_count
        sign = "+" if delta >= 0 else ""
        lines.append(f"**{verified_count}** total verified detectors in `_tier_registry.yaml`.")
        lines.append(f"Delta vs prior rollup: **{sign}{delta}**.")
    else:
        lines.append(f"**{verified_count}** total verified detectors in `_tier_registry.yaml`.")
        lines.append("_(No prior daily rollup found for delta computation.)_")
    lines.append("")

    # --- M14-trap incidents ---
    lines.append("## M14-Trap Incidents")
    lines.append("")
    # Scan commits + error logs for M14-trap mentions
    m14_mentions: list[str] = []
    for c in commits:
        if re.search(r'm14.trap|m14_trap|over.claim|false.positive.batch', c["subject"], re.I):
            m14_mentions.append(f"Commit `{c['short_sha']}`: {c['subject'][:100]}")
    for e in errors:
        if re.search(r'm14.trap|over.claim', e["source"], re.I):
            m14_mentions.append(f"Error log `{e['source']}`: {e['error_count']} errors")
    if m14_mentions:
        lines.append(f"**{len(m14_mentions)} M14-trap mention(s) detected:**")
        lines.append("")
        for m in m14_mentions:
            lines.append(f"- {m}")
    else:
        lines.append("_No M14-trap incidents detected in commits or error logs for this date._")
    lines.append("")

    # --- Routing observations ---
    lines.append("## Routing Observations")
    lines.append("")
    # Heuristic: scan commit subjects for provider names
    providers = {
        "claude": re.compile(r'\bclaude\b', re.I),
        "codex": re.compile(r'\bcodex\b', re.I),
        "kimi": re.compile(r'\bkimi\b', re.I),
        "opus": re.compile(r'\bopus\b', re.I),
        "sonnet": re.compile(r'\bsonnet\b', re.I),
        "minimax": re.compile(r'\bminimax\b', re.I),
    }
    provider_hits: dict[str, int] = {k: 0 for k in providers}
    for c in commits:
        for name, pat in providers.items():
            if pat.search(c["subject"]):
                provider_hits[name] += 1
    active = {k: v for k, v in provider_hits.items() if v > 0}
    if active:
        lines.append("Provider mentions in commit subjects:")
        lines.append("")
        for name, count in sorted(active.items(), key=lambda x: -x[1]):
            lines.append(f"- **{name}**: {count} commit mention(s)")
    else:
        lines.append(
            "_No provider-specific routing signals in commit subjects. "
            "Check `obsidian-vault/agent-runs/` for dispatch metadata._"
        )
    lines.append("")

    # --- Hourly events (ACT-17, if present) ---
    if hourly_events:
        lines.append("## Hourly Events (ACT-17)")
        lines.append("")
        lines.append(f"**{len(hourly_events)} hourly event file(s):**")
        lines.append("")
        for ev in hourly_events:
            snippet = ev["snippet"].replace("\n", " ")[:120]
            lines.append(f"- `{ev['filename']}` — {snippet}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_rollup(date_str: str, vault_dir: Path) -> Path:
    """Generate a daily rollup for date_str. Returns the output path."""
    generated_at = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    commits = _load_commits_for_date(date_str, vault_dir)
    prs = _load_prs_for_date(date_str, vault_dir)
    errors = _load_errors_for_date(date_str, vault_dir)
    agent_runs = _load_agent_runs_for_date(date_str, vault_dir)
    hourly_events = _load_hourly_events_for_date(date_str, vault_dir)
    verified_count = _count_verified_detectors()
    yesterday_count = _verified_count_for_date(date_str, vault_dir)
    stale_notice = _staleness_notice(vault_dir, date_str)

    content = _render_rollup(
        date_str=date_str,
        commits=commits,
        prs=prs,
        errors=errors,
        agent_runs=agent_runs,
        hourly_events=hourly_events,
        verified_count=verified_count,
        yesterday_count=yesterday_count,
        stale_notice=stale_notice,
        generated_at=generated_at,
    )

    # Enforce 100 KB cap
    if len(content.encode("utf-8")) > OUTPUT_CAP_BYTES:
        content = content[: OUTPUT_CAP_BYTES - 200]
        content += "\n\n> [!warning] Output truncated at 100 KB cap. See vault sources for full detail.\n"

    out_dir = vault_dir / "rollups" / "daily"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{date_str}.md"
    out_path.write_text(content, encoding="utf-8")

    commits_str = f"{len(commits)} commit(s)"
    prs_str = f"{len(prs)} PR(s)"
    errs_str = f"{len(errors)} error source(s)"
    size_kb = len(content.encode("utf-8")) / 1024
    print(
        f"  [daily-rollup] {date_str} → {out_path.relative_to(vault_dir.parent)} "
        f"({size_kb:.1f} KB) | {commits_str} | {prs_str} | {errs_str}"
    )
    return out_path


def _date_range(start: str, end: str) -> list[str]:
    """Return list of ISO date strings from start to end inclusive."""
    s = _dt.date.fromisoformat(start)
    e = _dt.date.fromisoformat(end)
    dates = []
    cur = s
    while cur <= e:
        dates.append(cur.isoformat())
        cur += _dt.timedelta(days=1)
    return dates


def main() -> None:
    parser = argparse.ArgumentParser(
        description="memory-rollup-daily.py — generate daily vault rollup"
    )
    parser.add_argument("--date", default=None,
                        help="Date to roll up (YYYY-MM-DD). Defaults to today.")
    parser.add_argument("--vault-dir", default=str(VAULT_DEFAULT),
                        help="Path to obsidian-vault directory.")
    parser.add_argument("--backfill", type=int, default=0, metavar="N",
                        help="Generate rollups for the last N days.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be generated without writing.")
    args = parser.parse_args()

    vault_dir = Path(args.vault_dir)
    if not vault_dir.exists():
        # Vault may not be built yet — create rollups dir at minimum
        print(f"[daily-rollup] WARNING: vault not found at {vault_dir}. "
              "Run `make vault-refresh` first for full data.")

    today = _dt.date.today().isoformat()

    if args.backfill > 0:
        end = _dt.date.today()
        start = end - _dt.timedelta(days=args.backfill - 1)
        dates = _date_range(start.isoformat(), end.isoformat())
        print(f"[daily-rollup] Backfilling {len(dates)} days ({dates[0]} → {dates[-1]})")
        for d in dates:
            if args.dry_run:
                print(f"  [dry-run] would generate {d}")
            else:
                generate_rollup(d, vault_dir)
        return

    date_str = args.date or today
    if args.dry_run:
        print(f"[daily-rollup] dry-run: would generate {date_str}")
        return
    generate_rollup(date_str, vault_dir)


if __name__ == "__main__":
    main()
