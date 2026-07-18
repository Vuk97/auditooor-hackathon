#!/usr/bin/env python3
"""
codex-activity-snapshot.py - Visibility into Codex CLI activity on the shared repo.

Usage:
    python3 tools/codex-activity-snapshot.py [--workspace <path>] [--since <date>] [--json|--markdown]

Output (markdown default):
  - Recent commits authored-by or co-authored-by Codex
  - Currently-modified Codex in-flight files (hits_ledger, V3_CLOSEOUT, reports/v3_*)
  - Shared-path hotspots: files both Claude and Codex touched in last 7 days
  - Risk flags: directories where Codex committed within 1h and Claude has staged work
  - "Safe to commit" recommendations

Schema: auditooor.codex_activity_snapshot.v1
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

# Codex author identifiers (email patterns)
CODEX_AUTHOR_EMAILS = [
    "codex@auditooor.local",
    "codex@openai.com",
    "noreply@openai.com",
]

# Codex co-author trailer patterns (case-insensitive)
CODEX_CO_AUTHOR_PATTERNS = [
    "co-authored-by: codex",
]

# Claude author identifiers
CLAUDE_AUTHOR_EMAILS = [
    "noreply@anthropic.com",
    "claude@anthropic.com",
]

# Codex in-flight file patterns (relative to workspace root)
CODEX_INFLIGHT_PATTERNS = [
    "_hits_ledger.yaml",
    "V3_CLOSEOUT",
    "reports/v3_",
]

# Codex in-flight mtime window (seconds)
CODEX_INFLIGHT_MTIME_WINDOW = 4 * 3600  # 4 hours

# High-risk Codex commit window for risk flags (seconds)
RISK_WINDOW_CODEX_RECENT = 3600  # 1 hour

DEFAULT_SINCE = "7 days ago"
DEFAULT_HOTSPOT_SINCE = "7 days ago"


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git(args: list[str], cwd: Path) -> str:
    """Run a git command and return stdout (empty string on failure)."""
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return ""
        return result.stdout.strip()
    except Exception:
        return ""


def _is_codex_author(author_email: str) -> bool:
    email_lc = author_email.lower()
    return any(pat in email_lc for pat in CODEX_AUTHOR_EMAILS)


def _is_claude_author(author_email: str) -> bool:
    email_lc = author_email.lower()
    return any(pat in email_lc for pat in CLAUDE_AUTHOR_EMAILS)


def _commit_has_codex_coauthor(body: str) -> bool:
    body_lc = body.lower()
    return any(pat in body_lc for pat in CODEX_CO_AUTHOR_PATTERNS)


def get_recent_commits(workspace: Path, since: str) -> list[dict]:
    """Return list of commit dicts with author/co-author info."""
    # --format: hash|author_name|author_email|timestamp_unix|subject
    raw = _git(
        ["log", f"--since={since}", "--format=%H|%an|%ae|%at|%s"],
        workspace,
    )
    if not raw:
        return []

    commits = []
    for line in raw.splitlines():
        parts = line.split("|", 4)
        if len(parts) < 5:
            continue
        sha, name, email, ts_str, subject = parts
        try:
            ts = int(ts_str)
        except ValueError:
            ts = 0
        commits.append(
            {
                "sha": sha[:12],
                "sha_full": sha,
                "author_name": name,
                "author_email": email,
                "timestamp": ts,
                "subject": subject,
                "is_codex_author": _is_codex_author(email),
            }
        )

    # Enrich with co-author info by reading commit body for Codex trailers
    for commit in commits:
        body = _git(["show", "-s", "--format=%B", commit["sha_full"]], workspace)
        commit["has_codex_coauthor"] = _commit_has_codex_coauthor(body)
        commit["is_codex_commit"] = (
            commit["is_codex_author"] or commit["has_codex_coauthor"]
        )
        # Also track if Claude authored
        commit["is_claude_author"] = _is_claude_author(commit["author_email"])

    return commits


def get_files_changed_by_commits(
    workspace: Path, commit_shas: list[str]
) -> set[str]:
    """Return set of relative file paths touched by given commits."""
    if not commit_shas:
        return set()
    files: set[str] = set()
    for sha in commit_shas:
        raw = _git(
            ["diff-tree", "--no-commit-id", "-r", "--name-only", sha],
            workspace,
        )
        for line in raw.splitlines():
            f = line.strip()
            if f:
                files.add(f)
    return files


def get_staged_files(workspace: Path) -> list[str]:
    """Return list of currently staged (index) files."""
    raw = _git(["diff", "--cached", "--name-only"], workspace)
    return [line.strip() for line in raw.splitlines() if line.strip()]


def get_unstaged_modified_files(workspace: Path) -> list[str]:
    """Return list of unstaged modified tracked files."""
    raw = _git(["diff", "--name-only"], workspace)
    return [line.strip() for line in raw.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# In-flight file detection
# ---------------------------------------------------------------------------

def find_codex_inflight_files(workspace: Path) -> list[dict]:
    """Find files matching Codex in-flight patterns with recent mtime."""
    now = time.time()
    results = []
    for root, dirs, files in os.walk(workspace):
        # Skip .git
        dirs[:] = [d for d in dirs if d != ".git"]
        for fname in files:
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(workspace))
            # Check pattern match
            matched_pattern = None
            for pat in CODEX_INFLIGHT_PATTERNS:
                if pat in rel or pat in fname:
                    matched_pattern = pat
                    break
            if matched_pattern is None:
                continue
            try:
                mtime = fpath.stat().st_mtime
            except OSError:
                continue
            age_s = now - mtime
            results.append(
                {
                    "path": rel,
                    "mtime": mtime,
                    "age_seconds": age_s,
                    "within_4h": age_s <= CODEX_INFLIGHT_MTIME_WINDOW,
                    "matched_pattern": matched_pattern,
                    "mtime_human": datetime.fromtimestamp(
                        mtime, tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M UTC"),
                }
            )
    results.sort(key=lambda x: x["mtime"], reverse=True)
    return results


# ---------------------------------------------------------------------------
# Shared-path hotspot analysis
# ---------------------------------------------------------------------------

def compute_shared_hotspots(
    codex_files: set[str], claude_files: set[str]
) -> list[str]:
    """Return sorted list of files both Codex and Claude touched."""
    shared = sorted(codex_files & claude_files)
    return shared


def dir_of(path: str) -> str:
    p = Path(path)
    if p.parent == Path("."):
        return "."
    return str(p.parent)


# ---------------------------------------------------------------------------
# Risk flag computation
# ---------------------------------------------------------------------------

def compute_risk_flags(
    commits: list[dict],
    staged_files: list[str],
    unstaged_files: list[str],
) -> list[dict]:
    """
    Risk: a Codex commit landed within 1h in a directory where Claude has
    uncommitted (staged or unstaged) work.
    """
    now = time.time()
    recent_codex_dirs: dict[str, int] = {}  # dir -> most recent ts
    for c in commits:
        if not c.get("is_codex_commit"):
            continue
        age = now - c["timestamp"]
        if age > RISK_WINDOW_CODEX_RECENT:
            continue
        # We need the files for this commit - pass them in the commit dict
        for f in c.get("files_changed", []):
            d = dir_of(f)
            if d not in recent_codex_dirs or recent_codex_dirs[d] < c["timestamp"]:
                recent_codex_dirs[d] = c["timestamp"]

    claude_uncommitted_dirs: set[str] = set()
    for f in staged_files + unstaged_files:
        claude_uncommitted_dirs.add(dir_of(f))

    risks: list[dict] = []
    for d, ts in recent_codex_dirs.items():
        if d in claude_uncommitted_dirs:
            age_min = int((now - ts) / 60)
            risks.append(
                {
                    "directory": d,
                    "codex_last_commit_minutes_ago": age_min,
                    "reason": (
                        f"Codex committed to '{d}' {age_min}m ago; "
                        "Claude has uncommitted work there"
                    ),
                }
            )
    return risks


def compute_safe_to_commit(
    staged_files: list[str], codex_files_7d: set[str]
) -> list[dict]:
    """Classify each staged file as safe or risky."""
    results = []
    for f in staged_files:
        overlap = f in codex_files_7d
        results.append(
            {
                "file": f,
                "safe": not overlap,
                "reason": (
                    "Codex also touched this file in last 7d - verify diff before committing"
                    if overlap
                    else "Codex has not touched this file in last 7d"
                ),
            }
        )
    return results


# ---------------------------------------------------------------------------
# Main snapshot builder
# ---------------------------------------------------------------------------

def build_snapshot(workspace: Path, since: str = DEFAULT_SINCE) -> dict:
    all_commits = get_recent_commits(workspace, since)

    # Enrich commits with files_changed for risk-flag computation
    # (batch only Codex commits to stay fast)
    codex_commit_shas = [
        c["sha_full"] for c in all_commits if c.get("is_codex_commit")
    ]
    claude_commit_shas = [
        c["sha_full"] for c in all_commits if c.get("is_claude_author")
    ]

    codex_files_changed = get_files_changed_by_commits(workspace, codex_commit_shas)
    claude_files_changed = get_files_changed_by_commits(workspace, claude_commit_shas)

    # Attach per-commit file lists (for risk flags)
    for c in all_commits:
        if c.get("is_codex_commit"):
            c["files_changed"] = list(
                get_files_changed_by_commits(workspace, [c["sha_full"]])
            )
        else:
            c["files_changed"] = []

    codex_commits = [c for c in all_commits if c.get("is_codex_commit")]
    inflight_files = find_codex_inflight_files(workspace)

    shared_hotspots = compute_shared_hotspots(
        codex_files_changed, claude_files_changed
    )

    staged = get_staged_files(workspace)
    unstaged = get_unstaged_modified_files(workspace)

    risk_flags = compute_risk_flags(all_commits, staged, unstaged)
    safe_recs = compute_safe_to_commit(staged, codex_files_changed)

    return {
        "schema": "auditooor.codex_activity_snapshot.v1",
        "workspace": str(workspace),
        "since": since,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "codex_commits": [
            {
                "sha": c["sha"],
                "author_email": c["author_email"],
                "timestamp_human": datetime.fromtimestamp(
                    c["timestamp"], tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M UTC"),
                "subject": c["subject"],
                "is_codex_author": c["is_codex_author"],
                "has_codex_coauthor": c["has_codex_coauthor"],
                "files_changed_count": len(c.get("files_changed", [])),
            }
            for c in codex_commits
        ],
        "inflight_files": inflight_files,
        "shared_hotspots": shared_hotspots,
        "codex_files_changed_count": len(codex_files_changed),
        "claude_files_changed_count": len(claude_files_changed),
        "staged_files": staged,
        "unstaged_modified_files": unstaged,
        "risk_flags": risk_flags,
        "safe_to_commit": safe_recs,
    }


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def format_markdown(snap: dict) -> str:
    lines: list[str] = []
    lines.append("# Codex Activity Snapshot")
    lines.append(f"Generated: {snap['generated_at']}")
    lines.append(f"Workspace: `{snap['workspace']}`")
    lines.append(f"Since: `{snap['since']}`")
    lines.append("")

    # --- Codex commits
    codex_commits = snap["codex_commits"]
    lines.append(f"## Codex Commits ({len(codex_commits)} found)")
    if codex_commits:
        for c in codex_commits:
            author_tag = (
                "direct-author" if c["is_codex_author"] else "co-author"
            )
            lines.append(
                f"- `{c['sha']}` [{c['timestamp_human']}] ({author_tag}) "
                f"{c['subject']} [{c['files_changed_count']} files]"
            )
    else:
        lines.append("_No Codex commits found in window._")
    lines.append("")

    # --- In-flight files
    inflight = snap["inflight_files"]
    within_4h = [f for f in inflight if f["within_4h"]]
    lines.append(
        f"## Codex In-Flight Files ({len(inflight)} total, "
        f"{len(within_4h)} modified within 4h)"
    )
    if inflight:
        for f in inflight[:20]:
            flag = " **[FRESH]**" if f["within_4h"] else ""
            lines.append(
                f"- `{f['path']}`{flag} - last modified {f['mtime_human']}"
            )
        if len(inflight) > 20:
            lines.append(f"  ... and {len(inflight) - 20} more")
    else:
        lines.append("_No in-flight Codex files detected._")
    lines.append("")

    # --- Shared hotspots
    hotspots = snap["shared_hotspots"]
    lines.append(
        f"## Shared-Path Hotspots ({len(hotspots)} files both touched)"
    )
    if hotspots:
        for h in hotspots[:20]:
            lines.append(f"- `{h}`")
        if len(hotspots) > 20:
            lines.append(f"  ... and {len(hotspots) - 20} more")
    else:
        lines.append("_No shared-path hotspots detected._")
    lines.append("")

    # --- Risk flags
    risks = snap["risk_flags"]
    lines.append(f"## Risk Flags ({len(risks)} active)")
    if risks:
        for r in risks:
            lines.append(f"- **RISK**: {r['reason']}")
    else:
        lines.append("_No active risk flags._")
    lines.append("")

    # --- Safe-to-commit
    safe_recs = snap["safe_to_commit"]
    lines.append(f"## Safe-to-Commit Recommendations ({len(safe_recs)} staged files)")
    if safe_recs:
        for r in safe_recs:
            icon = "OK" if r["safe"] else "WARN"
            lines.append(f"- [{icon}] `{r['file']}` - {r['reason']}")
    else:
        lines.append("_No staged files._")
    lines.append("")

    return "\n".join(lines)


def format_json(snap: dict) -> str:
    return json.dumps(snap, indent=2)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Snapshot Codex CLI activity on the shared auditooor repo"
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Path to git workspace (default: auto-detect from this file's location)",
    )
    parser.add_argument(
        "--since",
        default=DEFAULT_SINCE,
        help=f"Git --since date string (default: '{DEFAULT_SINCE}')",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--json", action="store_true", help="Output JSON"
    )
    output_group.add_argument(
        "--markdown", action="store_true", help="Output Markdown (default)"
    )

    args = parser.parse_args(argv)

    if args.workspace:
        workspace = Path(args.workspace).resolve()
    else:
        # Default: two levels up from this file (tools/codex-activity-snapshot.py)
        workspace = Path(__file__).resolve().parent.parent

    if not (workspace / ".git").exists():
        print(f"ERROR: '{workspace}' is not a git repository", file=sys.stderr)
        return 1

    snap = build_snapshot(workspace, since=args.since)

    if args.json:
        print(format_json(snap))
    else:
        print(format_markdown(snap))

    return 0


if __name__ == "__main__":
    sys.exit(main())
