#!/usr/bin/env python3
"""Wave-2 PR-A (PR #728) - auto-generated PR changelog generator.

Walks ``git log <base>..<branch>`` and produces a structured changelog
ready for use in the squash-merge body of a Wave-X consolidated PR. Each
commit is parsed for:

- short + long SHA
- subject line
- ISO date + author
- full body
- ``MCP context_pack_id`` (commit-msg hook footer)
- ``W2.x`` lane reference (parsed from subject or body)
- file-change stats from ``git show --stat`` last line

Commits are grouped by W2.x lane. The markdown output includes a top
summary table, a section per lane, and a footer listing every unique
``context_pack_id`` referenced by the contributing commits. The JSON
output emits the envelope schema ``auditooor.hackerman_pr_changelog.v1``.

Wave-2-A close-criteria detection: the tool greps each commit body for
the six SKILL.md close criteria phrases and annotates which commit(s)
landed each criterion in the markdown ``## Close Criteria Coverage``
section.

CLI examples:

    # default - markdown for wave-2-corpus-migration vs main
    python3 tools/hackerman-pr-changelog-generator.py

    # JSON form for downstream consumers
    python3 tools/hackerman-pr-changelog-generator.py --format json

    # write to file
    python3 tools/hackerman-pr-changelog-generator.py --output /tmp/clog.md

    # alternate branch
    python3 tools/hackerman-pr-changelog-generator.py \\
        --branch wave-3-foo --base main

Schema: ``auditooor.hackerman_pr_changelog.v1``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.hackerman_pr_changelog.v1"

DEFAULT_BRANCH = "wave-2-corpus-migration"
DEFAULT_BASE = "main"

# W2.x lane reference regex. Matches W2.1 through W2.99 and tolerates
# "W2.1A" / "W2.4.b" suffixes. Greedy on minor segment.
_LANE_RE = re.compile(r"\bW2\.(\d+[A-Za-z0-9]*)\b")

# MCP context_pack_id regex. The commit-msg hook footer is:
#   context_pack_id: auditooor.vault_context_pack.v1:resume:<hex>
# We tolerate alternative shapes (e.g. ``MCP context_pack_id: <...>``).
_CTX_RE = re.compile(
    r"(?:MCP\s+)?context_pack_id\s*:\s*(\S+)",
    re.IGNORECASE,
)

# Wave-2-A close criteria from SKILL.md (PR #728). Each tuple is
# (id, label, regex). Each regex is matched case-insensitive against
# the full commit body+subject corpus.
CLOSE_CRITERIA: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "C1",
        "Schema v1->v1.1 mutating migration",
        re.compile(r"schema\s*v1.*v1\.1|hackerman_record\.v1_1|v1\.1\s+migration", re.IGNORECASE),
    ),
    (
        "C2",
        "Five additive indexes (cve / ghsa / firm / tier / date)",
        re.compile(r"additive\s+index|by_cve_id|by_ghsa_id|by_firm|by_verification_tier|by_incident_date", re.IGNORECASE),
    ),
    (
        "C3",
        "Tier-3 -> tier-2 promotion (W2.3 residual)",
        re.compile(r"tier-?3\s*->|tier-?3.*tier-?2|tier-2\s+promotion|W2\.3", re.IGNORECASE),
    ),
    (
        "C4",
        "R38 / R39 gates wired as Check #73 / #74",
        re.compile(r"R38.*R39|Check\s*#?73|Check\s*#?74|bug-class-shift|attack-class-orphan", re.IGNORECASE),
    ),
    (
        "C5",
        "Cosmos-sdk dupe canonicalization (W2.6)",
        re.compile(r"cosmos-?sdk\s+dupe|cosmos.*canonicaliz|W2\.6", re.IGNORECASE),
    ),
    (
        "C6",
        "Pre-merge gate + close-readiness verdict",
        re.compile(r"pre-?merge|close-?readiness|wave2-a-close|PR\s*#?728", re.IGNORECASE),
    ),
]


def _run_git(repo: Path, args: list[str], check: bool = True) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo)] + args,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (rc={proc.returncode}): "
            f"{proc.stderr.strip()}"
        )
    return proc.stdout


def _enumerate_commits(repo: Path, base: str, branch: str) -> list[str]:
    """Return list of long SHAs in ``base..branch`` (oldest first)."""
    out = _run_git(
        repo,
        ["log", "--reverse", "--format=%H", f"{base}..{branch}"],
        check=False,
    ).strip()
    if not out:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _parse_commit(repo: Path, sha: str) -> dict[str, Any]:
    """Parse a single commit by full SHA."""
    raw = _run_git(
        repo,
        [
            "show",
            "--no-patch",
            "--format=%H%x1f%h%x1f%aI%x1f%an%x1f%s%x1f%b",
            sha,
        ],
    )
    parts = raw.rstrip("\n").split("\x1f", 5)
    if len(parts) < 6:
        parts = parts + [""] * (6 - len(parts))
    full_sha, short_sha, date, author, subject, body = parts
    stat_raw = _run_git(repo, ["show", "--stat", "--format=", sha])
    stat_line = ""
    for line in reversed(stat_raw.strip().splitlines()):
        if "changed" in line:
            stat_line = line.strip()
            break
    insertions = 0
    deletions = 0
    files_changed = 0
    m = re.search(r"(\d+)\s+files?\s+changed", stat_line)
    if m:
        files_changed = int(m.group(1))
    m = re.search(r"(\d+)\s+insertion", stat_line)
    if m:
        insertions = int(m.group(1))
    m = re.search(r"(\d+)\s+deletion", stat_line)
    if m:
        deletions = int(m.group(1))
    haystack = subject + "\n" + body
    lanes_seen: list[str] = []
    for m in _LANE_RE.finditer(haystack):
        tag = f"W2.{m.group(1)}"
        if tag not in lanes_seen:
            lanes_seen.append(tag)
    ctx_match = _CTX_RE.search(body)
    context_pack_id = ctx_match.group(1) if ctx_match else None
    return {
        "sha": full_sha,
        "short_sha": short_sha,
        "date": date,
        "author": author,
        "subject": subject,
        "body": body,
        "lanes": lanes_seen if lanes_seen else ["Unclassified"],
        "context_pack_id": context_pack_id,
        "files_changed": files_changed,
        "insertions": insertions,
        "deletions": deletions,
        "stat_line": stat_line,
    }


def _group_by_lane(commits: list[dict[str, Any]]) -> "OrderedDict[str, list[dict[str, Any]]]":
    """Group commits by lane. A commit with N lane refs appears in N groups."""
    groups: "OrderedDict[str, list[dict[str, Any]]]" = OrderedDict()
    for c in commits:
        for lane in c["lanes"]:
            groups.setdefault(lane, []).append(c)
    def _sort_key(name: str) -> tuple[int, str]:
        if name == "Unclassified":
            return (99, name)
        m = re.match(r"W2\.(\d+)", name)
        if m:
            return (int(m.group(1)), name)
        return (50, name)
    return OrderedDict(sorted(groups.items(), key=lambda kv: _sort_key(kv[0])))


def _detect_close_criteria(commits: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """For each close criterion, find the contributing commits."""
    results: list[dict[str, Any]] = []
    for cid, label, regex in CLOSE_CRITERIA:
        hits: list[dict[str, str]] = []
        for c in commits:
            haystack = c["subject"] + "\n" + c["body"]
            if regex.search(haystack):
                hits.append(
                    {"short_sha": c["short_sha"], "subject": c["subject"]}
                )
        results.append(
            {
                "id": cid,
                "label": label,
                "covered": bool(hits),
                "commits": hits,
            }
        )
    return results


def _render_markdown(
    branch: str,
    base: str,
    head_sha: str,
    commits: list[dict[str, Any]],
    lanes: "OrderedDict[str, list[dict[str, Any]]]",
    criteria: list[dict[str, Any]],
    total_ins: int,
    total_del: int,
    unique_ctx: list[str],
) -> str:
    """Render markdown changelog. No em-dashes."""
    out: list[str] = []
    out.append(f"# PR Changelog: {branch} -> {base}")
    out.append("")
    out.append(f"- Base: `{base}`")
    out.append(f"- Branch: `{branch}`")
    out.append(f"- Head SHA: `{head_sha}`")
    out.append(f"- Commit count: {len(commits)}")
    out.append(f"- Total insertions: {total_ins}")
    out.append(f"- Total deletions: {total_del}")
    out.append("")
    if not commits:
        out.append("No commits in `{0}..{1}`.".format(base, branch))
        return "\n".join(out) + "\n"
    # Summary table
    out.append("## Summary by Lane")
    out.append("")
    out.append("| Lane | Commits | Files | Insertions | Deletions |")
    out.append("|---|---:|---:|---:|---:|")
    for lane, lcommits in lanes.items():
        ins = sum(c["insertions"] for c in lcommits)
        dele = sum(c["deletions"] for c in lcommits)
        files = sum(c["files_changed"] for c in lcommits)
        out.append(
            f"| {lane} | {len(lcommits)} | {files} | {ins} | {dele} |"
        )
    out.append("")
    # Per-lane section
    out.append("## Commits by Lane")
    out.append("")
    for lane, lcommits in lanes.items():
        out.append(f"### {lane}")
        out.append("")
        for c in lcommits:
            stat = (
                f"{c['files_changed']}f / "
                f"+{c['insertions']} / -{c['deletions']}"
            )
            out.append(
                f"- `{c['short_sha']}` {c['subject']}  ({stat})"
            )
        out.append("")
    # Close criteria coverage
    out.append("## Wave-2-A Close Criteria Coverage")
    out.append("")
    out.append("| ID | Label | Covered | Commit count |")
    out.append("|---|---|:---:|---:|")
    for cr in criteria:
        mark = "yes" if cr["covered"] else "no"
        out.append(
            f"| {cr['id']} | {cr['label']} | {mark} | {len(cr['commits'])} |"
        )
    out.append("")
    for cr in criteria:
        if not cr["covered"]:
            continue
        out.append(f"**{cr['id']} - {cr['label']}**")
        out.append("")
        for h in cr["commits"]:
            out.append(f"- `{h['short_sha']}` {h['subject']}")
        out.append("")
    # Footer: unique MCP context_pack_ids
    out.append("## MCP context_pack_ids")
    out.append("")
    if unique_ctx:
        for cid in unique_ctx:
            out.append(f"- `{cid}`")
    else:
        out.append("- (none extracted)")
    out.append("")
    return "\n".join(out) + "\n"


def _render_json(
    branch: str,
    base: str,
    head_sha: str,
    commits: list[dict[str, Any]],
    lanes: "OrderedDict[str, list[dict[str, Any]]]",
    criteria: list[dict[str, Any]],
    total_ins: int,
    total_del: int,
    unique_ctx: list[str],
) -> str:
    lanes_json: dict[str, list[str]] = OrderedDict()
    for lane, lcommits in lanes.items():
        lanes_json[lane] = [c["short_sha"] for c in lcommits]
    envelope = {
        "schema": SCHEMA_VERSION,
        "branch": branch,
        "base": base,
        "head_sha": head_sha,
        "total_commits": len(commits),
        "total_insertions": total_ins,
        "total_deletions": total_del,
        "unique_context_pack_ids": unique_ctx,
        "close_criteria": criteria,
        "lanes": lanes_json,
        "commits": [
            {
                "sha": c["sha"],
                "short_sha": c["short_sha"],
                "date": c["date"],
                "author": c["author"],
                "subject": c["subject"],
                "lanes": c["lanes"],
                "context_pack_id": c["context_pack_id"],
                "files_changed": c["files_changed"],
                "insertions": c["insertions"],
                "deletions": c["deletions"],
                "stat_line": c["stat_line"],
            }
            for c in commits
        ],
    }
    return json.dumps(envelope, indent=2, sort_keys=False) + "\n"


def generate(
    repo: Path,
    base: str,
    branch: str,
    fmt: str,
) -> str:
    shas = _enumerate_commits(repo, base, branch)
    commits = [_parse_commit(repo, s) for s in shas]
    lanes = _group_by_lane(commits)
    criteria = _detect_close_criteria(commits)
    total_ins = sum(c["insertions"] for c in commits)
    total_del = sum(c["deletions"] for c in commits)
    unique_ctx: list[str] = []
    for c in commits:
        cid = c["context_pack_id"]
        if cid and cid not in unique_ctx:
            unique_ctx.append(cid)
    head_sha = ""
    if shas:
        head_sha = shas[-1]
    if fmt == "json":
        return _render_json(
            branch, base, head_sha, commits, lanes, criteria,
            total_ins, total_del, unique_ctx,
        )
    return _render_markdown(
        branch, base, head_sha, commits, lanes, criteria,
        total_ins, total_del, unique_ctx,
    )


def _default_repo() -> Path:
    here = Path(__file__).resolve()
    return here.parents[1]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Generate a structured PR changelog from `git log base..branch`. "
            "Groups commits by W2.x lane and annotates Wave-2-A close-"
            "criteria coverage."
        ),
    )
    p.add_argument(
        "--branch",
        default=DEFAULT_BRANCH,
        help=f"Branch ref (default: {DEFAULT_BRANCH})",
    )
    p.add_argument(
        "--base",
        default=DEFAULT_BASE,
        help=f"Base ref (default: {DEFAULT_BASE})",
    )
    p.add_argument(
        "--format",
        choices=["markdown", "json"],
        default="markdown",
        help="Output format (default: markdown)",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Output path (default: stdout)",
    )
    p.add_argument(
        "--repo",
        default=None,
        help="Repo path (default: tool's repo root)",
    )
    args = p.parse_args(argv)
    repo = Path(args.repo).resolve() if args.repo else _default_repo()
    if not (repo / ".git").exists() and not (repo / ".git").is_file():
        print(f"ERROR: {repo} is not a git repo", file=sys.stderr)
        return 2
    out = generate(repo, args.base, args.branch, args.format)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
