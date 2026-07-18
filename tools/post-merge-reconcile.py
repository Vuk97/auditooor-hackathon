#!/usr/bin/env python3
"""post-merge-reconcile.py — find auto-closed PRs after a merge batch.

Background
----------
V5-P0-20 / Gap 37: when a base branch is deleted on its own merge, every PR
that was open against that base becomes auto-closed by GitHub. The losses
are silent — the harness sees ``state=closed`` and treats the work as
finished, but the diff was never landed on ``main``.

PR #233 merged with base-branch deletion took out PRs #235/#238/#239 in
this exact way. We reland-cycled them one-by-one. The cost was about an
hour of lost engineer time per drop. With 5+ parallel PRs typical, the
problem scales.

This tool runs after a merge batch and answers two questions:

  1. Which PRs auto-closed without merging since the cutoff?
  2. Of those, which still contain unlanded code (their head SHA is not
     reachable from main / the merged sibling)?

It also reconciles ``docs/V5_P0_FOLLOWUPS.md`` row status: if a row says
``DETECTED`` but a PR merged since the cutoff has a title that mentions
the same V5-P0-NN id, flag for status update to ``FIXED``.

Discipline
----------
- Stdlib only.
- ``--dry-run`` prints what it would have done without writing files.
- Network: uses ``gh`` CLI (gh api / gh pr list). Skips gracefully when
  ``gh`` is not installed (returns 2 with a clear error).
- ``--mock-dir <path>`` reads JSON fixtures from disk instead of calling
  ``gh`` — used in tests and for offline reproductions.
- Output: a markdown summary on stdout AND a JSON manifest at
  ``<repo>/.audit_logs/post_merge_reconcile_<ts>.json`` (or
  ``--manifest <path>``).

Schema
------
The JSON manifest is ``schema=auditooor.post_merge_reconcile.v1`` with
fields::

    {
      "schema": "auditooor.post_merge_reconcile.v1",
      "since": "<base ref or ISO ts>",
      "merged_prs": [<#>, ...],
      "auto_closed_prs": [<#>, ...],
      "auto_closed_with_unlanded_code": [
        {"number": <#>, "title": "...", "head_sha": "...",
         "needs_reopen": true}
      ],
      "tracker_status_updates": [
        {"row_id": "V5-P0-17", "from": "DETECTED", "to": "FIXED",
         "evidence_pr": <#>}
      ]
    }

Usage
-----
::

    python3 tools/post-merge-reconcile.py --since HEAD~5 --dry-run
    python3 tools/post-merge-reconcile.py --since 2026-04-25T00:00:00Z
    python3 tools/post-merge-reconcile.py --mock-dir tools/tests/fixtures/reconcile/case_a

Exit codes
----------
0  reconcile clean (no auto-closed PRs with unlanded code, no stale tracker rows)
1  at least one auto-closed-with-unlanded-code PR found, OR a tracker row
   needs status update
2  invocation / I/O error
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]


# ---- gh wrappers / mock loader --------------------------------------------


def _gh(repo: Path, *args: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """Run ``gh`` and return ``(rc, stdout, stderr)`` (stripped)."""
    try:
        proc = subprocess.run(
            ["gh", *args],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"


def _load_mock_json(mock_dir: Path, name: str) -> object:
    """Load a JSON fixture file by name (without extension)."""
    p = mock_dir / f"{name}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


# ---- core reconcile logic --------------------------------------------------


_V5_P0_RE = re.compile(r"V5-P0-(\d+)", re.IGNORECASE)


def list_merged_prs(
    repo: Path,
    since: str,
    *,
    mock_dir: Path | None = None,
) -> list[dict]:
    """List PRs merged since ``since``.

    ``since`` can be a git ref or an ISO timestamp; we forward to
    ``gh pr list --state=merged --search ...`` and filter by mergedAt
    locally (gh's ``--search merged:>...`` query syntax is the canonical
    way, but we keep a Python filter as a belt-and-braces guard against
    timezone surprises).
    """
    if mock_dir is not None:
        rows = _load_mock_json(mock_dir, "merged_prs")
        return rows if isinstance(rows, list) else []
    # Resolve `since` to an ISO ts. If it looks like an ISO already, keep
    # it. Otherwise treat as a git ref and read the commit time.
    iso = _resolve_since_to_iso(repo, since)
    rc, out, err = _gh(
        repo, "pr", "list",
        "--state", "merged",
        "--limit", "100",
        "--search", f"merged:>={iso}",
        "--json", "number,title,mergedAt,headRefName,baseRefName,mergeCommit",
    )
    if rc != 0 or not out:
        return []
    try:
        rows = json.loads(out)
    except ValueError:
        return []
    return rows if isinstance(rows, list) else []


def list_closed_unmerged_prs(
    repo: Path,
    since: str,
    *,
    mock_dir: Path | None = None,
) -> list[dict]:
    """List PRs closed (without merge) since ``since``."""
    if mock_dir is not None:
        rows = _load_mock_json(mock_dir, "closed_unmerged_prs")
        return rows if isinstance(rows, list) else []
    iso = _resolve_since_to_iso(repo, since)
    rc, out, err = _gh(
        repo, "pr", "list",
        "--state", "closed",
        "--limit", "100",
        "--search", f"is:closed is:unmerged closed:>={iso}",
        "--json", "number,title,closedAt,headRefName,baseRefName,headRefOid",
    )
    if rc != 0 or not out:
        return []
    try:
        rows = json.loads(out)
    except ValueError:
        return []
    return rows if isinstance(rows, list) else []


def _resolve_since_to_iso(repo: Path, since: str) -> str:
    """If ``since`` looks like an ISO ts, keep it. Else treat as a git ref
    and read the commit time. Default cutoff: 24h ago.
    """
    if not since:
        cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=24)
        return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    if re.match(r"^\d{4}-\d{2}-\d{2}T", since) or re.match(r"^\d{4}-\d{2}-\d{2}$", since):
        return since
    # Treat as a git ref.
    try:
        proc = subprocess.run(
            ["git", "log", "-1", "--format=%cI", since],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        pass
    # Fallback: 24h ago.
    cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=24)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha_in_main(repo: Path, sha: str, *, mock_dir: Path | None = None) -> bool:
    """Return True iff ``sha`` is reachable from ``main``.

    Edge case (Kimi pre-review): if the SHA is empty or the local clone
    doesn't have it, we conservatively return False (treat as unlanded)
    rather than silently skipping. The cost of a false-positive
    needs-reopen flag is one extra manual review; the cost of a missed
    auto-closure is hours of lost work.
    """
    if not sha:
        return False
    if mock_dir is not None:
        # Map: sha -> bool, in `main_reachable.json`.
        m = _load_mock_json(mock_dir, "main_reachable")
        if isinstance(m, dict):
            return bool(m.get(sha, False))
        return False
    try:
        proc = subprocess.run(
            ["git", "merge-base", "--is-ancestor", sha, "main"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        return proc.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def parse_followups_status(text: str) -> dict[str, str]:
    """Parse a markdown table with ``V5-P0-NN`` rows; return a map of
    ``id -> status``. Status tokens: DETECTED, FIXED, IN_PROGRESS, etc.

    The parser is conservative: it reads each line, looks for a
    ``V5-P0-NN`` token and any of the recognised status tokens on the
    same line. Lines without both are skipped.
    """
    statuses: dict[str, str] = {}
    known = {"DETECTED", "FIXED", "IN_PROGRESS", "DEFERRED", "WONTFIX"}
    for line in text.splitlines():
        idm = _V5_P0_RE.search(line)
        if not idm:
            continue
        row_id = "V5-P0-" + idm.group(1)
        # Pick the first known status word on the line.
        for tok in known:
            if re.search(rf"\b{tok}\b", line):
                statuses[row_id] = tok
                break
    return statuses


def reconcile(
    repo: Path,
    since: str,
    *,
    mock_dir: Path | None = None,
) -> dict:
    """Run the reconcile and return a manifest dict."""
    merged = list_merged_prs(repo, since, mock_dir=mock_dir)
    closed = list_closed_unmerged_prs(repo, since, mock_dir=mock_dir)

    # Build the auto-closed list: closed-without-merge whose head SHA is
    # NOT reachable from main. Those are the ones that lost work.
    auto_closed_unlanded: list[dict] = []
    for pr in closed:
        head_sha = pr.get("headRefOid") or ""
        in_main = _sha_in_main(repo, head_sha, mock_dir=mock_dir)
        if not in_main:
            auto_closed_unlanded.append({
                "number": pr.get("number"),
                "title": pr.get("title", ""),
                "head_sha": head_sha,
                "head_ref": pr.get("headRefName", ""),
                "base_ref": pr.get("baseRefName", ""),
                "closed_at": pr.get("closedAt", ""),
                "needs_reopen": True,
            })

    # Tracker reconciliation. Read docs/V5_P0_FOLLOWUPS.md if present.
    tracker_path = REPO_ROOT / "docs" / "V5_P0_FOLLOWUPS.md"
    tracker_updates: list[dict] = []
    if tracker_path.exists():
        text = tracker_path.read_text(encoding="utf-8")
        statuses = parse_followups_status(text)
        # If a merged PR title contains V5-P0-NN, the corresponding row is
        # likely now FIXED. Suggest the update; do NOT auto-write.
        for pr in merged:
            title = pr.get("title", "") or ""
            for m in _V5_P0_RE.finditer(title):
                row_id = "V5-P0-" + m.group(1)
                cur = statuses.get(row_id)
                if cur and cur != "FIXED":
                    tracker_updates.append({
                        "row_id": row_id,
                        "from": cur,
                        "to": "FIXED",
                        "evidence_pr": pr.get("number"),
                        "evidence_title": title,
                    })

    return {
        "schema": "auditooor.post_merge_reconcile.v1",
        "since": since,
        "merged_prs": [pr.get("number") for pr in merged if pr.get("number")],
        "auto_closed_prs": [pr.get("number") for pr in closed if pr.get("number")],
        "auto_closed_with_unlanded_code": auto_closed_unlanded,
        "tracker_status_updates": tracker_updates,
    }


def render_markdown(manifest: dict) -> str:
    lines: list[str] = []
    lines.append(f"# post-merge reconcile (since {manifest['since']})")
    lines.append("")
    lines.append(
        f"- merged PRs: {len(manifest['merged_prs'])}"
        + (f" — {manifest['merged_prs']}" if manifest['merged_prs'] else "")
    )
    lines.append(
        f"- auto-closed PRs: {len(manifest['auto_closed_prs'])}"
        + (
            f" — {manifest['auto_closed_prs']}"
            if manifest["auto_closed_prs"]
            else ""
        )
    )
    unlanded = manifest["auto_closed_with_unlanded_code"]
    if unlanded:
        lines.append("")
        lines.append("## Auto-closed PRs with unlanded code (NEEDS REOPEN)")
        for row in unlanded:
            lines.append(
                f"- #{row['number']}: {row['title']!r}  "
                f"head={row['head_sha'][:8]} base={row['base_ref']}"
            )
    updates = manifest["tracker_status_updates"]
    if updates:
        lines.append("")
        lines.append("## Tracker rows that need status updates")
        for row in updates:
            lines.append(
                f"- {row['row_id']}: {row['from']} -> {row['to']}  "
                f"(merged via #{row['evidence_pr']})"
            )
    if not unlanded and not updates:
        lines.append("")
        lines.append("RECONCILE CLEAN — no auto-closed PRs with unlanded code "
                     "and no stale tracker rows.")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Post-merge reconcile: find auto-closed PRs that lost code, "
            "and stale V5-P0-NN tracker rows after a merge batch "
            "(V5-P0-20, Gap 37)."
        ),
    )
    p.add_argument("--repo", type=Path, default=Path.cwd(),
                   help="Repo root (default: cwd).")
    p.add_argument("--since", default="HEAD~5",
                   help="Cutoff: a git ref or ISO ts (default: HEAD~5).")
    p.add_argument("--mock-dir", type=Path, default=None,
                   help="Read gh outputs from JSON fixtures (testing only).")
    p.add_argument("--manifest", type=Path, default=None,
                   help="Path to write the JSON manifest "
                        "(default: <repo>/.audit_logs/post_merge_reconcile_<ts>.json)")
    p.add_argument("--dry-run", action="store_true",
                   help="Print what it would do; do not write the manifest.")
    p.add_argument("--json", action="store_true",
                   help="Print JSON manifest to stdout instead of markdown.")
    args = p.parse_args(argv)

    if args.mock_dir is None and shutil.which("gh") is None:
        print("[post-merge-reconcile] error: `gh` not on PATH",
              file=sys.stderr)
        return 2

    try:
        manifest = reconcile(args.repo, args.since, mock_dir=args.mock_dir)
    except Exception as exc:  # pragma: no cover (defensive)
        print(f"[post-merge-reconcile] reconcile error: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(manifest, indent=2))
    else:
        print(render_markdown(manifest))

    if not args.dry_run:
        out_path = args.manifest
        if out_path is None:
            ts = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            out_dir = args.repo / ".audit_logs"
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"post_merge_reconcile_{ts}.json"
        try:
            out_path.write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            if not args.json:
                print(f"\nmanifest: {out_path}")
        except OSError as exc:
            print(f"[post-merge-reconcile] could not write manifest: {exc}",
                  file=sys.stderr)
            return 2

    has_unlanded = bool(manifest["auto_closed_with_unlanded_code"])
    has_stale = bool(manifest["tracker_status_updates"])
    return 1 if (has_unlanded or has_stale) else 0


if __name__ == "__main__":
    sys.exit(main())
