#!/usr/bin/env python3
"""
mcp-pin-drift-check.py — Track E-3 (Wave-4 Big-Plan)

Detects drift between the vault-mcp-server.py in the worktree and its
canonical mirror at ~/auditooor-mcp/.

Four drift classes, ordered by severity:
  1  doc-count drift    — AGENTS.md / README.md / VAULT_MCP_SERVER.md claim N callables;
                          actual grep yields K
  2  content drift      — worktree vault-mcp-server.py hash != ~/auditooor-mcp/ hash
  3  upstream drift     — ~/auditooor-mcp/ HEAD is behind origin/main by >=1 commit
  4  mirror-gap drift   — worktree has commits touching vault-mcp-server.py that are
                          absent from ~/auditooor-mcp/

Exit codes:
  0  all clear
  1  doc-count drift (advisory)
  2  content drift
  3  upstream drift
  4  mirror-gap drift
  Highest-priority code wins when multiple faults present.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MCP_REPO = Path.home() / "auditooor-mcp"
MCP_SERVER_RELPATH = Path("tools") / "vault-mcp-server.py"

# Docs to check for callable-count claims.
DOC_TARGETS: list[tuple[str, Path]] = [
    ("AGENTS.md", REPO_ROOT / "AGENTS.md"),
    ("README.md", REPO_ROOT / "README.md"),
    ("docs/VAULT_MCP_SERVER.md", REPO_ROOT / "docs" / "VAULT_MCP_SERVER.md"),
]
# Pattern: "<N> registered callables" or "<N> callable" in a doc line
# Negative lookbehind excludes L-prefixed codes like "L19 callable" and date patterns like "2026-05-07 callables"
_DOC_COUNT_RE = re.compile(r"(?<![\w-])(\d+)\s+(?:registered\s+)?callable", re.IGNORECASE)


def count_actual_callables(mcp_server_path: Path) -> int:
    """Count vault_<name> entries in the TOOL_SCHEMAS section via regex."""
    text = mcp_server_path.read_text(encoding="utf-8", errors="replace")
    names = set(re.findall(r'"name":\s*"(vault_\w+)"', text))
    return len(names)


def parse_doc_counts(docs: list[tuple[str, Path]]) -> dict[str, int | str]:
    """Return mapping of doc-label -> first integer count claim found, or 'no claim'."""
    result: dict[str, int | str] = {}
    for label, path in docs:
        if not path.exists():
            result[label] = "missing"
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        m = _DOC_COUNT_RE.search(text)
        if m:
            result[label] = int(m.group(1))
        else:
            result[label] = "no claim"
    return result


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def git_head_sha(repo: Path) -> str | None:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo, capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def git_remote_head_sha(repo: Path, remote_branch: str = "origin/main") -> str | None:
    """Return SHA of remote tracking branch without fetching."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", remote_branch],
            cwd=repo, capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def git_upstream_lag(repo: Path) -> int:
    """Number of commits on origin/main not yet in HEAD. Does NOT fetch."""
    try:
        r = subprocess.run(
            ["git", "rev-list", "--count", "HEAD..origin/main"],
            cwd=repo, capture_output=True, text=True, timeout=10
        )
        return int(r.stdout.strip()) if r.returncode == 0 else -1
    except Exception:
        return -1


def git_commits_touching_file(repo: Path, relpath: Path, since_sha: str | None = None) -> list[str]:
    """Return commit SHAs that touch relpath in repo, optionally since a base SHA."""
    cmd = ["git", "log", "--oneline", "--follow", "--", str(relpath)]
    if since_sha:
        cmd = ["git", "log", "--oneline", "--follow", f"{since_sha}..HEAD", "--", str(relpath)]
    try:
        r = subprocess.run(cmd, cwd=repo, capture_output=True, text=True, timeout=15)
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        return [l.split()[0] for l in lines if l]
    except Exception:
        return []


def check_mirror_gap(worktree: Path, mcp_repo: Path) -> tuple[int, list[str]]:
    """
    Return (count_of_gap_commits, list_of_gap_commit_shas).
    Gap = commits in worktree that touch vault-mcp-server.py but whose SHA is not
    present in the mcp_repo's log for the same file.
    Strategy: get mcp_repo's HEAD sha; list worktree commits after that sha.
    """
    mcp_head = git_head_sha(mcp_repo)
    if mcp_head is None:
        return (0, [])
    # Commits in worktree touching the file AFTER mcp_repo HEAD
    gap_commits = git_commits_touching_file(worktree, MCP_SERVER_RELPATH, since_sha=mcp_head)
    return (len(gap_commits), gap_commits)


def run(mcp_repo: Path, strict: bool = False, as_json: bool = False) -> int:
    worktree_server = REPO_ROOT / MCP_SERVER_RELPATH
    mcp_server = mcp_repo / MCP_SERVER_RELPATH

    # --- actual callable count ---
    if worktree_server.exists():
        actual_count = count_actual_callables(worktree_server)
    else:
        actual_count = 0

    # --- doc counts ---
    doc_counts = parse_doc_counts(DOC_TARGETS)
    doc_drift = False
    doc_drift_details: list[str] = []
    for label, claimed in doc_counts.items():
        if isinstance(claimed, int) and claimed != actual_count:
            doc_drift = True
            doc_drift_details.append(f"{label} claims {claimed}, actual={actual_count}")

    # --- content hash ---
    hash_worktree: str | None = None
    hash_mcp: str | None = None
    content_drift = False
    if worktree_server.exists():
        hash_worktree = file_sha256(worktree_server)
    if mcp_server.exists():
        hash_mcp = file_sha256(mcp_server)
    if hash_worktree and hash_mcp:
        content_drift = hash_worktree != hash_mcp
    elif hash_worktree and not hash_mcp:
        content_drift = True  # mcp copy missing

    # --- upstream lag ---
    mcp_head = git_head_sha(mcp_repo)
    mcp_origin = git_remote_head_sha(mcp_repo)
    upstream_lag = git_upstream_lag(mcp_repo)
    upstream_drift = upstream_lag > 0

    # --- mirror gap ---
    gap_count, gap_shas = check_mirror_gap(REPO_ROOT, mcp_repo)
    mirror_drift = gap_count > 0

    # --- verdict ---
    if content_drift or mirror_drift or upstream_drift or doc_drift:
        if content_drift or mirror_drift:
            verdict = "drift-detected"
        elif upstream_drift:
            verdict = "upstream-behind"
        else:
            verdict = "doc-count-mismatch"
    else:
        verdict = "in-sync"

    # --- exit code ---
    exit_code = 0
    # Priority: 4 > 3 > 2 > 1
    if doc_drift:
        exit_code = max(exit_code, 1)
    if content_drift:
        exit_code = max(exit_code, 2)
    if upstream_drift:
        exit_code = max(exit_code, 3)
    if mirror_drift:
        exit_code = max(exit_code, 4)

    output: dict[str, Any] = {
        "actual_count": actual_count,
        "doc_counts": doc_counts,
        "doc_drift": doc_drift,
        "doc_drift_details": doc_drift_details,
        "content_hash_worktree": hash_worktree,
        "content_hash_mcp_repo": hash_mcp,
        "content_drift": content_drift,
        "mcp_repo_head": mcp_head,
        "mcp_repo_origin_main": mcp_origin,
        "upstream_lag_commits": upstream_lag,
        "mirror_gap_count": gap_count,
        "mirror_gap_shas": gap_shas,
        "verdict": verdict,
        "exit_code": exit_code,
    }

    if as_json:
        print(json.dumps(output, indent=2))
    else:
        _print_human(output, strict=strict)

    return exit_code


def _print_human(out: dict[str, Any], strict: bool) -> None:
    tag = "[mcp-pin-drift-check]"
    verdict = out["verdict"]

    if verdict == "in-sync":
        print(f"{tag} OK  all checks pass — {out['actual_count']} callables, content in-sync, upstream current")
        return

    print(f"{tag} verdict={verdict}")
    print(f"  actual callable count : {out['actual_count']}")

    if out["doc_drift"]:
        print("  DOC-COUNT DRIFT (advisory, exit=1):")
        for detail in out["doc_drift_details"]:
            print(f"    - {detail}")

    if out["content_drift"]:
        print("  CONTENT DRIFT (exit=2):")
        print(f"    worktree hash : {out['content_hash_worktree']}")
        print(f"    mcp-repo hash : {out['content_hash_mcp_repo']}")

    if out["upstream_lag_commits"] > 0:
        print(f"  UPSTREAM DRIFT (exit=3): mcp-repo is {out['upstream_lag_commits']} commit(s) behind origin/main")
        print(f"    recommendation: git -C ~/auditooor-mcp pull origin main")

    if out["mirror_gap_count"] > 0:
        print(f"  MIRROR GAP (exit=4): {out['mirror_gap_count']} worktree commit(s) touching vault-mcp-server.py not in mcp-repo:")
        for sha in out["mirror_gap_shas"]:
            print(f"    {sha}")


def main() -> None:
    p = argparse.ArgumentParser(
        description="Detect drift between worktree vault-mcp-server.py and ~/auditooor-mcp/ mirror."
    )
    p.add_argument("--mcp-repo", default=str(DEFAULT_MCP_REPO),
                   help="Path to the auditooor-mcp canonical repo (default: ~/auditooor-mcp)")
    p.add_argument("--strict", action="store_true",
                   help="Exit non-zero on any drift, including advisory doc-count drift")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="Emit JSON output instead of human-readable text")
    args = p.parse_args()

    mcp_repo = Path(args.mcp_repo).expanduser().resolve()
    if not mcp_repo.exists():
        if args.as_json:
            print(json.dumps({"error": f"mcp_repo not found: {mcp_repo}", "exit_code": 2}))
        else:
            print(f"[mcp-pin-drift-check] ERROR: mcp_repo not found: {mcp_repo}", file=sys.stderr)
        sys.exit(2)

    code = run(mcp_repo=mcp_repo, strict=args.strict, as_json=args.as_json)
    if not args.strict and code == 1:
        # doc-count drift is advisory only; don't exit non-zero in non-strict mode
        code = 0
    sys.exit(code)


if __name__ == "__main__":
    main()
