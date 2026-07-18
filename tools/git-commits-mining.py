#!/usr/bin/env python3
"""git-commits-mining.py — Tier-6 GitHub commits miner for prior-audited workspaces.

Mines the upstream GitHub repo of a prior-audited workspace for security-fix-shaped
commits since the audit-pin date. Mirrors the mine-solodit.py / solodit-ingest.py
shape but for git history (not Solodit DB).

POC implementation for Worker-KK loop-8 (centrifuge-v3). Future loops repeat the
flow per workspace.

Usage (POC mode, hard-coded centrifuge inputs):
    python3 tools/git-commits-mining.py \\
        --workspace centrifuge-v3 \\
        --upstream centrifuge/protocol \\
        --since 2026-01-13 \\
        --out reports/git_commits_mining_centrifuge-v3_2026-05-06.json

Stdlib-only. Uses ``gh api`` shell-out for commit enumeration (no python deps).
Falls back to local ``git log`` if ``gh auth status`` fails.

Schema: ``auditooor.git_commits_mining.v1`` (additive bump to ``schema_version: "1.1"``)
    {
      "schema": "auditooor.git_commits_mining.v1",
      "schema_version": "1.1",
      "workspace": "<ws>",
      "upstream_repo": "<owner/repo>",
      "audit_pin_sha": "<sha>",
      "since_date": "<ISO date>",
      "generated_at": "<ISO timestamp>",
      "commits_scanned": <int>,
      "security_fix_count": <int>,
      "filter_regex": "<regex>",
      "fallback_used": <bool>,
      "commits": [
        {
          "sha": "<full-sha>",
          "url": "https://github.com/<owner>/<repo>/commit/<sha>",
          "date": "<ISO>",
          "subject": "<first-line>",
          "classification": "security_fix|code_quality|feature|unclear",
          "bug_class": "<class>" | null,
          "summary": "<reviewer-derived summary>",
          "derivable_pattern": "yes|no|maybe",
          "files_in_scope_src": [<paths>],
          "patterns": [
            {
              "id": "...",
              "...": "...",
              "impact_contract_preflight": {  # v1.1 advisory-only annotation
                "schema_version": "auditooor.impact_contract_preflight.v1",
                "route": "exploit-memory",
                "artifact_class": "planning",
                "decision": {"code": "...", "blocked": false, ...},
                ...
              }
            }, ...
          ]
        }, ...
      ]
    }

v1.1 migration semantics:
- Old v1 reports remain valid (no retroactive rewrite). The new
  ``schema_version`` field is additive; consumers reading ``schema`` keep
  working, and consumers asking for explicit version semantics see ``"1.1"``.
- ``impact_contract_preflight`` is attached per pattern in ``commits[].patterns[]``
  via ``build_packet(route="exploit-memory")`` from
  ``tools/impact-contract-preflight.py``. It is **advisory-only**: mining is
  exploration, not submission, so the gate never fail-closes here. Decisions
  are surfaced for downstream draft generators to inherit (see SS L10 audit:
  ``docs/next-loop/impact_contract_universal_coverage_2026-05-07.md`` Patch C).
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Optional


SCHEMA_VERSION = "1.3"
SOLIDITY_SCHEMA = "auditooor.git_commits_mining.v1.2-solidity"
SOLIDITY_SCHEMA_VERSION = "1.3-solidity"
GH_TIMEOUT_SECONDS = 15
GIT_TIMEOUT_SECONDS = 15
LOCAL_GIT_ONLY_EXIT_CODE = 3


# Heuristic regex from task spec. Wide on purpose; we then cull by inspecting diffs.
SECURITY_FIX_REGEX = re.compile(
    r"(fix|patch|hardening|cve|advisory|security|vuln|exploit|reentrancy|"
    r"overflow|underflow|access.?control|auth|race|invariant)",
    re.IGNORECASE,
)

SOLIDITY_FIX_REGEX = re.compile(
    r"(fix|patch|hardening|security|vuln|exploit|invariant|initialize|initializer|"
    r"upgrade|storage|proxy|reentrancy|guard|access|liquidation|interest|ordering|oracle)",
    re.IGNORECASE,
)

# Negative filter — drop commits that are obviously not protocol fixes.
NON_PROTOCOL_REGEX = re.compile(
    r"(formatting|natspec|coverage\b|^docs|README|^CI\b|\bci\)|test\b|"
    r"deployment|deploy|registry|spell|wiring|env\b|script)",
    re.IGNORECASE,
)

SOLIDITY_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str], int], ...] = (
    ("fix", re.compile(r"\bfix(?:e[sd]?|ing)?\b", re.IGNORECASE), 3),
    ("invariant", re.compile(r"\binvariant\b", re.IGNORECASE), 3),
    ("initialize", re.compile(r"\b(?:initialize|initializer|reinitializer)\b", re.IGNORECASE), 2),
    ("upgrade", re.compile(r"\bupgrade(?:able|d)?\b", re.IGNORECASE), 2),
    ("storage", re.compile(r"\b(?:storage|layout|slot|gap)\b", re.IGNORECASE), 2),
    ("proxy", re.compile(r"\b(?:proxy|delegatecall|erc1967|uups|transparent)\b", re.IGNORECASE), 2),
    ("reentrancy", re.compile(r"\breentranc(?:y|ies)\b", re.IGNORECASE), 3),
    ("guard", re.compile(r"\bguard\b", re.IGNORECASE), 2),
    ("access", re.compile(r"\b(?:access|auth|owner|role)\b", re.IGNORECASE), 2),
    ("liquidation", re.compile(r"\bliquidat(?:e|ion)\b", re.IGNORECASE), 3),
    ("interest", re.compile(r"\binterest\b", re.IGNORECASE), 2),
    ("ordering", re.compile(r"\border(?:ing)?\b", re.IGNORECASE), 2),
    ("oracle", re.compile(r"\boracle\b", re.IGNORECASE), 2),
)
SOLIDITY_INHERITANCE_PATCH_REGEX = re.compile(
    r"^[+-]\s*(?:abstract\s+)?contract\s+\w+\s+is\s+[^{\n]+",
    re.IGNORECASE | re.MULTILINE,
)
SOLIDITY_OZ_INITIALIZER_REGEX = re.compile(
    r"(?:\binitializer\b|\breinitializer\b|__\w+_init(?:_unchained)?\b|\bInitializable\b|\bonlyInitializing\b)",
    re.IGNORECASE,
)
SOLIDITY_STORAGE_LAYOUT_REGEX = re.compile(
    r"(?:__gap\b|storage\s+gap|storage\s+slot|StorageSlot\b|ERC1967\b|\blayout\b)",
    re.IGNORECASE,
)
SOLIDITY_STATE_VAR_PATCH_REGEX = re.compile(
    r"^[+-]\s*(?!//)(?:\w+\s+)*(?:mapping\s*\(|\w+\[\]?|address|bool|bytes\d*|int\d*|string|uint\d*)\b",
    re.MULTILINE,
)

DISCUSSION_CLASSIFICATIONS = (
    "open",
    "closed",
    "accepted",
    "wont-fix",
    "fixed",
    "team-aware",
    "unknown",
)
_DISCUSSION_STATUS_PATTERNS = {
    "wont-fix": re.compile(r"\b(?:wont\s*fix|not planned|declined|rejected|won't fix)\b", re.I),
    "accepted": re.compile(r"\b(?:accepted|acknowledged|confirmed|valid finding)\b", re.I),
    "fixed": re.compile(r"\b(?:fixed|resolved|patched|implemented|merged)\b", re.I),
    "team-aware": re.compile(r"\b(?:security team|core team|maintainers?|triage team|team review)\b", re.I),
}


def _gh_env(base_env: Optional[dict[str, str]] = None) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    env["GH_PROMPT_DISABLED"] = "1"
    env["GH_NO_BROWSER"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    if env.get("GITHUB_TOKEN") and not env.get("GH_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    return env


def _has_gh_token(base_env: Optional[dict[str, str]] = None) -> bool:
    env = _gh_env(base_env)
    return bool(env.get("GH_TOKEN"))


def run_gh(args: list[str], timeout: int = GH_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_gh_env(),
    )


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    # GIT_NO_LAZY_FETCH=1 (git >= 2.36): on a PARTIAL/blobless clone (--filter=blob:none,
    # the disk-saving default for fetch-targets/step-0d), a blob-content op like
    # `git show --find-renames <historical_sha>` would otherwise trigger an on-demand
    # NETWORK fetch of every missing blob FOR EACH COMMIT - turning backward/bidirectional
    # commit-mining across N repos into thousands of network round-trips (observed: make
    # audit network-thrashing for minutes on an 18-repo Lido workspace). With this set, the
    # blob-content `git show` fails FAST and locally; the caller already tolerates that
    # (local_git_commit_detail: patch_text="" when patch.returncode!=0), and the tree-level
    # `git show --name-only` (changed paths, no blob content) still succeeds offline - so
    # shaped-commit classification keeps its subject+paths signal with zero network. Generic:
    # applies to every blobless-cloned workspace; full clones are unaffected (blobs present).
    env["GIT_NO_LAZY_FETCH"] = "1"
    return env


def run_git(
    repo: pathlib.Path,
    args: list[str],
    timeout: int = GIT_TIMEOUT_SECONDS,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=_git_env(),
    )


def _extract_keyring_token() -> Optional[str]:
    """Pull a token out of the local `gh` keyring via `gh auth token`.

    Non-interactive shells (cron, MCP-spawned tools) frequently cannot see the
    keyring-backed credential that an interactive `gh auth login` established, so
    `gh api` silently degrades to anonymous/local-only. Materialising the token
    once and injecting it into the process env makes every later `gh api` call
    authenticate, which is the generic fix for the "connected to GitHub but ran
    local-git-only" degradation. Returns None if no token is available.
    """
    try:
        r = run_gh(["auth", "token", "--hostname", "github.com"])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    tok = (r.stdout or "").strip()
    return tok if r.returncode == 0 and tok else None


_GH_AUTH_OK_CACHE: Optional[bool] = None


def gh_auth_ok() -> bool:
    """True iff gh is usable; CACHED per-process + STATUS-FIRST.

    Perf/correctness fix (found stalling an 18-repo Lido make audit): this is
    called once PER in-scope repo by audit-target-commit-mining. The old order
    ran `gh auth token` FIRST, which BLOCKS on the OS keychain (observed: a
    `timeout 30 gh auth token` per repo -> minutes of stall on a machine where
    the keyring credential is not non-interactively readable). Now:
      1) module-level cache -> probe ONCE per process, not 18x;
      2) `gh auth status` FIRST (a fast liveness check that does NOT decrypt /
         prompt the keychain like `gh auth token` does) - if it is not authed we
         return False immediately and NEVER touch the hanging token path;
      3) only when status says authed do we materialise the token (safe then)
         and inject GH_TOKEN so later `gh api` calls authenticate.
    Net: zero keychain hangs in the no-auth case (the common cron/MCP shell),
    and a single fast probe otherwise. Generic across every workspace.
    """
    global _GH_AUTH_OK_CACHE
    if _GH_AUTH_OK_CACHE is not None:
        return _GH_AUTH_OK_CACHE
    result = False
    if _has_gh_token():
        result = True
    else:
        try:
            status = run_gh(["auth", "status", "--hostname", "github.com"])
            if status.returncode == 0:
                # Authed: now it is safe to materialise the keyring token (it will
                # not hang) so non-interactive `gh api` calls do not degrade.
                tok = _extract_keyring_token()
                if tok:
                    os.environ["GH_TOKEN"] = tok
                result = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            result = False
    _GH_AUTH_OK_CACHE = result
    return result


def gh_commits_since(repo: str, since_iso: str) -> list[dict]:
    """Enumerate commits via `gh api repos/<repo>/commits?since=...`. Paginates."""
    cmd = [
        "gh",
        "api",
        "--paginate",
        f"repos/{repo}/commits?since={since_iso}&per_page=100",
        "--jq",
        ".[] | {sha: .sha, date: .commit.author.date, "
        "message: .commit.message}",
    ]
    r = run_gh(cmd[1:])
    if r.returncode != 0:
        raise RuntimeError(f"gh api failed: {r.stderr.strip()}")
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def gh_commits_window(repo: str, ref: str, window: int) -> list[dict]:
    """Enumerate a bounded history window reachable from ``ref``."""
    if window <= 0:
        return []
    cmd = [
        "gh",
        "api",
        f"repos/{repo}/commits?sha={ref}&per_page={window}",
        "--jq",
        ".[] | {sha: .sha, date: .commit.author.date, "
        "message: .commit.message}",
    ]
    r = run_gh(cmd[1:])
    if r.returncode != 0:
        raise RuntimeError(f"gh api failed: {r.stderr.strip()}")
    out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def gh_commit_files(repo: str, sha: str) -> list[str]:
    """Return list of paths touched by the commit (filtered to src/)."""
    cmd = [
        "gh",
        "api",
        f"repos/{repo}/commits/{sha}",
        "--jq",
        "[.files[]?.filename]",
    ]
    r = run_gh(cmd[1:])
    if r.returncode != 0:
        return []
    try:
        return json.loads(r.stdout) or []
    except json.JSONDecodeError:
        return []


def gh_commit_detail(repo: str, sha: str) -> dict[str, Any]:
    """Return the raw GitHub commit payload for ``sha``."""
    cmd = ["gh", "api", f"repos/{repo}/commits/{sha}"]
    r = run_gh(cmd[1:])
    if r.returncode != 0:
        return {}
    try:
        payload = json.loads(r.stdout)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


# --------------------------------------------------------------------------
# Unauthenticated public GitHub API path (gh-auth-free remote mine).
#
# The gh CLI path needs a keyring token (`gh auth token`), which HANGS in
# non-interactive shells where the macOS keychain wants an interactive unlock -
# so an audit loop silently degrades to local-git-only and NEVER forward-mines
# post-pin upstream security fixes. For PUBLIC repos those commits are readable
# with NO auth at all via api.github.com. This tier sits between gh-auth and
# local-git-only: real remote forward+backward mine without the keychain.
# --------------------------------------------------------------------------
_PUBLIC_API_TIMEOUT = 20


def _public_api_get(path: str):
    """GET https://api.github.com/<path> UNAUTHENTICATED. Returns parsed JSON,
    or None on any error (404 private/not-found, 403 rate-limit, network)."""
    import urllib.request as _u
    import urllib.error as _ue
    url = f"https://api.github.com/{path.lstrip('/')}"
    try:
        req = _u.Request(url, headers={
            "User-Agent": "auditooor-commit-mining",
            "Accept": "application/vnd.github+json",
        })
        with _u.urlopen(req, timeout=_PUBLIC_API_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except (_ue.HTTPError, _ue.URLError, TimeoutError, ValueError, OSError):
        return None


def public_repo_accessible(repo: str) -> bool:
    """True iff the repo is a PUBLIC GitHub repo readable without auth."""
    d = _public_api_get(f"repos/{repo}")
    return isinstance(d, dict) and not d.get("private", True) and bool(d.get("full_name"))


def _public_paginate_commits(repo: str, query: str, hard_cap: int = 1000) -> list[dict]:
    """Paginate repos/<repo>/commits?<query> unauthenticated; normalize shape."""
    out: list[dict] = []
    page = 1
    while len(out) < hard_cap:
        data = _public_api_get(f"repos/{repo}/commits?{query}&per_page=100&page={page}")
        if not isinstance(data, list) or not data:
            break
        for c in data:
            if not isinstance(c, dict):
                continue
            commit = c.get("commit") or {}
            author = commit.get("author") or {}
            out.append({
                "sha": c.get("sha"),
                "date": author.get("date"),
                "message": commit.get("message", ""),
            })
        if len(data) < 100:
            break
        page += 1
    return out


def public_commits_since(repo: str, since_iso: str) -> list[dict]:
    return _public_paginate_commits(repo, f"since={since_iso}")


def public_commits_window(repo: str, ref: str, window: int) -> list[dict]:
    if window <= 0:
        return []
    data = _public_api_get(f"repos/{repo}/commits?sha={ref}&per_page={min(window, 100)}")
    out: list[dict] = []
    if isinstance(data, list):
        for c in data[:window]:
            if not isinstance(c, dict):
                continue
            commit = c.get("commit") or {}
            author = commit.get("author") or {}
            out.append({
                "sha": c.get("sha"),
                "date": author.get("date"),
                "message": commit.get("message", ""),
            })
    return out


def public_commit_detail(repo: str, sha: str) -> dict[str, Any]:
    d = _public_api_get(f"repos/{repo}/commits/{sha}")
    return d if isinstance(d, dict) else {}


def public_commit_date(repo: str, sha: str) -> Optional[str]:
    d = _public_api_get(f"repos/{repo}/commits/{sha}")
    if isinstance(d, dict):
        date = ((d.get("commit") or {}).get("author") or {}).get("date")
        if isinstance(date, str) and len(date) >= 10:
            return date[:10]
    return None


def _parse_api_json(result: subprocess.CompletedProcess[str]) -> Any:
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return None


def gh_api_json(path: str) -> Any:
    """Read one GitHub REST resource through authenticated ``gh api``."""
    return _parse_api_json(run_gh(["api", path]))


def _discussion_text(pr: dict[str, Any], comments: list[dict[str, Any]], reviews: list[dict[str, Any]]) -> str:
    parts = [pr.get("title"), pr.get("body")]
    parts.extend(c.get("body") for c in comments if isinstance(c, dict))
    parts.extend(r.get("body") for r in reviews if isinstance(r, dict))
    parts.extend(label.get("name") for label in pr.get("labels", []) if isinstance(label, dict))
    return "\n".join(str(part) for part in parts if isinstance(part, str))


def classify_discussion_language(
    pr: dict[str, Any], comments: list[dict[str, Any]], reviews: list[dict[str, Any]]
) -> dict[str, Any]:
    """Classify issue/PR discussion language without treating it as triage proof."""
    text = _discussion_text(pr, comments, reviews)
    signals = [name for name, pattern in _DISCUSSION_STATUS_PATTERNS.items() if pattern.search(text)]
    state = str(pr.get("state") or "").lower()
    merged = bool(pr.get("merged_at"))
    if "wont-fix" in signals:
        classification = "wont-fix"
    elif merged or "fixed" in signals:
        classification = "fixed"
    elif "accepted" in signals:
        classification = "accepted"
    elif state == "open":
        classification = "open"
    elif state == "closed":
        classification = "closed"
    elif "team-aware" in signals:
        classification = "team-aware"
    else:
        classification = "unknown"
    return {"classification": classification, "signals": signals}


def _compact_discussion_item(item: dict[str, Any]) -> dict[str, Any]:
    user = item.get("user") or {}
    return {
        "id": item.get("id"),
        "author": user.get("login") if isinstance(user, dict) else None,
        "author_association": item.get("author_association"),
        "body_excerpt": str(item.get("body") or "")[:500],
        "created_at": item.get("created_at"),
        "html_url": item.get("html_url"),
    }


def collect_github_discussion_evidence(
    repo: str,
    shaped: list[dict[str, Any]],
    api_get: Any,
) -> list[dict[str, Any]]:
    """Collect bounded PR discussion evidence for shaped commits.

    ``api_get`` is injected so authenticated gh and unauthenticated public API
    paths share the same behavior. API errors are intentionally treated as an
    empty, advisory evidence set.
    """
    evidence: list[dict[str, Any]] = []
    for commit in shaped:
        sha = commit.get("sha")
        if not isinstance(sha, str):
            continue
        prs = api_get(f"repos/{repo}/commits/{sha}/pulls?per_page=100")
        if not isinstance(prs, list):
            continue
        for pr in prs:
            if not isinstance(pr, dict) or not isinstance(pr.get("number"), int):
                continue
            number = pr["number"]
            comments = api_get(f"repos/{repo}/issues/{number}/comments?per_page=100")
            reviews = api_get(f"repos/{repo}/pulls/{number}/reviews?per_page=100")
            comments = comments if isinstance(comments, list) else []
            reviews = reviews if isinstance(reviews, list) else []
            language = classify_discussion_language(pr, comments, reviews)
            evidence.append({
                "schema": "auditooor.git_discussion_evidence.v1",
                "evidence_type": "github_pr_discussion",
                "reconciliation_key": f"github:{repo}:pr:{number}:commit:{sha}",
                "commit_sha": sha,
                "pull_request_number": number,
                "pull_request_url": pr.get("html_url") or f"https://github.com/{repo}/pull/{number}",
                "issue_url": f"https://github.com/{repo}/issues/{number}",
                "source_ref": pr.get("html_url") or f"https://github.com/{repo}/pull/{number}",
                "title": pr.get("title"),
                "state": pr.get("state"),
                "merged_at": pr.get("merged_at"),
                "labels": [label.get("name") for label in pr.get("labels", []) if isinstance(label, dict)],
                "discussion_classification": language["classification"],
                "discussion_status": language["classification"],
                "discussion_language_classification": language["classification"],
                "classification_signals": language["signals"],
                "comments": [_compact_discussion_item(item) for item in comments[:20] if isinstance(item, dict)],
                "reviews": [_compact_discussion_item(item) for item in reviews[:20] if isinstance(item, dict)],
            })
    return evidence


def collect_public_commits(
    repo: str,
    since_iso: str,
    audit_pin: Optional[str],
    mode: str,
    window: Optional[int],
    bounded_forward_window: bool = False,
) -> list[dict]:
    if mode in {"forward", "bidirectional"}:
        if bounded_forward_window and window:
            forward = public_commits_window(repo, "HEAD", window)
        else:
            forward = public_commits_since(repo, since_iso)
    else:
        forward = []
    backward = []
    if mode in {"backward", "bidirectional"} and audit_pin and window:
        backward = public_commits_window(repo, audit_pin, window)
    merged: list[dict] = []
    seen: set[str] = set()
    for commit in forward + backward:
        sha = commit.get("sha")
        if not isinstance(sha, str) or sha in seen:
            continue
        seen.add(sha)
        merged.append(commit)
    return merged


def _normalize_github_repo_slug(value: str) -> str:
    raw = value.strip().rstrip("/")
    if raw.startswith("git@github.com:"):
        raw = raw.split(":", 1)[1]
    elif "github.com/" in raw:
        raw = raw.split("github.com/", 1)[1]
    raw = re.sub(r"\.git$", "", raw.rstrip("/"))
    parts = [part for part in raw.split("/") if part]
    if len(parts) >= 2:
        return "/".join(parts[:2]).lower()
    return raw.lower()


def _is_git_repo(repo: pathlib.Path) -> bool:
    try:
        r = run_git(repo, ["rev-parse", "--is-inside-work-tree"])
        if r.returncode == 0 and r.stdout.strip() == "true":
            return True
        # BARE repos (mirror/partial clones used for offline commit mining) have no
        # work tree, so --is-inside-work-tree returns "false" - but `git log` works
        # fine on them. Accept them too, else --local-repo on a cached bare clone is
        # rejected and the miner falls through to the (here unauthenticated) gh path.
        rb = run_git(repo, ["rev-parse", "--is-bare-repository"])
        return rb.returncode == 0 and rb.stdout.strip() == "true"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _local_repo_matches_upstream(repo: pathlib.Path, upstream: str) -> bool:
    try:
        r = run_git(repo, ["config", "--get", "remote.origin.url"])
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    if r.returncode != 0:
        return False
    return _normalize_github_repo_slug(r.stdout.strip()) == _normalize_github_repo_slug(upstream)


def resolve_local_repo(upstream: str, local_repo: Optional[str] = None) -> Optional[pathlib.Path]:
    if local_repo:
        candidate = pathlib.Path(local_repo).expanduser().resolve()
        return candidate if _is_git_repo(candidate) else None
    cwd = pathlib.Path.cwd()
    if _is_git_repo(cwd) and _local_repo_matches_upstream(cwd, upstream):
        return cwd
    return None


def _parse_git_log(stdout: str) -> list[dict]:
    commits = []
    for line in stdout.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        sha, date, message = parts
        commits.append({"sha": sha, "date": date, "message": message})
    return commits


def local_git_commits_since(local_repo: pathlib.Path, since_iso: str) -> list[dict]:
    r = run_git(local_repo, ["log", f"--since={since_iso}", "--format=%H%x09%cI%x09%s"])
    if r.returncode != 0:
        return []
    return _parse_git_log(r.stdout)


def local_git_commits_window(local_repo: pathlib.Path, ref: str, window: int) -> list[dict]:
    if window <= 0:
        return []
    r = run_git(local_repo, ["log", "-n", str(window), "--format=%H%x09%cI%x09%s", ref])
    if r.returncode != 0:
        return []
    return _parse_git_log(r.stdout)


def collect_local_commits(
    local_repo: pathlib.Path,
    since_iso: str,
    audit_pin: Optional[str],
    mode: str,
    window: Optional[int],
    bounded_forward_window: bool = False,
) -> list[dict]:
    if mode in {"forward", "bidirectional"}:
        if bounded_forward_window and window:
            forward = local_git_commits_window(local_repo, "HEAD", window)
        else:
            forward = local_git_commits_since(local_repo, since_iso)
    else:
        forward = []
    backward = []
    if mode in {"backward", "bidirectional"} and audit_pin and window:
        backward = local_git_commits_window(local_repo, audit_pin, window)
    merged: list[dict] = []
    seen: set[str] = set()
    for commit in forward + backward:
        sha = commit.get("sha")
        if not isinstance(sha, str) or sha in seen:
            continue
        seen.add(sha)
        merged.append(commit)
    return merged


def local_git_commit_date(local_repo: pathlib.Path, sha: str) -> Optional[str]:
    r = run_git(local_repo, ["show", "-s", "--format=%cI", sha])
    if r.returncode != 0:
        return None
    value = r.stdout.strip()
    return value[:10] if len(value) >= 10 else None


def local_git_commit_detail(local_repo: pathlib.Path, sha: str) -> dict[str, Any]:
    names = run_git(local_repo, ["show", "--format=", "--name-only", sha])
    patch = run_git(local_repo, ["show", "--format=", "--find-renames", "--find-copies", sha])
    if names.returncode != 0:
        return {}
    patch_text = patch.stdout if patch.returncode == 0 else ""
    files = [
        {"filename": line.strip(), "patch": patch_text}
        for line in names.stdout.splitlines()
        if line.strip()
    ]
    return {
        "commit": {"author": {"date": local_git_commit_date(local_repo, sha)}},
        "files": files,
    }


def _load_impact_preflight_builder() -> Optional[Any]:
    """Lazily load build_packet from tools/impact-contract-preflight.py.

    Returns None if the helper is unavailable (advisory-only — mining must
    never fail-closed on the gate). Mirrors the loader used by
    tools/exploit-memory-brief.py and tools/harness-scaffold-emitter.py.
    """
    tool = pathlib.Path(__file__).resolve().with_name("impact-contract-preflight.py")
    if not tool.exists():
        return None
    try:
        spec = importlib.util.spec_from_file_location("impact_contract_preflight", tool)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, "build_packet", None)
    except Exception:  # noqa: BLE001 — advisory-only; never fail-closed
        return None


def _build_pattern_preflight_text(commit: dict, pattern: dict) -> str:
    """Render a small text bundle for the gate parser to evaluate.

    Mining patterns rarely carry a Markdown 'Impact Contract' section;
    that's expected. The gate falls back to artifact-class classification
    (``planning`` via ``kind: poc_plan``-style payload) and surfaces an
    advisory `planning-artifact-advisory-bypass` decision.
    """
    parts = [
        f"# git-commits-mining pattern: {pattern.get('id', '<unnamed>')}",
        f"Commit: {commit.get('sha', '<unknown>')}",
        f"Subject: {commit.get('subject', '')}",
        f"Classification: {commit.get('classification', '')}",
        f"Pattern shape: {pattern.get('shape', '')}",
        f"Pattern language: {pattern.get('language', '')}",
        f"Pattern confidence: {pattern.get('confidence', '')}",
    ]
    return "\n".join(str(p) for p in parts if p is not None)


def _attach_pattern_preflights(commits: list[dict]) -> dict[str, int]:
    """Attach build_packet(route='exploit-memory') to each commit's patterns[].

    Advisory-only — mining is exploration, not submission. Returns a small
    counters dict for the report's ``impact_contract_preflight_summary``.
    """
    builder = _load_impact_preflight_builder()
    counters = {
        "patterns_seen": 0,
        "packets_attached": 0,
        "advisory_bypass": 0,
        "explicit": 0,
        "unmapped": 0,
        "loader_unavailable": 0,
    }
    for commit in commits or []:
        patterns = commit.get("patterns")
        if not isinstance(patterns, list):
            continue
        for pattern in patterns:
            if not isinstance(pattern, dict):
                continue
            counters["patterns_seen"] += 1
            if builder is None:
                pattern["impact_contract_preflight"] = {
                    "schema_version": "auditooor.impact_contract_preflight.v1",
                    "route": "exploit-memory",
                    "artifact_class": "planning",
                    "advisory_only": True,
                    "impact_contract": {
                        "explicit": False,
                        "fields": {},
                        "actor_fields_present": [],
                        "anchor_fields_present": [],
                        "missing": [],
                    },
                    "decision": {
                        "code": "unmapped",
                        "blocked": False,
                        "advisory_bypass": True,
                        "summary": "impact-contract-preflight loader unavailable; advisory unmapped",
                    },
                }
                counters["loader_unavailable"] += 1
                counters["unmapped"] += 1
                continue
            try:
                packet = builder(
                    payload={"kind": "poc_plan"},
                    text=_build_pattern_preflight_text(commit, pattern),
                    route="exploit-memory",
                )
                packet = dict(packet)
                packet["advisory_only"] = True  # mining never fail-closes
                pattern["impact_contract_preflight"] = packet
                counters["packets_attached"] += 1
                decision_code = (
                    packet.get("decision", {}).get("code", "") if isinstance(packet, dict) else ""
                )
                if decision_code == "impact-contract-explicit":
                    counters["explicit"] += 1
                elif decision_code == "planning-artifact-advisory-bypass":
                    counters["advisory_bypass"] += 1
                else:
                    counters["unmapped"] += 1
            except Exception as exc:  # noqa: BLE001 — advisory-only
                pattern["impact_contract_preflight"] = {
                    "schema_version": "auditooor.impact_contract_preflight.v1",
                    "route": "exploit-memory",
                    "artifact_class": "planning",
                    "advisory_only": True,
                    "decision": {
                        "code": "unmapped",
                        "blocked": False,
                        "advisory_bypass": True,
                        "summary": f"build_packet raised: {type(exc).__name__}",
                    },
                }
                counters["unmapped"] += 1
    return counters


def filter_security_shaped(commits: list[dict]) -> list[dict]:
    out = []
    for c in commits:
        subj = c.get("message", "").splitlines()[0] if c.get("message") else ""
        if not SECURITY_FIX_REGEX.search(subj):
            continue
        if NON_PROTOCOL_REGEX.search(subj):
            continue
        out.append(c)
    return out


def normalize_language(raw: Optional[str]) -> str:
    value = (raw or "go").strip().lower()
    aliases = {
        "go": "go",
        "golang": "go",
        "rust": "rust",
        "rs": "rust",
        "sol": "solidity",
        "solidity": "solidity",
    }
    if value not in aliases:
        raise ValueError(f"unsupported --lang: {raw}")
    return aliases[value]


def resolve_mode_and_window(
    language: str,
    mode: Optional[str],
    window: Optional[int],
) -> tuple[str, Optional[int]]:
    if mode is None:
        mode = "bidirectional" if language == "solidity" else "forward"
    if window is None and language == "solidity":
        window = 60
    return mode, window


def derive_since_date(
    repo: str,
    since: Optional[str],
    since_pin: bool,
    audit_pin: Optional[str],
) -> Optional[str]:
    if since is not None:
        return since
    if since_pin:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if audit_pin:
        detail = gh_commit_detail(repo, audit_pin)
        date_value = detail.get("commit", {}).get("author", {}).get("date")
        if isinstance(date_value, str) and len(date_value) >= 10:
            return date_value[:10]
    return None


def derive_since_date_local(
    local_repo: pathlib.Path,
    since: Optional[str],
    since_pin: bool,
    audit_pin: Optional[str],
) -> Optional[str]:
    if since is not None:
        return since
    if since_pin:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if audit_pin:
        return local_git_commit_date(local_repo, audit_pin)
    return None


def derive_since_date_public(
    repo: str,
    since: Optional[str],
    since_pin: bool,
    audit_pin: Optional[str],
) -> Optional[str]:
    if since is not None:
        return since
    if since_pin:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if audit_pin:
        return public_commit_date(repo, audit_pin)
    return None


def collect_commits(
    repo: str,
    since_iso: str,
    audit_pin: Optional[str],
    mode: str,
    window: Optional[int],
    bounded_forward_window: bool = False,
) -> list[dict]:
    if mode in {"forward", "bidirectional"}:
        if bounded_forward_window and window:
            forward = gh_commits_window(repo, "HEAD", window)
        else:
            forward = gh_commits_since(repo, since_iso)
    else:
        forward = []
    backward = []
    if mode in {"backward", "bidirectional"} and audit_pin and window:
        backward = gh_commits_window(repo, audit_pin, window)
    merged: list[dict] = []
    seen: set[str] = set()
    for commit in forward + backward:
        sha = commit.get("sha")
        if not isinstance(sha, str) or sha in seen:
            continue
        seen.add(sha)
        merged.append(commit)
    return merged


def _solidity_detail_files(commit: dict, detail: dict[str, Any]) -> list[dict[str, Any]]:
    detail_files = detail.get("files")
    if isinstance(detail_files, list):
        return [f for f in detail_files if isinstance(f, dict)]
    commit_files = commit.get("files")
    if isinstance(commit_files, list):
        return [f for f in commit_files if isinstance(f, dict)]
    return []


def analyze_solidity_commit(commit: dict, detail: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    detail = detail or {}
    files = _solidity_detail_files(commit, detail)
    affected_paths = sorted(
        {
            path
            for file_info in files
            if isinstance((path := file_info.get("filename")), str) and path.endswith(".sol")
        }
    )
    patches = [
        patch
        for file_info in files
        if isinstance(file_info.get("filename"), str)
        and file_info["filename"].endswith(".sol")
        and isinstance((patch := file_info.get("patch")), str)
    ]
    detail_message = detail.get("commit", {}).get("message")
    text = "\n".join(
        part
        for part in (commit.get("message", ""), detail_message if isinstance(detail_message, str) else "")
        if part
    )
    patch_text = "\n".join(patches)
    proxy_storage_layout_changed = bool(
        SOLIDITY_STORAGE_LAYOUT_REGEX.search(text)
        or SOLIDITY_STORAGE_LAYOUT_REGEX.search(patch_text)
        or (
            SOLIDITY_STATE_VAR_PATCH_REGEX.search(patch_text)
            and re.search(r"\b(?:storage|layout|proxy|upgrade)\b", text, re.IGNORECASE)
        )
    )
    inheritance_changed = bool(SOLIDITY_INHERITANCE_PATCH_REGEX.search(patch_text))
    oz_upgradeable_initialize_changed = bool(
        SOLIDITY_OZ_INITIALIZER_REGEX.search(text)
        or SOLIDITY_OZ_INITIALIZER_REGEX.search(patch_text)
    )
    matched_keywords: list[str] = []
    score = len(affected_paths)
    for label, pattern, weight in SOLIDITY_SIGNAL_PATTERNS:
        if pattern.search(text):
            matched_keywords.append(label)
            score += weight
    if proxy_storage_layout_changed:
        score += 3
    if inheritance_changed:
        score += 2
    if oz_upgradeable_initialize_changed:
        score += 2
    return {
        "affected_solidity_paths": affected_paths,
        "proxy_storage_layout_changed": proxy_storage_layout_changed,
        "inheritance_changed": inheritance_changed,
        "oz_upgradeable_initialize_changed": oz_upgradeable_initialize_changed,
        "solidity_keywords_matched": matched_keywords,
        "solidity_score": score,
    }


def filter_security_shaped_for_language(
    commits: list[dict],
    language: str,
    repo: Optional[str] = None,
    detail_loader: Optional[Any] = None,
) -> list[dict]:
    if language != "solidity":
        return filter_security_shaped(commits)

    detail_loader = detail_loader or gh_commit_detail
    out = []
    for commit in commits:
        message = commit.get("message", "")
        subject = message.splitlines()[0] if message else ""
        if not SOLIDITY_FIX_REGEX.search(message):
            continue
        if NON_PROTOCOL_REGEX.search(subject):
            continue
        detail = detail_loader(repo, commit["sha"]) if repo and commit.get("sha") else {}
        analysis = analyze_solidity_commit(commit, detail)
        if not analysis["affected_solidity_paths"]:
            continue
        enriched = dict(commit)
        enriched["_solidity_analysis"] = analysis
        out.append(enriched)
    return out


# Keyword-tier commit classification. The broad security-fix regex matches every
# "fix:" commit (incl. lint/build/typo), so each shaped commit is tagged with an
# is_noise flag + a coarse bug_class - otherwise consumers (hunt prioritiser,
# hacker briefs) treat "fix: lint" as a security lead and every lead shows an empty
# class. The optional LLM ETL (hackerman-etl-from-git-mining.py) refines these;
# this is the always-on baseline so bug_class/is_noise are never absent.
_NOISE_RE = re.compile(
    r"\b(lint|fmt|format(ting)?|gofmt|typo|spelling|comment|docs?|readme|changelog|"
    r"rename|naming|bump|dep|deps|dependency|dependencies|\bci\b|workflow|chore|"
    r"whitespace|cleanup|build|compile|version|gas[- ]?golf|codeowner|selectors?|"
    r"storage[- ]?gap|storage[- ]?layout)\b",
    re.I,
)
_BUG_CLASS_PATTERNS = (
    ("reentrancy", r"reentran"),
    ("access-control", r"access[- ]?control|unauthor|permission|only[- ]?(owner|admin)|privileg|\brole\b|\bacl\b"),
    ("arithmetic", r"overflow|underflow|safe ?math|rounding|precision loss"),
    ("dos", r"\bdos\b|denial[- ]of[- ]service|deadlock|\bhalt|stuck|\bhang|panic|\boom\b|out[- ]of[- ]memory|poison|exhaust"),
    ("consensus", r"consensus|chain[- ]split|finaliz|milestone|checkpoint|equivocat|\bvote|light client|witness|fork choice"),
    ("bridge", r"bridge|exit[- ]?root|\bclaim|deposit|withdraw|cross[- ]?chain|merkle|state[- ]?sync"),
    ("staking", r"\bstak|slash|unstake|delegat|validator ?share|validatorshare|dethrone"),
    ("signature-replay", r"signature|ecrecover|ecdsa|\breplay|\bnonce"),
    ("oracle", r"oracle|\bprice\b"),
    ("validation", r"validat|sanit|missing[- ]?check|zero[- ]?addr|\bnil\b|\bnull\b|bounds"),
)


def classify_commit_subject(subject: str) -> dict[str, Any]:
    """Coarse keyword classification of a commit subject -> bug_class/is_noise."""
    s = subject.lower()
    bug_class = None
    for cls, pat in _BUG_CLASS_PATTERNS:
        if re.search(pat, s):
            bug_class = cls
            break
    # noise = a housekeeping keyword present AND no security bug-class matched.
    is_noise = bool(_NOISE_RE.search(s)) and bug_class is None
    if bug_class is not None:
        classification = "security_fix"
    elif is_noise:
        classification = "code_quality"
    else:
        classification = "unclear"
    return {"bug_class": bug_class, "is_noise": is_noise, "classification": classification}


def build_shaped_commit_entry(commit: dict, upstream: str, language: str) -> dict[str, Any]:
    subject = commit["message"].splitlines()[0]
    entry = {
        "sha": commit["sha"],
        "date": commit["date"],
        "subject": subject,
        "url": f"https://github.com/{upstream}/commit/{commit['sha']}",
    }
    entry.update(classify_commit_subject(subject))
    if language == "solidity":
        entry.update(commit.get("_solidity_analysis", {}))
    return entry


def build_commit_inventory_entry(commit: dict, upstream: str) -> dict[str, str]:
    """Build an unclassified candidate for mandatory semantic awareness review.

    This stays separate from ``shaped_commits_index``. Shape heuristics may
    prioritize review work but cannot decide which upstream history is eligible
    for awareness, duplicate, or known-issue reconciliation.
    """
    sha = str(commit.get("sha") or "").strip()
    date = str(commit.get("date") or "").strip()
    message = str(commit.get("message") or "").strip()
    if not sha or not date or not message:
        raise ValueError("commit_inventory_entry_malformed")
    return {
        "sha": sha,
        "date": date,
        "subject": message.splitlines()[0],
        "url": f"https://github.com/{upstream}/commit/{sha}",
    }


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Authentication: remote GitHub enumeration uses non-interactive gh api. "
            "Use existing `gh auth status --hostname github.com` credentials or set "
            "GH_TOKEN/GITHUB_TOKEN. The tool never invokes `gh auth login`; if no "
            "remote auth is available, it tries --local-repo or an upstream-matched "
            "current checkout and otherwise exits 3 without prompting."
        ),
    )
    p.add_argument("--workspace", required=True, help="audited workspace name (e.g. centrifuge-v3)")
    p.add_argument("--upstream", required=True, help="<owner>/<repo> upstream GitHub")
    p.add_argument(
        "--lang",
        default="go",
        help="source language family: go|rust|sol|solidity (default: go)",
    )
    p.add_argument(
        "--mode",
        "--direction",
        dest="mode",
        choices=("forward", "backward", "bidirectional"),
        default=None,
        help="commit scan direction; Solidity defaults to bidirectional",
    )
    p.add_argument(
        "--window",
        type=int,
        default=None,
        help="bounded backward/bidirectional history window; Solidity defaults to 60",
    )
    p.add_argument(
        "--audit-pin",
        required=False,
        default=None,
        help="SHA the audit was pinned to (optional in v1.1; falls back to --since)",
    )
    p.add_argument(
        "--since",
        required=False,
        default=None,
        help="ISO date (YYYY-MM-DD) of audit-pin commit",
    )
    p.add_argument(
        "--since-pin",
        action="store_true",
        help="(v1.1) treat --since as the audit-pin date even if --audit-pin is omitted; "
        "if --since is also missing, default to today",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        help="(v1.1) cap shaped-commit enumeration at this many entries (0 = no cap)",
    )
    p.add_argument(
        "--bounded-forward-window",
        action="store_true",
        help="For bidirectional windowed scans, enumerate the forward side from HEAD with --window instead of paginating all commits since --since.",
    )
    p.add_argument(
        "--local-repo",
        default=None,
        help="optional local checkout for local-git-only fallback when gh auth/token is unavailable",
    )
    # --out is the canonical flag; --output is a v1.1 alias matching the
    # Worker-XX smoke-mining recipe.
    out_group = p.add_mutually_exclusive_group(required=True)
    out_group.add_argument("--out", help="output JSON path")
    out_group.add_argument("--output", help="output JSON path (v1.1 alias for --out)")
    args = p.parse_args()

    out_arg = args.out or args.output
    try:
        language = normalize_language(args.lang)
    except ValueError as exc:
        sys.stderr.write(f"[ERR] {exc}\n")
        return 2
    mode, window = resolve_mode_and_window(language, args.mode, args.window)
    local_repo = resolve_local_repo(args.upstream, args.local_repo)
    fallback_used = False
    public_api_used = False
    discussion_api_get: Optional[Any] = None

    if not gh_auth_ok():
        # PREFER the unauthenticated public API over local-git-only: the local
        # clone is checked out AT the audit pin, so it has NO post-pin commits to
        # forward-mine (the post-release security fixes that reveal bugs in the
        # deployed release). For a PUBLIC repo those commits are readable with no
        # auth - real remote mine, no hanging keychain. Local is the last resort.
        if public_repo_accessible(args.upstream):
            public_api_used = True
            discussion_api_get = _public_api_get
            sys.stderr.write(
                "[INFO] git-commits-mining: no gh auth/token; using UNAUTHENTICATED "
                "public GitHub API (real remote forward+backward mine; public repo)\n"
            )
        elif local_repo is not None:
            fallback_used = True
            discussion_api_get = None
            sys.stderr.write(
                "[WARN] git-commits-mining: no gh auth/token and repo not public-readable; "
                "using local-git-only mode\n"
            )
        else:
            sys.stderr.write(
                "[WARN] git-commits-mining: no gh auth/token, repo not public-readable, "
                "and no local git checkout; skipping remote commit mining without prompting\n"
            )
            return LOCAL_GIT_ONLY_EXIT_CODE

    if fallback_used and local_repo is not None:
        args.since = derive_since_date_local(
            local_repo,
            args.since,
            args.since_pin,
            args.audit_pin,
        )
    elif public_api_used:
        args.since = derive_since_date_public(
            args.upstream, args.since, args.since_pin, args.audit_pin
        )
        if args.since is None and args.audit_pin and local_repo is not None:
            public_api_used = False
            fallback_used = True
            discussion_api_get = None
            sys.stderr.write(
                "[WARN] git-commits-mining: public audit-pin date unavailable; "
                "using local-git-only mode\n"
            )
            args.since = derive_since_date_local(
                local_repo, args.since, args.since_pin, args.audit_pin
            )
    else:
        discussion_api_get = gh_api_json
        try:
            args.since = derive_since_date(args.upstream, args.since, args.since_pin, args.audit_pin)
        except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as exc:
            if local_repo is None:
                sys.stderr.write(
                    f"[ERR] git-commits-mining: gh audit-pin date lookup failed: {exc}\n"
                )
                return LOCAL_GIT_ONLY_EXIT_CODE
            fallback_used = True
            discussion_api_get = None
            sys.stderr.write(
                f"[WARN] git-commits-mining: gh audit-pin date lookup failed "
                f"({type(exc).__name__}); using local-git-only mode\n"
            )
            args.since = derive_since_date_local(
                local_repo,
                args.since,
                args.since_pin,
                args.audit_pin,
            )
        if args.since is None and args.audit_pin and local_repo is not None:
            fallback_used = True
            discussion_api_get = None
            sys.stderr.write(
                "[WARN] git-commits-mining: remote audit-pin date unavailable; "
                "using local-git-only mode\n"
            )
            args.since = derive_since_date_local(
                local_repo,
                args.since,
                args.since_pin,
                args.audit_pin,
            )
    if args.since is None:
        sys.stderr.write("[ERR] --since YYYY-MM-DD is required (or provide --audit-pin / --since-pin)\n")
        return 2

    audit_pin = args.audit_pin or f"since:{args.since}"

    since_iso = f"{args.since}T00:00:00Z"
    try:
        if fallback_used and local_repo is not None:
            commits = collect_local_commits(
                local_repo,
                since_iso,
                args.audit_pin,
                mode,
                window,
                args.bounded_forward_window,
            )
            detail_loader = lambda _repo, sha: local_git_commit_detail(local_repo, sha)
        elif public_api_used:
            commits = collect_public_commits(
                args.upstream,
                since_iso,
                args.audit_pin,
                mode,
                window,
                args.bounded_forward_window,
            )
            detail_loader = public_commit_detail
        else:
            commits = collect_commits(
                args.upstream,
                since_iso,
                args.audit_pin,
                mode,
                window,
                args.bounded_forward_window,
            )
            detail_loader = gh_commit_detail
        shaped = filter_security_shaped_for_language(
            commits,
            language,
            repo=args.upstream,
            detail_loader=detail_loader,
        )
    except (FileNotFoundError, RuntimeError, subprocess.TimeoutExpired) as exc:
        if not fallback_used and local_repo is not None:
            fallback_used = True
            discussion_api_get = None
            sys.stderr.write(
                f"[WARN] git-commits-mining: gh enumeration failed ({type(exc).__name__}); "
                "using local-git-only mode\n"
            )
            commits = collect_local_commits(
                local_repo,
                since_iso,
                args.audit_pin,
                mode,
                window,
                args.bounded_forward_window,
            )
            shaped = filter_security_shaped_for_language(
                commits,
                language,
                repo=args.upstream,
                detail_loader=lambda _repo, sha: local_git_commit_detail(local_repo, sha),
            )
        else:
            sys.stderr.write(f"[ERR] git-commits-mining: gh/local enumeration failed: {exc}\n")
            return LOCAL_GIT_ONLY_EXIT_CODE
    if args.limit and args.limit > 0:
        shaped = shaped[: args.limit]

    shaped_entries = [build_shaped_commit_entry(c, args.upstream, language) for c in shaped]
    discussion_records: list[dict[str, Any]] = []
    discussion_api_failed = False
    if discussion_api_get is not None:
        base_discussion_api_get = discussion_api_get

        def tracked_discussion_api_get(path: str) -> Any:
            nonlocal discussion_api_failed
            value = base_discussion_api_get(path)
            if value is None:
                discussion_api_failed = True
            return value

        try:
            discussion_records = collect_github_discussion_evidence(
                args.upstream, shaped, tracked_discussion_api_get
            )
        except (OSError, RuntimeError, subprocess.TimeoutExpired):
            # Discussion is supplementary evidence. A transient API failure must
            # not discard the local/remote commit mine or mislabel it as a finding.
            discussion_records = []
    discussion_by_sha: dict[str, list[dict[str, Any]]] = {}
    for record in discussion_records:
        discussion_by_sha.setdefault(record["commit_sha"], []).append(record)
    for entry in shaped_entries:
        entry["discussion_evidence_refs"] = [
            {
                "pull_request_number": record["pull_request_number"],
                "discussion_classification": record["discussion_classification"],
                "evidence_type": record["evidence_type"],
            }
            for record in discussion_by_sha.get(entry["sha"], [])
        ]

    # POC: emit minimal entries — for the centrifuge-v3 run, the human-classified
    # commits[] block is hand-curated in reports/<file>.json (see Worker-KK doc).
    # This script is the discovery tool; classification stays a reviewer step.
    report_commits: list[dict] = []  # reviewer-curated classification lives in the JSON file
    try:
        commit_inventory = [build_commit_inventory_entry(commit, args.upstream) for commit in commits]
    except ValueError as exc:
        sys.stderr.write(f"[ERR] git-commits-mining: {exc}\n")
        return 2

    # v1.1: attach impact_contract_preflight per pattern (advisory-only). Today
    # report_commits is empty by design (script is discovery, classification
    # is reviewer-step); but the helper is idempotent and ready for the day a
    # downstream tool (e.g. mining-brief-generator.py) hands us pre-classified
    # commits[] with patterns[]. We also call it on shaped_commits_index in the
    # `commits` slot so consumers can verify integration end-to-end.
    pattern_summary = _attach_pattern_preflights(report_commits)

    report: dict[str, Any] = {
        "schema": SOLIDITY_SCHEMA if language == "solidity" else "auditooor.git_commits_mining.v1",
        "schema_version": SOLIDITY_SCHEMA_VERSION if language == "solidity" else SCHEMA_VERSION,
        "workspace": args.workspace,
        "upstream_repo": args.upstream,
        "audit_pin_sha": audit_pin,
        "since_date": args.since,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "commits_scanned": len(commits),
        "security_fix_count": len(shaped),
        "filter_regex": SOLIDITY_FIX_REGEX.pattern if language == "solidity" else SECURITY_FIX_REGEX.pattern,
        "fallback_used": fallback_used,
        "commit_inventory": commit_inventory,
        "shaped_commits_index": shaped_entries,
        "discussion_metadata": {
            "status": (
                "available"
                if discussion_api_get is not None and not discussion_api_failed
                else "not_applicable"
            ),
            "reason": (
                "github_api_available"
                if discussion_api_get is not None and not discussion_api_failed
                else (
                    "github_issue_metadata_unavailable"
                    if discussion_api_get is not None
                    else "github_issue_metadata_unavailable_in_local_git_only_mode"
                )
            ),
            "evidence_record_count": len(discussion_records),
        },
        "discussion_evidence": discussion_records,
        "commits": report_commits,
        "impact_contract_preflight_summary": {
            "route": "exploit-memory",
            "advisory_only": True,
            **pattern_summary,
        },
    }
    if language == "solidity":
        report["language"] = language
        report["mode"] = mode
        report["window"] = window
    if fallback_used and local_repo is not None:
        report["fallback_mode"] = "local-git-only"
        report["local_repo"] = str(local_repo)
    elif public_api_used:
        # A real REMOTE mine (post-pin forward commits included) via the
        # unauthenticated public API - NOT the local-git-only degradation. Mark it
        # distinctly so the step-integrity commit-mining gate credits it as a genuine
        # remote mine rather than DEGRADING it.
        report["fallback_mode"] = "public-unauthenticated-api"
        report["remote_mine"] = True

    out_path = pathlib.Path(out_arg)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"[OK] wrote {out_path} ({len(commits)} scanned, {len(shaped)} shaped, "
        f"schema_version={report['schema_version']})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
