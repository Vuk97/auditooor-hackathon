#!/usr/bin/env python3
"""
secret-scrub-changed-files.py — High-confidence secret detector for git diffs.

Scans changed files (added/modified) between HEAD and an upstream ref for
secret patterns. Designed for pre-push gate use: exits 2 if any HIGH pattern
fires, exits 0 if clean.

PR #658 Lane 7 — Tier-B #11 deliverable.

Usage:
    python3 tools/secret-scrub-changed-files.py \\
        [--upstream <ref>]   \\  # default: @{upstream}, fallback: HEAD~1
        [--json]             \\  # emit JSON to stdout
        [--exit-fail]        \\  # exit 2 if any HIGH finding
        [--exclude <path>]      # skip path(s); default: tools/calibration/llm_budget_log.jsonl

Exit codes:
    0 — clean (no HIGH findings)
    1 — error (git unavailable, bad ref, etc.)
    2 — HIGH findings found (only when --exit-fail is passed)

Pattern set (high-confidence only — tuned to avoid FP on normal diffs):
    aws-access-key        AKIA[0-9A-Z]{16}
    github-pat            ghp_/ghs_/gho_/ghu_/github_pat_  prefix + ≥36 chars
    gitlab-pat            glpat- prefix + ≥20 chars
    generic-sk-token      sk-/sk_ (not preceded by alphanum) + ≥20 alphanum
    pem-private-key       -----BEGIN ... PRIVATE KEY-----
    slack-token           xoxb-/xoxp-/xoxa- prefix + alphanum
    hex32-suspicious      64-hex blob near assignment/key/secret/token keyword
    private-key-evm       0x + exactly 64 hex chars (not an address or public tx hash)

Entropy helper: Shannon entropy ≥ 3.5 bits/char used as secondary filter on
hex32-suspicious to reduce FP from bytecode literals.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Return Shannon entropy (bits/char) of the string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def _match_window(line: str, match: re.Match, radius: int = 96) -> str:
    """Return local context around a regex match on a single line."""
    start, end = match.span(0)
    return line[max(0, start - radius): min(len(line), end + radius)]


_LOCAL_SECRET_KEYWORD_RE = re.compile(
    r"(?:secret|private[_\s-]?key|api[_\s-]?key|token|password|mnemonic|seed)",
    re.IGNORECASE,
)

_PUBLIC_CHAIN_HASH_CONTEXT_RE = re.compile(
    r"(?:"
    r"public[-_\s]?exploit[-_\s]?tx|exploit[-_\s]?tx|"
    r"\btransaction(?:\s+hash)?\b|\btx(?:id|hash)?\b|\btx\b|"
    r"\bevent\s+topic\b|\btopic\b|\bcommandId\b|\bmessageHash\b|"
    r"\bblockHash\b|\bmerkle\s+root\b|\bhash\b|code[_\s-]?hash|"
    r"\battacker\b|\baccount\b|\baddress\b|\bcontract\b|\bproxy\b|"
    r"\bimplementation\b|\brecipient\b|\bsender\b|\btarget\b"
    r")",
    re.IGNORECASE,
)

_DIRECT_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?:secret|private[_\s-]?key|api[_\s-]?key|password|mnemonic|seed)\s*[:=]\s*['\"]?\s*$",
    re.IGNORECASE,
)


def _looks_like_public_chain_hash(match: re.Match, line: str) -> bool:
    """Suppress public tx/hash IDs without weakening direct secret assignment checks."""
    start, _ = match.span(0)
    prefix = line[max(0, start - 48): start]
    if _DIRECT_SECRET_ASSIGNMENT_RE.search(prefix):
        return False
    return bool(_PUBLIC_CHAIN_HASH_CONTEXT_RE.search(_match_window(line, match)))


def _verify_hex32_suspicious(match: re.Match, line: str) -> bool:
    if _looks_like_public_chain_hash(match, line):
        return False
    # Scope the keyword check to local context. Corpus rows often contain a
    # public tx hash and an unrelated phrase like "private key compromise" on
    # the same JSONL line; the whole-line check turns those into false hits.
    window = _match_window(line, match)
    return (
        bool(_LOCAL_SECRET_KEYWORD_RE.search(window))
        and _shannon_entropy((match.group(2) or match.group(0)).lower()) >= 3.5
    )


def _verify_evm_private_key(match: re.Match, line: str) -> bool:
    if _looks_like_public_chain_hash(match, line):
        return False
    return _shannon_entropy(match.group(1)[2:].lower()) >= 3.2


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

class _Pattern:
    def __init__(
        self,
        name: str,
        regex: str,
        severity: str = "HIGH",
        description: str = "",
        verify: Any = None,
        flags: int = 0,
    ):
        self.name = name
        self.re = re.compile(regex, flags)
        self.severity = severity
        self.description = description
        self._verify = verify or (lambda m, line: True)

    def verify(self, m: re.Match, line: str) -> bool:
        return self._verify(m, line)


_PATTERNS: list[_Pattern] = [
    _Pattern(
        name="aws-access-key",
        regex=r"AKIA[0-9A-Z]{16}",
        severity="HIGH",
        description="AWS access key ID (AKIA prefix)",
    ),
    _Pattern(
        name="github-pat",
        regex=r"(?:ghp_|ghs_|gho_|ghu_|github_pat_)[a-zA-Z0-9_]{36,}",
        severity="HIGH",
        description="GitHub personal/server/OAuth/user access token",
    ),
    _Pattern(
        name="gitlab-pat",
        regex=r"glpat-[a-zA-Z0-9_-]{20,}",
        severity="HIGH",
        description="GitLab personal access token (glpat- prefix)",
    ),
    _Pattern(
        name="generic-sk-token",
        # Require "sk" not preceded by alphanumeric (avoids "risk", "task", etc.).
        # Allow underscores in the body so Stripe sk_test_xxx tokens are caught.
        regex=r"(?<![a-zA-Z0-9])sk[-_][a-zA-Z0-9_]{20,}",
        severity="HIGH",
        description="Generic sk-/sk_ API token (OpenAI, Anthropic, Stripe, etc.)",
    ),
    _Pattern(
        name="pem-private-key",
        regex=r"-----BEGIN\s+[A-Z ]*PRIVATE KEY-----",
        severity="HIGH",
        description="PEM-encoded private key block header",
        flags=re.IGNORECASE,
    ),
    _Pattern(
        name="slack-token",
        regex=r"xox[abp]-[0-9A-Za-z\-]{10,}",
        severity="HIGH",
        description="Slack OAuth token (xoxb-/xoxp-/xoxa- prefix)",
    ),
    _Pattern(
        # 64 contiguous hex chars (32 bytes) near a key/secret/token keyword
        # in local context.  Shannon entropy ≥ 3.5 as secondary filter.
        name="hex32-suspicious",
        regex=r"(?<![0-9a-fA-F])(0x)?([0-9a-fA-F]{64})(?![0-9a-fA-F])",
        severity="HIGH",
        description="64-hex blob (32 bytes) near secret/key/token keyword",
        verify=_verify_hex32_suspicious,
    ),
    _Pattern(
        # EVM private key: 0x + exactly 64 hex chars (not an address which is 40)
        name="private-key-evm",
        regex=r"(?<![0-9a-fA-F])(0x[0-9a-fA-F]{64})(?![0-9a-fA-F])",
        severity="HIGH",
        description="Raw 32-byte EVM private key (0x + 64 hex chars)",
        verify=_verify_evm_private_key,
        flags=re.IGNORECASE,
    ),
]

# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def _git_changed_files(upstream: str, repo_root: Path) -> list[str]:
    """
    Return list of added/copied/modified file paths relative to repo root.
    Falls back to HEAD~1 if @{upstream} fails (no remote set).
    """
    def _run(ref: str) -> list[str]:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACM", f"{ref}..HEAD"],
            capture_output=True, text=True, cwd=str(repo_root),
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip())
        return [f for f in result.stdout.splitlines() if f.strip()]

    try:
        return _run(upstream)
    except RuntimeError as e:
        if upstream == "@{upstream}":
            # No remote tracking branch — fall back to HEAD~1
            try:
                return _run("HEAD~1")
            except RuntimeError:
                return []
        raise


def _get_file_content(fpath: Path) -> list[str]:
    """Read file lines; return [] on any error."""
    try:
        return fpath.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def scan_file(fpath: Path, repo_root: Path) -> list[dict[str, Any]]:
    """Scan a single file for high-confidence secret patterns."""
    rel = str(fpath.relative_to(repo_root))
    lines = _get_file_content(fpath)
    findings: list[dict[str, Any]] = []

    for lineno, line in enumerate(lines, start=1):
        for pat in _PATTERNS:
            for m in pat.re.finditer(line):
                if not pat.verify(m, line):
                    continue
                # Redact the match value in the excerpt
                start, end = m.span(0)
                excerpt = (line[:start] + "[REDACTED]" + line[end:]).strip()[:160]
                findings.append({
                    "file": rel,
                    "line": lineno,
                    "pattern": pat.name,
                    "severity": pat.severity,
                    "description": pat.description,
                    "excerpt": excerpt,
                })

    return findings


def run_scrub(
    upstream: str,
    repo_root: Path,
    excludes: list[str],
) -> list[dict[str, Any]]:
    """Run secret scrub over all changed files. Returns list of findings."""
    changed = _git_changed_files(upstream, repo_root)

    all_findings: list[dict[str, Any]] = []
    for rel_path in changed:
        # Apply exclude list (path-suffix match)
        if any(rel_path == exc or rel_path.endswith(exc) for exc in excludes):
            continue
        fpath = repo_root / rel_path
        if not fpath.is_file():
            continue
        all_findings.extend(scan_file(fpath, repo_root))

    return all_findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan git-changed files for high-confidence secrets before push. "
            "Exit 2 (when --exit-fail) if any HIGH finding detected."
        )
    )
    parser.add_argument(
        "--upstream",
        default="@{upstream}",
        help=(
            "Git ref to diff against (default: @{upstream}). "
            "Falls back to HEAD~1 if no upstream tracking branch."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Emit findings as JSON array to stdout (one object per finding).",
    )
    parser.add_argument(
        "--exit-fail",
        action="store_true",
        help="Exit 2 if any HIGH finding is detected (for pre-push gate use).",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        dest="excludes",
        metavar="PATH",
        help=(
            "Exclude file path from scan (suffix match). "
            "May be repeated. Default includes tools/calibration/llm_budget_log.jsonl."
        ),
    )
    args = parser.parse_args()

    # Always exclude the calibration log
    default_excludes = ["tools/calibration/llm_budget_log.jsonl"]
    excludes = list(set(default_excludes + args.excludes))

    # Resolve repo root
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        )
        repo_root = Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        print("ERROR: not inside a git repository", file=sys.stderr)
        return 1

    try:
        findings = run_scrub(args.upstream, repo_root, excludes)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    high_findings = [f for f in findings if f.get("severity") == "HIGH"]

    if args.json_output:
        output = {
            "upstream": args.upstream,
            "total": len(findings),
            "high_count": len(high_findings),
            "findings": findings,
        }
        print(json.dumps(output, indent=2))
    else:
        if not findings:
            print("[secret-scrub] clean — no secrets detected in changed files.")
        else:
            for f in findings:
                print(
                    f"[{f['severity']}] {f['file']}:{f['line']} "
                    f"({f['pattern']}) — {f['description']}"
                )
            print(f"\n{len(high_findings)} HIGH finding(s) in {len(findings)} total.")

    if args.exit_fail and high_findings:
        if not args.json_output:
            print(
                "\nPRE-PUSH BLOCKED: secret(s) detected in changed files. "
                "Redact before pushing.",
                file=sys.stderr,
            )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
