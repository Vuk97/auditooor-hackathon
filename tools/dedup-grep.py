#!/usr/bin/env python3
"""
dedup-grep — full-text prior-audit dedup for depth-mine candidates.

Scans `<workspace>/prior_audits/*.txt` and `<workspace>/prior_audits/DIGEST_*.md`
for keywords drawn from a candidate brief (or supplied explicitly via --keyword).
Emits cited line-level matches so depth-mine agents can clear the dedup gate
before declaring NOVEL.

Why this exists
---------------
Engagement-5 (The Graph, PR #119) had a depth-mine agent declare a candidate
NOVEL after only checking `KNOWN_ISSUES.md` summary entries. A 30-second
manual full-text grep found OZ-2025-L-02 "Double Jeopardy" discussing the
exact same mechanism. The candidate had to be closed as Acknowledged-not-fixed
(Immunefi-OOS). See `reference/anti_patterns.md` #26 for the long-form anti-
pattern.

Usage
-----
    # Auto-extract keywords from a candidate markdown brief
    tools/dedup-grep.py <workspace> --candidate path/to/candidate.md

    # Explicit keywords (overrides auto-extraction)
    tools/dedup-grep.py <workspace> --keyword disputeId --keyword fisherman

    # JSON output (for skill-prompt integration)
    tools/dedup-grep.py <workspace> --candidate brief.md --json

Exit codes
----------
    0 — ran successfully (whether hits or no hits)
    1 — workspace or candidate path invalid
    2 — bad arguments
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Iterable, List, Tuple


# Tokens we never want as standalone keywords — they match too broadly.
_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "into", "this", "that", "would",
    "could", "should", "than", "then", "there", "where", "which", "while",
    "when", "what", "have", "has", "are", "was", "were", "been", "being",
    "but", "not", "all", "any", "any", "may", "can", "if", "is", "it", "of",
    "in", "on", "at", "by", "to", "as", "or", "an", "a", "be", "do", "we",
    "us", "our", "you", "your", "they", "them", "their", "his", "her",
    # Common audit boilerplate
    "audit", "report", "finding", "severity", "high", "medium", "low",
    "critical", "informational", "issue", "bug", "vulnerability", "title",
    "description", "impact", "summary", "section", "page",
    # Solidity universals (too broad on their own)
    "function", "contract", "address", "uint", "bool", "bytes", "memory",
    "storage", "calldata", "external", "internal", "public", "private",
    "view", "pure", "payable", "returns", "require", "revert", "if", "else",
})

# Identifiers worth preserving even if shorter than the min-length cutoff.
_KEEP_SHORT = frozenset({"poc", "abi", "eip", "erc", "dao", "mev", "ddos"})

_BACKTICK_RE = re.compile(r"`([^`\n]{2,80})`")
_FUNCTION_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]+)\s*\(")
_CAPITALIZED_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,40})\b")
# camelCase / mixedCase identifiers (`disputeId`, `blockNumber`, `_fisherman`).
# Catches lowercase-leading tokens with at least one internal uppercase.
_CAMELCASE_RE = re.compile(r"\b(_?[a-z][A-Za-z0-9_]*[A-Z][A-Za-z0-9_]*)\b")
_HEADING_RE = re.compile(r"^#{1,6}\s+(.+?)\s*$", re.MULTILINE)


def _normalize_keyword(raw: str) -> str:
    """Lowercase, strip surrounding punctuation, collapse whitespace."""
    text = raw.strip().strip(".,;:()[]{}<>\"'`")
    return text.lower()


def _is_useful_keyword(kw: str) -> bool:
    # Min length 3 — short function names like `add`, `set`, `foo` are kept
    # when they survive the stopword filter (which already drops most short
    # prose tokens like "the", "and", "for"). The _KEEP_SHORT exception
    # handles 3-letter audit-domain abbreviations explicitly.
    if len(kw) < 3 and kw not in _KEEP_SHORT:
        return False
    if kw in _STOPWORDS:
        return False
    if kw.isdigit():
        return False
    return True


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def extract_keywords(text: str, max_keywords: int = 16) -> List[str]:
    """Pull mechanism keywords from a candidate markdown brief.

    Sources, in priority order:
      1. Backticked identifiers (`disputeId`, `_fisherman`, `Vault.deposit`)
      2. Function calls referenced by name (`createIndexingDispute(...)`)
      3. camelCase / mixedCase identifiers (`disputeId`, `blockNumber`)
      4. Capitalized contract / type names (`DisputeManager`, `EIP712`)
      5. Significant words from the first markdown heading
    """
    candidates: List[str] = []
    for match in _BACKTICK_RE.findall(text):
        for token in re.split(r"[.\s,;()]+", match):
            kw = _normalize_keyword(token)
            if _is_useful_keyword(kw):
                candidates.append(kw)
    for match in _FUNCTION_CALL_RE.findall(text):
        kw = _normalize_keyword(match)
        if _is_useful_keyword(kw):
            candidates.append(kw)
    for match in _CAMELCASE_RE.findall(text):
        kw = _normalize_keyword(match)
        if _is_useful_keyword(kw):
            candidates.append(kw)
    for match in _CAPITALIZED_RE.findall(text):
        kw = _normalize_keyword(match)
        if _is_useful_keyword(kw):
            candidates.append(kw)
    headings = _HEADING_RE.findall(text)
    if headings:
        for word in re.split(r"[\s\-_/.,;()]+", headings[0]):
            kw = _normalize_keyword(word)
            if _is_useful_keyword(kw):
                candidates.append(kw)
    return _dedupe_preserve_order(candidates)[:max_keywords]


def _prior_audit_files(workspace: Path) -> List[Path]:
    base = workspace / "prior_audits"
    if not base.is_dir():
        return []
    files: List[Path] = []
    files.extend(sorted(base.glob("*.txt")))
    files.extend(sorted(base.glob("DIGEST_*.md")))
    files.extend(sorted(base.glob("digest_*.md")))
    return files


def _grep_file(path: Path, keywords: List[str]) -> List[dict]:
    hits: List[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    lower_lines = [(i + 1, line) for i, line in enumerate(text.splitlines())]
    for lineno, line in lower_lines:
        lowered = line.lower()
        for kw in keywords:
            if kw in lowered:
                hits.append({
                    "file": str(path),
                    "line": lineno,
                    "keyword": kw,
                    "snippet": line.strip()[:200],
                })
                break  # one hit per line is enough
    return hits


def grep_prior_audits(workspace: Path, keywords: List[str]) -> dict:
    """Run the full-text grep and return a structured result dict."""
    files = _prior_audit_files(workspace)
    all_hits: List[dict] = []
    for path in files:
        all_hits.extend(_grep_file(path, keywords))
    return {
        "workspace": str(workspace),
        "keywords": keywords,
        "files_scanned": [str(f) for f in files],
        "files_scanned_count": len(files),
        "hit_count": len(all_hits),
        "hits": all_hits,
    }


def render_text(result: dict) -> str:
    lines: List[str] = []
    lines.append(
        f"# dedup-grep: {result['hit_count']} hit(s) across "
        f"{result['files_scanned_count']} prior-audit file(s)"
    )
    lines.append(f"keywords: {', '.join(result['keywords']) or '(none)'}")
    lines.append("")
    if not result["hit_count"]:
        lines.append("(no matches — candidate passes summary-level dedup)")
        lines.append("")
        lines.append("NOTE: zero hits is necessary but not sufficient. The")
        lines.append("candidate may still match a prior finding under different")
        lines.append("terminology. Consider running with broader keywords.")
        return "\n".join(lines)
    by_file: dict = {}
    for hit in result["hits"]:
        by_file.setdefault(hit["file"], []).append(hit)
    for filepath, file_hits in by_file.items():
        rel = filepath
        lines.append(f"## {rel} — {len(file_hits)} hit(s)")
        for hit in file_hits[:25]:
            lines.append(
                f"  L{hit['line']:>5} [{hit['keyword']}]: {hit['snippet']}"
            )
        if len(file_hits) > 25:
            lines.append(f"  … {len(file_hits) - 25} more match(es)")
        lines.append("")
    return "\n".join(lines)


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("workspace", help="audit workspace dir (must contain prior_audits/)")
    parser.add_argument(
        "--candidate",
        help="path to a candidate markdown brief — keywords auto-extracted",
    )
    parser.add_argument(
        "--keyword",
        action="append",
        default=[],
        help="explicit keyword (repeatable). Overrides --candidate auto-extraction.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--out", help="write output to file instead of stdout")
    parser.add_argument(
        "--max-keywords",
        type=int,
        default=12,
        help="cap auto-extracted keywords (default 12)",
    )
    args = parser.parse_args(argv)

    workspace = Path(args.workspace).expanduser().resolve()
    if not workspace.is_dir():
        print(f"workspace not found: {workspace}", file=sys.stderr)
        return 1

    keywords: List[str] = []
    if args.keyword:
        keywords = [_normalize_keyword(k) for k in args.keyword if _normalize_keyword(k)]
    elif args.candidate:
        candidate_path = Path(args.candidate).expanduser()
        if not candidate_path.is_file():
            print(f"candidate not found: {candidate_path}", file=sys.stderr)
            return 1
        keywords = extract_keywords(
            candidate_path.read_text(encoding="utf-8", errors="replace"),
            max_keywords=args.max_keywords,
        )
    else:
        print("must supply --candidate or --keyword", file=sys.stderr)
        return 2

    if not keywords:
        print("no usable keywords extracted; supply --keyword explicitly", file=sys.stderr)
        return 2

    result = grep_prior_audits(workspace, keywords)
    payload = json.dumps(result, indent=2) if args.json else render_text(result)

    if args.out:
        Path(args.out).write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
