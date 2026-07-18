#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""prior_lane_scan.py - CAPABILITY-GAP-2 (2026-05-25).

Scan prior lane artefacts for NEGATIVE/DROP/CLOSED chains whose hypothesis
keywords overlap the current lane's hypothesis. Output is wired into
``tools/spawn-worker.sh`` via the ``--inject-prior-lanes`` flag so workers
see the relevant prior verdicts BEFORE re-deriving them.

Evidence anchor: COMP-5 burned ~1h re-deriving
``hb_loop9_chained_cross_component.md`` Chain 3 (timeout x delivery partial-
landing across two contracts) - a chain whose NEGATIVE verdict was already
in the workspace's `.auditooor/` corpus.

Sources scanned (de-duped by content):

  1. ``vault_known_dead_ends`` MCP callable - top N dead-ends for the
     workspace.
  2. ``<workspace>/.auditooor/hb_loop*_*.md`` and ``<workspace>/.auditooor/
     loop*_*.md`` - hyperbridge/sibling lane closeout / hunt artefacts.
  3. ``reports/v3_iter_*/lane_*/results.md`` (last 60 days by default) -
     v3 iteration lane reports.

For each source the scanner extracts chain titles (markdown ``## Chain N``,
``## Path A``, or top-level headings) and grep-matches hypothesis keywords
against the chain body. Matches whose body contains a NEGATIVE/DROP/CLOSED
verdict marker are returned, ranked by overlap_score.

CLI:

    python3 tools/lib/prior_lane_scan.py \\
        --workspace /Users/wolf/audits/hyperbridge \\
        --lane-id COMP-5 \\
        --hypothesis-keywords "double refund handler timeout"

Output (JSON on stdout):

    {
      "schema": "auditooor.prior_lane_scan.v1",
      "scan_summary": {
        "workspace": "...",
        "lane_id": "...",
        "keyword_tokens": [...],
        "sources_scanned": {...},
        "candidates_considered": int,
        "matches_returned": int,
        "warnings": [...]
      },
      "prior_negative_chains": [
        {
          "title": "Chain 3 - timeout x delivery partial-landing across two contracts",
          "verdict": "NEGATIVE-sound",
          "source": "/Users/wolf/audits/hyperbridge/.auditooor/hb_loop9_chained_cross_component.md",
          "sha": "<git sha or 'untracked'>",
          "overlap_summary": "keywords matched: timeout, handler, refund (3/4); verdict marker NEGATIVE-sound at line 247"
        },
        ...
      ]
    }

Hard rules:
  - Pure best-effort. Missing workspace dir / missing .auditooor/ / missing
    MCP server = graceful warn-only path, exit 0, empty list.
  - No mutation: tool is read-only. Never modifies the workspace.
  - Bounded I/O: caps the per-source file count and per-file body slice to
    keep dispatch latency under 1s on typical workspaces.
  - The keyword tokenizer is intentionally simple (whitespace + comma
    split, lowercase, dedupe, drop stopwords); callers that want richer
    matching should pre-process the hypothesis themselves.

Tests: tools/tests/test_prior_lane_scan.py
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA = "auditooor.prior_lane_scan.v1"

# Verdict markers we care about. NEGATIVE-sound / DROP / CLOSED / KILLED /
# DOES NOT CLOSE are the canonical phrases prior lanes use to mean
# "investigated, no fileable finding here".
VERDICT_PATTERNS = [
    r"\bNEGATIVE[- ]sound\b",
    r"\bNEGATIVE[- ]NO[- ]FINDING\b",
    r"\bNEGATIVE[- ]CLOSED\b",
    r"\bNEGATIVE\b",
    r"\bDROP[- ]verdict\b",
    r"\bDROP\b",
    r"\bCLOSED\b",
    r"\bKILLED\b",
    r"\bDOES NOT CLOSE\b",
    r"\bNO[- ]NOVEL\b",
]

_VERDICT_RE = re.compile("|".join(VERDICT_PATTERNS), re.IGNORECASE)

# Heading regex - matches level-1 (`# foo`) and level-2 (`## Chain 3 - foo`)
# headings only. Level-3+ (`### Verdict - Chain 3: ...`) are KEPT INSIDE
# their parent section so verdict markers stay attached to the chain they
# concern. Without this, a `### Verdict - ...` subsection would split the
# chain body away from its verdict marker and prevent matches.
_HEADING_RE = re.compile(r"^(#{1,2})\s+(.+?)\s*$", re.MULTILINE)

# Stopwords removed from the keyword token set before grep. Keep small.
_STOPWORDS = frozenset(
    {
        "the", "a", "an", "and", "or", "of", "to", "in", "on", "for",
        "with", "via", "by", "is", "are", "was", "were", "be", "been",
        "across", "between", "from", "into", "at", "as",
    }
)

# Default scan caps - keep dispatch latency bounded.
DEFAULT_MCP_LIMIT = 10
DEFAULT_LOCAL_FILE_CAP = 60
DEFAULT_REPORTS_LOOKBACK_DAYS = 60
DEFAULT_REPORTS_FILE_CAP = 120
DEFAULT_MATCH_LIMIT = 8

# Repo root for results.md scan (best-effort).
_REPO_ROOT_DEFAULT = pathlib.Path("/Users/wolf/auditooor-mcp")

# ---------------------------------------------------------------------------
# KNOWN-DEAD-END (KDE) store: file_line match mode (K3-deadend-injection).
#
# A KDE store row records "investigated this exact code site, no fileable
# finding". Variants are coalesced below using the SAME field-name set the
# vault server's vault_known_dead_ends ranker uses (reason/file_line/id/class),
# so a target whose file_line was already drilled to a NEGATIVE verdict gets
# the prior dead-end injected into its brief BEFORE it re-derives it.
#
# Stores scanned (de-duped by dead_end_id), all OPTIONAL (completeness-safe:
# no store -> empty list -> behave exactly as today, no injection / no drop):
#   - reports/known_dead_ends.jsonl                 (repo-global)
#   - <ws>/.auditooor/known_dead_ends.jsonl         (workspace-local)
#   - <ws>/.auditooor/dead_end_ledger.jsonl         (workspace ledger)
#   - reports/dead_end_ledger.jsonl                 (repo ledger, if present)
# ---------------------------------------------------------------------------

# Field-variant coalescing - mirrors vault-mcp-server.py field_text() name set
# so the same KDE corpus reads identically here and in the ranker.
_KDE_FILE_LINE_KEYS = ("file_line", "evidence_file_line", "file", "source")
_KDE_REASON_KEYS = (
    "reason", "kill_reason", "recommended_action", "lesson_summary",
    "summary", "engineering_note",
)
_KDE_ID_KEYS = ("dead_end_id", "record_id", "candidate_id", "kill_id", "chain_id")
_KDE_DROP_CLASS_KEYS = (
    "drop_class", "dead_end_class", "attack_class", "kill_verdict",
    "verdict", "class", "status",
)
_KDE_PIN_KEYS = ("audit_pin", "target_pin", "pin", "commit", "sha", "head", "head_sha")

# Verdict markers that mean "investigated, no fileable finding". A KDE row whose
# coalesced drop_class / status does NOT look terminal is still kept (a row in a
# known-dead-end store is dead by construction); this set only RANKS / labels.
_KDE_TERMINAL_TOKENS = (
    "drop", "negative", "closed", "killed", "fp", "no-finding", "no novel",
    "dead", "does not close", "won't fix", "wont fix", "acknowledged",
)


def _coalesce(row: Dict[str, Any], keys: Iterable[str]) -> str:
    """Return the first non-empty stringified value among ``keys`` (variant
    coalescing identical to the vault ranker's field_text ordering)."""
    for k in keys:
        v = row.get(k)
        if isinstance(v, list):
            for item in v:
                if item not in (None, ""):
                    return str(item)
            continue
        if v not in (None, ""):
            return str(v)
    return ""


def _normalize_file_line(raw: str) -> Tuple[str, Optional[int]]:
    """Split a ``path:line`` (or bare ``path``) into (norm_path, line_or_None).

    Tolerant: handles ``path:line``, ``path#line``, ``path:line-col``, a bare
    path, and a trailing ``#L<line>`` GitHub-style anchor. Path is lowercased
    and backslashes normalized so the same site matches across OS / casing
    accidents without under-matching.
    """
    s = str(raw or "").strip()
    if not s:
        return "", None
    s = s.replace("\\", "/")
    line: Optional[int] = None
    # GitHub-style #L123 anchor.
    m = re.search(r"#L?(\d+)\s*$", s)
    if m:
        line = int(m.group(1))
        s = s[: m.start()]
    else:
        m = re.search(r":(\d+)(?:[:\-]\d+)?\s*$", s)
        if m:
            line = int(m.group(1))
            s = s[: m.start()]
    return s.strip().rstrip(":#").lower(), line


def _pin_matches(row_pin: str, target_pin: str) -> bool:
    """Completeness-safe pin compare.

    If EITHER side is empty/unknown the row is KEPT (a dead-end with no recorded
    pin is still a dead-end at every pin; never silently under-warn). When both
    are present, match on prefix-equality in either direction (short SHAs).
    """
    rp = (row_pin or "").strip().lower()
    tp = (target_pin or "").strip().lower()
    if not rp or not tp:
        return True
    return rp.startswith(tp) or tp.startswith(rp)


def _coalesce_kde_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw KDE store row to the uniform fields the brief / drop-filter
    consume: {dead_end_id, file_line, norm_path, line, drop_class, reason, pin}."""
    file_line = _coalesce(row, _KDE_FILE_LINE_KEYS)
    norm_path, line = _normalize_file_line(file_line)
    return {
        "dead_end_id": _coalesce(row, _KDE_ID_KEYS) or "(unnamed-dead-end)",
        "file_line": file_line,
        "norm_path": norm_path,
        "line": line,
        "drop_class": _coalesce(row, _KDE_DROP_CLASS_KEYS) or "dead-end",
        "reason": _coalesce(row, _KDE_REASON_KEYS),
        "pin": _coalesce(row, _KDE_PIN_KEYS),
    }


def _kde_store_paths(
    workspace: pathlib.Path, repo_root: pathlib.Path
) -> List[pathlib.Path]:
    return [
        repo_root / "reports" / "known_dead_ends.jsonl",
        workspace / ".auditooor" / "known_dead_ends.jsonl",
        workspace / ".auditooor" / "dead_end_ledger.jsonl",
        repo_root / "reports" / "dead_end_ledger.jsonl",
    ]


def _load_kde_rows(
    workspace: pathlib.Path,
    repo_root: pathlib.Path,
    warnings: List[str],
    *,
    max_rows: int = 20000,
) -> List[Dict[str, Any]]:
    """Load + coalesce all KDE rows from every present store. De-dupe by
    dead_end_id (first writer wins). Completeness-safe: any unreadable / absent
    store is skipped with a warn, never fatal."""
    out: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    found_any = False
    for store in _kde_store_paths(workspace, repo_root):
        if not store.is_file():
            continue
        found_any = True
        try:
            raw = store.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            warnings.append(f"kde:read-failed:{store.name}:{exc}")
            continue
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                row = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            coalesced = _coalesce_kde_row(row)
            did = coalesced["dead_end_id"]
            # De-dupe only on a real id; unnamed rows are all kept (each is a
            # distinct site by file_line).
            if did != "(unnamed-dead-end)":
                if did in seen_ids:
                    continue
                seen_ids.add(did)
            out.append(coalesced)
            if len(out) >= max_rows:
                warnings.append(f"kde:row-cap:{max_rows}")
                return out
    if not found_any:
        warnings.append("kde:no-store-present")
    return out


def scan_file_line_dead_ends(
    workspace: pathlib.Path,
    target_file_lines: Iterable[str],
    *,
    target_pin: str = "",
    repo_root: Optional[pathlib.Path] = None,
    warnings: Optional[List[str]] = None,
    match_limit: int = DEFAULT_MATCH_LIMIT,
) -> List[Dict[str, Any]]:
    """Return KNOWN-DEAD-END rows whose coalesced file_line matches one of the
    target's file_line(s) at the current ``target_pin``.

    Matching:
      - exact (norm_path AND line equal), OR
      - path-only when the target supplies no line (so a whole-file lane still
        surfaces every dead-end in that file), OR
      - path-only when the KDE row records no line.
    Pin is compared completeness-safely (see :func:`_pin_matches`).

    Completeness-safe: empty target set or no KDE store -> empty list, no drop.
    """
    if warnings is None:
        warnings = []
    if repo_root is None:
        repo_root = _REPO_ROOT_DEFAULT

    # Normalize the target file_lines into (norm_path, line_or_None) tuples,
    # plus a path->lines index for O(1) lookup.
    targets: List[Tuple[str, Optional[int]]] = []
    for tfl in target_file_lines:
        np, ln = _normalize_file_line(tfl)
        if np:
            targets.append((np, ln))
    if not targets:
        return []

    kde_rows = _load_kde_rows(workspace, repo_root, warnings)
    if not kde_rows:
        return []

    matched: List[Dict[str, Any]] = []
    for kde in kde_rows:
        kpath = kde["norm_path"]
        kline = kde["line"]
        if not kpath:
            continue
        if not _pin_matches(kde["pin"], target_pin):
            continue
        hit = False
        for tpath, tline in targets:
            if tpath != kpath:
                continue
            # exact when both have a line; else path-level match (either side
            # missing a line still counts - never under-warn).
            if kline is not None and tline is not None:
                if kline == tline:
                    hit = True
                    break
            else:
                hit = True
                break
        if hit:
            matched.append(kde)
    return matched[:match_limit]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tokenize_keywords(raw: str) -> List[str]:
    """Whitespace + comma split, lowercase, dedupe, drop stopwords + tiny tokens."""
    if not raw:
        return []
    pieces = re.split(r"[\s,]+", raw.strip())
    out: List[str] = []
    seen: set[str] = set()
    for p in pieces:
        norm = p.strip().lower()
        if not norm or norm in _STOPWORDS:
            continue
        if len(norm) < 3:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out


def _git_sha_for_file(path: pathlib.Path) -> str:
    """Return short git SHA that last touched `path`, or 'untracked'."""
    try:
        repo_root = _resolve_repo_root(path.parent)
        if repo_root is None:
            return "untracked"
        rel = path.resolve()
        try:
            rel = rel.relative_to(repo_root)
        except ValueError:
            return "untracked"
        rc = subprocess.run(
            ["git", "-C", str(repo_root), "log", "-1", "--format=%h", "--", str(rel)],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if rc.returncode == 0:
            sha = rc.stdout.strip()
            return sha if sha else "untracked"
    except Exception:
        pass
    return "untracked"


def _resolve_repo_root(start: pathlib.Path) -> Optional[pathlib.Path]:
    cur = start.resolve()
    while True:
        if (cur / ".git").exists():
            return cur
        if cur.parent == cur:
            return None
        cur = cur.parent


def _safe_read_text(path: pathlib.Path, max_bytes: int = 200_000) -> str:
    """Read a file at most max_bytes, return empty string on any failure."""
    try:
        if not path.is_file():
            return ""
        with path.open("rb") as fh:
            data = fh.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _split_into_sections(body: str) -> List[Tuple[str, int, str]]:
    """Split body by top-level markdown headings.

    Returns list of (heading_text, heading_line_no, section_body).
    Sections are non-overlapping; the first section's "heading" is empty
    if the document does not begin with a heading.
    """
    sections: List[Tuple[str, int, str]] = []
    matches = list(_HEADING_RE.finditer(body))
    if not matches:
        return [("", 0, body)]
    if matches[0].start() > 0:
        sections.append(("", 0, body[: matches[0].start()]))
    for idx, m in enumerate(matches):
        heading = m.group(2).strip()
        # Compute heading line number (1-based) for citation friendliness.
        line_no = body.count("\n", 0, m.start()) + 1
        start = m.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(body)
        sections.append((heading, line_no, body[start:end]))
    return sections


def _score_section(
    section_body: str, tokens: List[str]
) -> Tuple[int, List[str]]:
    """Return (overlap_count, matched_tokens) for a section."""
    if not tokens:
        return 0, []
    body_low = section_body.lower()
    matched: List[str] = []
    for tok in tokens:
        if tok in body_low:
            matched.append(tok)
    return len(matched), matched


def _find_verdict_marker(section_body: str) -> Optional[Tuple[str, int]]:
    """Return (verdict_phrase, line_no_within_section) if a marker matches."""
    m = _VERDICT_RE.search(section_body)
    if not m:
        return None
    line_no = section_body.count("\n", 0, m.start()) + 1
    return m.group(0), line_no


# ---------------------------------------------------------------------------
# Source: vault_known_dead_ends MCP callable
# ---------------------------------------------------------------------------

def _scan_mcp_known_dead_ends(
    workspace: pathlib.Path,
    limit: int,
    repo_root: pathlib.Path,
    warnings: List[str],
) -> List[Dict[str, Any]]:
    """Invoke vault_known_dead_ends; return normalized candidate rows."""
    server = repo_root / "tools" / "vault-mcp-server.py"
    if not server.is_file():
        warnings.append("mcp:server-missing")
        return []
    args_json = json.dumps(
        {"workspace_path": str(workspace), "limit": int(limit)}
    )
    try:
        rc = subprocess.run(
            ["python3", str(server), "--call", "vault_known_dead_ends",
             "--args", args_json],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except Exception as exc:
        warnings.append(f"mcp:invoke-failed:{exc}")
        return []
    if rc.returncode != 0:
        warnings.append(f"mcp:rc={rc.returncode}")
        return []
    try:
        payload = json.loads(rc.stdout or "{}")
    except json.JSONDecodeError as exc:
        warnings.append(f"mcp:json-decode:{exc}")
        return []
    if not isinstance(payload, dict):
        warnings.append("mcp:payload-not-dict")
        return []
    raw_rows = payload.get("dead_ends") or []
    out: List[Dict[str, Any]] = []
    if not isinstance(raw_rows, list):
        return out
    for r in raw_rows[:limit]:
        if not isinstance(r, dict):
            continue
        title = str(r.get("title") or r.get("name") or r.get("id") or "")[:200]
        verdict = str(
            r.get("verdict") or r.get("status") or "NEGATIVE-from-MCP"
        )[:80]
        body = (
            str(r.get("summary") or r.get("description") or r.get("notes")
                or "")
        )
        out.append({
            "kind": "mcp:known_dead_end",
            "title": title,
            "verdict": verdict,
            "source": "vault_known_dead_ends",
            "sha": "n/a",
            "body": body[:4000],
        })
    return out


# ---------------------------------------------------------------------------
# Source: workspace .auditooor/ loop artefacts
# ---------------------------------------------------------------------------

def _scan_workspace_loop_files(
    workspace: pathlib.Path,
    file_cap: int,
    warnings: List[str],
) -> List[Dict[str, Any]]:
    aud = workspace / ".auditooor"
    if not aud.is_dir():
        warnings.append("workspace:missing-.auditooor")
        return []
    candidates: List[pathlib.Path] = []
    for pattern in ("hb_loop*_*.md", "loop*_*.md"):
        try:
            candidates.extend(sorted(aud.glob(pattern)))
        except Exception:
            continue
    # De-duplicate while preserving order.
    seen: set[pathlib.Path] = set()
    deduped: List[pathlib.Path] = []
    for p in candidates:
        if p in seen:
            continue
        seen.add(p)
        deduped.append(p)
    deduped = deduped[:file_cap]
    out: List[Dict[str, Any]] = []
    for p in deduped:
        body = _safe_read_text(p)
        if not body:
            continue
        sha = _git_sha_for_file(p)
        for heading, line_no, sec in _split_into_sections(body):
            out.append({
                "kind": "workspace:loop_md",
                "title": heading or p.name,
                "verdict_hint": None,
                "source": str(p),
                "sha": sha,
                "body": sec,
                "heading_line_no": line_no,
            })
    return out


# ---------------------------------------------------------------------------
# Source: reports/v3_iter_*/lane_*/results.md (last 60 days)
# ---------------------------------------------------------------------------

def _scan_repo_lane_results(
    repo_root: pathlib.Path,
    lookback_days: int,
    file_cap: int,
    warnings: List[str],
) -> List[Dict[str, Any]]:
    reports_dir = repo_root / "reports"
    if not reports_dir.is_dir():
        warnings.append("repo:no-reports-dir")
        return []
    cutoff = _dt.datetime.now(tz=_dt.timezone.utc).timestamp() - (
        int(lookback_days) * 86400
    )
    matches: List[pathlib.Path] = []
    # Bounded glob: only v3_iter_* subdirs.
    try:
        iter_dirs = sorted(
            (p for p in reports_dir.iterdir() if p.is_dir()
             and p.name.startswith("v3_iter_")),
            reverse=True,
        )
    except Exception as exc:
        warnings.append(f"repo:iter-listing-failed:{exc}")
        return []
    for iter_dir in iter_dirs:
        try:
            for lane_dir in iter_dir.iterdir():
                if not lane_dir.is_dir() or not lane_dir.name.startswith("lane_"):
                    continue
                results_md = lane_dir / "results.md"
                if not results_md.is_file():
                    continue
                try:
                    mtime = results_md.stat().st_mtime
                except Exception:
                    continue
                if mtime < cutoff:
                    continue
                matches.append(results_md)
                if len(matches) >= file_cap:
                    break
        except Exception:
            continue
        if len(matches) >= file_cap:
            break
    out: List[Dict[str, Any]] = []
    for p in matches:
        body = _safe_read_text(p)
        if not body:
            continue
        sha = _git_sha_for_file(p)
        # results.md files are usually short and single-topic; treat the
        # whole file as one "section" rooted at the first heading.
        sections = _split_into_sections(body)
        if not sections:
            continue
        for heading, line_no, sec in sections:
            out.append({
                "kind": "repo:lane_results",
                "title": heading or p.name,
                "verdict_hint": None,
                "source": str(p),
                "sha": sha,
                "body": sec,
                "heading_line_no": line_no,
            })
    return out


# ---------------------------------------------------------------------------
# Core scanner
# ---------------------------------------------------------------------------

def scan_prior_lanes(
    workspace: pathlib.Path,
    lane_id: str,
    keyword_tokens: List[str],
    *,
    repo_root: Optional[pathlib.Path] = None,
    mcp_limit: int = DEFAULT_MCP_LIMIT,
    local_file_cap: int = DEFAULT_LOCAL_FILE_CAP,
    reports_lookback_days: int = DEFAULT_REPORTS_LOOKBACK_DAYS,
    reports_file_cap: int = DEFAULT_REPORTS_FILE_CAP,
    match_limit: int = DEFAULT_MATCH_LIMIT,
    enable_mcp: bool = True,
    target_file_lines: Optional[Iterable[str]] = None,
    target_pin: str = "",
) -> Dict[str, Any]:
    """Scan all sources, return result dict ready for JSON emission.

    When ``target_file_lines`` is supplied, KNOWN-DEAD-END rows whose file_line
    matches the target at ``target_pin`` are resolved first and surfaced as a
    distinct ``prior_dead_ends`` list (ranked ABOVE keyword overlap matches),
    so a worker never re-derives a site already drilled to a NEGATIVE verdict.
    """
    warnings: List[str] = []
    if repo_root is None:
        repo_root = _REPO_ROOT_DEFAULT

    # File-line dead-end match mode (K3-deadend-injection). Completeness-safe:
    # no target file_lines / no KDE store -> empty list (no injection).
    dead_ends: List[Dict[str, Any]] = []
    if target_file_lines:
        dead_ends = scan_file_line_dead_ends(
            workspace,
            target_file_lines,
            target_pin=target_pin,
            repo_root=repo_root,
            warnings=warnings,
            match_limit=match_limit,
        )

    candidates: List[Dict[str, Any]] = []
    if enable_mcp:
        candidates.extend(
            _scan_mcp_known_dead_ends(workspace, mcp_limit, repo_root, warnings)
        )
    candidates.extend(
        _scan_workspace_loop_files(workspace, local_file_cap, warnings)
    )
    candidates.extend(
        _scan_repo_lane_results(
            repo_root, reports_lookback_days, reports_file_cap, warnings
        )
    )

    # Rank candidates by overlap_score and presence of verdict marker.
    ranked: List[Dict[str, Any]] = []
    for c in candidates:
        body = c.get("body") or ""
        overlap_count, matched_toks = _score_section(body, keyword_tokens)
        if overlap_count == 0:
            continue
        verdict_marker = _find_verdict_marker(body)
        # MCP rows carry their verdict at row-level; trust c.get("verdict").
        if c.get("kind") == "mcp:known_dead_end":
            verdict_phrase = c.get("verdict") or "NEGATIVE-from-MCP"
            verdict_line = None
        elif verdict_marker is not None:
            verdict_phrase, verdict_line = verdict_marker
        else:
            # Skip sections without a clear NEGATIVE/DROP/CLOSED marker.
            continue
        overlap_summary_bits = []
        if matched_toks:
            overlap_summary_bits.append(
                f"keywords matched: {', '.join(matched_toks)} "
                f"({overlap_count}/{len(keyword_tokens)})"
            )
        if verdict_line is not None:
            heading_line = c.get("heading_line_no") or 0
            absolute_line = heading_line + verdict_line
            overlap_summary_bits.append(
                f"verdict marker '{verdict_phrase}' near line {absolute_line}"
            )
        else:
            overlap_summary_bits.append(f"verdict '{verdict_phrase}'")
        ranked.append({
            "title": c.get("title") or "(untitled)",
            "verdict": verdict_phrase,
            "source": c.get("source") or "?",
            "sha": c.get("sha") or "untracked",
            "overlap_summary": "; ".join(overlap_summary_bits),
            "_score": overlap_count,
            "_kind": c.get("kind"),
        })

    ranked.sort(key=lambda r: (-r["_score"], r.get("title", "")))
    trimmed = ranked[:match_limit]
    # Strip private fields.
    for r in trimmed:
        r.pop("_score", None)
        r.pop("_kind", None)

    return {
        "schema": SCHEMA,
        "scan_summary": {
            "workspace": str(workspace),
            "lane_id": lane_id,
            "keyword_tokens": list(keyword_tokens),
            "sources_scanned": {
                "mcp_known_dead_ends_enabled": bool(enable_mcp),
                "mcp_limit": int(mcp_limit),
                "local_loop_md_cap": int(local_file_cap),
                "reports_lookback_days": int(reports_lookback_days),
                "reports_file_cap": int(reports_file_cap),
            },
            "candidates_considered": len(candidates),
            "matches_returned": len(trimmed),
            "dead_ends_returned": len(dead_ends),
            "target_pin": str(target_pin or ""),
            "warnings": warnings,
            "match_limit": int(match_limit),
        },
        "prior_dead_ends": dead_ends,
        "prior_negative_chains": trimmed,
    }


# ---------------------------------------------------------------------------
# Brief composition helper (consumed by spawn-worker.sh)
# ---------------------------------------------------------------------------

def render_brief_section(result: Dict[str, Any]) -> str:
    """Render the scan result as a markdown brief-section.

    Returned string is the entire "STEP 1.5 - Prior-Lane Scan" block,
    designed to be appended AFTER the META-1 block by spawn-worker.sh.
    """
    summary = result.get("scan_summary") or {}
    rows = result.get("prior_negative_chains") or []
    dead_ends = result.get("prior_dead_ends") or []
    lines: List[str] = []
    lines.append("<!-- BEGIN prior-lane-scan (CAPABILITY-GAP-2) -->")
    lines.append("")

    # ----- PRIOR DEAD-ENDS (K3-deadend-injection) -----------------------
    # Ranked ABOVE keyword overlap: these are exact-site verdicts at the
    # current pin. Only rendered when the file_line match mode found rows;
    # otherwise omitted entirely so empty-store behaviour is unchanged.
    if dead_ends:
        lines.append(
            "## PRIOR DEAD-ENDS (do not re-derive; cite dead_end_id if you concur)"
        )
        lines.append("")
        lines.append(
            "_Exact code sites below were already investigated to a NEGATIVE / "
            "DROP verdict at this pin. Do NOT re-derive them. If your hypothesis "
            "is the SAME site/class, cite the `dead_end_id` and concur; if it is "
            "structurally DISTINCT, say why in your results.md._"
        )
        lines.append("")
        for idx, de in enumerate(dead_ends, 1):
            did = str(de.get("dead_end_id") or "(unnamed-dead-end)")[:120]
            fl = str(de.get("file_line") or "(no file_line)")[:200]
            dc = str(de.get("drop_class") or "dead-end")[:80]
            reason = str(de.get("reason") or "")[:400]
            lines.append(
                f"{idx}. `{fl}` - **{dc}** (dead_end_id: `{did}`)"
            )
            if reason:
                lines.append(f"   - reason: {reason}")
        lines.append("")

    lines.append("## STEP 1.5 - Prior-Lane Scan (Gap 2)")
    lines.append("")
    lines.append(
        "_Auto-injected by `tools/lib/prior_lane_scan.py` before lane "
        "spawn. Workers MUST acknowledge each prior chain below via the "
        "`prior_negative_chains_acknowledged: [...]` frontmatter field in "
        "their `results.md`, or explicitly mark the scan empty._"
    )
    lines.append("")
    keyword_tokens = summary.get("keyword_tokens") or []
    if keyword_tokens:
        lines.append(
            f"**Hypothesis keywords**: `{', '.join(keyword_tokens)}`"
        )
        lines.append("")
    lines.append(
        f"**Sources scanned**: MCP `vault_known_dead_ends` (limit "
        f"{summary.get('sources_scanned', {}).get('mcp_limit', '?')}), "
        f"workspace `.auditooor/(hb_)loop*_*.md` (cap "
        f"{summary.get('sources_scanned', {}).get('local_loop_md_cap', '?')}), "
        f"repo `reports/v3_iter_*/lane_*/results.md` (last "
        f"{summary.get('sources_scanned', {}).get('reports_lookback_days', '?')} "
        f"days, cap "
        f"{summary.get('sources_scanned', {}).get('reports_file_cap', '?')})"
    )
    lines.append("")
    lines.append(
        f"**Candidates considered**: {summary.get('candidates_considered', 0)} "
        f"| **Matches returned**: {summary.get('matches_returned', 0)}"
    )
    lines.append("")
    warnings = summary.get("warnings") or []
    if warnings:
        lines.append("**Scan warnings**:")
        for w in warnings[:5]:
            lines.append(f"- `{w}`")
        lines.append("")
    if not rows:
        lines.append(
            "_No matching prior NEGATIVE / DROP / CLOSED chains found. "
            "Mark `prior_negative_chains_acknowledged: []` in your "
            "frontmatter and proceed._"
        )
        lines.append("")
    else:
        lines.append(
            f"**Prior NEGATIVE/DROP/CLOSED chains** (top {len(rows)}; "
            "acknowledge each in your reply):"
        )
        lines.append("")
        for idx, row in enumerate(rows, 1):
            title = str(row.get("title") or "(untitled)")[:160]
            verdict = str(row.get("verdict") or "")[:60]
            source = str(row.get("source") or "?")
            sha = str(row.get("sha") or "untracked")[:40]
            overlap = str(row.get("overlap_summary") or "")[:300]
            lines.append(
                f"{idx}. **{title}** (verdict: `{verdict}`)"
            )
            lines.append(f"   - source: `{source}` (sha `{sha}`)")
            lines.append(f"   - overlap: {overlap}")
        lines.append("")
        lines.append(
            "_Required: include `prior_negative_chains_acknowledged: ["
            + ", ".join([
                f'"{(r.get("title") or "")[:80]}"' for r in rows[:3]
            ])
            + "...]` (full list) in your results.md frontmatter. "
            "Cite each by title; explain whether your hypothesis is "
            "structurally distinct or whether the prior verdict already "
            "covers it._"
        )
        lines.append("")
    lines.append("<!-- END prior-lane-scan (CAPABILITY-GAP-2) -->")
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan prior lanes for hypothesis overlap (CAPABILITY-GAP-2)."
    )
    parser.add_argument("--workspace", required=True, type=pathlib.Path)
    parser.add_argument("--lane-id", required=True)
    parser.add_argument(
        "--hypothesis-keywords",
        required=True,
        help="Comma- or whitespace-separated hypothesis keywords.",
    )
    parser.add_argument("--repo-root", type=pathlib.Path, default=None)
    parser.add_argument("--mcp-limit", type=int, default=DEFAULT_MCP_LIMIT)
    parser.add_argument("--local-file-cap", type=int, default=DEFAULT_LOCAL_FILE_CAP)
    parser.add_argument("--reports-lookback-days", type=int,
                        default=DEFAULT_REPORTS_LOOKBACK_DAYS)
    parser.add_argument("--reports-file-cap", type=int,
                        default=DEFAULT_REPORTS_FILE_CAP)
    parser.add_argument("--match-limit", type=int, default=DEFAULT_MATCH_LIMIT)
    parser.add_argument(
        "--target-file-lines",
        default="",
        help="Comma- or whitespace-separated file_line(s) (path:line) for the "
        "lane's files; enables KNOWN-DEAD-END file_line match mode (K3).",
    )
    parser.add_argument(
        "--target-pin",
        default="",
        help="Current target pin (git sha); KDE rows are matched "
        "completeness-safely against it (unknown pin on either side = keep).",
    )
    parser.add_argument(
        "--no-mcp", action="store_true",
        help="Skip vault_known_dead_ends MCP call (for tests / offline).",
    )
    parser.add_argument(
        "--render-brief", action="store_true",
        help="Emit the markdown brief section instead of raw JSON.",
    )
    args = parser.parse_args(argv)

    tokens = _tokenize_keywords(args.hypothesis_keywords)
    target_file_lines = [
        p for p in re.split(r"[\s,]+", (args.target_file_lines or "").strip()) if p
    ]
    workspace = args.workspace
    if not workspace.exists():
        # Graceful warn-only path.
        result = {
            "schema": SCHEMA,
            "scan_summary": {
                "workspace": str(workspace),
                "lane_id": args.lane_id,
                "keyword_tokens": tokens,
                "sources_scanned": {},
                "candidates_considered": 0,
                "matches_returned": 0,
                "dead_ends_returned": 0,
                "target_pin": str(args.target_pin or ""),
                "warnings": [f"workspace:not-found:{workspace}"],
                "match_limit": int(args.match_limit),
            },
            "prior_dead_ends": [],
            "prior_negative_chains": [],
        }
    else:
        result = scan_prior_lanes(
            workspace=workspace,
            lane_id=args.lane_id,
            keyword_tokens=tokens,
            repo_root=args.repo_root,
            mcp_limit=args.mcp_limit,
            local_file_cap=args.local_file_cap,
            reports_lookback_days=args.reports_lookback_days,
            reports_file_cap=args.reports_file_cap,
            match_limit=args.match_limit,
            enable_mcp=not args.no_mcp,
            target_file_lines=target_file_lines,
            target_pin=args.target_pin,
        )

    if args.render_brief:
        sys.stdout.write(render_brief_section(result))
    else:
        sys.stdout.write(json.dumps(result, sort_keys=True, indent=2))
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
