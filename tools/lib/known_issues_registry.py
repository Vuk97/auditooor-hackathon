"""Shared reader for the per-workspace known-issues registry
``.auditooor/known_issues.json`` (schema ``auditooor.known_issues.v1``).

WHY (RANK-2 wiring 2026-06-23): the structured registry - the durable home for
operator-declared acknowledged / OOS / won't-fix issues - was read by ONLY
``tools/falsification-triage.py``. The hunt-dispatch ranker, the R47 paste-ready
gate, and the hunt-agent prompt were blind to it, so an operator-declared
acknowledged-OOS issue still ranked, fanned out to paid verification agents, and
could reach filing before R47 (which only fires at paste-ready time) caught it.

This module is the single, additive, generic seam those consumers share. It is
ADVISORY: it surfaces the registered OOS keywords/hints so a consumer can dedup /
hard-zero / prime an agent prompt. Operator override via the existing
``r47-rebuttal`` (extension-distinct argument) is unaffected - nothing here
hard-blocks an extension-distinct draft; it only adds known-issue awareness.

Stdlib only. Degrades to ``[]`` when the file is absent or malformed.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.known_issues.v1"

# Statuses that mark an issue as out-of-scope / acknowledged / won't-fix - i.e.
# a rediscovery is NOT independently fileable absent an extension-distinct
# argument (R47/R45/R53). Other statuses (e.g. "open", "in-scope") are ignored
# so this never suppresses live in-scope work.
OOS_STATUSES = frozenset({"acknowledged-oos", "known-issue", "wont-fix"})


def _registry_path(ws: Path) -> Path:
    return ws / ".auditooor" / "known_issues.json"


def _load_raw(ws: Path) -> dict:
    """Load and parse the registry; degrade to an empty registry on any error."""
    p = _registry_path(ws)
    if not p.is_file():
        return {"issues": []}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"issues": []}
    if not isinstance(data, dict):
        return {"issues": []}
    return data


def _norm_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _str_list(value: Any) -> list[str]:
    """Coerce a registry list field to a clean list[str] (drop empties)."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    out: list[str] = []
    for item in value:
        s = str(item).strip()
        if s:
            out.append(s)
    return out


def load_known_oos(ws: str | Path) -> list[dict]:
    """Return the OOS / acknowledged / won't-fix issues from the registry.

    Each returned dict has stable keys::

        {"id": str, "status": str, "title": str,
         "keywords": [str, ...], "invariant_hints": [str, ...],
         "rule": str, "source": str}

    Only issues whose ``status`` is in :data:`OOS_STATUSES` are returned. The
    list is ``[]`` when the registry is absent, malformed, or has no OOS issues
    (generic, never raises). ADDITIVE: callers append these as extra dedup /
    hard-zero / prompt-priming signals on top of their existing prose scans.
    """
    ws = Path(ws)
    data = _load_raw(ws)
    issues = data.get("issues")
    if not isinstance(issues, list):
        return []
    out: list[dict] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue
        status = _norm_status(issue.get("status"))
        if status not in OOS_STATUSES:
            continue
        out.append({
            "id": str(issue.get("id") or "").strip(),
            "status": status,
            "title": str(issue.get("title") or "").strip(),
            "keywords": _str_list(issue.get("keywords")),
            "invariant_hints": _str_list(issue.get("invariant_hints")),
            "rule": str(issue.get("rule") or "").strip(),
            # falsification-triage reads source|cite; mirror that coalesce.
            "source": str(issue.get("source") or issue.get("cite") or "").strip(),
        })
    return out


def oos_keyword_terms(ws: str | Path) -> list[tuple[str, list[str]]]:
    """Convenience: per-issue (id, terms) where terms = keywords + invariant_hints.

    Used by consumers that want to build a per-issue pattern/dedup line. Issues
    with no usable terms are dropped (an empty-term pattern would match nothing
    useful / everything). Generic; degrades to ``[]``.
    """
    out: list[tuple[str, list[str]]] = []
    for issue in load_known_oos(ws):
        terms = list(issue["keywords"]) + list(issue["invariant_hints"])
        terms = [t for t in terms if t]
        if not terms:
            continue
        out.append((issue["id"] or issue["title"] or "known-issue", terms))
    return out
