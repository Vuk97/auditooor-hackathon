#!/usr/bin/env python3
"""Re-order a newline-delimited list of source paths (read from stdin) so that
files with higher guard-risk come first, using a workspace's
``.auditooor/guard_triage.json`` (produced by ``tools/guard-triage.py``).

This is a GENERIC, additive funnel helper: callers that previously did
``... | sort -u | head -n N`` to pick the first N candidate contracts were
choosing ALPHABETICALLY, ignoring guard-risk. Piping through this tool instead
makes the cap/budget select the highest guard-risk files first while staying a
no-op (alphabetical, deduped) when no guard_triage.json is present.

Behaviour
---------
* Reads paths (one per line) from stdin. Blank lines dropped.
* De-duplicates, preserving FIRST occurrence (replaces ``sort -u``).
* Per-file guard-risk = max(score) over guard_triage ``risk_units`` whose
  ``unit`` file-component matches the path (ws-relative match, basename
  fallback). Higher risk first; unranked files last; ties broken alphabetically.
* If guard_triage.json is missing/unreadable/empty -> falls back to ``sorted``
  (exactly ``sort -u``), preserving existing behaviour. Never raises on bad
  input (fail-open).

Usage:
    ... | python3 tools/rank-paths-by-guard-triage.py --workspace <ws>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional


def _norm(p: str) -> str:
    return p.replace("\\", "/").strip()


def _unit_file(unit: str) -> str:
    """``src/.../File.sol:funcname`` -> ``src/.../File.sol`` (strip trailing :func)."""
    u = _norm(unit)
    if ":" not in u:
        return u
    head, _, tail = u.rpartition(":")
    # strip the suffix only when it looks like a bare identifier (the func name),
    # i.e. no path separator and no dot/extension -> not a "File.sol" or ":line".
    if head and "/" not in tail and "." not in tail and not tail.isdigit():
        return head
    # ``loc`` form ``File.sol:294`` -> also strip the line number
    if head and tail.isdigit():
        return head
    return u


def load_file_risk(ws: Path) -> Dict[str, int]:
    """Map ws-relative file path -> max guard-risk score. {} when unavailable."""
    gt = ws / ".auditooor" / "guard_triage.json"
    if not gt.is_file():
        return {}
    try:
        data = json.loads(gt.read_text(encoding="utf-8"))
    except Exception:
        return {}
    risk: Dict[str, int] = {}
    for ru in (data.get("risk_units") or []):
        try:
            unit = ru.get("unit") or ru.get("loc") or ""
            score = int(ru.get("score") or 0)
        except Exception:
            continue
        f = _unit_file(unit)
        if f and score > risk.get(f, -1):
            risk[f] = score
    return risk


def _ws_rel(path: str, ws: Path) -> str:
    pn = _norm(path)
    try:
        ap = Path(pn)
        if ap.is_absolute():
            return _norm(str(ap.resolve().relative_to(ws.resolve())))
    except Exception:
        pass
    return pn[2:] if pn.startswith("./") else pn


def rank(paths: List[str], file_risk: Dict[str, int], ws: Optional[Path]) -> List[str]:
    # de-dupe, preserve first occurrence
    seen: set = set()
    ordered: List[str] = []
    for p in paths:
        n = _norm(p)
        if n and n not in seen:
            seen.add(n)
            ordered.append(n)

    if not file_risk:
        return sorted(ordered)  # exact sort -u fallback

    base_risk: Dict[str, int] = {}
    for f, s in file_risk.items():
        b = f.rsplit("/", 1)[-1]
        if s > base_risk.get(b, -1):
            base_risk[b] = s

    def score_for(p: str) -> int:
        rel = _ws_rel(p, ws) if ws else _norm(p)
        if rel in file_risk:
            return file_risk[rel]
        base = rel.rsplit("/", 1)[-1]
        return base_risk.get(base, -1)

    return sorted(ordered, key=lambda p: (-score_for(p), p))


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True)
    args = ap.parse_args(argv)

    ws = Path(args.workspace)
    file_risk = load_file_risk(ws)
    for p in rank(sys.stdin.read().splitlines(), file_risk, ws):
        sys.stdout.write(p + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
