#!/usr/bin/env python3
"""scope_authority - THE single, language-agnostic source of truth for
"is this file / unit in the audit scope".

WHY THIS EXISTS (strata 2026-07-01, operator-caught, generic):
The audit pipeline has ~50 tools that make OOS / vendored / trusted / interface /
"not-in-scope" dispositions. Each one that decides scope by a LOCAL heuristic
(a basename set, a path guess, or - the strata bug - a bare "OpenZeppelin"
substring match) can contradict the AUTHORITATIVE in-scope manifest the setup
step already produced (`inscope_units.jsonl`, written by
`workspace-coverage-heatmap.py::write_inscope_manifest` at README step-1/1c).
On strata that mislabeled 56 in-scope first-party governance verdicts as
"vendored-trusted-library - out of scope". The fix is not per-tool: it is ONE
authority that every disposition consults, plus a gate that fails closed when a
disposition marks an in-scope unit OOS.

This module is deliberately dependency-free and LANGUAGE-AGNOSTIC: it keys on
the `inscope_units.jsonl` records (file + function, any of solidity / rust / go /
cairo / cosmos), never on file extension or contract idiom. An in-scope unit is
FIRST-PARTY BY DEFINITION - whatever library it imports or extends.

Contract used by callers:
  - load_inscope(ws) -> InscopeSet
  - is_inscope_file(ws, path_or_relstr) -> bool
  - is_inscope_unit(ws, file, fn) -> bool

False-green-safe: if the manifest is ABSENT (setup not run) the authority returns
False for everything (it cannot ASSERT in-scope), so a caller falls back to its
own heuristic rather than silently trusting an empty authority.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

# Disposition classes / verdict tokens that mean "OUT OF SCOPE / not a first-party
# attack surface". A gate uses this to detect an in-scope unit wrongly OOS'd.
# Extend here (one place) as new OOS-family class strings appear in any tool.
OOS_FAMILY_TOKENS = frozenset({
    "vendored-trusted-library",
    "vendored", "vendored-library", "trusted-library",
    "out-of-scope-surface", "out-of-scope", "out_of_scope", "oos",
    "trusted-infra", "trusted-infrastructure", "trusted-infra-compromise",
    "not-in-scope", "not_in_scope", "off-scope", "off_scope",
    "third-party-dep", "third_party", "upstream-unmodified",
})


class InscopeSet:
    __slots__ = ("relpaths", "basenames", "units", "present")

    def __init__(self, relpaths, basenames, units, present):
        self.relpaths = relpaths      # frozenset[str] ws-relative posix paths
        self.basenames = basenames    # frozenset[str] file basenames
        self.units = units            # frozenset[(basename, fnkey)]
        self.present = present        # bool: manifest existed + was non-empty


_CACHE: dict[str, InscopeSet] = {}


def _fnkey(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def _manifest_path(ws: Path) -> Path:
    return ws / ".auditooor" / "inscope_units.jsonl"


def load_inscope(ws: Path | str) -> InscopeSet:
    ws = Path(ws)
    key = str(ws)
    hit = _CACHE.get(key)
    if hit is not None:
        return hit
    rel: set[str] = set()
    base: set[str] = set()
    units: set[tuple[str, str]] = set()
    present = False
    p = _manifest_path(ws)
    try:
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(rec, dict):
                continue
            f = str(rec.get("file", "") or "").replace("\\", "/").strip().lstrip("./")
            if not f:
                continue
            present = True
            rel.add(f)
            bn = Path(f).name
            base.add(bn)
            fn = rec.get("function") or rec.get("fn") or ""
            units.add((bn, _fnkey(str(fn))))
    except OSError:
        pass
    out = InscopeSet(frozenset(rel), frozenset(base), frozenset(units), present)
    _CACHE[key] = out
    return out


def _relify(ws: Path, path_or_str) -> tuple[str, str]:
    """Return (ws_relative_posix_or_empty, basename)."""
    s = str(path_or_str).replace("\\", "/").strip()
    # strip a trailing :line / ::fn the callers sometimes carry
    s_noln = re.sub(r":\d+$", "", s)
    bn = Path(s_noln.split("::", 1)[0]).name
    rel = ""
    try:
        p = Path(s_noln)
        if p.is_absolute():
            rel = str(p.resolve().relative_to(ws.resolve())).replace("\\", "/")
        else:
            rel = s_noln.lstrip("./")
    except (ValueError, OSError):
        rel = s_noln.lstrip("./")
    return rel, bn


def is_inscope_file(ws: Path | str, path_or_str, *, exact: bool = False) -> bool:
    ws = Path(ws)
    ins = load_inscope(ws)
    if not ins.present:
        return False
    rel, bn = _relify(ws, path_or_str)
    raw = str(path_or_str or "").strip()
    # Exact mode is for source-bearing consumers that must preserve directory
    # identity. Compatibility mode retains the historical basename join for
    # partial/relativized evidence references.
    if exact:
        if rel:
            return rel in ins.relpaths
        if Path(raw).is_absolute():
            return False
    elif rel and rel in ins.relpaths:
        return True
    return bool(bn) and bn in ins.basenames


def is_inscope_unit(ws: Path | str, file: str, fn: str) -> bool:
    ws = Path(ws)
    ins = load_inscope(ws)
    if not ins.present:
        return False
    _, bn = _relify(ws, file)
    if not bn:
        return False
    if (bn, _fnkey(fn)) in ins.units:
        return True
    # file in scope but fn unknown -> still first-party file
    return bn in ins.basenames


def is_oos_family(token: str) -> bool:
    t = str(token or "").strip().lower()
    if not t:
        return False
    if t in OOS_FAMILY_TOKENS:
        return True
    # Fuzzy (compound/substring) matching applies ONLY to slug-like CLASS
    # TOKENS - never to a free-text narrative. A disposition class is a short
    # hyphenated slug ("out-of-scope-test-only", "vendored", "oos-curator-config");
    # a verdict/reason NARRATIVE is prose (has spaces) that merely MENTIONS an OOS
    # artifact in its explanation (e.g. "reached from the OUT-OF-SCOPE mock vault").
    # Substring-matching OOS phrases inside prose is the #1 inscope-disposition
    # false-red (strata Tranche.sol NOT-FILEABLE mis-flagged as an OOS closure
    # because its reasoning explained an OOS-mock selector collision). A class
    # token has no interior whitespace and is short.
    if any(c.isspace() for c in t) or len(t) > 64:
        return False
    # COVERAGE-ACCOUNTING vs PROGRAM-SCOPE DISPOSITION: a token like
    # "out-of-scope-fcc-filtered" (coverage-plane-build.py / completeness-matrix-
    # build.py's _is_fcc_filtered_nonentry) classifies a FUNCTION as not-a-
    # callable-attack-surface (internal/private/view/pure/interface-signature) -
    # an orthogonal COVERAGE-BOOKKEEPING axis, not a claim that the containing
    # unit is excluded from the PROGRAM's audit scope. Exclude this class before
    # the generic "out-of-scope" substring check below, else any artifact whose
    # schema exposes this status as a flat top-level field (coverage_plane.jsonl)
    # trips the same false-red the class-token/narrative split above already
    # fixed once (strata coverage_plane.jsonl 2026-07-02: 24 in-scope units
    # wrongly flagged "closed OOS" for functions that are merely non-entry).
    if "fcc-filtered" in t or "fcc_filtered" in t:
        return False
    # compound OOS tokens (e.g. "oos-curator-config", "out-of-scope-test-only").
    # Never match plain "in-scope"/"covered". "oos" only as a prefix/segment so
    # it can't hit an unrelated word that merely contains the letters.
    if t.startswith(("oos-", "oos_")) or "-oos-" in t or "_oos_" in t:
        return True
    return any(tok in t for tok in ("out-of-scope", "out_of_scope", "vendored",
                                    "trusted-infra", "not-in-scope", "not_in_scope"))


def clear_cache() -> None:
    _CACHE.clear()
