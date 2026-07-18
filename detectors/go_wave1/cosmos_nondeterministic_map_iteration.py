"""
cosmos_nondeterministic_map_iteration.py

Detects `for k := range someMap` / `for k, v := range someMap` iteration
where the loop body performs a CONSENSUS-RELEVANT side effect (a store
write, a coin transfer, an event emit, or appends to an ordered slice)
WITHOUT sorting the keys first.

Go map iteration order is randomized per process. If a state-machine
handler iterates a map and writes ordered state, two validators executing
the same block produce different AppHashes -> consensus failure / chain
halt that requires a coordinated restart.

The deterministic pattern is to collect keys into a slice and
`sort.Slice` / `sort.Strings` before iterating, or to use the SDK
`storetypes` iterator (which is key-ordered by construction).

Bug class: HIGH/CRITICAL (apphash-divergence -> consensus failure).
Attack-class anchor: zero-coverage class `apphash-divergence`
("Validators produce different AppHash causing consensus failure").
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_nondeterministic_map_iteration"

# `for k := range m` or `for k, v := range m` over an identifier.
_RANGE_MAP_RE = re.compile(
    r"\bfor\s+[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)?\s*:?=\s*range\s+"
    r"([A-Za-z_][\w.]*)\b",
)

# Consensus-relevant side effects performed inside the loop body.
_SIDE_EFFECT_RE = re.compile(
    r"(\.Set\s*\(|\.Delete\s*\(|store\.Set|store\.Delete"
    r"|SendCoins|MintCoins|BurnCoins|AddCoins|SubtractCoins"
    r"|\.EmitEvent|EmitTypedEvent"
    r"|\.Commit\s*\(|\bappend\s*\()"
)

# Evidence the keys were sorted before the consensus loop.
_SORT_RE = re.compile(
    r"\bsort\.(Slice|SliceStable|Strings|Ints|Sort)\b"
)

# Map declared via `make(map[` or `map[...]...{` literal -> confirms it is
# a Go map (not a slice that happens to be ranged).
_MAP_DECL_TMPL = (
    r"\b{v}\b\s*:?=\s*(make\s*\(\s*map\[|map\[)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        if not _SIDE_EFFECT_RE.search(body_text):
            continue

        flagged = set()
        for m in _RANGE_MAP_RE.finditer(body_text):
            var = m.group(1)
            if var in flagged:
                continue
            # Only flag identifiers that are declared as a Go map in scope.
            decl = re.compile(_MAP_DECL_TMPL.format(v=re.escape(var)))
            looks_like_map = bool(decl.search(body_text)) or \
                var.lower().endswith("map") or var.lower().endswith("maps") \
                or var.lower().endswith("byid") or var.lower().endswith("set")
            if not looks_like_map:
                continue
            # Sorting anywhere in the function is treated as the safe shape.
            if _SORT_RE.search(body_text):
                continue
            flagged.add(var)
            hits.append({
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": engine.text(fn).splitlines()[0][:160],
                "message": (
                    f"`{name}` ranges over Go map `{var}` and performs a "
                    f"consensus-relevant side effect (store write / coin "
                    f"transfer / event / ordered append) without sorting "
                    f"keys. Map order is random per process; validators "
                    f"diverge on AppHash. Sort keys before iterating. "
                    f"(class: apphash-divergence)"),
            })
    return hits
