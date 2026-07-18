"""
cosmos_beginblock_unbounded_iteration.py

Detects `BeginBlocker` / `EndBlocker` / `PreBlocker` functions that iterate
an unbounded, attacker-growable collection (a full store-prefix scan, a
`range` over all module entries) WITHOUT a per-block work cap.

ABCI block-lifecycle hooks run on every validator every block. They are
NOT gas-metered against any single transaction. If an attacker can grow
a collection cheaply (open many orders, register many markets, create
many small positions) and the EndBlocker iterates ALL of them with no
`maxPerBlock` / pagination / batch limit, every block gets slower until
block production stalls -> network-level liveness degradation.

The safe pattern caps the per-block work: a `limit` constant, a
`maxIterations` counter, `break` after N, or a paginated cursor that
processes a bounded slice and resumes next block.

Bug class: HIGH (dos-cap-weakening / state-bloat -> liveness).
Attack-class anchor: zero-coverage class `dos-cap-weakening`
("Resource cap weakened enabling denial-of-service") with
`per-block-gas-amplification` as the narrow mechanism.
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_beginblock_unbounded_iteration"

# ABCI block-lifecycle hook names.
_HOOK_RE = re.compile(r"(BeginBlocker|EndBlocker|PreBlocker)$")

# An unbounded iteration: a store-prefix iterator OR a range over a
# whole-collection getter.
_UNBOUNDED_ITER_RE = re.compile(
    r"(\.Iterator\s*\(\s*nil\s*,\s*nil\s*\)"      # full-store iterator
    r"|\.Iterator\s*\(\s*\)"
    r"|store\.Iterator\b"
    r"|\bfor\b[^\n]*\brange\s+[A-Za-z_][\w.]*\.(GetAll|All|List|Iterate)"
    r"|\.GetAll[A-Za-z]*\s*\(\s*ctx\s*\)"
    r"|\.IterateAll\b)"
)

# Evidence of a per-block work cap.
_CAP_RE = re.compile(
    r"(\bmaxPerBlock\b|\bMaxPerBlock\b|\bmaxIterations\b|\blimit\b|\bLimit\b"
    r"|\bbatchSize\b|\bBatchSize\b|\bbreak\b|\bcursor\b|\bCursor\b"
    r"|\bpageLimit\b|\bMaxBlockWork\b|i\s*>=\s*[A-Za-z0-9_]+|count\s*>=)"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _HOOK_RE.search(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        if not _UNBOUNDED_ITER_RE.search(body_text):
            continue
        if _CAP_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"ABCI hook `{name}` iterates an unbounded, "
                f"attacker-growable collection with no per-block work cap. "
                f"An attacker cheaply grows the collection; every block "
                f"slows until block production stalls. Add a maxPerBlock "
                f"limit / paginated cursor. "
                f"(class: dos-cap-weakening; mechanism: "
                f"per-block-gas-amplification)"),
        })
    return hits
