"""
go-cosmos-block-hook-work-cap-missing.py

Sibling detector for Go/Cosmos dos-cap-weakening recall.

Flags ABCI block hooks that process attacker-growable queues or stores without
a local work cap, batch size, cursor, or break condition. This is separate
from cosmos_beginblock_unbounded_iteration so the held-out origin fixture can
be recalled by an independent same-class detector.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-cosmos-block-hook-work-cap-missing"


_HOOK_RE = re.compile(r"(BeginBlocker|EndBlocker|PreBlocker)$")

_ATTACKER_GROWABLE_RE = re.compile(
    r"(order|orders|queue|queued|settlement|settlements|market|markets|"
    r"position|positions|account|accounts|packet|packets)",
    re.IGNORECASE,
)

_FULL_COLLECTION_RE = re.compile(
    r"Iterator\s*\(\s*nil\s*,\s*nil\s*\)|"
    r"\bfor\b[^\n{]*\brange\s+[A-Za-z_][\w.]*\.(?:GetAll|All|List|Iterate)[A-Za-z]*\s*\("
    r"|GetAll[A-Za-z]*\s*\(\s*ctx\s*\)|"
    r"IterateAll[A-Za-z]*\s*\(",
    re.IGNORECASE,
)

_CAP_SIGNAL_RE = re.compile(
    r"\b(maxPerBlock|MaxPerBlock|maxIterations|limit|Limit|batchSize|"
    r"BatchSize|cursor|Cursor|pageLimit|MaxBlockWork)\b|"
    r"\bbreak\b|"
    r"\b(count|i|processed)\s*(?:>=|>)\s*[A-Za-z0-9_]+",
    re.IGNORECASE,
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
        if not _FULL_COLLECTION_RE.search(body_text):
            continue
        if not _ATTACKER_GROWABLE_RE.search(body_text):
            continue
        if _CAP_SIGNAL_RE.search(body_text):
            continue
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"ABCI hook `{name}` processes an attacker-growable "
                "collection with no per-block work cap. This is a "
                "dos-cap-weakening sibling detector for block hook liveness "
                "failure."
            ),
        })
    return hits
