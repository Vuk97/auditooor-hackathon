"""
cosmos_nil_pointer_panic_on_getter.py

Detects Go functions that dereference the result of a fallible lookup
(map/store getter that can return a nil pointer or a (value, found) pair)
WITHOUT first checking the `found` boolean or a `!= nil` guard.

In cosmos-sdk keepers the canonical pattern is:
    market, found := k.GetMarket(ctx, id)
    if !found { return ErrMarketNotFound }
    use(market.Field)             // safe

The bug shape is the same call followed by an immediate field/method
access on the returned pointer with no intervening `found`/`nil` check:
    market, _ := k.GetMarket(ctx, id)
    use(market.Field)             // panics if market == nil

A panic inside DeliverTx/BeginBlocker/EndBlocker aborts block execution
on every validator -> chain halt.

Bug class: HIGH/CRITICAL (nil-pointer-panic -> node panic / chain halt).
Attack-class anchor: zero-coverage class `nil-pointer-panic`
("Nil pointer dereference causes node panic").
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_nil_pointer_panic_on_getter"

# A fallible lookup: `x, found := k.GetX(...)` or `x, _ := k.GetX(...)`.
# We capture the bound variable and whether the 2nd return is discarded.
_LOOKUP_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*,\s*(found|ok|exists|_)\s*:?=\s*"
    r"[A-Za-z_][\w.]*\.(Get|Find|Lookup|Load|Fetch)[A-Za-z_]*\s*\(",
)

# Pointer-returning single-value getter: `x := k.GetXPtr(...)`.
_PTR_LOOKUP_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*:?=\s*"
    r"[A-Za-z_][\w.]*\.(Get|Find|Lookup|Load|Fetch)[A-Za-z_]*\s*\(",
)

# A guard that proves the caller checked the lookup result.
_GUARD_TMPL = (
    r"(!\s*{v}\b"                       # if !found
    r"|\b{v}\s*==\s*nil"                # if x == nil
    r"|\b{v}\s*!=\s*nil"                # if x != nil
    r"|!\s*found\b|!\s*ok\b|!\s*exists\b"
    r"|\bfound\b|\bok\b|\bexists\b)"
)


def _uses_field_of(body_text: str, var: str) -> bool:
    """True if the variable is dereferenced (field access / method call)."""
    return re.search(rf"\b{re.escape(var)}\.", body_text) is not None


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

        flagged_vars = set()

        for m in _LOOKUP_RE.finditer(body_text):
            var, second = m.group(1), m.group(2)
            if var in flagged_vars or var == "_":
                continue
            # Discarded `_` second return means no found-check is possible.
            if second != "_":
                # caller kept the bool; require it to be used as a guard.
                guard = re.compile(_GUARD_TMPL.format(v=re.escape(second)))
                if guard.search(body_text):
                    continue
            if not _uses_field_of(body_text, var):
                continue
            flagged_vars.add(var)
            hits.append({
                "severity": "high",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": engine.text(fn).splitlines()[0][:160],
                "message": (
                    f"`{name}` dereferences `{var}` from a fallible "
                    f"Get/Find lookup without a found/nil check. A nil "
                    f"result panics; inside DeliverTx/BeginBlocker this "
                    f"halts the chain. Check the (value, found) bool or "
                    f"`!= nil` before use. (class: nil-pointer-panic)"),
            })
    return hits
