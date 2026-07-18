"""
cosmos_unchecked_error_on_state_write.py

Detects calls to state-mutating / fund-moving SDK methods whose returned
`error` is discarded with `_` (or whose error return is ignored entirely
by using the call as a bare statement).

In cosmos-sdk a discarded error on a bank transfer, store write, or coin
mint silently swallows a failure. The handler then proceeds as if the
mutation succeeded -> accounting drift, double-spend, or a state-vs-event
mismatch. On a consensus path this is a correctness bug, not a cosmetic
one: a swallowed `SendCoins` error lets a handler emit a success event
and return nil while no coins moved.

The safe pattern always binds and checks the error:
    if err := k.bankKeeper.SendCoins(ctx, a, b, amt); err != nil {
        return err
    }

Bug class: HIGH (unchecked-error-return -> accounting drift / silent loss).
Attack-class anchor: zero-coverage class `unchecked-error-return`
(canonical Go static-analysis class; cosmos-sdk fund-path instantiation).
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_unchecked_error_on_state_write"

# Fund-moving / state-mutating SDK method names whose error MUST be checked.
_RISKY_CALL = (
    r"(SendCoins|SendCoinsFromModuleToAccount|SendCoinsFromAccountToModule"
    r"|SendCoinsFromModuleToModule|MintCoins|BurnCoins|DelegateCoins"
    r"|UndelegateCoins|Transfer|Withdraw|SetBalance"
    r"|Mint|Burn|Settle|Payout|Distribute)"
)

# `_ = k.SendCoins(...)` or `_, _ = ...` — error explicitly discarded.
_DISCARD_RE = re.compile(
    r"(?:^|\n)\s*(?:_\s*,\s*)*_\s*=\s*[A-Za-z_][\w.]*\." + _RISKY_CALL +
    r"\s*\(",
)

# Bare-statement call: `k.bankKeeper.SendCoins(...)` on its own line with
# no `:=` / `=` / `if` / `return` / `err` capture in front of it.
_BARE_CALL_RE = re.compile(
    r"(?:^|\n)[ \t]*[A-Za-z_][\w.]*\." + _RISKY_CALL + r"\s*\(",
)


def _line_has_capture(line: str) -> bool:
    """True if the line binds the call result (err :=, x, err :=, return ...)."""
    stripped = line.strip()
    if stripped.startswith(("if ", "return ", "err ")):
        return True
    # `x := ...` or `x, err := ...` or `x = ...`
    if re.match(r"^[A-Za-z_][\w.]*(\s*,\s*[A-Za-z_][\w.]*)*\s*:?=", stripped):
        # but `_ = ...` is a discard, not a real capture
        head = stripped.split("=")[0]
        if re.fullmatch(r"[\s_,]*", head):
            return False
        return True
    return False


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

        flagged_lines = set()

        # Explicit `_ =` discard.
        for m in _DISCARD_RE.finditer(body_text):
            ln = engine.line(fn) + body_text[:m.start()].count("\n")
            if ln in flagged_lines:
                continue
            flagged_lines.add(ln)
            hits.append(_hit(engine, fn, name, ln,
                             "discards the error with `_`"))

        # Bare-statement call (no capture at all).
        for m in _BARE_CALL_RE.finditer(body_text):
            seg = body_text[m.start():]
            line = seg.split("\n", 2)[1] if seg.startswith("\n") \
                else seg.split("\n", 1)[0]
            if _line_has_capture(line):
                continue
            ln = engine.line(fn) + body_text[:m.start()].count("\n")
            ln += 1 if body_text[m.start():m.start() + 1] == "\n" else 0
            if ln in flagged_lines:
                continue
            flagged_lines.add(ln)
            hits.append(_hit(engine, fn, name, ln,
                             "calls a fund-moving SDK method as a bare "
                             "statement, ignoring its error return"))
    return hits


def _hit(engine, fn, name, line, why):
    return {
        "severity": "high",
        "line": line,
        "col": engine.col(fn),
        "snippet": engine.text(fn).splitlines()[0][:160],
        "message": (
            f"`{name}` {why}. A swallowed error on a bank/mint/settle call "
            f"lets the handler proceed and emit success while no funds "
            f"moved -> accounting drift. Bind and check the error. "
            f"(class: unchecked-error-return)"),
    }
