"""
cosmos_genesis_missing_validation.py

Detects module `InitGenesis` functions that consume genesis-state fields
(write params, set balances, register markets) WITHOUT first calling the
genesis `Validate()` / `ValidateGenesis()` invariant check.

Cosmos-sdk modules define a `GenesisState` with a `Validate()` method that
enforces structural invariants (no duplicate IDs, non-negative balances,
well-formed addresses, params in range). `InitGenesis` MUST call it before
writing any field to the store. A chain that starts (or upgrades) from a
malformed genesis can corrupt module state at block 0, and because the
malformed value is now consensus state, recovery requires a coordinated
hardfork.

The safe pattern calls validation up front:
    if err := genState.Validate(); err != nil { panic(err) }

Bug class: HIGH/CRITICAL (genesis-state-injection -> corrupt chain start).
Attack-class anchor: zero-coverage class `genesis-state-injection`
("Malformed genesis state injected to compromise chain startup").
Platform: cosmos-sdk app-chains (dYdX, Osmosis, Sei, Spark coordinator).
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.cosmos_genesis_missing_validation"

# InitGenesis-shaped function names.
_INIT_GENESIS_RE = re.compile(r"^InitGenesis$|InitGenesis$")

# The handler consumes genesis fields by writing module state.
_CONSUMES_GENESIS_RE = re.compile(
    r"(\.Set[A-Za-z]*\s*\(|store\.Set|\.SetParams\s*\("
    r"|genState\.|genesisState\.|gs\.|data\.[A-Z])"
)

# Evidence the genesis was validated before consumption.
_VALIDATE_RE = re.compile(
    r"(\.Validate\s*\(\s*\)"
    r"|ValidateGenesis\s*\("
    r"|\.ValidateBasic\s*\(\s*\)"
    r"|validateGenesis\s*\()"
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        if not _INIT_GENESIS_RE.search(name):
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        # Must actually consume genesis state.
        if not _CONSUMES_GENESIS_RE.search(body_text):
            continue
        if _VALIDATE_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` writes module state from genesis fields without "
                f"calling genState.Validate() first. A malformed genesis "
                f"corrupts module state at block 0; the bad value becomes "
                f"consensus state and recovery needs a hardfork. Validate "
                f"genesis before consuming it. "
                f"(class: genesis-state-injection)"),
        })
    return hits
