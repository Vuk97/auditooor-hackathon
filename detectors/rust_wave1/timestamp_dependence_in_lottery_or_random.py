"""
timestamp_dependence_in_lottery_or_random.py

Flags fns whose name suggests randomness / lottery / raffle / winner
selection and whose body derives an output from `env.ledger().timestamp()`,
`env.ledger().sequence()`, or `env.prng()` without a commit-reveal scheme
or VRF.

Heuristic:
  1. fn name contains one of: `random`, `lottery`, `raffle`, `winner`,
     `jackpot`, `pick_`, `seed_`, `draw_`, `roll_`.
  2. Body references `ledger().timestamp()` or `ledger().sequence()` in a
     computation (assigned to a variable or used inside `%`, `/`, `>>`,
     `as` cast).
  3. Body has NO mention of `commit`, `reveal`, `vrf`, `oracle_rng`.
"""

from __future__ import annotations

import re

from _util import (
    function_items, fn_body, fn_name, text_of, walk_no_nested_fn,
    line_col, snippet_of, in_test_cfg,
)


_NAME_HINTS = ("random", "lottery", "raffle", "winner", "jackpot",
               "pick_", "seed_", "draw_", "roll_")

_TIME_PATTERNS = (
    r"ledger\s*\(\s*\)\s*\.\s*timestamp\s*\(\s*\)",
    r"ledger\s*\(\s*\)\s*\.\s*sequence\s*\(\s*\)",
    r"env\s*\.\s*prng\s*\(\s*\)",
)

_MITIGATION = ("commit", "reveal", "vrf", "oracle_rng", "Randao")


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        name = fn_name(fn, source)
        if not any(h in name for h in _NAME_HINTS):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)
        if not any(re.search(p, body_text) for p in _TIME_PATTERNS):
            continue
        if any(m in body_text for m in _MITIGATION):
            continue

        # locate a node
        target = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            t = text_of(n, source)
            if any(re.search(p, t) for p in _TIME_PATTERNS):
                target = n
                break
        if target is None:
            continue
        line, col = line_col(target)
        hits.append({
            "severity": "med",
            "line": line,
            "col": col,
            "snippet": snippet_of(target, source),
            "message": (
                f"fn `{name}` derives randomness from ledger timestamp/"
                f"sequence — miner/sequencer can predict or grind the "
                f"output (no commit-reveal/VRF seen)."
            ),
        })
    return hits
