"""
r94_governance_execute_no_timelock.py

Flags governance `execute` / `execute_proposal` / `run_action` fns that
dispatch the proposal body (invoke_contract, transfer, upgrade) without
any eta / delay / ready_at timestamp check.  A passing proposal is
then executed instantly, skipping the social review window.

Maps to Solidity:
  - governance-execute-no-timelock-delay
  - timelock-immediate-execute
  - sharedstake-timelock-call-allows-approve-bypass
  - glider-timelock-operation-ready-missing

Heuristic:
  - fn name contains `execute`, `run`, `dispatch`, `fire`, `trigger`
    AND body contains `proposal` or `operation` or `action` or `queue`.
  - Body makes an external / upgrade / invoke call.
  - Body does NOT compare `env.ledger().timestamp()` against a stored
    `eta` / `ready_at` / `delay` / `unlock_time` / `execute_after`.
  - Body does NOT contain any of the delay tokens.
"""

from __future__ import annotations

import re

from _util import (
    functions_in_contractimpl, fn_body, fn_name, is_pub, text_of,
    walk_no_nested_fn, line_col, snippet_of,
)


_EXEC_RE = re.compile(
    r"(^|_)(execute|run|dispatch|fire|trigger)(_|$)",
    re.IGNORECASE,
)

_GOV_TOKENS = ("proposal", "operation", "Proposal", "Operation",
               "action", "Action", "queue", "Queue")

_DELAY_TOKENS = ("eta", "ready_at", "ready_ts", "delay", "unlock_time",
                 "execute_after", "exec_after", "min_delay", "timelock",
                 "Timelock", "TIMELOCK", "MIN_DELAY", "grace_period")

_EXTERNAL_RE = re.compile(
    r"\.invoke_contract\s*\(|try_invoke_contract\s*\(|"
    r"[A-Za-z_][A-Za-z0-9_]*Client\s*::\s*new\s*\(|"
    r"::\s*Client\s*::\s*new\s*\(|"
    r"\.update_current_contract_wasm\s*\(|"
    r"\.upgrade\s*\("
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _EXEC_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_text = text_of(body, source)

        if not any(tok in body_text for tok in _GOV_TOKENS):
            continue
        if not _EXTERNAL_RE.search(body_text):
            continue

        # If any delay token is present, caller already has a timelock.
        if any(tok in body_text for tok in _DELAY_TOKENS):
            continue
        # Comparison of ledger timestamp against something? Could be a
        # custom delay. Only bail out on a strict comparison operator
        # surrounding `ledger().timestamp()`.
        if re.search(
            r"ledger\s*\(\s*\)\s*\.\s*timestamp\s*\(\s*\)\s*[<>]",
            body_text,
        ):
            continue

        # Locate the external call node for line info.
        ext_node = None
        for n in walk_no_nested_fn(body):
            if n.type != "call_expression":
                continue
            if _EXTERNAL_RE.search(text_of(n, source)):
                ext_node = n
                break
        if ext_node is None:
            continue

        line, col = line_col(ext_node)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(ext_node, source),
            "message": (
                f"governance fn `{name}` dispatches a proposal / operation "
                f"with no `eta` / `delay` / `ready_at` timestamp check — "
                f"passes execute instantly, bypassing the timelock review "
                f"window."
            ),
        })
    return hits
