"""
r94_loop_callback_63_64_gas_rule_bypass_stuck_withdraw.py

Flags finalize / process_withdrawal / finalize_withdrawal fns that
forward caller-supplied `gas_limit` / `callback_gas` to an external
call WITHOUT reserving a stipend (≥ gasleft() / 64) for post-call
resumption — attacker picks limit that leaves the finalize path
stuck.

Source: Solodit #6495 (Optimism Portal).
Class: callback-63-64-gas-rule-bypass-stuck-withdraw (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(r"(?i)(finalize_withdrawal|process_withdrawal|execute_withdrawal|prove_withdrawal|finalize_\w+)")
_FORWARDS_GAS_RE = re.compile(
    fr"(\.call\{{\s*gas\s*:\s*{IDENT}(gas_limit|callback_gas)|"
    fr"invoke_with_gas\s*\([^)]*\b(gas_limit|callback_gas)\b|"
    fr"env\.invoke_contract_with_gas\s*\([^)]*\b(gas_limit|callback_gas)\b)"
)
_STIPEND_RESERVE_RE = re.compile(
    fr"(gasleft\s*\(\s*\)\s*\*\s*63\s*/\s*64|"
    fr"MIN_FINALIZE_GAS|"
    fr"gasleft\s*\(\s*\)\s*-\s*{IDENT}finalize_reserve|"
    fr"require\s*\(\s*gasleft\s*\(\s*\)\s*>\s*{IDENT}gas_limit\s*\*\s*64\s*/\s*63)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _FORWARDS_GAS_RE.search(body_nc):
            continue
        if _STIPEND_RESERVE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` forwards caller-supplied gas_limit "
                f"to external call without reserving 63/64-rule "
                f"stipend for post-call resumption — attacker picks "
                f"limit that sticks the finalize (callback-63-64-gas-"
                f"rule-bypass-stuck-withdraw). See Solodit #6495 "
                f"(Optimism Portal)."
            ),
        })
    return hits
