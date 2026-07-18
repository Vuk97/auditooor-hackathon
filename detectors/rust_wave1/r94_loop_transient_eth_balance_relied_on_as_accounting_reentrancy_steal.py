"""
r94_loop_transient_eth_balance_relied_on_as_accounting_reentrancy_steal.py

Flags swap / trade fns that compute a refund / payout using
`address(this).balance` / `env.current_contract_balance()` while
ETH is only transiently held during the tx. Attacker's callback
re-enters a second trade that observes the transient ETH and
walks away with it.

Source: Solodit #13577 (ConsenSys 0x Exchange v4 MetaTransactionsFeature).
Class: transient-eth-balance-relied-on-as-accounting-reentrancy-steal (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(sell_to_liquidity_provider|sellToLiquidityProvider|"
    r"fill_meta_transaction|fillMetaTransaction|"
    r"execute_meta_transaction|executeMetaTransaction|"
    r"swap_native|fill_order_native|refund_native)"
)
_TRANSIENT_BALANCE_RE = re.compile(
    r"(?i)(address\s*\(\s*this\s*\)\s*\.\s*balance|"
    r"env\s*\.\s*current_contract_balance\s*\(\s*\)|"
    r"self\s*\.\s*balance\s*\(\s*\)|"
    r"self_balance\s*\(\s*\)|"
    r"this\s*\.\s*balance)"
)
_GUARD_RE = re.compile(
    r"(?i)(non_reentrant|nonReentrant|reentrancy_guard|"
    r"_status\s*=\s*ENTERED|mutex|"
    r"balance_before\s*=|balanceBefore\s*=|"
    r"transient_lock|transient_accounting|"
    r"exactMsgValue|exact_msg_value|"
    r"track_entered_eth)"
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
        if not _TRANSIENT_BALANCE_RE.search(body_nc):
            continue
        if _GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reads `address(this).balance` for "
                f"refund / payout accounting while ETH is transiently "
                f"held — without a reentrancy guard, attacker's "
                f"callback re-enters a second trade and observes the "
                f"transient ETH "
                f"(transient-eth-balance-relied-on-as-accounting-reentrancy-steal). "
                f"See Solodit #13577 (ConsenSys 0x v4 MetaTransactionsFeature)."
            ),
        })
    return hits
