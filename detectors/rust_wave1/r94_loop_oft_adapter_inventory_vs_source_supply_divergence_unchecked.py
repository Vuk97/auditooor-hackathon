"""
r94_loop_oft_adapter_inventory_vs_source_supply_divergence_unchecked.py

Flags OFT/bridge adapter fns that release tokens from locked inventory on
receipt of a cross-chain message without asserting the global cross-chain
supply invariant (adapter_locked + destination_minted ==
canonical_source_locked + distributed). Divergence between adapter inventory
and source-chain supply goes undetected, allowing forged / replayed /
desynced messages to drain the adapter.

Source: Kelp rsETH exploit (banteg gist).
Class: oft-adapter-inventory-vs-source-supply-divergence-unchecked (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|_lz_receive|_lzReceive|"
    r"release_from_inventory|releaseFromInventory|"
    r"credit_to|_credit_to|"
    r"settle_oft_message|settleOftMessage)"
)
_RELEASE_RE = re.compile(
    r"(safe_transfer\s*\(|safeTransfer\s*\(|"
    r"token\.transfer\s*\(|underlying\.transfer\s*\(|"
    r"adapter_balance\s*-=|inventory\s*-=|"
    fr"balance_of\s*\(\s*{IDENT}self)"
)
_INVARIANT_CHECK_RE = re.compile(
    r"(source_locked_supply|sourceLockedSupply|"
    r"global_supply_invariant|globalSupplyInvariant|"
    r"source_total_supply_query|sourceTotalSupplyQuery|"
    r"light_client_root_matches|lightClientRootMatches|"
    r"verify_source_total_locked|"
    r"crossChainSupplyReconciliation|crossChainInvariantCheck|"
    r"assert_supply_invariant|assertSupplyInvariant|"
    r"validate_cross_chain_accounting)"
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
        if not _RELEASE_RE.search(body_nc):
            continue
        if _INVARIANT_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} releases tokens from adapter inventory "
                f"without asserting the global cross-chain supply "
                f"invariant (adapter locked + destination minted == "
                f"canonical source locked + distributed) — adapter "
                f"drift undetected "
                f"(oft-adapter-inventory-vs-source-supply-divergence-unchecked). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits
