"""
r94_loop_nft_royalty_receiver_external_call_reentrancy.py

Flags NFT `buy` / `purchase` fns that call ERC2981
`royaltyInfo` / `get_royalty_info` and then transfer the royalty
fee via a low-level call WITHOUT a reentrancy guard or
before-state-settlement — attacker-controlled royalty receiver
reenters the pool.

Source: Solodit #16243 (Caviar PrivatePool).
Class: nft-royalty-receiver-external-call-reentrancy (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(buy|purchase|sell|swap_nft|exchange_nft)")
_ROYALTY_LOOKUP_RE = re.compile(
    r"(royalty_info|royaltyInfo|get_royalty_info|erc2981::royalty_of)\s*\("
)
_ROYALTY_CALL_RE = re.compile(
    r"royalty_receiver\s*\.\s*(call|transfer|send)\s*\{?|"
    fr"\.call\{{?\s*value\s*:\s*{IDENT}royalty|"
    r"royalty_receiver\.\s*call\s*\("
)
_REENTRANCY_GUARD_RE = re.compile(
    r"non_reentrant|nonReentrant|ReentrancyGuard|reentrancy_lock|reentrancy_guard|"
    r"state_settled_before_call|cei_order\s*=\s*\"checks_effects_interactions\""
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
        if not _ROYALTY_LOOKUP_RE.search(body_nc):
            continue
        if not _ROYALTY_CALL_RE.search(body_nc):
            continue
        if _REENTRANCY_GUARD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` fetches royalty_receiver from "
                f"ERC2981 and transfers via low-level call without "
                f"a reentrancy guard — attacker-controlled receiver "
                f"reenters the pool (nft-royalty-receiver-external-"
                f"call-reentrancy). See Solodit #16243 (Caviar)."
            ),
        })
    return hits
