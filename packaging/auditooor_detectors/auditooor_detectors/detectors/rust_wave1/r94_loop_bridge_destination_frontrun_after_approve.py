"""
r94_loop_bridge_destination_frontrun_after_approve.py

Flags bridge fns that accept a caller-supplied destination address
+ an NFT/token ID AND call transferFrom(owner, …) where `owner` is
derived from an external lookup (not from the caller identity) —
attacker frontruns the owner's approve with own destination address.

Source: Solodit #50956 (Halborn Gains Trade NFTMintingBridge).
Class: bridge-destination-frontrun-after-approve (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(bridge_nft|bridge_token|send_bridge|transfer_and_bridge|bridge_mint)")
_SIG_DEST_PARAM_RE = re.compile(
    r"fn\s+\w+\s*\([^)]*\b(destination|dest|receiver|to|target_address|dest_addr)\s*:"
)
_TRANSFER_FROM_OWNER_RE = re.compile(
    r"\.transfer_from\s*\(\s*(owner|token_owner|nft_owner|current_owner)|"
    r"transferFrom\s*\(\s*(owner|tokenOwner|nftOwner|currentOwner)|"
    r"owner_of\s*\(\s*\w+\s*\)[\s,]"
)
_CALLER_BOUND_RE = re.compile(
    r"require_auth\s*\(\s*owner|msg_sender\s*\(\s*\)\s*==\s*owner|"
    r"env\.invoker\s*\(\s*\)\s*==\s*owner|"
    r"assert[!_]?eq\s*\(\s*caller\s*,\s*owner"
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
        sig_text = snippet_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _SIG_DEST_PARAM_RE.search(sig_text):
            continue
        if not _TRANSFER_FROM_OWNER_RE.search(body_nc):
            continue
        if _CALLER_BOUND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": sig_text[:200],
            "message": (
                f"pub fn `{name}` takes a caller-supplied destination "
                f"address and moves the NFT from `owner` without "
                f"binding caller == owner — attacker frontruns with "
                f"own destination (bridge-destination-frontrun-after-"
                f"approve). See Solodit #50956 (Gains Trade)."
            ),
        })
    return hits
