"""
r94_loop_layerzero_remote_transfer_caller_supplied_from_unauth_pull.py

Flags cross-chain / LayerZero remote-transfer receive fns that
use a `from` / `owner` parameter supplied by the caller (e.g.
decoded from an unauthenticated input) to pull funds, rather
than reading `from` out of the attested LZ source payload.
Attacker supplies another user's address and drains balance.

Source: Solodit #31064 (Sherlock Tapioca USDO remote transfer).
Class: layerzero-remote-transfer-caller-supplied-from-unauth-pull (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(remote_transfer|cross_chain_transfer|"
    r"receive_remote_transfer|execute_remote_transfer|"
    r"handle_remote_transfer|lz_receive_transfer|"
    r"_credit_to|credit_and_transfer)"
)
# Pulls tokens / balance from `from` / `owner` parameter.
_PULL_RE = re.compile(
    fr"(?i)(\btransfer_from\s*\(|"
    fr"\bburn_from\s*\(\s*{IDENT}from|"
    fr"\b_burn\s*\(\s*{IDENT}from|"
    fr"balances\s*\[\s*{IDENT}from\s*\]\s*-\s*=|"
    fr"decrement_balance\s*\(\s*{IDENT}from|"
    fr"debit\s*\(\s*{IDENT}(from|owner))"
)
# Require a `from` or `owner` parameter in the signature (heuristic: fn body sees `from` identifier).
_FROM_PARAM_RE = re.compile(
    r"(?i)(\bfrom\b|\bowner\b)"
)
# Safe: from is decoded from the LZ payload, or is msg.sender.
_PAYLOAD_BIND_RE = re.compile(
    fr"(?i)(from\s*=\s*decode\w*\s*\(\s*&?\s*payload|"
    fr"let\s+\(\s*{IDENT}from[^\)]*\)\s*=\s*{IDENT}decode\w*\s*\(\s*&?\s*payload|"
    fr"let\s+{IDENT}from\s*=\s*abi_decode\s*\(\s*&?\s*payload|"
    fr"let\s+\(\s*{IDENT}from[^\)]*\)\s*=\s*abi_decode\s*\(\s*&?\s*payload|"
    fr"from\s*=\s*msg\.sender|"
    fr"from\s*=\s*_msgSender\s*\(\s*\)|"
    fr"require\s*\(\s*{IDENT}from\s*==\s*msg\.sender|"
    fr"require\s*\(\s*{IDENT}from\s*==\s*_msgSender|"
    fr"assert_eq\s*!?\s*\(\s*{IDENT}from\s*,\s*{IDENT}caller|"
    fr"read_from_payload|parse_from_payload|"
    fr"abi_decode\s*\([^)]*payload)"
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
        if not _PULL_RE.search(body_nc):
            continue
        if _PAYLOAD_BIND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` pulls tokens from a caller-supplied "
                f"`from` / `owner` parameter instead of decoding it "
                f"from the attested LZ source payload — attacker "
                f"passes another user's address and drains balance "
                f"(layerzero-remote-transfer-caller-supplied-from-unauth-pull). "
                f"See Solodit #31064 (Sherlock Tapioca USDO)."
            ),
        })
    return hits
