"""
r94_loop_user_supplied_domain_separator_cross_chain_replay.py

Flags pub fns that accept a caller-supplied `domain_separator`
parameter instead of using a hardcoded / chain-id-bound domain —
attacker passes another chain's domain to replay a signature.

Source: Solodit #56703 (Code4rena Next Generation Forwarder).
Class: user-supplied-domain-separator-cross-chain-replay (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(forward|execute_meta|executeMeta|"
    r"relayed_forward|permit_and_call|meta_tx_call)"
)
_USER_DOMAIN_RE = re.compile(
    r"(domain_separator\s*:\s*(\w+|\[u8;\s*32\]|bytes32|BytesN<32>)|"
    r"domainSeparator\s*:\s*(\w+|\[u8;\s*32\]|bytes32)|"
    r"ds\s*:\s*bytes32|"
    r"domain_sep\s*:\s*\[u8;\s*32\])"
)
_HARDCODED_DOMAIN_RE = re.compile(
    r"(DOMAIN_SEPARATOR\s*\(\s*\)|"
    r"_domainSeparatorV4\s*\(\s*\)|"
    r"self\.domain_separator\s*\(\s*\)|"
    r"self\.eip712_domain|"
    fr"block\.chainid\s*==\s*{IDENT}cached)"
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
        # Full fn text (signature + body) for param detection
        fn_text = source[fn.start_byte:fn.end_byte].decode('utf8', errors='replace')
        if not _USER_DOMAIN_RE.search(fn_text):
            continue
        body_nc = body_text_nocomment(body, source)
        if _HARDCODED_DOMAIN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} accepts a caller-supplied "
                f"domain_separator parameter instead of using a "
                f"hardcoded / chain-id-bound domain — attacker passes "
                f"another chain's domain to replay a signature "
                f"(user-supplied-domain-separator-cross-chain-replay). "
                f"See Solodit #56703 (Code4rena Next Generation Forwarder)."
            ),
        })
    return hits
