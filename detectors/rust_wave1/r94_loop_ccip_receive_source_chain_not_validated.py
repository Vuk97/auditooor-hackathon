"""
r94_loop_ccip_receive_source_chain_not_validated.py

Flags CCIP/xchain receive handlers (_ccip_receive, handle_ccip,
receive_any2evm) that process Any2EVMMessage without validating
`source_chain_selector` against an allowlist.

Source: Solodit #55536 (Cyfrin YieldFi BridgeCCIP).
Class: ccip-receive-source-chain-not-validated (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(ccip_receive|_ccip_receive|handle_ccip|receive_any2evm|receive_ccip)")
_USES_MESSAGE_RE = re.compile(
    r"(any2evm_message|message\.data|message\.sender|message\.sourceChain)"
)
_CHAIN_CHECK_RE = re.compile(
    r"(source_chain_selector|sourceChainSelector|source_chain)\s*(==|!=)|"
    r"allowed_chain\s*\(|is_allowed_chain|chain_allowlist\s*\.\s*contains|"
    r"approved_chain\s*\(|source_chain_allow"
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
        if not _USES_MESSAGE_RE.search(body_nc):
            continue
        if _CHAIN_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` handles CCIP/xchain message without "
                f"validating source_chain_selector against an "
                f"allowlist — attacker sends from cheap side-chain "
                f"(ccip-receive-source-chain-not-validated). See "
                f"Solodit #55536 (YieldFi)."
            ),
        })
    return hits
