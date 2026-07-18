"""
r94_loop_stargate_mtoft_native_rebalance_sgrecieve_missing.py

Flags mTOFT / Stargate rebalance fns that transfer native ETH
cross-chain (stargateRouter.swap / sendNative) but do NOT invoke
`sgReceive` (or equivalent composer callback) on arrival. The
native value sits unowned in the destination contract and is
sweepable by any caller of an unauthenticated wrap / donate path.

Source: Solodit #31060 (Sherlock Tapioca mTOFT rebalancing).
Class: stargate-mtoft-native-rebalance-sgrecieve-missing (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(rebalance|send_to_eid|cross_chain_rebalance|"
    r"bridge_native|bridge_eth|rebalance_native|"
    r"transfer_to_dst_chain|cross_chain_sweep)"
)
_NATIVE_SEND_RE = re.compile(
    r"(?i)(stargate_router\.swap|stargate\.swap|"
    r"sendNative|send_native|"
    r"router\s*\.\s*swap\s*\{\s*value\s*:|"
    fr"send_with_value|payable\s*\(\s*{IDENT}router\s*\)|"
    r"lz_compose_send|lzComposeSend)"
)
_SG_RECEIVE_BIND_RE = re.compile(
    r"(?i)(sg_receive|sgReceive|lz_compose|lzCompose|"
    r"compose_message|composeMessage|"
    r"onReceive|on_receive|attach_composer|composer_addr)"
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
        if not _NATIVE_SEND_RE.search(body_nc):
            continue
        if _SG_RECEIVE_BIND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` bridges native ETH cross-chain via "
                f"Stargate / LayerZero Compose without attaching an "
                f"sgReceive / lzCompose callback — native value sits "
                f"unowned at destination, sweepable by any caller of "
                f"an unauthenticated wrap/donate path "
                f"(stargate-mtoft-native-rebalance-sgrecieve-missing). "
                f"See Solodit #31060 (Sherlock Tapioca mTOFT)."
            ),
        })
    return hits
