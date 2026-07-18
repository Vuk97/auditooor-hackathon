"""
r94_loop_lz_oft_single_dvn_configuration_quorum_bypass.py

Flags LayerZero OApp/OFT config fns that set `required_dvn_count = 1` and
`optional_dvn_count = 0` — a single compromised DVN can attest arbitrary
packets with no quorum defense-in-depth.

Source: Kelp rsETH $220M exploit (2026-04-18, postmortem by banteg).
Class: lz-oft-single-dvn-configuration-quorum-bypass (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(set_config|setConfig|set_send_config|set_receive_config|"
    r"init_oapp_config|configure_dvn|set_dvns)"
)
_SINGLE_DVN_RE = re.compile(
    r"(required_dvn_count\s*(:|=)\s*1\b|"
    r"requiredDVNCount\s*(:|=)\s*1\b|"
    fr"requiredDVNs\s*:\s*{IDENT}\s*\[\s*\w+\s*\]\s*\/\/\s*len\s*=\s*1|"
    r"requiredDVNCount\s*=\s*uint8\s*\(\s*1\s*\)|"
    r"confirmations\s*:\s*0)"
)
_OPTIONAL_ZERO_RE = re.compile(
    r"(optional_dvn_count\s*(:|=)\s*0\b|"
    r"optionalDVNCount\s*(:|=)\s*0\b|"
    r"optional_dvn_threshold\s*(:|=)\s*0\b)"
)
_QUORUM_OVERRIDE_RE = re.compile(
    r"(multiSigGate|"
    r"require_dvn_count\s*(:|=)\s*(2|3|4|5)|"
    r"optional_dvn_threshold\s*(:|=)\s*[1-9]|"
    r"TIMELOCK|multisig_config)"
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
        if not _SINGLE_DVN_RE.search(body_nc):
            continue
        if not _OPTIONAL_ZERO_RE.search(body_nc):
            continue
        if _QUORUM_OVERRIDE_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} configures a LayerZero OApp with "
                f"requiredDVNCount=1 and optionalDVNCount=0 — a single "
                f"compromised DVN can attest arbitrary packets, no quorum "
                f"defense-in-depth "
                f"(lz-oft-single-dvn-configuration-quorum-bypass). "
                f"Kelp rsETH $220M exploit 2026-04-18."
            ),
        })
    return hits
