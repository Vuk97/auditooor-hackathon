"""
r94_loop_bridge_generic_call_arbitrary_target.py

Flags bridge/swap facet fns that accept a user-supplied (target,
calldata) pair and forward it via low-level invoke/call without
allow-listing the target — attacker calls token.transferFrom(victim,
attacker, allowance) through the bridge.

Source: Solodit #7040 (LI.FI GenericBridgeFacet).
Class: bridge-generic-call-arbitrary-target (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(swap_and_bridge|bridge|swap_generic|start_bridge|generic_bridge|execute_swap)")
_ARB_CALL_RE = re.compile(
    r"\.invoke_contract\s*\(|\.call\s*\(|env\.invoke_contract|env\.invoke|"
    r"dispatch_call\s*\(|dyn_invoke\s*\("
)
_USES_USER_TARGET_RE = re.compile(
    r"(target|callee|dest_contract|bridge_target|to_contract)\s*:\s*\w+|"
    r"invoke_contract\s*\(\s*(target|callee|dest|bridge_target|to_contract)\b|"
    r"\.call\s*\(\s*(target|callee|dest|bridge_target|to_contract)\b|"
    r"\.invoke_contract\s*\(\s*(target|callee|dest|bridge_target|to_contract)\b"
)
_ALLOWLIST_RE = re.compile(
    r"(allow_?list|whitelist|is_approved|approved_target|target_allowed|"
    r"allowed_target|is_valid_target)"
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
        if not _ARB_CALL_RE.search(body_nc):
            continue
        if not _USES_USER_TARGET_RE.search(body_nc):
            continue
        if _ALLOWLIST_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` forwards user-supplied target + "
                f"calldata via invoke/call with no target allowlist "
                f"— attacker calls token.transferFrom(victim, attacker, "
                f"allowance) through the bridge "
                f"(bridge-generic-call-arbitrary-target). See "
                f"Solodit #7040 (LI.FI)."
            ),
        })
    return hits
