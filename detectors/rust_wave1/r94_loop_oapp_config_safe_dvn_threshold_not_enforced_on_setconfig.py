"""
r94_loop_oapp_config_safe_dvn_threshold_not_enforced_on_setconfig.py

Flags OApp / UlnConfig setter fns that write a new config without asserting
a safe DVN threshold (requiredDVNCount >= 2 or optionalDVNThreshold >= 1) —
a single-DVN path is accepted silently, enabling a compromised-DVN takeover.

Source: Kelp rsETH exploit (banteg gist).
Class: oapp-config-safe-dvn-threshold-not-enforced-on-setconfig (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(set_config|setConfig|set_send_config|set_receive_config|"
    r"update_uln_config|updateUlnConfig|init_oapp_config|apply_config)"
)
_WRITES_CONFIG_RE = re.compile(
    r"(self\s*\.\s*config\s*=|ulnConfig\s*=|send_config\s*=|"
    r"receive_config\s*=|save_config\s*\(|store_config|"
    r"\bconfig\s*=\s*UlnConfig\s*\{)"
)
_SAFE_THRESHOLD_RE = re.compile(
    fr"(require\s*\(\s*{IDENT}(required_dvn_count|requiredDVNCount)\s*>=?\s*2|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}(required_dvn_count|requiredDVNCount)\s*>=?\s*2|"
    r"MIN_REQUIRED_DVN_COUNT|SAFE_DVN_THRESHOLD|"
    r"assert_safe_dvn_threshold|validateDVNThreshold|"
    fr"require\s*\(\s*{IDENT}(optional_dvn_threshold|optionalDVNThreshold)\s*>=?\s*1)"
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
        if not _WRITES_CONFIG_RE.search(body_nc):
            continue
        if _SAFE_THRESHOLD_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn {name} writes an OApp / UlnConfig without "
                f"asserting requiredDVNCount >= safe threshold (>=2) or "
                f"optionalDVNThreshold >= 1 — a mis-configured single-DVN "
                f"path is accepted silently "
                f"(oapp-config-safe-dvn-threshold-not-enforced-on-setconfig). "
                f"Kelp rsETH $220M exploit."
            ),
        })
    return hits
