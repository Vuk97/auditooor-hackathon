"""
r94_loop_bridge_receive_message_conditional_auth_missing.py

Flags receive_message fns whose sender authorization is inside a
conditional branch (`if threshold == 1 { require_sender(...) }`)
— other branches accept any external caller.

Source: Solodit #52248 (Lucid Labs AssetController).
Class: bridge-receive-message-conditional-auth-missing (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(receive_message|on_message|handle_message|relay_message)")
_CONDITIONAL_AUTH_RE = re.compile(
    r"if\s+\w+\.(threshold|role|kind)\s*==\s*\w+\s*\{[^}]*?(require_auth|require_sender|only_relayer|allowed_sender)",
    re.DOTALL,
)
_UNCONDITIONAL_AUTH_RE = re.compile(
    r"\A\s*(require_auth\s*\(|only_relayer\s*\(|require\s*\(\s*sender|assert[!_]?\s*\(\s*msg\s*\.\s*sender)"
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
        if not _CONDITIONAL_AUTH_RE.search(body_nc):
            continue
        # if an unconditional early-require is the FIRST statement, treat as safe
        if _UNCONDITIONAL_AUTH_RE.search(body_nc.split("{", 1)[-1].lstrip()):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` authorizes sender only inside a "
                f"conditional branch — other branches accept any "
                f"external caller (bridge-receive-message-conditional-"
                f"auth-missing). See Solodit #52248 (Lucid Labs)."
            ),
        })
    return hits
