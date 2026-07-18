"""
initializer_first_caller_config_takeover.py

Flags public Rust setup, register, configure, or migrate entrypoints that
write long-lived bridge route, chain, gateway, or peer configuration while
lacking caller authorization. If the function accepts both source and
destination chain identifiers, it also expects a same-chain rejection guard.

Class: initializer-front-run / first-caller route config takeover.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
    text_of,
)


_FN_NAME_RE = re.compile(
    r"(?i)("
    r"^(?:init|initialize|setup|configure|register|create|add|migrate)"
    r"(?:_|[a-z0-9])*"
    r"(?:route|path|chain|gateway|bridge|lane|peer|remote|config|owner|admin)"
    r"|^(?:set_peer|set_counterpart|set_remote_gateway|set_remote_bridge|"
    r"set_trusted_remote|configure_route|setup_route|register_route|"
    r"register_chain|add_chain|create_chain|migrate_to_gateway|"
    r"migrate_chain_to_gateway|initialize_gateway)$"
    r")"
)

_BRIDGE_CONFIG_CONTEXT_RE = re.compile(
    r"(?i)\b(bridge|gateway|route|path|chain|lane|remote|peer|"
    r"trusted_remote|registry|config)\b"
)

_SOURCE_CHAIN_RE = re.compile(
    r"(?i)\b(?:source|src|origin|from)[a-z0-9_]*(?:chain|domain|id)[a-z0-9_]*\b"
)

_DEST_CHAIN_RE = re.compile(
    r"(?i)\b(?:destination|dest|dst|remote|target|to)[a-z0-9_]*"
    r"(?:chain|domain|id)[a-z0-9_]*\b"
)

_CONFIG_WRITE_RE = re.compile(
    r"(?is)("
    r"(?:\b\w+\s*\.\s*)?\w*(?:rout|gateway|chain|peer|remote|registry|config)\w*"
    r"\s*\.\s*(?:insert|set|push)\s*\("
    r"|self\s*\.\s*\w*(?:rout|gateway|chain|peer|remote|registry|"
    r"config|owner|admin|authority)\w*\s*="
    r"|storage\s*\(\s*\)\s*\.\s*(?:persistent|instance)\s*\(\s*\)"
    r"\s*\.\s*set\s*\("
    r")"
)

_AUTH_GUARD_RE = re.compile(
    r"(?is)("
    r"\.require_auth\s*\(|require_auth\s*\(|require_admin\s*\(|"
    r"require_owner\s*\(|ensure_?(?:owner|admin|governance|governor|"
    r"factory|deployer)\s*\(|assert_?(?:owner|admin)\s*\(|"
    r"check_?(?:owner|admin|role)\s*\(|has_role\s*\(|"
    r"only_?(?:owner|admin|governance|governor|factory|deployer)|"
    r"(?:caller|sender|invoker|env\.invoker\s*\(\s*\)|ctx\.sender\s*\(\s*\))"
    r"\s*==\s*(?:owner|admin|governance|governor|factory|deployer)|"
    r"(?:owner|admin|governance|governor|factory|deployer)\s*==\s*"
    r"(?:caller|sender|invoker|env\.invoker\s*\(\s*\)|ctx\.sender\s*\(\s*\))"
    r")"
)

_SAME_CHAIN_GUARD_RE = re.compile(
    r"(?is)("
    r"assert_ne!\s*\(\s*[^,;{}]*(?:source|src|origin|from)[^,;{}]*,\s*"
    r"[^,;{}]*(?:destination|dest|dst|remote|target|to)"
    r"|(?:source|src|origin|from)[a-z0-9_]*(?:chain|domain|id)[a-z0-9_]*"
    r"\s*!=\s*(?:destination|dest|dst|remote|target|to)[a-z0-9_]*"
    r"(?:chain|domain|id)[a-z0-9_]*"
    r"|(?:destination|dest|dst|remote|target|to)[a-z0-9_]*(?:chain|domain|id)"
    r"[a-z0-9_]*\s*!=\s*(?:source|src|origin|from)[a-z0-9_]*"
    r"(?:chain|domain|id)[a-z0-9_]*"
    r"|(?:source|src|origin|from)[a-z0-9_]*(?:chain|domain|id)[a-z0-9_]*"
    r"\s*==\s*(?:destination|dest|dst|remote|target|to)[a-z0-9_]*"
    r"(?:chain|domain|id)[a-z0-9_]*[^;{}]{0,120}"
    r"(?:return\s+Err|panic!|bail!|ensure!|SameChain|InvalidSameChain)"
    r"|SameChain|InvalidSameChain"
    r")"
)

_FIRST_WRITE_GUARD_RE = re.compile(
    r"(?is)("
    r"contains_key\s*\(|\.has\s*\(|\.get\s*\([^;{}]{0,160}\)\s*"
    r"\.\s*is_(?:none|some)\s*\(|is_empty\s*\(|len\s*\(\s*\)\s*==\s*0|"
    r"already_(?:initialized|registered)|route_exists|not_registered|"
    r"initialized|registered|created"
    r")"
)


def run(tree, source: bytes, filepath: str):  # noqa: ARG001
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        fn_text = text_of(fn, source)
        body_nc = body_text_nocomment(body, source)
        if not _BRIDGE_CONFIG_CONTEXT_RE.search(fn_text):
            continue
        if not _CONFIG_WRITE_RE.search(body_nc):
            continue
        if _AUTH_GUARD_RE.search(body_nc):
            continue

        has_source_dest = bool(_SOURCE_CHAIN_RE.search(fn_text) and _DEST_CHAIN_RE.search(fn_text))
        missing_same_chain_guard = has_source_dest and not _SAME_CHAIN_GUARD_RE.search(body_nc)
        has_first_write_guard = bool(_FIRST_WRITE_GUARD_RE.search(body_nc))
        if not (missing_same_chain_guard or has_first_write_guard):
            continue

        reasons = ["no caller authorization"]
        if missing_same_chain_guard:
            reasons.append("no same-chain route rejection")
        if has_first_write_guard:
            reasons.append("first-write route guard only")

        line, col = line_col(fn)
        hits.append(
            {
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source, 220),
                "message": (
                    f"pub fn `{name}` writes bridge route, chain, or gateway "
                    f"configuration with {', '.join(reasons)}. A first caller "
                    f"can claim or wedge the route namespace before the intended "
                    f"initializer runs."
                ),
            }
        )

    return hits
