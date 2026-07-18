"""
r94_loop_cosmwasm_reply_handler_missing.py

Flags CosmWasm contracts that construct a `SubMsg` with
`ReplyOn::Always` / `ReplyOn::Success` / `ReplyOn::Error` but the
source file does NOT define a `reply(...)` entry point. Without
the reply handler, the contract silently ignores submsg outcomes.

Class: cosmwasm-reply-handler-missing (rust_only).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_REPLY_ON_RE = re.compile(r"ReplyOn::(Always|Success|Error)|reply_on\s*:\s*ReplyOn::(Always|Success|Error)")
_REPLY_ENTRY_RE = re.compile(
    r"#\[cfg_attr\s*\([^)]*\)\]\s*pub\s+fn\s+reply\s*\(|"
    r"#\[entry_point\]\s*pub\s+fn\s+reply\s*\(|"
    r"pub\s+fn\s+reply\s*\(\s*deps:\s*DepsMut",
    re.MULTILINE,
)


def run(tree, source: bytes, filepath: str):
    hits = []
    source_str = source.decode("utf8", errors="replace")

    reply_on_sites = list(_REPLY_ON_RE.finditer(source_str))
    if not reply_on_sites:
        return hits
    if _REPLY_ENTRY_RE.search(source_str):
        return hits

    # Emit one hit at the first ReplyOn site
    first = reply_on_sites[0]
    # Approximate line number
    prefix = source_str[:first.start()]
    line = prefix.count("\n") + 1
    hits.append({
        "severity": "high",
        "line": line,
        "col": 0,
        "snippet": first.group(0)[:80],
        "message": (
            f"source file constructs `SubMsg` with `{first.group(0)}` "
            f"but defines no `reply(deps, env, msg)` entry point. "
            f"Contract silently ignores submsg outcomes — partial "
            f"execution / state drift on submsg failure."
        ),
    })
    return hits
