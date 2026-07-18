"""
r94_loop_htlc_reward_overwrite.py

Flags HTLC lock_reward fns that unconditionally write the reward field
without preserving / checking any previously-locked reward.

Source: Hexens Train Protocol LYSWP2-family.
Class: htlc-reward-overwrite (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name,
    text_of, line_col, snippet_of, is_pub,
    body_text_nocomment,
)

_FN_NAME_RE = re.compile(r"(?i)(lock_?reward|set_?reward|update_?reward|add_?reward)")
_WRITE_RE = re.compile(
    r"\.reward\s*=\s*\w|lock\.reward\s*=\s*\w|"
    r"store_reward\s*\(|set_reward\s*\(|\.set\s*\([^)]*reward"
)
_PRESERVE_CHECK_RE = re.compile(
    r"\.reward\s*==\s*(0|None|\[0)|\.reward\.is_none|"
    r"require!?\s*\([^)]*\.reward\s*(==|\.is_none)|"
    r"if\s+\w+\.reward\s*(==|is_none)|"
    r"previous_reward|prev_reward|existing_reward|current_reward"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node
    for fn, _impl in functions_in_contractimpl(root, source):
        if not is_pub(fn, source):
            continue
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _WRITE_RE.search(body_nc):
            continue
        if _PRESERVE_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` writes `lock.reward = ...` without "
                f"checking / preserving any previously-locked reward. "
                f"Second call overwrites prior LP reward. See Hexens "
                f"Train Protocol."
            ),
        })
    return hits
