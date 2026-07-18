"""
r94_loop_nonblocking_lzapp_channel_block_via_receive_precheck_revert.py

Flags NonblockingLzApp-style lzReceive / _blockingLzReceive fns
that perform pre-try invariant checks (require! / assert / panic)
*before* entering the try-catch / `catch_unwind` boundary. If the
pre-check reverts, the outer channel hits an uncaught revert and
is bricked — the whole point of NonblockingLzApp is that each
message failure stays isolated.

Source: Solodit #36451 (Pashov Honeyjar HoneyJarONFT).
Class: nonblocking-lzapp-channel-block-via-receive-precheck-revert (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(
    r"(?i)(lz_receive|lzReceive|"
    r"_blocking_lz_receive|_blockingLzReceive|"
    r"_nonblocking_lz_receive|_nonblockingLzReceive)"
)
# Must have a require!/assert/panic at the top (pre-try).
_PRE_CHECK_RE = re.compile(
    r"^\s*(require\s*\(|require!\s*\(|assert!\s*\(|panic\s*!\s*\()",
    re.MULTILINE,
)
# Safe: the body wraps work in try / catch_unwind / .ok() pattern.
_TRY_CATCH_RE = re.compile(
    r"(?i)(try\s*\{|catch_unwind|"
    r"\.\s*ok\s*\(\s*\)|"
    r"match\s+\w+\s*\(\s*\)\s*\{\s*Ok\s*\(|"
    r"catch\s+\w+\s*\{|"
    r"try_lz_receive)"
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
        if not _PRE_CHECK_RE.search(body_nc):
            continue
        if _TRY_CATCH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` performs a require / assert / panic "
                f"pre-check before any try-catch boundary — a revert "
                f"escapes the non-blocking guard and bricks the LZ "
                f"channel "
                f"(nonblocking-lzapp-channel-block-via-receive-precheck-revert). "
                f"See Solodit #36451 (Pashov Honeyjar HoneyJarONFT)."
            ),
        })
    return hits
