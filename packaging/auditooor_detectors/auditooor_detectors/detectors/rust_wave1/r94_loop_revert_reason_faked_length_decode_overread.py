"""
r94_loop_revert_reason_faked_length_decode_overread.py

Flags error-handling fns that decode revert data via `abi.decode` /
`decode_as_string` without first verifying the length prefix is
plausible — attacker crafts bytes with a length >> real payload,
decoder reads past buffer.

Source: Solodit #18634 (Sherlock GMX).
Class: revert-reason-faked-length-decode-overread (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(decode_reason|parse_revert|handle_revert|process_revert|on_callback_fail)")
_DECODE_UNSAFE_RE = re.compile(
    r"abi\.decode\s*\(\s*(reason|data|revert_data)\s*,\s*\(\s*string|"
    r"decode_string\s*\(\s*(reason|data|revert_data)\s*\)|"
    r"String::from_utf8\s*\(\s*(reason|data|revert_data)"
)
_LENGTH_VERIFY_RE = re.compile(
    r"(require|assert)\s*\(\s*(reason|data|revert_data)\.length\s*<=\s*\w+|"
    r"if\s+(reason|data|revert_data)\.(length|len\s*\(\s*\))\s*(<=|<)\s*\w+|"
    r"validate_reason_length|check_reason_size"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn, _impl in functions_in_contractimpl(tree.root_node, source):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.search(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _DECODE_UNSAFE_RE.search(body_nc):
            continue
        if _LENGTH_VERIFY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` decodes revert data without verifying "
                f"the length prefix — attacker crafts bytes with fake "
                f"length >> real payload, decoder overreads buffer "
                f"(revert-reason-faked-length-decode-overread). See "
                f"Solodit #18634 (GMX)."
            ),
        })
    return hits
