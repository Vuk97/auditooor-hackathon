"""
r94_loop_oracle_version_expired_stale_return.py

Flags versioned-oracle fns that, on commit-timeout for a requested
version, return the previous version's price wrapped as a 'valid'
price instead of returning/flagging INVALID.

Source: Solodit #31171 (Sherlock Perennial V2).
Class: oracle-version-expired-stale-return (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(at_version|at_timestamp|commit_version|version_at|get_version)")
_TIMEOUT_CHECK_RE = re.compile(r"timed_out|expired|commit_timeout|past_commit_deadline|GRACE_PERIOD")
_PREV_RETURN_RE = re.compile(
    r"return\s+previous_version|return\s+last_version|"
    fr"return\s+{IDENT}previous\.price|return\s+{IDENT}previous_valid|"
    r"\.valid\s*=\s*true"
)
_INVALID_FLAG_RE = re.compile(
    r"\.valid\s*=\s*false|return\s+OracleVersion::invalid|"
    r"return\s+\(.*?,\s*false\)|is_invalid|mark_invalid"
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
        if not _TIMEOUT_CHECK_RE.search(body_nc):
            continue
        if not _PREV_RETURN_RE.search(body_nc):
            continue
        if _INVALID_FLAG_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` detects a commit-timeout on a versioned "
                f"oracle but returns the previous version's price as "
                f"`valid = true` instead of marking INVALID. Stale price "
                f"used for settlement. See Solodit #31171 (Perennial V2)."
            ),
        })
    return hits
