"""
r94_loop_oracle_heartbeat_no_fallback.py

Flags oracle-reader fns that require `latest_round_data` to be fresh
(age <= heartbeat) and revert otherwise, with no fallback oracle /
circuit-breaker path.

Source: Solodit #3508 (Sherlock Float Capital).
Class: oracle-heartbeat-no-fallback (both).
"""

from __future__ import annotations
import re
from _util import (
    functions_in_contractimpl, fn_body, fn_name, text_of, line_col, snippet_of, is_pub, body_text_nocomment, IDENT,
)

_FN_NAME_RE = re.compile(r"(?i)(get_price|price_of|validate_round|check_heartbeat)")
_HEARTBEAT_RE = re.compile(r"heartbeat|HEARTBEAT|staleness_period|max_age|max_time")
_STRICT_REVERT_RE = re.compile(
    r"require!?\s*\([^)]*(age|updated_at|timestamp|now\s*-\s*updated_at)\s*<=?\s*\w*(heartbeat|max_age|max_time)|"
    fr"revert\s+{IDENT}Stale|StalePrice|assert!?\s*\([^)]*staleness",
    re.IGNORECASE,
)
_FALLBACK_RE = re.compile(
    r"fallback_oracle|fallback_feed|secondary_feed|backup_oracle|"
    r"try_primary|else_if_stale|fallback_to_\w+"
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
        if not _HEARTBEAT_RE.search(body_nc):
            continue
        if not _STRICT_REVERT_RE.search(body_nc):
            continue
        if _FALLBACK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "medium",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` reverts on oracle staleness with no "
                f"fallback feed / circuit-breaker. Heartbeat miss freezes "
                f"the entire market. See Solodit #3508 (Float Capital)."
            ),
        })
    return hits
