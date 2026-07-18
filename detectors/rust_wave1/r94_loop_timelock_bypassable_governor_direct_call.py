"""
r94_loop_timelock_bypassable_governor_direct_call.py

Flags config-setter / admin fns whose auth check is
`caller == governor || caller == timelock` (disjunction) — governor
can call the target directly, skipping the timelock delay.

Source: Solodit #1091 (C4 Malt Finance).
Class: timelock-bypassable-governor-direct-call (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(set_\w+|update_\w+|configure_\w+|set_config|set_params|set_fees)")
_DUAL_AUTH_RE = re.compile(
    fr"(caller\s*==\s*{IDENT}governor\s*\|\|\s*caller\s*==\s*{IDENT}timelock|"
    fr"caller\s*==\s*{IDENT}timelock\s*\|\|\s*caller\s*==\s*{IDENT}governor|"
    r"msg\.sender\s*==\s*governor\s*\|\|\s*msg\.sender\s*==\s*timelock|"
    r"only_governor_or_timelock|require\s*\(\s*governor\s*==|onlyOwnerOrTimelock)"
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
        if not _DUAL_AUTH_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` gates on governor OR timelock "
                f"(disjunction) — governor can call target directly, "
                f"skipping timelock delay (timelock-bypassable-"
                f"governor-direct-call). See Solodit #1091 (Malt "
                f"Finance)."
            ),
        })
    return hits
