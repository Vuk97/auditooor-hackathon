"""
r94_loop_state_mutation_between_read_and_write_delta.py

Flags fns that mutate a state variable and then read the SAME variable
again for delta computation — delta reflects the MUTATED value,
not the value at entry.

Pattern:
    self.is_governance = false;
    delta = get_prior_conviction(user);   # reads *after* mutation

Source: Solodit #42203 (C4 FairSide ERC20ConvictionScore).
Class: state-mutation-between-read-and-write-delta (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(fr"(?i)(update_{IDENT}score|update_{IDENT}delta|_updateConvictionScore|_update_conviction)")
_PATTERN_RE = re.compile(
    r"(is_governance|\w+_eligible|self\.\w+)\s*=\s*(false|0|0x0)\s*;[\s\S]{0,300}?"
    r"(get_prior\w*|get_past\w*|get_prev\w*|read_previous\w*)\s*\(",
    re.DOTALL,
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
        if not _PATTERN_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"fn `{name}` mutates state field (e.g. is_governance=false) "
                f"BEFORE reading the prior-block value for delta "
                f"computation — the read sees the mutated state, delta "
                f"is wrong (state-mutation-between-read-and-write-delta). "
                f"See Solodit #42203 (FairSide ConvictionScore)."
            ),
        })
    return hits
