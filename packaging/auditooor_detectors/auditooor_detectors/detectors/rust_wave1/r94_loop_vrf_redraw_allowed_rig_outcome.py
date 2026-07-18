"""
r94_loop_vrf_redraw_allowed_rig_outcome.py

Flags draw/raffle `start_draw` / `redraw` fns that call VRF-style
`request_random_words` AGAIN after a prior request completed,
letting the host keep re-rolling until favorable outcome lands.

Source: Solodit #6395 (C4 Forgeries RandomDraw).
Class: vrf-redraw-allowed-rig-outcome (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(redraw|retry_draw|restart_draw|reroll|cancel_and_redraw|force_draw)")
_VRF_REQUEST_RE = re.compile(
    r"request_random_words|requestRandomWords|request_randomness|"
    r"vrf_coordinator\.\s*request|coordinator\.\s*request|request_roll"
)
_OUTCOME_COMMITTED_RE = re.compile(
    r"require\s*\(\s*!\s*(draw\.outcome_committed|outcome_set|finalized)|"
    r"if\s+\w*\.?outcome_committed\s*\{|"
    r"if\s+\w*\.?finalized\s*\{|"
    r"assert[!_]?\s*\(\s*!\s*(draw\.committed|outcome_committed|finalized)"
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
        if not _VRF_REQUEST_RE.search(body_nc):
            continue
        if _OUTCOME_COMMITTED_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` redraws VRF randomness without "
                f"checking outcome-committed / finalized flag — "
                f"host can keep re-rolling until favorable outcome "
                f"(vrf-redraw-allowed-rig-outcome). See Solodit "
                f"#6395 (Forgeries)."
            ),
        })
    return hits
