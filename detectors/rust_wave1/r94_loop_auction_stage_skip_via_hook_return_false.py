"""
r94_loop_auction_stage_skip_via_hook_return_false.py

Flags multi-stage proposal / auction fns that call a helper returning
bool and SKIP to the next stage when helper returns false — without
distinguishing "helper errored" from "stage complete".

Source: Solodit #3304 (PartyDAO ListOnOpenseaProposal).
Class: auction-stage-skip-via-hook-return-false (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(r"(?i)(execute|next_stage|advance_stage|propose|execute_step)")
_HOOK_PATTERN_RE = re.compile(
    r"(_settle\w+|_check\w+|_try\w+|finalize\w*)\s*\([^)]*\)[\s\S]{0,120}?"
    r"(!\s*\w+|==\s*false|\s*\?\s*false)[\s\S]{0,80}?"
    r"(next_stage|advance_stage|goto_\w+|proceed_to|execute_next|list_on_opensea)"
)
_DISTINCT_ERR_RE = re.compile(
    fr"(enum\s+{IDENT}Result|Ok\s*\(|Err\s*\(|Result<|FailureReason|HookStatus|"
    r"match\s+\w+\s*\{[\s\S]{0,200}?Err|try_\w+\s*\?\s*)"
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
        if not _HOOK_PATTERN_RE.search(body_nc):
            continue
        if _DISTINCT_ERR_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` advances stage when settle-hook "
                f"returns false — no distinction between 'errored' "
                f"and 'complete', attacker forces hook failure to "
                f"skip on-chain stage (auction-stage-skip-via-hook-"
                f"return-false). See Solodit #3304 (PartyDAO)."
            ),
        })
    return hits
