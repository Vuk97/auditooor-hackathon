"""
r94_loop_stableswap_disjoint_multihop_breaks_invariant.py

Flags stableswap `multihop_swap` / `swap_chain` fns that perform
two or more `swap_step` / `compute_d` calls sequentially on the
*same* pool, recomputing D between them. Each step checks its
own invariant but the aggregate multihop violates the true
invariant — value leaks.

Source: Solodit #54987 (Code4rena MANTRA pool-manager).
Class: stableswap-disjoint-multihop-breaks-invariant (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT

_FN_NAME_RE = re.compile(
    r"(?i)(multihop_swap|swap_chain|swap_path|"
    r"route_swap|swap_batch|multi_swap|"
    r"chained_stable_swap|swap_a_to_b_to_c)"
)
# Multiple `swap` / `stable_swap_step` / `compute_d` calls.
_MULTI_STEP_RE = re.compile(
    r"(?i)(stable_swap_step[\s\S]{0,500}stable_swap_step|"
    r"compute_d[\s\S]{0,500}compute_d|"
    r"swap_step[\s\S]{0,500}swap_step|"
    r"get_y[\s\S]{0,500}get_y)"
)
# Safe: aggregate invariant check or uses an atomic multihop / single-pool path.
_AGG_CHECK_RE = re.compile(
    r"(?i)(assert_aggregate_invariant|"
    r"final_d\s*>=\s*initial_d|"
    fr"assert\w*\s*!?\s*\(\s*{IDENT}final_d\s*>=\s*{IDENT}start_d|"
    fr"require\s*\(\s*{IDENT}dFinal\s*>=\s*{IDENT}dStart|"
    r"accumulated_k_check|"
    r"atomic_multihop|batched_invariant_check)"
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
        if not _MULTI_STEP_RE.search(body_nc):
            continue
        if _AGG_CHECK_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` chains two or more stableswap "
                f"steps on the same pool (compute_d / swap_step) "
                f"without an aggregate `final_d >= start_d` check — "
                f"each step's own invariant passes but the multihop "
                f"breaks the invariant and leaks value "
                f"(stableswap-disjoint-multihop-breaks-invariant). "
                f"See Solodit #54987 (Code4rena MANTRA pool-manager)."
            ),
        })
    return hits
