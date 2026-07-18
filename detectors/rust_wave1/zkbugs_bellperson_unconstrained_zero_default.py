"""
zkbugs_bellperson_unconstrained_zero_default.py

Flags Bellperson-style circuits that allocate a "zero" value as a private
witness and then pass it into selector/pick/multi-case default paths without
first constraining it to the field zero.

Source: zkBugs / lurk-rs
`inference_Soundness_failure_due_to_0_value_not_enforced`.
"""
from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    line_col,
    snippet_of,
)


_ZERO_ALLOC_RE = re.compile(
    r"\blet\s+(?P<var>[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"
    r"(?:(?:AllocatedNum|Num|FpVar)::)?(?:alloc|new_witness)\s*"
    r"\([^;]*(?:zero\s*\(\)|ZERO|0(?:u\d+)?)",
    re.S,
)

_SELECTOR_USE_TEMPLATES = (
    r"\b(?:selector_dot_product|multi_case|pick|select|mux)\s*\([^;]*\b{var}\b",
    r"\b{var}\b\s*\.\s*(?:select|pick|mux)\s*\(",
)

_CONSTRAINT_TEMPLATES = (
    r"\b{var}\b\s*\.\s*(?:enforce_equal|inputize|assert_is_zero|is_zero)\s*\(",
    r"(?:enforce_equal|assert_is_zero|is_zero)\s*\([^;]*\b{var}\b",
    r"\bcs\s*\.\s*enforce\s*\([^;]*\b{var}\b[^;]*(?:zero\s*\(\)|ZERO|0(?:u\d+)?)",
)


def _selector_use_re(var: str) -> re.Pattern[str]:
    escaped = re.escape(var)
    return re.compile("|".join(t.format(var=escaped) for t in _SELECTOR_USE_TEMPLATES), re.S)


def _constraint_re(var: str) -> re.Pattern[str]:
    escaped = re.escape(var)
    return re.compile("|".join(t.format(var=escaped) for t in _CONSTRAINT_TEMPLATES), re.S)


def unconstrained_zero_default_vars(body_nc: str) -> list[str]:
    """Return allocated zero witness names used in selector defaults without constraints."""
    out: list[str] = []
    if not re.search(r"(AllocatedNum|new_witness|selector_dot_product|multi_case|pick|mux)", body_nc):
        return out
    for match in _ZERO_ALLOC_RE.finditer(body_nc):
        var = match.group("var")
        if not _selector_use_re(var).search(body_nc):
            continue
        if _constraint_re(var).search(body_nc):
            continue
        out.append(var)
    return out


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        for var in unconstrained_zero_default_vars(body_nc):
            line, col = line_col(fn)
            hits.append(
                {
                    "severity": "high",
                    "line": line,
                    "col": col,
                    "snippet": snippet_of(fn, source)[:200],
                    "message": (
                        f"Function `{fn_name(fn, source)}` allocates `{var}` as a private zero witness "
                        "and feeds it into a selector/default path without constraining it to zero. "
                        "A prover can assign a non-zero witness to the default branch. See zkBugs "
                        "lurk-rs inference_Soundness_failure_due_to_0_value_not_enforced."
                    ),
                }
            )
    return hits
