"""
r94_loop_zkvm_timestamp_field_modulus_overflow.py

Flags zkVM step-counter / timestamp field elements represented in
a small prime field (BabyBear, Goldilocks, etc.) without an
explicit range-check / bound enforcement — after 2^31 steps the
timestamp wraps to 0 and invalid paths prove/verify.

Source: Solodit #53416 (Cantina OpenVM).
Class: zkvm-timestamp-field-modulus-overflow (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment

_FN_NAME_RE = re.compile(r"(?i)(increment_timestamp|advance_timestamp|next_step|tick|increment_clock|update_pc|update_step)")
_FIELD_RE = re.compile(
    r"(BabyBear|Goldilocks|BabyBearField|Mersenne31|BN254ScalarField|"
    r"F::one\s*\(\s*\)|Self::F::|"
    r"timestamp\s*:\s*F\b|timestamp\s*:\s*Self::F|"
    r"step\s*:\s*F\b|clock\s*:\s*F\b)"
)
_BOUND_RE = re.compile(
    r"(?i)(range_check|assert\w*\s*!?\s*\(\s*\w*(timestamp|step|clock)\s*<|"
    r"require\w*\s*\(\s*\w*(timestamp|step|clock)\s*<|"
    r"\w*(timestamp|step|clock)\.checked_add|"
    r"\w*(timestamp|step|clock)\s*<\s*\w*(MAX|BOUND|LIMIT)|"
    r"is_less_than|less_than_check|bound_check)"
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
        if not _FIELD_RE.search(body_nc):
            continue
        if _BOUND_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` advances a field-typed timestamp / "
                f"step counter without a range-check — after ~2^31 "
                f"steps the timestamp wraps modulo the field prime "
                f"(BabyBear/Goldilocks/etc.), enabling invalid paths "
                f"to prove/verify (zkvm-timestamp-field-modulus-overflow). "
                f"See Solodit #53416 (Cantina OpenVM)."
            ),
        })
    return hits
