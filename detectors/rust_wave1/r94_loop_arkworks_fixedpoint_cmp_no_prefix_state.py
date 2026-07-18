"""
r94_loop_arkworks_fixedpoint_cmp_no_prefix_state.py

Flags Arkworks-style fixed-point / big-integer comparison gadgets that
compare MSB-first bit pairs with a single Boolean accumulator:

    acc = true
    for (p, q) in zip(self_bits, other_bits) {
        this_bit_ok = p.or(&q.not())?
        acc = acc.and(&this_bit_ok)?
    }
    acc.enforce_equal(false)?

This is the Penumbra NCC-E008695-V7F root cause: the circuit does not
track the prefix state ("still equal" / "lt" / "gt"), so any differing bit
can satisfy the proof instead of only the first differing bit.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    line_col,
    snippet_of,
)


_CMP_FN_RE = re.compile(r"(?i)(enforce_)?(cmp|compare|comparison)|lt|gt|less|greater")
_ACC_TRUE_RE = re.compile(
    r"\blet\s+mut\s+acc(?:\s*:\s*Boolean(?:\s*<[^>]+>)?)?\s*="
    r"\s*Boolean(?:::\s*<[^>]+>)?::constant\s*\(\s*true\s*\)"
)
_ZIP_BITS_RE = re.compile(r"\bfor\s*\([^)]*bit[^)]*,[^)]*bit[^)]*\)\s+in\s+zip\s*\(")
_PER_BIT_OR_NOT_RE = re.compile(r"\.or\s*\([^)]*\.not\s*\(\s*\)[^)]*\)")
_ACC_AND_RE = re.compile(r"\bacc\s*=\s*acc\.and\s*\(")
_ENFORCE_FALSE_RE = re.compile(
    r"\bacc\.enforce_equal\s*\(\s*&?\s*Boolean(?:::\s*<[^>]+>)?::constant"
    r"\s*\(\s*false\s*\)"
)
_PREFIX_STATE_RE = re.compile(r"\blet\s+mut\s+(?:gt|lt|greater|less)\b")


def run(tree, source: bytes, filepath: str):
    hits = []
    root = tree.root_node

    for fn in function_items(root):
        name = fn_name(fn, source)
        if not _CMP_FN_RE.search(name):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_nc = body_text_nocomment(body, source)
        if _PREFIX_STATE_RE.search(body_nc):
            continue

        required = (
            _ACC_TRUE_RE.search(body_nc),
            _ZIP_BITS_RE.search(body_nc),
            _PER_BIT_OR_NOT_RE.search(body_nc),
            _ACC_AND_RE.search(body_nc),
            _ENFORCE_FALSE_RE.search(body_nc),
        )
        if not all(required):
            continue

        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"`{name}` appears to implement an Arkworks bitwise comparison "
                "with a single `acc` Boolean that ANDs every per-bit predicate "
                "and only enforces `acc == false`. This misses the MSB-prefix "
                "state (`lt`/`gt` or still-equal), so invalid fixed-point "
                "inequalities can verify. See Penumbra NCC-E008695-V7F."
            ),
        })

    return hits
