"""
zkbugs_unsound_fixed_point_addition.py

Flags the Penumbra/arkworks fixed-point addition shape where a limb sum is
bit-constrained to 64 bits and then the same bit vector is sliced at [64..] as
the carry. The first carry bit is unconstrained/absent; the fix is to constrain
the raw 64-bit limb sum to 65 bits before deriving c1.

Source: zkBugs
  penumbra-zone/penumbra/zksecurity_Unsound_fixed_point_addition
Fix: penumbra-zone/penumbra@ddab070, "fix: 65th bit is used for first carry bit"
Class: arkworks-unsound-fixed-point-addition.
"""

from __future__ import annotations

import re

from _util import body_text_nocomment, fn_body, fn_name, function_items, line_col, snippet_of


_FN_NAME_RE = re.compile(r"(?i)(checked_)?add")
_ARKWORKS_HINT_RE = re.compile(
    r"(bit_constrain\s*\(|UInt64::from_bits_le|le_bits_to_fp_var|"
    r"ark_r1cs_std|AllocVar|R1CSVar|FpVar|Boolean::<)"
)
_VULN_WIDTH_RE = re.compile(
    r"let\s+(?P<bits>\w+_bits)\s*=\s*bit_constrain\s*\("
    r"\s*(?P<raw>\w+_raw)\s*,\s*64\s*\)\s*\?"
    r"(?P<tail>.*?)"
    r"(?P=bits)\s*\[\s*64\s*\.\.\s*\]",
    re.DOTALL,
)
_LOW_LIMB_RE = re.compile(
    r"UInt64::from_bits_le\s*\(\s*&?\s*(?P<bits>\w+_bits)\s*"
    r"\[\s*0\s*\.\.\s*64\s*\]\s*\)"
)


def run(tree, source: bytes, filepath: str):
    hits = []
    for fn in function_items(tree.root_node):
        name = fn_name(fn, source)
        if not _FN_NAME_RE.fullmatch(name):
            continue
        body = fn_body(fn)
        if body is None:
            continue
        body_nc = body_text_nocomment(body, source)
        if not _ARKWORKS_HINT_RE.search(body_nc):
            continue

        for match in _VULN_WIDTH_RE.finditer(body_nc):
            bits_name = match.group("bits")
            tail = match.group("tail")
            low_limb = _LOW_LIMB_RE.search(tail)
            if low_limb is None or low_limb.group("bits") != bits_name:
                continue

            line, col = line_col(fn)
            hits.append({
                "severity": "high",
                "line": line,
                "col": col,
                "snippet": snippet_of(fn, source)[:200],
                "message": (
                    f"fn `{name}` constrains `{bits_name}` with "
                    f"`bit_constrain(..., 64)` but later derives carry from "
                    f"`{bits_name}[64..]`. The 65th carry bit is absent, so "
                    f"fixed-point addition can be proven with an unsound "
                    f"carry. Constrain the first raw limb sum to 65 bits "
                    f"before deriving c1 (zkBugs Penumbra unsound "
                    f"fixed-point addition, fix ddab070)."
                ),
            })
            break
    return hits
