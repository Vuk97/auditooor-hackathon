"""
r94_loop_bls_point_doubling_edge_case_forgery.py

Flags BLS / EC point-doubling routines that use the standard
slope = 3x^2 / 2y formula without an explicit identity / P == -P
branch — attacker crafts inputs hitting y == 0 / P == -P to forge
a valid signature (division-by-zero case the circuit never
constrains).

Source: Solodit #21284 (TrailOfBits Succinct Telepathy bls.circom).
Class: bls-point-doubling-edge-case-forgery (both).
"""

from __future__ import annotations
import re
from _util import functions_in_contractimpl, fn_body, fn_name, line_col, snippet_of, is_pub, body_text_nocomment, IDENT, CALL

_FN_NAME_RE = re.compile(
    r"(?i)(double_point|point_doubling|ec_double|g1_double|"
    r"g2_double|bls_double|_double|doubling|double_step)"
)
_SLOPE_RE = re.compile(
    fr"(3\s*\*\s*{IDENT}x\s*\*\s*{IDENT}x|"
    fr"3\s*\*\s*{IDENT}\.?\s*x\s*\.?\s*\s*square\s*\(|"
    fr"2\s*\*\s*{IDENT}y\s*\b|"
    fr"slope\s*=|lambda\s*=|lam\s*=)"
)
# Safe: explicit identity check (y == 0, P == -P, point_at_infinity, is_zero)
_IDENTITY_RE = re.compile(
    fr"(?i)(is_infinity|point_at_infinity|is_identity|"
    fr"is_zero\s*\(\s*\)|is_zero\s*\(\s*{IDENT}y\s*\)|"
    fr"{IDENT}y\s*==\s*0|{IDENT}y\.is_zero|"
    fr"P\s*==\s*-\s*P|P\s*\.\s*neg\s*\(\s*\)\s*==|"
    fr"neg_point|check_infinity)"
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
        if not _SLOPE_RE.search(body_nc):
            continue
        if _IDENTITY_RE.search(body_nc):
            continue
        line, col = line_col(fn)
        hits.append({
            "severity": "high",
            "line": line,
            "col": col,
            "snippet": snippet_of(fn, source)[:200],
            "message": (
                f"pub fn `{name}` implements EC point doubling via "
                f"slope = 3x²/2y without an identity / P == -P "
                f"branch — attacker crafts inputs where y == 0 to "
                f"hit the unconstrained edge-case and forge sigs "
                f"(bls-point-doubling-edge-case-forgery). "
                f"See Solodit #21284 (ToB Succinct Telepathy bls.circom)."
            ),
        })
    return hits
