"""
dual-direction-swap-math-asymmetry — periphery anchoring-trap detector
(Cantina Revert #102 — and the general shape).

Detects mirror-direction function pairs that compute a fee or rounding
asymmetrically. Canonical shape:

  - `_swapExactInput`  → result.amountOut = rawAmountOut - totalFees
  - `_swapExactOutput` → result.amountIn  = rawAmountIn  + totalFees

(or any pair that uses `output - fee` on one path and `input + fee` on
the mirror path; or one path uses `Math.Rounding.Floor` and the mirror
uses `Math.Rounding.Ceil` against the user; or one path multiplies by
`(1 - f)` and the mirror divides by `(1 + f)` instead of `(1 - f)`.)

The general shape is universal: any pair of "mirror" entrypoints whose
fee/rounding arithmetic is structurally non-symmetric will produce a
direction-dependent effective fee rate that an arbitrageur can extract
across split exact-input vs exact-output swaps. Detector is shape-
based: discovers two mirror functions in the same contract and
inspects whether one path has an additive fee on one side and a
subtractive fee on the other for the user-leg amount.

Module exposes a regex-based `scan(source: str, file_path: str)` API.
Stdlib-only.

Severity preset: Medium. Verbatim Cantina-confirmed Medium for the
Revert source case; downstream calibration may upgrade given pool TVL.

Spec source: `docs/REVERT_GAP_ANALYSIS_2026-05-08.md` § Finding #102.
DO NOT EDIT BY HAND without updating the spec doc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


DETECTOR_NAME = "dual-direction-swap-math-asymmetry"
DETECTOR_SEVERITY_DEFAULT = "Medium"


@dataclass
class Finding:
    detector: str
    file: str
    line: int
    severity: str
    message: str
    function: Optional[str] = None


_FN_HEADER_RE = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)

# Mirror-pair candidates. We pair "ExactInput" <-> "ExactOutput" by
# stripping the suffix and matching on the remaining stem.
_EXACT_IN_NAME_RE = re.compile(r"^(?P<stem>_?[a-zA-Z0-9_]*?)[Ee]xact[Ii]nput$")
_EXACT_OUT_NAME_RE = re.compile(r"^(?P<stem>_?[a-zA-Z0-9_]*?)[Ee]xact[Oo]utput$")

# Generic mirror-pair stem extraction (e.g. `_swapIn` / `_swapOut`).
_GENERIC_IN_NAME_RE = re.compile(r"^(?P<stem>_?[a-zA-Z0-9_]+?)[Ii]n$")
_GENERIC_OUT_NAME_RE = re.compile(r"^(?P<stem>_?[a-zA-Z0-9_]+?)[Oo]ut$")

# Fee / rounding signal patterns.
_FEE_VAR_RE = re.compile(
    r"\b(?:totalFees|fees?|fee|protocolFees?|hookFees?|lpFees?)\b",
)

# `output - fee` shape (subtractive, fee deducted from output)
_SUB_FEE_RE = re.compile(
    r"=\s*[A-Za-z_][A-Za-z0-9_]*\s*-\s*(?:totalFees|fees?|fee|protocolFees?|hookFees?|lpFees?)\b",
)
# `input + fee` shape (additive, fee added on top of input)
_ADD_FEE_RE = re.compile(
    r"=\s*[A-Za-z_][A-Za-z0-9_]*\s*\+\s*(?:totalFees|fees?|fee|protocolFees?|hookFees?|lpFees?)\b",
)

# Math.Rounding.Floor vs Math.Rounding.Ceil asymmetry signal
_ROUND_FLOOR_RE = re.compile(r"Math\.Rounding\.Floor|Rounding\.Floor")
_ROUND_CEIL_RE = re.compile(r"Math\.Rounding\.Ceil|Rounding\.Ceil")

# `* (1 - f)` vs `/ (1 + f)` asymmetric multiplicative form (loose)
_ONE_MINUS_F_RE = re.compile(
    r"\*\s*\(\s*(?:[A-Za-z0-9_]+\s*-\s*[A-Za-z0-9_]+|"
    r"1e\d+\s*-\s*[A-Za-z0-9_]+|"
    r"FEE_DENOM\s*-\s*[A-Za-z0-9_]+)\s*\)",
)
_ONE_PLUS_F_RE = re.compile(
    r"/\s*\(\s*(?:[A-Za-z0-9_]+\s*\+\s*[A-Za-z0-9_]+|"
    r"1e\d+\s*\+\s*[A-Za-z0-9_]+|"
    r"FEE_DENOM\s*\+\s*[A-Za-z0-9_]+)\s*\)",
)


def _split_functions(source: str) -> List[tuple]:
    out = []
    pos = 0
    while True:
        m = _FN_HEADER_RE.search(source, pos)
        if not m:
            break
        name = m.group("name")
        i = m.end()
        depth_paren = 1
        while i < len(source) and depth_paren > 0:
            c = source[i]
            if c == "(":
                depth_paren += 1
            elif c == ")":
                depth_paren -= 1
            i += 1
        body_start = -1
        j = i
        while j < len(source):
            if source[j] == ";":
                break
            if source[j] == "{":
                body_start = j
                break
            j += 1
        if body_start < 0:
            pos = max(j, i)
            continue
        depth = 1
        k = body_start + 1
        while k < len(source) and depth > 0:
            c = source[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            k += 1
        body_end = k
        body_text = source[body_start + 1:body_end - 1]
        body_start_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, body_text, body_start_line, m.start()))
        pos = body_end
    return out


def _classify_fee_arithmetic(body: str) -> dict:
    """
    Return a dict of arithmetic-shape booleans observed in the function
    body. Used to compare two mirror functions for asymmetry.
    """
    return {
        "has_sub_fee": bool(_SUB_FEE_RE.search(body)),
        "has_add_fee": bool(_ADD_FEE_RE.search(body)),
        "has_round_floor": bool(_ROUND_FLOOR_RE.search(body)),
        "has_round_ceil": bool(_ROUND_CEIL_RE.search(body)),
        "has_one_minus_f": bool(_ONE_MINUS_F_RE.search(body)),
        "has_one_plus_f": bool(_ONE_PLUS_F_RE.search(body)),
    }


def _find_mirror_pairs(fns: List[tuple]) -> List[Tuple[tuple, tuple, str]]:
    """
    Return a list of (in_fn_tuple, out_fn_tuple, pair_kind) where each
    tuple is (name, body, body_line, start_offset).
    """
    by_stem_exact: dict[str, dict[str, tuple]] = {}
    by_stem_generic: dict[str, dict[str, tuple]] = {}

    for fn in fns:
        name = fn[0]
        m_in = _EXACT_IN_NAME_RE.match(name)
        m_out = _EXACT_OUT_NAME_RE.match(name)
        if m_in:
            by_stem_exact.setdefault(m_in.group("stem"), {})["in"] = fn
            continue
        if m_out:
            by_stem_exact.setdefault(m_out.group("stem"), {})["out"] = fn
            continue
        m_gin = _GENERIC_IN_NAME_RE.match(name)
        m_gout = _GENERIC_OUT_NAME_RE.match(name)
        if m_gin:
            by_stem_generic.setdefault(m_gin.group("stem"), {})["in"] = fn
            continue
        if m_gout:
            by_stem_generic.setdefault(m_gout.group("stem"), {})["out"] = fn
            continue

    pairs: List[Tuple[tuple, tuple, str]] = []
    for stem, slots in by_stem_exact.items():
        if "in" in slots and "out" in slots:
            pairs.append((slots["in"], slots["out"], "exact-input/exact-output"))
    for stem, slots in by_stem_generic.items():
        if "in" in slots and "out" in slots:
            # avoid double-counting if also matched as exact pair (rare)
            already = any(
                (slots["in"][0] == p[0][0] and slots["out"][0] == p[1][0])
                for p in pairs
            )
            if not already:
                pairs.append((slots["in"], slots["out"], "generic-mirror"))
    return pairs


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    fns = _split_functions(source)
    pairs = _find_mirror_pairs(fns)
    if not pairs:
        return findings

    for in_fn, out_fn, kind in pairs:
        in_name, in_body, in_line, _ = in_fn
        out_name, out_body, out_line, _ = out_fn
        in_sig = _classify_fee_arithmetic(in_body)
        out_sig = _classify_fee_arithmetic(out_body)

        reasons: List[str] = []

        # Fee asymmetry: input deducts from output, output adds to input
        # (or any cross-direction asymmetry where one path does sub and
        # the mirror does add but neither is the other's structural
        # complement of `(1 - f)` form).
        if (in_sig["has_sub_fee"] and out_sig["has_add_fee"]
                and not in_sig["has_one_minus_f"]
                and not out_sig["has_one_minus_f"]):
            reasons.append(
                f"`{in_name}` subtracts fee from output (`x - fee`) while "
                f"`{out_name}` adds fee on top of input (`y + fee`); "
                "neither path uses the symmetric `(1 - f)` / `(1 + f)` "
                "gross-up form, producing direction-dependent effective "
                "fee rates"
            )

        # Rounding asymmetry against the user
        if in_sig["has_round_floor"] and out_sig["has_round_ceil"]:
            # both flooring/ceiling AGAINST user: input floors output
            # (user receives less), output ceils input (user pays more) —
            # consistent ROUND-AGAINST-USER direction is fine; but
            # combined with fee-side asymmetry it becomes a fire signal
            reasons.append(
                f"`{in_name}` uses Math.Rounding.Floor while `{out_name}` "
                "uses Math.Rounding.Ceil; verify both round AGAINST the "
                "user consistently"
            )
        elif in_sig["has_round_ceil"] and out_sig["has_round_floor"]:
            # rounding INVERTED against expected direction (user gains
            # in one path, loses in mirror): definite asymmetry
            reasons.append(
                f"`{in_name}` uses Math.Rounding.Ceil while `{out_name}` "
                "uses Math.Rounding.Floor; rounding direction is "
                "inverted between mirror paths (one path rounds in user "
                "favour, the other against)"
            )

        # Multiplicative asymmetry: `* (1 - f)` on one side without the
        # complement `/ (1 - f)` on the mirror (Curve / stableswap
        # textbook gross-up form). Fire when one path uses `* (1 - f)`
        # and the mirror uses `/ (1 + f)` (off-by-direction).
        if (in_sig["has_one_minus_f"] and out_sig["has_one_plus_f"]
                and not out_sig["has_one_minus_f"]):
            reasons.append(
                f"`{in_name}` uses `* (1 - f)` form while `{out_name}` "
                "uses `/ (1 + f)` form; correct symmetric form is "
                "`/ (1 - f)` on the exact-output side"
            )

        if not reasons:
            continue

        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=in_line,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=in_name,
                message=(
                    f"Mirror-pair fee/rounding asymmetry between "
                    f"`{in_name}` and `{out_name}` ({kind}): "
                    + "; ".join(reasons)
                    + ". L29-Discovery anchoring-trap (Revert Cantina #102)."
                ),
            )
        )

    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
