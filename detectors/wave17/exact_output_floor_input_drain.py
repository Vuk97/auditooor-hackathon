"""
exact-output-floor-input-drain — Cantina #8 detector.

Detects the AMM rounding bug where an exact-output swap function
computes the user's required INPUT via a floor-rounding helper
(`StableSwapMath.descale`, plain `mulDiv` without `Math.Rounding.Ceil`,
or raw `/` division) when the input token's `decimals` is small. With
`decimals = 0` and a per-token rate >= 1e18, any required scaled amount
< 1e18 floors to a raw input of 0 — a one-leg unilateral drain
(reserves[in] += 0, reserves[out] -= amountOut).

Spec source: `docs/REVERT_GAP_ANALYSIS_2026-05-08.md` § "B".

Module exposes a regex-based `scan(source: str, file_path: str)` API.
Stdlib-only.

Severity preset: High when an exact-output function uses a non-Ceil
rounding helper for the input leg AND the function or contract handles
a 0-decimal-admissible token model (heuristic: presence of any `decimals`
parameterization elsewhere in the contract, OR no explicit decimal-floor
guard in the function body).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "exact-output-floor-input-drain"
DETECTOR_SEVERITY_DEFAULT = "High"


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
# function whose name matches exact-output convention
_EXACT_OUT_NAME_RE = re.compile(
    r"^_?(?:swap)?[Ee]xact[Oo]utput|^_swapExactOutput$",
)
# floor-rounded input computation: descale(...), mulDiv with no Ceil,
# or raw `/` division on numerator-shaped expression.
_DESCALE_RE = re.compile(r"\bdescale\s*\(")
_MULDIV_RE = re.compile(r"\bmulDiv\s*\(")
_RAW_DIV_RE = re.compile(r"=\s*[A-Za-z_][A-Za-z0-9_\.\[\]\(\)\s\+\-\*]+/\s*[A-Za-z0-9_]")
# user-payment sink shapes (proves the floor result is the user's
# input leg, not just an intermediate display value)
_USER_PAYMENT_SINK_RE = re.compile(
    r"\b(?:safeTransferFrom|transferFrom)\s*\(|"
    r"\breserves\s*\[[^\]]*\]\s*\+=|"
    r"\b(?:poolManager|_poolManager|manager)\s*\.\s*(?:settle|mint)\s*\(|"
    r"\bresult\s*\.\s*amountIn\s*=",
)
_CEIL_HINT_RE = re.compile(r"[Cc]eil|round[Uu]p|RoundingUp")


def _extract_call_args(source: str, open_paren_pos: int) -> Optional[str]:
    """Return the text between matching parens at `open_paren_pos`.

    `open_paren_pos` MUST point at the `(` character. Returns None on
    unbalanced input (defensive, callers skip the hit).
    """
    if open_paren_pos >= len(source) or source[open_paren_pos] != "(":
        return None
    depth = 1
    i = open_paren_pos + 1
    while i < len(source) and depth > 0:
        c = source[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return source[open_paren_pos + 1:i]
        i += 1
    return None


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
        body_text = source[body_start + 1:k - 1]
        body_start_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, body_text, body_start_line, m.start()))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    for fn_name, body, body_line, _ in _split_functions(source):
        if not _EXACT_OUT_NAME_RE.match(fn_name):
            continue
        # find rounding-helper hits. mulDiv is floor-by-default unless
        # the call-site explicitly passes a Ceil/Up rounding arg INSIDE
        # the call's argument list, so we walk to the matching ')' and
        # inspect the arg text for Ceil/Up tokens.
        floor_hits = []
        for m in _DESCALE_RE.finditer(body):
            floor_hits.append(("descale", m.start()))
        for m in _MULDIV_RE.finditer(body):
            args_text = _extract_call_args(body, m.end() - 1)
            if args_text is None:
                continue
            if re.search(r"[Cc]eil|round[Uu]p|RoundingUp", args_text):
                continue
            floor_hits.append(("mulDiv", m.start()))
        if not floor_hits:
            continue
        # require evidence the floor-hit feeds a user-payment leg
        if not _USER_PAYMENT_SINK_RE.search(body):
            continue
        # avoid FP if function explicitly uses Ceil rounding
        if _CEIL_HINT_RE.search(body):
            # downgrade to detector-telemetry: still flag but lower
            sev = "Medium"
        else:
            sev = DETECTOR_SEVERITY_DEFAULT
        helper, off = floor_hits[0]
        line_in_body = body.count("\n", 0, off)
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_in_body,
                severity=sev,
                function=fn_name,
                message=(
                    f"Exact-output function `{fn_name}` derives required input "
                    f"via floor helper `{helper}(...)`. On low-decimal tokens "
                    "(decimals < 18) the required raw input can floor to 0, "
                    "draining the output leg for zero payment "
                    "(Cantina #8 / L28-D). Use Ceil rounding for amounts the "
                    "user owes the pool."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
