"""
v4-hook-beforeswap-slippage-bypass — Cantina #991 detector.

Uniswap-v4 custom-accounting hooks override `_beforeSwap` and return a
non-zero `BeforeSwapDelta`. When the hook returns non-zero delta, the
PoolManager downstream sets `amountToSwap = 0`, neutralizing both the
user-supplied `params.sqrtPriceLimitX96` and the manager's slippage
checks. The hook MUST therefore enforce per-call user slippage / price
limit ITSELF.

This detector flags `_beforeSwap` implementations that:
  - return a non-zero `BeforeSwapDelta` (constructed via
    `toBeforeSwapDelta(...)`), AND
  - perform internal pricing (call `_swap`, `_executeSwap`, etc.), AND
  - do NOT reference `sqrtPriceLimitX96`, `amountOutMinimum`, `minOut`,
    `minAmountOut`, or `priceLimit` anywhere in the function body.

Spec: `docs/REVERT_GAP_ANALYSIS_2026-05-08.md` § "C".

Severity preset: Medium (Likelihood Low x Impact High).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


DETECTOR_NAME = "v4-hook-beforeswap-slippage-bypass"
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
_NONZERO_DELTA_RE = re.compile(
    r"\btoBeforeSwapDelta\s*\(",
)
_INTERNAL_PRICING_RE = re.compile(
    r"\b_swap\s*\(|\b_executeSwap\s*\(|\b_priceSwap\s*\(",
)
_USER_SLIPPAGE_RE = re.compile(
    r"\bsqrtPriceLimitX96\b|"
    r"\bamountOutMin(?:imum)?\b|"
    r"\bminOut\b|"
    r"\bminAmountOut\b|"
    r"\bpriceLimit\b",
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
        body_text = source[body_start + 1:k - 1]
        body_start_line = source.count("\n", 0, body_start + 1) + 1
        out.append((name, body_text, body_start_line, m.start()))
        pos = k
    return out


def scan(source: str, file_path: str = "<unknown>") -> List[Finding]:
    findings: List[Finding] = []
    # cheap up-front filter: must be a v4-hook file (imports
    # BeforeSwapDelta) — saves work on unrelated contracts.
    if "BeforeSwapDelta" not in source:
        return findings

    for fn_name, body, body_line, _ in _split_functions(source):
        if fn_name != "_beforeSwap" and fn_name != "beforeSwap":
            continue
        if not _NONZERO_DELTA_RE.search(body):
            # zero-delta hooks defer pricing to PoolManager; not in scope
            continue
        if not _INTERNAL_PRICING_RE.search(body):
            # delta returned but no internal pricing call detected;
            # may be a no-op hook — out of scope.
            continue
        # Walk all function bodies in the same file (proxy for the
        # contract's pricing closure). If any function body actually
        # USES the slippage tokens — i.e. references them in an
        # expression / require / revert / branch — the hook is OK.
        # We skip mentions that occur in struct/interface declarations
        # by only inspecting function body texts produced by
        # _split_functions.
        slippage_consumed = False
        for _other_name, other_body, _ol, _ofs in _split_functions(source):
            for m in _USER_SLIPPAGE_RE.finditer(other_body):
                start = m.start()
                # require the token to appear in an expression context
                # (i.e. surrounded by something other than a type/decl
                # keyword). Cheap heuristic: the line must contain
                # at least one operator OR the token must appear after
                # a `.` (member access) or inside a require/if/revert.
                line_start = other_body.rfind("\n", 0, start) + 1
                line_end = other_body.find("\n", start)
                if line_end < 0:
                    line_end = len(other_body)
                line = other_body[line_start:line_end]
                if re.search(r"\.|[<>=!]=?|\?|\|\||&&|\brequire\b|\bif\b|\brevert\b|\breturn\b|=", line):
                    slippage_consumed = True
                    break
            if slippage_consumed:
                break
        if slippage_consumed:
            continue
        # body line for the toBeforeSwapDelta call
        m = _NONZERO_DELTA_RE.search(body)
        line_in_body = body.count("\n", 0, m.start()) if m else 0
        findings.append(
            Finding(
                detector=DETECTOR_NAME,
                file=file_path,
                line=body_line + line_in_body,
                severity=DETECTOR_SEVERITY_DEFAULT,
                function=fn_name,
                message=(
                    f"`{fn_name}` returns non-zero BeforeSwapDelta and prices "
                    "the swap internally without consuming user slippage / "
                    "priceLimit params. PoolManager's slippage is bypassed by "
                    "the non-zero delta short-circuit (Cantina #991 / L28-A "
                    "primitive #1). Hook must enforce user slippage itself."
                ),
            )
        )
    return findings


__all__ = ["scan", "Finding", "DETECTOR_NAME", "DETECTOR_SEVERITY_DEFAULT"]
