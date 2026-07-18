"""
rounding-boundary-or-position-self-sandwich

Hand-written detector for the Fire6 RD recall split. The source-backed
seed shapes are:

* detectors/rust_wave1/test_fixtures/attacker_self_sandwiches_swap_in_open_close_position_positive.rs
* detectors/rust_wave1/test_fixtures/bitmap_64_reserve_off_by_one_positive.rs

This Slither detector ports those two same-class shapes to Solidity fixtures:
position entrypoints that hardcode a zero-output or full-slippage internal
swap, and reserve bitmap arithmetic that shifts by an unbounded reserve index.
It is detector-fixture-smoke-only and is not submission evidence.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


_NOISE_RE = re.compile(
    r'"(?:[^"\\]|\\.)*"|'
    r"'(?:[^'\\]|\\.)*'|"
    r"//[^\n\r]*|"
    r"/\*.*?\*/",
    re.DOTALL,
)


def _strip_comments_and_strings(text: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = match.group(0)
        return "\n" * token.count("\n") if "\n" in token else " "

    return _NOISE_RE.sub(repl, text or "")


_POSITION_NAME_RE = re.compile(
    r"(?i)(open|close|reduce|adjust|leverage|flashclose).*position|"
    r"(open|close|reduce|adjust|leverage|flashclose)"
)
_POSITION_CONTEXT_RE = re.compile(
    r"(?i)(executeSwap|execute_swap|_swap|swap\s*\(|router\.|pool\.swap|"
    r"positions?\s*\[|collateral|debt)"
)
_ZERO_OR_FULL_SLIPPAGE_RE = re.compile(
    r"(?i)(min(?:Amount)?Out|min_amount_out)\s*:\s*0\b|"
    r"(min(?:Amount)?Out|min_amount_out)\s*=\s*0\b|"
    r"(max(?:Slippage)?Bps|max_slippage_bps|slippageBps)\s*:\s*(?:10000|10_000)\b|"
    r"(max(?:Slippage)?Bps|max_slippage_bps|slippageBps)\s*=\s*(?:10000|10_000)\b"
)
_POSITION_GUARD_RE = re.compile(
    r"(?i)(MAX_SLIPPAGE|PROTOCOL_MAX_SLIPPAGE|maxAllowedSlippage|"
    r"require\s*\([^;]*(?:slippage|maxSlippage|maxSlippageBps)\s*<=|"
    r"require\s*\([^;]*(?:min(?:Amount)?Out|amountOut|received)\s*>\s*0|"
    r"healthFactor|health_factor|minHealthFactor|min_health_factor)"
)

_BOUNDARY_CONTEXT_RE = re.compile(
    r"(?i)(reserveId|reserve_id|idx|bitmap|UserConfiguration|setBorrowing|"
    r"setUsingAsCollateral|isBorrowing|isUsingAsCollateral)"
)
_BOUNDARY_DIRECT_SHIFT_RE = re.compile(
    r"<<\s*\(?\s*(?:uint\d*\s*\([^)]*\)\s*)?"
    r"(reserveId|reserve_id|idx|index)\s*(?:\)|\s*)\*\s*2\b",
    re.IGNORECASE,
)
_BOUNDARY_SHIFT_VAR_RE = re.compile(
    r"\b(?:uint(?:8|16|32|64|128|256)?|uint)\s+"
    r"(?P<shift>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:uint\d*\s*\([^)]*\)|reserveId|reserve_id|idx|index)\s*\*\s*2\s*;"
    r"[\s\S]{0,360}<<\s*(?P=shift)\b",
    re.IGNORECASE,
)
_BOUNDARY_GUARD_RE = re.compile(
    r"(?i)(MAX_RESERVES|safeReserveId|safe_reserve_id|checkReserve|"
    r"InvalidReserve|require\s*\([^;]*(?:reserveId|reserve_id|idx|index)\s*<\s*64|"
    r"require\s*\([^;]*(?:reserveId|reserve_id|idx|index)\s*<=\s*63|"
    r"if\s*\([^;]*(?:reserveId|reserve_id|idx|index)\s*>=\s*64\s*\)\s*(?:revert|return))"
)


def _is_position_self_sandwich(name: str, body: str) -> bool:
    if not _POSITION_NAME_RE.search(name):
        return False
    if not _POSITION_CONTEXT_RE.search(body):
        return False
    if not _ZERO_OR_FULL_SLIPPAGE_RE.search(body):
        return False
    return not _POSITION_GUARD_RE.search(body)


def _is_boundary_shift(body: str) -> bool:
    if not _BOUNDARY_CONTEXT_RE.search(body):
        return False
    if _BOUNDARY_GUARD_RE.search(body):
        return False
    return bool(_BOUNDARY_DIRECT_SHIFT_RE.search(body) or _BOUNDARY_SHIFT_VAR_RE.search(body))


class RoundingBoundaryOrPositionSelfSandwich(AbstractDetector):
    ARGUMENT = "rounding-boundary-or-position-self-sandwich"
    HELP = (
        "Position swap path hardcodes zero output or full slippage without a cap, "
        "or reserve bitmap arithmetic shifts by an unbounded reserve index."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "rounding-boundary-or-position-self-sandwich.yaml"
    )
    WIKI_TITLE = "Rounding boundary or position self-sandwich"
    WIKI_DESCRIPTION = (
        "A value-moving position path can be self-sandwiched when it internally "
        "swaps with minAmountOut zero or maxSlippageBps 10000 and no protocol "
        "cap. The sibling boundary class is reserve bitmap math that shifts by "
        "reserveId * 2 without proving reserveId < 64."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A position opener or closer creates swap params with minAmountOut zero "
        "and maxSlippageBps 10000 before mutating collateral or debt. An attacker "
        "uses the same open or close path around their own price movement. In the "
        "boundary sibling, an out-of-range reserveId shifts beyond the 64-reserve "
        "layout and corrupts neighboring flags."
    )
    WIKI_RECOMMENDATION = (
        "Require non-zero minimum output and cap slippage before the swap, then "
        "check post-swap health. For reserve bitmaps, require reserveId < 64 before "
        "computing reserveId * 2 or a derived shift."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                if is_leaf_helper(function):
                    continue
                visibility = getattr(function, "visibility", "") or ""
                if visibility not in {"external", "public"}:
                    continue
                name = getattr(function, "name", "") or ""
                body = _strip_comments_and_strings(_source(function))
                if _is_position_self_sandwich(name, body):
                    info = [
                        function,
                        (
                            " - rounding-boundary-or-position-self-sandwich: "
                            "position swap uses zero output or full slippage "
                            "without a protocol cap or health guard."
                        ),
                    ]
                    results.append(self.generate_result(info))
                    continue
                if _is_boundary_shift(body):
                    info = [
                        function,
                        (
                            " - rounding-boundary-or-position-self-sandwich: "
                            "reserve bitmap shift derives from an unbounded "
                            "reserve index."
                        ),
                    ]
                    results.append(self.generate_result(info))
        return results
