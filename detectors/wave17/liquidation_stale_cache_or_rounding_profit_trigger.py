"""
liquidation-stale-cache-or-rounding-profit-trigger

Manual Slither detector for the Fire6 liquidation-trigger-poison recall queue.
It intentionally combines two narrow source-backed branches:

1. Borrow, health, collateral, or liquidation trigger logic consumes cached
   Uniswap-style position liquidity without a same-path fresh position read.
2. Liquidation math fixes seized collateral or max-liquidable values before
   applying a liquidator-favoring rounding or inconsistent value-domain cap.

Capability posture: NOT_SUBMIT_READY. Fixture-smoke/source-shape evidence only.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract  # noqa: E402

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


def _strip_comments_and_strings(source: str) -> str:
    token_re = re.compile(
        r'"(?:[^"\\]|\\.)*"|'
        r"'(?:[^'\\]|\\.)*'|"
        r"//[^\n\r]*|"
        r"/\*.*?\*/",
        re.DOTALL,
    )

    def replace_token(match: re.Match[str]) -> str:
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return token_re.sub(replace_token, source or "")


def _function_source(function) -> str:
    try:
        return function.source_mapping.content or ""
    except Exception:
        return ""


def _function_name(function) -> str:
    return str(getattr(function, "name", "") or "")


class LiquidationStaleCacheOrRoundingProfitTrigger(AbstractDetector):
    ARGUMENT = "liquidation-stale-cache-or-rounding-profit-trigger"
    HELP = (
        "Liquidation or borrow trigger logic consumes stale cached Uniswap "
        "liquidity, or computes liquidation profit from a rounded intermediate "
        "without a protocol-favoring final readjustment."
    )
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "liquidation-stale-cache-or-rounding-profit-trigger.yaml"
    )
    WIKI_TITLE = "Liquidation trigger poison through stale collateral cache or profit-favoring rounding"
    WIKI_DESCRIPTION = (
        "Source-backed shape from Arcadia stale Uniswap liquidity, Navi max "
        "liquidation inaccuracy, and Morpho liquidation rounding."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "The trigger path accepts cached collateral liquidity after the real "
        "position changed, or liquidation math fixes the collateral side before "
        "rounding debt shares/assets in the liquidator's favor."
    )
    WIKI_RECOMMENDATION = (
        "Read live position liquidity in the same trigger path, normalize debt "
        "and collateral domains, and recompute debt assets from final settled "
        "shares."
    )

    _STALE_ENTRY_RE = re.compile(
        r"\b(borrow\w*|liquidat\w*|health\w*|checkHealth|checkSolv\w*|"
        r"solvenc\w*|collateral(Value)?|accountValue|positionValue|ltv|"
        r"loanToValue|icr|mcr)\b",
        re.IGNORECASE,
    )
    _CACHE_RE = re.compile(
        r"\b(cachedLiquidity|cachedPositionLiquidity|storedLiquidity|"
        r"positionLiquidity|liquidityAtDeposit|depositedLiquidity|"
        r"accountLiquidity)\b|accounts\s*\[[^\]]+\]\s*\.\s*liquidity",
        re.IGNORECASE,
    )
    _CACHE_TRIGGER_USE_RE = re.compile(
        r"\b(collateral(Value)?|borrowLimit|borrowable|healthFactor|"
        r"loanToValue|ltv|liquidat\w*|debt|solvenc\w*|unsafe)\b",
        re.IGNORECASE,
    )
    _FRESH_LIQUIDITY_RE = re.compile(
        r"\b(positionManager|nftPositionManager|nonfungiblePositionManager|"
        r"pool)\s*\.\s*positions\s*\(|\b(getPositionInfo|refreshLiquidity|"
        r"updateLiquidity|syncLiquidity)\s*\(",
        re.IGNORECASE,
    )

    _LIQUIDATION_ENTRY_RE = re.compile(
        r"\b(liquidat\w*|preLiquidat\w*|settleLiquidat\w*|executeLiquidat\w*)\b",
        re.IGNORECASE,
    )
    _REPAID_ASSETS_FROM_SEIZED_RE = re.compile(
        r"\brepaidAssets\s*=\s*[^;]*(seizedAssets|collateralToSeize|"
        r"collateralAmount|seizedCollateral)[^;]*",
        re.IGNORECASE | re.DOTALL,
    )
    _REPAID_ASSETS_ROUND_UP_RE = re.compile(
        r"\brepaidAssets\s*=\s*[^;]*(toAssetsUp|mulDivUp|wDivUp|"
        r"divUp|ceilDiv)[^;]*",
        re.IGNORECASE | re.DOTALL,
    )
    _REPAID_SHARES_DOWN_RE = re.compile(
        r"\brepaidShares\s*=\s*[^;]*(toSharesDown|mulDivDown|wDivDown)"
        r"[^;]*repaidAssets|"
        r"\brepaidShares\s*=\s*[^;]*repaidAssets[^;]*(toSharesDown|"
        r"mulDivDown|wDivDown)",
        re.IGNORECASE | re.DOTALL,
    )
    _FINAL_READJUST_RE = re.compile(
        r"\brepaidShares\s*=\s*[^;]*(toSharesUp|mulDivUp|wDivUp)|"
        r"\brepaidAssets\s*=\s*[^;]*(toAssetsUp\s*\(\s*repaidShares|"
        r"repaidShares[^;]*toAssetsUp|mulDivUp\s*\(\s*repaidShares|"
        r"wMulUp\s*\(\s*repaidShares)",
        re.IGNORECASE | re.DOTALL,
    )

    _MAX_LIQ_ENTRY_RE = re.compile(
        r"\b(calculateMaxLiquidation|calculate_max_liquidation|maxLiquidation|"
        r"max_liquidation|maxLiquidable)\b",
        re.IGNORECASE,
    )
    _MAX_COLLATERAL_RE = re.compile(
        r"\bmax\w*Collateral\w*\s*=\s*[^;]*collateralValue",
        re.IGNORECASE | re.DOTALL,
    )
    _MAX_DEBT_RE = re.compile(
        r"\bmax\w*Debt\w*\s*=\s*[^;]*debtValue",
        re.IGNORECASE | re.DOTALL,
    )
    _MAX_PROFIT_RE = re.compile(
        r"\b(liquidationBonus|liquidationIncentive|bonus|discount|profit|seize\w*)\b",
        re.IGNORECASE,
    )
    _MAX_NORMALIZED_GUARD_RE = re.compile(
        r"\b(normalize\w*|sameScale|oracleScale)\b|"
        r"\b(Math\.)?min\s*\([^;]*(max\w*Debt|max\w*Collateral)",
        re.IGNORECASE | re.DOTALL,
    )

    @classmethod
    def _matches_stale_cache_trigger(cls, function) -> bool:
        name = _function_name(function)
        src = _strip_comments_and_strings(_function_source(function))
        context = f"{name}\n{src}"
        if not cls._STALE_ENTRY_RE.search(context):
            return False
        if not cls._CACHE_RE.search(src):
            return False
        if not cls._CACHE_TRIGGER_USE_RE.search(src):
            return False
        return not cls._FRESH_LIQUIDITY_RE.search(src)

    @classmethod
    def _matches_repaid_roundtrip(cls, function) -> bool:
        name = _function_name(function)
        src = _strip_comments_and_strings(_function_source(function))
        if not cls._LIQUIDATION_ENTRY_RE.search(name):
            return False
        if not cls._REPAID_ASSETS_FROM_SEIZED_RE.search(src):
            return False
        if not cls._REPAID_ASSETS_ROUND_UP_RE.search(src):
            return False
        if not cls._REPAID_SHARES_DOWN_RE.search(src):
            return False
        return not cls._FINAL_READJUST_RE.search(src)

    @classmethod
    def _matches_max_liquidation_inaccuracy(cls, function) -> bool:
        name = _function_name(function)
        src = _strip_comments_and_strings(_function_source(function))
        context = f"{name}\n{src}"
        if not cls._MAX_LIQ_ENTRY_RE.search(context):
            return False
        if not cls._MAX_COLLATERAL_RE.search(src):
            return False
        if not cls._MAX_DEBT_RE.search(src):
            return False
        if not cls._MAX_PROFIT_RE.search(src):
            return False
        return not cls._MAX_NORMALIZED_GUARD_RE.search(src)

    @classmethod
    def _match_reasons(cls, function) -> list[str]:
        reasons: list[str] = []
        if cls._matches_stale_cache_trigger(function):
            reasons.append("stale liquidity cache used in trigger path")
        if cls._matches_repaid_roundtrip(function):
            reasons.append("liquidation debt shares rounded down without final asset readjustment")
        if cls._matches_max_liquidation_inaccuracy(function):
            reasons.append("max liquidation collateral and debt caps use unnormalized value domains")
        return reasons

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            for function in contract.functions_and_modifiers_declared:
                name = _function_name(function)
                if not name or name.startswith("slither"):
                    continue
                if getattr(function, "is_constructor", False):
                    continue
                reasons = self._match_reasons(function)
                if not reasons:
                    continue
                info = [
                    function,
                    " - liquidation-stale-cache-or-rounding-profit-trigger: "
                    + "; ".join(reasons)
                    + ".",
                ]
                results.append(self.generate_result(info))
        return results
