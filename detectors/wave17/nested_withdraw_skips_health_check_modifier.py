"""
nested-withdraw-skips-health-check-modifier

Fixture-smoke/source-shape detector for a leverage wrapper that calls a
lending-core bare withdraw variant from a public/external withdraw-like
entrypoint without a visible health modifier or post-call health assertion.

Submission posture: NOT_SUBMIT_READY. This is intentionally narrow and backed
only by the checked-in fixture pair.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_leaf_helper, is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_CONTEXT_RE = re.compile(
    r"(?is)\b(?:healthStateCheck|healthyUser|checkHealth|syncPool|"
    r"I\w*Lending|debtShares|borrowShares|collateral)\b"
)
_ENTRYPOINT_RE = re.compile(
    r"(?i)^(?:manualWithdraw|manuallyWithdraw|withdraw|redeem|"
    r"decreaseLiquidity|removeCollateral|exit)"
)
_BARE_WITHDRAW_CALL_RE = re.compile(
    r"(?is)\.\s*(?:withdrawExactShares|withdrawExact|_withdrawBare|"
    r"bareWithdraw|_bareWithdraw|redeemRaw|coreWithdraw|withdrawInternal)\s*\("
)
_HEALTH_GUARD_RE = re.compile(
    r"(?is)\b(?:healthStateCheck|_healthStateCheck|healthyUser|checkHealth|"
    r"_checkHealth|collateralRatioOK|isHealthy|requireHealthy|"
    r"assertNotLiquidatable)\b|healthFactor\s*>="
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _has_health_modifier(function) -> bool:
    try:
        modifiers = list(function.modifiers or [])
    except Exception:
        modifiers = []
    for modifier in modifiers:
        if _HEALTH_GUARD_RE.search(getattr(modifier, "name", "") or ""):
            return True
    return False


class NestedWithdrawSkipsHealthCheckModifier(AbstractDetector):
    ARGUMENT = "nested-withdraw-skips-health-check-modifier"
    HELP = (
        "Withdraw-like wrapper calls a lending-core bare withdraw variant "
        "without a visible health modifier or post-call health assertion."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "nested-withdraw-skips-health-check-modifier.yaml"
    )
    WIKI_TITLE = "Leverage wrapper calls bare withdraw without health check"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only: this row flags the owned "
        "manualWithdraw-style wrapper shape where a public/external entrypoint "
        "calls `withdrawExactShares` or a similar bare withdraw variant and "
        "does not visibly run a health check. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A leveraged wrapper calls `wiseLending.withdrawExactShares(...)` from "
        "`manualWithdraw(...)` under only a sync modifier. If the wrapper does "
        "not then assert borrower health, collateral can be removed past the "
        "LTV boundary and leave the position liquidatable or undercollateralized."
    )
    WIKI_RECOMMENDATION = (
        "Run the lending core health check after the bare withdraw, add the "
        "health modifier to the wrapper, or expose only guarded withdraw paths. "
        "Do not promote this row from fixture smoke alone."
    )

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue

            contract_src = _source(contract)
            if not _CONTEXT_RE.search(contract_src):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if is_leaf_helper(function):
                    continue
                if not _ENTRYPOINT_RE.search(function.name or ""):
                    continue

                function_src = _source(function)
                if not function_src:
                    continue
                if not _BARE_WITHDRAW_CALL_RE.search(function_src):
                    continue
                if _has_health_modifier(function):
                    continue
                if _HEALTH_GUARD_RE.search(function_src):
                    continue

                info = [
                    function,
                    (
                        " — nested-withdraw-skips-health-check-modifier: "
                        "withdraw-like wrapper calls a bare withdraw variant "
                        "without a visible health modifier or post-call health "
                        "assertion. NOT_SUBMIT_READY: fixture-smoke/source-"
                        "shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))
        return results
