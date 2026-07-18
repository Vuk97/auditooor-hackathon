"""
oz-multicall-value-splitting-lets-single-payment-authorize-many

Fixture-smoke/source-shape detector for the owned OZ Multicall footgun shape:
an inherited `multicall` delegatecall surface plus a payable authorization path
that gates on `msg.value >= price` without visible per-call value accounting.

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


_MULTICALL_BASE_RE = re.compile(r"\bMulticall(?:Upgradeable)?\b")
_MSG_VALUE_PRICE_GATE_RE = re.compile(
    r"require\s*\(\s*msg\.value\s*(?:>=|==)\s*[A-Za-z_][A-Za-z0-9_\.]*",
    re.IGNORECASE,
)
_AUTHORIZATION_EFFECT_RE = re.compile(
    r"\b(?:seatAuthorized|authorized|purchased|minted|claimed|allowlisted)"
    r"\s*\[[^\]]+\]\s*=\s*(?:true|msg\.sender)\b|"
    r"\b(?:_safeMint|_mint|mint)\s*\(",
    re.IGNORECASE | re.DOTALL,
)
_SAFE_VALUE_ACCOUNTING_RE = re.compile(
    r"address\s*\(\s*this\s*\)\s*\.\s*balance|"
    r"\b(?:accountedBalance|consumedValue|spentValue|valueConsumed|"
    r"_callNotInMulticall|notInMulticall)\b",
    re.IGNORECASE,
)
_MULTICALL_NAME_RE = re.compile(r"^multicall$", re.IGNORECASE)


def _source_of(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _inherits_multicall(contract) -> bool:
    for inherited in getattr(contract, "inheritance", []) or []:
        if _MULTICALL_BASE_RE.search(getattr(inherited, "name", "") or ""):
            return True
    return _MULTICALL_BASE_RE.search(getattr(contract, "name", "") or "") is not None


def _has_delegatecall_multicall_surface(contract) -> bool:
    for function in getattr(contract, "functions", []) or []:
        if not _MULTICALL_NAME_RE.match(getattr(function, "name", "") or ""):
            continue
        source = _source_of(function)
        if "delegatecall" in source:
            return True
    return False


class OzMulticallValueSplittingLetsSinglePaymentAuthorizeMany(AbstractDetector):
    ARGUMENT = "oz-multicall-value-splitting-lets-single-payment-authorize-many"
    HELP = (
        "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: a contract "
        "inherits OZ-style Multicall and exposes a payable authorization path "
        "that checks `msg.value >= price` without visible per-call value "
        "accounting, so one outer payment can authorize many delegatecalled "
        "sub-calls."
    )
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = (
        "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/"
        "oz-multicall-value-splitting-lets-single-payment-authorize-many.yaml"
    )
    WIKI_TITLE = "OZ Multicall reuses one payment across many payable authorization calls"
    WIKI_DESCRIPTION = (
        "Fixture-smoke/source-shape proof only. This row flags the owned shape "
        "where a contract inherits `Multicall`, exposes a delegatecall-backed "
        "`multicall`, and has a payable public/external authorization path that "
        "uses `require(msg.value >= price...)` without visible value-consumption "
        "accounting such as `accountedBalance` or an equivalent balance delta "
        "check. NOT_SUBMIT_READY."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "A sale contract inherits OZ `Multicall` and exposes payable "
        "`authorizeSeat(uint256 seatId)` with `require(msg.value >= "
        "pricePerSeat)`. The attacker batches many `authorizeSeat(...)` "
        "sub-calls through `multicall(...)` while sending only one "
        "`pricePerSeat` payment. Each delegatecalled leg sees the same "
        "`msg.value`, so multiple seats can be authorized for one payment. "
        "This row does not claim corpus-backed exploit evidence beyond the "
        "fixture/source-shape proof."
    )
    WIKI_RECOMMENDATION = (
        "Do not rely on `msg.value` alone inside functions reachable from a "
        "delegatecall multicall surface. Either make those entrypoints "
        "non-delegatable, reject payable multicall usage, or track consumed "
        "value per outer transaction with explicit accounting. Keep this row "
        "NOT_SUBMIT_READY until real corpus-backed exploit evidence exists."
    )

    SUBMISSION_POSTURE = "NOT_SUBMIT_READY"
    COVERAGE_CLAIM = "detector_fixture_smoke_only"
    PROMOTION_ALLOWED = False

    def _detect(self):
        results = []

        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not _inherits_multicall(contract):
                continue
            if not _has_delegatecall_multicall_surface(contract):
                continue

            for function in contract.functions_and_modifiers_declared:
                if getattr(function, "visibility", "") not in {"external", "public"}:
                    continue
                if not getattr(function, "payable", False):
                    continue
                if is_leaf_helper(function):
                    continue
                if _MULTICALL_NAME_RE.match(getattr(function, "name", "") or ""):
                    continue

                source = _source_of(function)
                if not source:
                    continue
                if not _MSG_VALUE_PRICE_GATE_RE.search(source):
                    continue
                if not _AUTHORIZATION_EFFECT_RE.search(source):
                    continue
                if _SAFE_VALUE_ACCOUNTING_RE.search(source):
                    continue

                info = [
                    function,
                    (
                        " — oz-multicall-value-splitting-lets-single-payment-"
                        "authorize-many: inherited multicall reuses one outer "
                        "payment across a payable authorization path with no "
                        "visible consumed-value accounting. NOT_SUBMIT_READY: "
                        "fixture-smoke/source-shape proof only."
                    ),
                ]
                results.append(self.generate_result(info))

        return results
