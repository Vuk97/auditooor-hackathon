"""
dh-bonding-curve-asymmetric-buy-sell.

Hand-tuned detector for the Truebit-style bonding-curve drain where buy and
sell quote functions implement separate reserve/supply formulas instead of
sharing one symmetric pricing helper.
"""

import re
import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


_BONDING_SOURCE_RE = re.compile(
    r"\b(bonding|curve|theta|reserve|totalSupply|slope|purchase|sale)\b",
    re.IGNORECASE,
)
_BUY_NAME_RE = re.compile(r"(buy|purchase|mint|quoteBuy|getPurchasePrice)", re.IGNORECASE)
_SELL_NAME_RE = re.compile(r"(sell|sale|burn|redeem|quoteSell|getSalePrice)", re.IGNORECASE)
_DIRECT_RESERVE_SUPPLY_MATH_RE = re.compile(
    r"(?=.*\breserve\b)(?=.*\btotalSupply\b)(?=.*\*)(?=.*/)",
    re.IGNORECASE | re.DOTALL,
)
_SHARED_HELPER_RE = re.compile(
    r"\b(_price|sharedPrice|priceFor|quoteFor|_quote)\s*\(",
    re.IGNORECASE,
)
_TRUEBIT_ASYMMETRY_RE = re.compile(
    r"\btheta\b[\s\S]{0,80}\+\s*\bk\b|\(\s*theta\s*\+\s*k\s*\)",
    re.IGNORECASE,
)
_SAFE_LIBRARY_RE = re.compile(
    r"\b(BalancerMath|BancorFormula|LogExpMath|UD60x18|PRBMath|FixedPointMathLib)\b",
    re.IGNORECASE,
)


def _source(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _is_direct_curve_formula(function) -> bool:
    body = _source(function)
    if _SAFE_LIBRARY_RE.search(body):
        return False
    if _SHARED_HELPER_RE.search(body) and not _DIRECT_RESERVE_SUPPLY_MATH_RE.search(body):
        return False
    return bool(_DIRECT_RESERVE_SUPPLY_MATH_RE.search(body))


def _formula_key(function) -> str:
    body = _source(function)
    body = re.sub(r"//.*|/\*[\s\S]*?\*/", "", body)
    body = re.sub(
        r"\bget(Purchase|Sale)Price\b|\b(buy|purchase|sell|sale)\b",
        "SIDE",
        body,
        flags=re.IGNORECASE,
    )
    body = re.sub(r"\s+", "", body)
    return body


class DhBondingCurveAsymmetricBuySell(AbstractDetector):
    ARGUMENT = "dh-bonding-curve-asymmetric-buy-sell"
    HELP = "Bonding-curve buy and sell use structurally-different formulas; cannot assume inverse symmetry."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-bonding-curve-asymmetric-buy-sell.yaml"
    WIKI_TITLE = "Bonding curve buy/sell formula asymmetry"
    WIKI_DESCRIPTION = "A correctly-designed bonding curve guarantees that `sellPrice(buy(dx))` returns exactly `dx` in the absence of fees — any asymmetry between the two formulas opens an arbitrage loop. A fee must be deducted AFTER the symmetric price is computed, not baked into the formula."
    WIKI_EXPLOIT_SCENARIO = "Truebit 2026-01 8540 ETH: `getPurchasePrice` multiplied by `theta`, `getSalePrice` by `theta + k` where `k > 0`. Attacker repeatedly bought then immediately sold, extracting `k/theta` of reserve per round until the pool was drained."
    WIKI_RECOMMENDATION = "Derive both buy and sell from the same core `price(state)` function, then apply a symmetric fee (e.g. swap output reduced by fraction). Property-test `sell(buy(x)) <= x` after fees for all x."

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            contract_source = _source(contract)
            if not _BONDING_SOURCE_RE.search(contract_source):
                continue

            buy_quotes = []
            sell_quotes = []
            for function in contract.functions_and_modifiers_declared:
                name = str(getattr(function, "name", ""))
                if name.startswith("slither"):
                    continue
                if getattr(function, "visibility", "") not in {"public", "external"}:
                    continue
                if not _is_direct_curve_formula(function):
                    continue
                if _BUY_NAME_RE.search(name):
                    buy_quotes.append(function)
                if _SELL_NAME_RE.search(name):
                    sell_quotes.append(function)

            contract_matched = False
            for buy in buy_quotes:
                buy_key = _formula_key(buy)
                for sell in sell_quotes:
                    sell_key = _formula_key(sell)
                    if buy_key == sell_key:
                        continue
                    if not (
                        _TRUEBIT_ASYMMETRY_RE.search(_source(buy))
                        or _TRUEBIT_ASYMMETRY_RE.search(_source(sell))
                    ):
                        continue
                    info = [
                        sell,
                        " — dh-bonding-curve-asymmetric-buy-sell: paired buy/sell quote functions use divergent direct reserve/totalSupply formulas.",
                    ]
                    results.append(self.generate_result(info))
                    contract_matched = True
                    break
                if contract_matched:
                    break
        return results
