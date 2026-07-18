"""
amm-bin-liquidity-overflow-check-only-on-mint-not-swap — generated from reference/patterns.dsl/amm-bin-liquidity-overflow-check-only-on-mint-not-swap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amm-bin-liquidity-overflow-check-only-on-mint-not-swap.yaml
Source: auditooor-R73-fixdiff-mined-pancake-infinity-core-c1e4f95a15
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmmBinLiquidityOverflowCheckOnlyOnMintNotSwap(AbstractDetector):
    ARGUMENT = "amm-bin-liquidity-overflow-check-only-on-mint-not-swap"
    HELP = "BinPool reserve-mutation path (swap / donate) omits the MAX_LIQUIDITY_PER_BIN overflow check that mint has. Attacker donates into a near-cap bin and overflows subsequent getLiquidity calls."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amm-bin-liquidity-overflow-check-only-on-mint-not-swap.yaml"
    WIKI_TITLE = "Bin AMM: per-bin liquidity cap enforced on mint but not on swap/donate"
    WIKI_DESCRIPTION = "Bin-liquidity AMMs (Trader Joe, PancakeSwap v4 Bin) compute per-bin 'liquidity' = `reserves.getLiquidity(price)` that must fit in uint256 after a specific conversion (price is ~2^128). The enforceable cap is MAX_LIQUIDITY_PER_BIN ≈ 6.5e70. Mint path enforces the cap; swap path recomputes `reserves` via `add(amountsInWithFees).sub(amountsOut)` and writes it back without checking; donate adds unilat"
    WIKI_EXPLOIT_SCENARIO = "(1) Attacker mints to bring bin N within 1 unit of MAX_LIQUIDITY_PER_BIN. (2) Attacker `donate(pool, amt0, amt1, '')` — reserves grow but cap is not re-checked. Now `getLiquidity(reservesOfBin[N], price)` overflows uint256. (3) Any subsequent swap through bin N reads overflowed liquidity — swap curve breaks (prices go haywire; attacker can drain adjacent bins by swapping through N at corrupt price"
    WIKI_RECOMMENDATION = "Enforce MAX_LIQUIDITY_PER_BIN on EVERY reserve mutation: mint, swap-exactly-in (inside the loop after updating reserveOfBin[activeId]), donate. Use a common helper `_setReservesChecked(bin, newReserves, price)` that reverts on overflow. Invariant test: for any sequence of (mint, swap, donate) intera"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(BinPool|activeBin|reserveOfBin|MAX_LIQUIDITY_PER_BIN|getLiquidity)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(swap|_swap|mint|donate|_donate|_executeSwap)'}, {'function.body_contains_regex': 'self\\.reserveOfBin\\[\\s*\\w+\\s*\\]\\s*=\\s*\\w+\\.add'}, {'function.body_not_contains_regex': 'MAX_LIQUIDITY_PER_BIN|BinPool__MaxLiquidityPerBinExceeded'}, {'function.body_contains_regex': 'getLiquidity\\s*\\(|getPriceFromId'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — amm-bin-liquidity-overflow-check-only-on-mint-not-swap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
