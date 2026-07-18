"""
certora-compound-exchange-rate-monotonic — generated from reference/patterns.dsl/certora-compound-exchange-rate-monotonic.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-compound-exchange-rate-monotonic.yaml
Source: certora-compound-v2/CToken/exchangeRateMonotonic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraCompoundExchangeRateMonotonic(AbstractDetector):
    ARGUMENT = "certora-compound-exchange-rate-monotonic"
    HELP = "cToken-like mutator writes cash/borrows/reserves/supply without calling `accrueInterest()` first — Certora `exchangeRateMonotonic` invariant violated."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-compound-exchange-rate-monotonic.yaml"
    WIKI_TITLE = "cToken mutation skips accrueInterest, exchange rate can drop"
    WIKI_DESCRIPTION = "Compound's Certora spec proves that `exchangeRateStored` is non-decreasing block-over-block (modulo reserve withdraws by admin). The core of the proof is that every state mutator first calls `accrueInterest()` and writes `accrualBlockNumber = block.number`. A mutator that updates cash / totalBorrows / totalReserves / totalSupply at a stale block causes the next `exchangeRateStored` computation to "
    WIKI_EXPLOIT_SCENARIO = "A patch adds `adminMint(user, tokens)` that writes `_balances[user] += tokens; totalSupply += tokens;` directly, skipping `accrueInterest`. Right before the next block's accrual, any user who notices calls `redeem(all)` — they redeem at the pre-accrual exchange rate and the protocol realizes the interest it just paid out for free. Net drain: accrued-but-not-applied interest."
    WIKI_RECOMMENDATION = "Every external mutator must start with `require(accrueInterest() == NO_ERROR);` (Compound's own pattern), or equivalent `if (accrualBlockNumber != block.number) { _accrueInterest(); }`. Reproduce Certora's `exchangeRateMonotonic` rule as a Foundry invariant."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(cToken|CToken|CErc20|CEther|exchangeRateStored|accrualBlockNumber|accrueInterest|borrowIndex|totalBorrows|totalReserves|totalCash|comptroller)'}, {'contract.has_state_var_matching': '(?i)(exchangeRate|totalCash|totalBorrows|totalReserves|totalSupply|accrualBlock|borrowIndex)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '(?i)^(mint|redeem|redeemUnderlying|borrow|repay|repayBorrow|repayBorrowBehalf|seize|transfer|transferFrom|_reduceReserves|_addReserves|sweep|sweepToken|adminMint|adminBurn|mintFresh|redeemFresh|borrowFresh|repayBorrowFresh)\\w*$'}, {'function.writes_storage_matching': '(?i)(totalCash|totalBorrows|totalReserves|totalSupply|_balances)'}, {'function.body_not_contains_regex': '(?i)(accrueInterest|_accrueInterest|accrualBlockNumber\\s*==\\s*block|getBlockNumber\\(\\)\\s*==\\s*accrualBlockNumber)'}, {'function.not_source_matches_regex': '(?i)(mintFresh\\s*\\(|redeemFresh\\s*\\(|borrowFresh\\s*\\(|repayBorrowFresh\\s*\\(|view\\s+returns|pure\\s+returns|accrueInterest\\s*\\(\\)\\s*;\\s*_)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — certora-compound-exchange-rate-monotonic: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
