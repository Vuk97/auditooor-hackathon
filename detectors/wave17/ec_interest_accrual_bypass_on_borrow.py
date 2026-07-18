"""
ec-interest-accrual-bypass-on-borrow — generated from reference/patterns.dsl/ec-interest-accrual-bypass-on-borrow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-interest-accrual-bypass-on-borrow.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcInterestAccrualBypassOnBorrow(AbstractDetector):
    ARGUMENT = "ec-interest-accrual-bypass-on-borrow"
    HELP = "borrow/redeem reads totalBorrows or borrowIndex without calling accrueInterest() first; stale debt allows over-borrowing against real collateral capacity."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-interest-accrual-bypass-on-borrow.yaml"
    WIKI_TITLE = "Interest accrual bypass on borrow — stale totalBorrows used for capacity check"
    WIKI_DESCRIPTION = "The borrow or redeem function reads totalBorrows (or borrowIndex, borrowBalanceStored) to compute available liquidity without first calling accrueInterest(). Between blocks, interest accumulates off-chain but is not reflected in the contract state until accrual runs. A borrower using a stale totalBorrows value can borrow against under-reported debt, exceeding the protocol's true capacity limit."
    WIKI_EXPLOIT_SCENARIO = "Block N-1: 1000 USDC borrowed, accrued. Block N: Interest would make real debt 1005 USDC. User calls borrow() without prior accrual. Contract sees totalBorrows=1000, computes available=200. User borrows 200. Real available was only 195 (post-accrual), 5 USDC extracted from reserves."
    WIKI_RECOMMENDATION = "Call accrueInterest() as the first operation in borrow(), redeem(), and any function that checks collateral factor against debt. This ensures totalBorrows reflects all interest up to the current block. In Compound V2: this is enforced by the accrualBlockNumber check — verify your fork preserves it."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'accrueInterest|totalBorrows|borrowIndex|borrowBalanceStored'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(borrow|_borrow|borrowInternal|mintCToken|redeemUnderlying)'}, {'function.body_contains_regex': 'totalBorrows\\b|borrowBalanceStored|borrowIndex\\b|getBorrowBalance'}, {'function.body_not_contains_regex': 'accrueInterest\\(\\)|_accrueInterest\\(\\)|accrue\\(\\)|accrualBlockNumber'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-interest-accrual-bypass-on-borrow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
