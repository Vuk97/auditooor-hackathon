"""
liquidation-dust-repay-dos — generated from reference/patterns.dsl/liquidation-dust-repay-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-dust-repay-dos.yaml
Source: solodit/C0345
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationDustRepayDos(AbstractDetector):
    ARGUMENT = "liquidation-dust-repay-dos"
    HELP = "Liquidation entry point guarded by a strict `require(shares > 0)` / `require(debt > 0)` / exact-amount gate that a borrower can bypass by burning 1 share or repaying 1 wei of dust immediately before the liquidation tx — DoSing the liquidator and indefinitely protecting an unhealthy position."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-dust-repay-dos.yaml"
    WIKI_TITLE = "Liquidation DoS via dust-shares repayment / strict positive gate"
    WIKI_DESCRIPTION = "A `liquidate` / `liquidatePosition` / `liquidateBorrow` entry point contains a strict numeric precondition such as `require(shares > 0)`, `require(debt != 0)`, or `require(amount == x)`. A borrower observing a pending liquidation can call `repay(...)` or `withdraw(1 share)` in the same block to flip the checked quantity to zero / an unexpected value, causing the liquidation to revert. Because the "
    WIKI_EXPLOIT_SCENARIO = "Alice opens a leveraged position on the protocol and it drifts into the liquidatable band. Liquidator Bob sends `liquidate(alice, maxShares)` through the public mempool. Alice sees the pending tx, frontruns it with `repay(1 share)` — her position now has `shares == 0 - 1 = underflow-prevented` / `debt != exact`, so Bob's `liquidate` reverts on `require(shares > 0)`. Alice repeats this every time a"
    WIKI_RECOMMENDATION = "Replace strict positive gates with tolerant ones: accept `shares == 0` as a no-op branch, or treat any non-negative debt as liquidatable down to zero in a single call. Alternatively (a) charge a non-trivial minimum repay amount that exceeds the liquidation gas cost, or (b) authorise liquidations to "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'debt|borrow|collateral|shares|position'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidate|_liquidate|liquidatePosition|forceLiquidate|liquidateBorrow)$'}, {'function.body_contains_regex': {'regex': 'require\\s*\\(.*(shares|debt|borrow|amount)\\s*(>\\s*0|!=\\s*0|\\s*==\\s*amount)'}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-dust-repay-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
