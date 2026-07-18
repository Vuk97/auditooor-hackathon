"""
comet-wrong-index-supply-vs-borrow-balance — generated from reference/patterns.dsl/comet-wrong-index-supply-vs-borrow-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-wrong-index-supply-vs-borrow-balance.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-804e90e4
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometWrongIndexSupplyVsBorrowBalance(AbstractDetector):
    ARGUMENT = "comet-wrong-index-supply-vs-borrow-balance"
    HELP = "Borrow-balance view converts principal using baseSupplyIndex instead of baseBorrowIndex (or symmetric supply-side mix-up). Interest accrual asymmetry between supply and borrow indices means one is always strictly larger, so the returned debt understates real obligations and lets borrowers under-repa"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-wrong-index-supply-vs-borrow-balance.yaml"
    WIKI_TITLE = "Borrow-balance computed against supply index (swapped-index bug)"
    WIKI_DESCRIPTION = "Index-based lending markets maintain two separate scaled accumulators: `baseSupplyIndex` (grows with supplier rate) and `baseBorrowIndex` (grows with borrower rate, always faster). Each index is the source of truth for converting stored principal back into the current underlying amount for its respective side. A view function that returns a borrower's debt MUST use the borrow index; a view that re"
    WIKI_EXPLOIT_SCENARIO = "Comet's `borrowBalanceOf(account)` originally called `presentValueBorrow(baseSupplyIndex, ...)` instead of `presentValueBorrow(baseBorrowIndex, ...)` (ChainSecurity 5.2, fixed in commit 804e90e4). Because `baseBorrowIndex > baseSupplyIndex` by the time-integrated rate-spread, the reported debt was systematically smaller than actual. A borrower calling `repayBorrow(borrowBalanceOf(self))` would sen"
    WIKI_RECOMMENDATION = "Audit every index-consuming view and write a diffing invariant: `borrowBalanceOf(x)` must use `baseBorrowIndex` (or `borrowIndex`, `cumulativeBorrowIndex`) and `balanceOf(x)` must use `baseSupplyIndex`. Add a unit test where `baseSupplyIndex` and `baseBorrowIndex` are set to clearly different values"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'baseSupplyIndex|baseBorrowIndex|supplyIndex|borrowIndex'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '^(borrowBalanceOf|debtOf|getBorrow|borrowBalance|borrowBalanceCurrent|borrowBalanceStored)$'}, {'function.body_contains_regex': 'presentValueBorrow\\s*\\(\\s*baseSupplyIndex|presentValueBorrow\\s*\\(\\s*supplyIndex|Borrow\\s*\\(\\s*baseSupplyIndex'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-wrong-index-supply-vs-borrow-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
