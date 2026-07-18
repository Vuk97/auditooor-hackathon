"""
comet-view-balance-uses-stored-index-no-simulated-accrue — generated from reference/patterns.dsl/comet-view-balance-uses-stored-index-no-simulated-accrue.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py comet-view-balance-uses-stored-index-no-simulated-accrue.yaml
Source: auditooor-R71-fixdiff-mined-compound-comet-e1d3777310
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CometViewBalanceUsesStoredIndexNoSimulatedAccrue(AbstractDetector):
    ARGUMENT = "comet-view-balance-uses-stored-index-no-simulated-accrue"
    HELP = "User-facing view (balanceOf, borrowBalanceOf, totalSupply, totalBorrow, getReserves) reads `baseSupplyIndex` / `baseBorrowIndex` directly from storage without simulating the accrual between `lastAccrualTime` and now. Integrators, liquidation bots, and frontends see stale balances that under-report u"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/comet-view-balance-uses-stored-index-no-simulated-accrue.yaml"
    WIKI_TITLE = "Balance / reserves view consumes stored index, skips just-in-time accrual"
    WIKI_DESCRIPTION = "Comet's interest-bearing indices (`baseSupplyIndex`, `baseBorrowIndex`) are advanced only when a mutating call runs `accrueInternal()`. View functions that price user balances against these indices — `balanceOf`, `borrowBalanceOf`, `totalSupply`, `totalBorrow`, `getReserves` — must extrapolate between the last accrual block and `block.timestamp` to return a live number. Reading the stored indices "
    WIKI_EXPLOIT_SCENARIO = "Comet originally had `balanceOf` in `CometExt` reading `presentValueSupply(baseSupplyIndex, ...)` directly. ChainSecurity 5.9 (commit e1d3777310) moved these views to `Comet.sol` and introduced `accruedInterestIndices(timeElapsed)` so each view computes `(baseSupplyIndex_, baseBorrowIndex_) = accruedInterestIndices(block.timestamp - lastAccrualTime)` before reading. Pre-fix attack: a yield aggrega"
    WIKI_RECOMMENDATION = "Every view that prices balances against an interest-bearing index must compute the index as-of `block.timestamp`, not as-of last mutation. Factor the index-extrapolation into a shared helper (`accruedInterestIndices(timeElapsed)` or `_simulatedIndex()`) and call it from all views AND from the mutati"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'baseSupplyIndex|baseBorrowIndex|lastAccrualTime|accruedInterestIndices'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '^(balanceOf|borrowBalanceOf|totalSupply|totalBorrow|getReserves|sharePrice|exchangeRate)$'}, {'function.body_contains_regex': 'presentValueSupply\\s*\\(\\s*baseSupplyIndex\\s*[,)]|presentValueBorrow\\s*\\(\\s*baseBorrowIndex\\s*[,)]'}, {'function.body_not_contains_regex': 'accruedInterestIndices|_simulatedIndex|baseSupplyIndex_|baseBorrowIndex_|block\\.timestamp\\s*-\\s*lastAccrualTime|getNowInternal\\s*\\(\\s*\\)\\s*-\\s*lastAccrualTime'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — comet-view-balance-uses-stored-index-no-simulated-accrue: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
