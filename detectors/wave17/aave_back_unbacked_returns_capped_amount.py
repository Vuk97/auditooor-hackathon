"""
aave-back-unbacked-returns-capped-amount — generated from reference/patterns.dsl/aave-back-unbacked-returns-capped-amount.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py aave-back-unbacked-returns-capped-amount.yaml
Source: auditooor-R71-fixdiff-mined-aave-v3-core-526a1e6965
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AaveBackUnbackedReturnsCappedAmount(AbstractDetector):
    ARGUMENT = "aave-back-unbacked-returns-capped-amount"
    HELP = "backUnbacked silently caps the requested amount at the outstanding unbacked balance but does not return the actual backed amount to the caller — bridge/integrator double-counts user funds."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/aave-back-unbacked-returns-capped-amount.yaml"
    WIKI_TITLE = "backUnbacked returns no value — caller cannot know true amount backed after capping"
    WIKI_DESCRIPTION = "Aave v3's Pool.backUnbacked(asset, amount, fee) lets a whitelisted bridge 'back' an outstanding unbacked balance with real underlying. The routine caps `amount` at the current `unbacked` balance because you cannot back more than what was minted — surplus is rejected silently. Pre-fix the function returned void, so the caller had no on-chain way to learn whether its whole `amount` was consumed or t"
    WIKI_EXPLOIT_SCENARIO = "Bridge contract B holds 1000 USDC earmarked for backing unbacked mints on Aave. It calls `pool.backUnbacked(USDC, 1000, fee)`. Aave's current unbacked balance is only 300 USDC, so the call consumes 300 USDC + fee; the remaining 700 stays in B's balance but B's internal accounting marks all 1000 as 'sent to Aave'. B now reports too little reserve, causing it to throttle new cross-chain mints or, if"
    WIKI_RECOMMENDATION = "Make backUnbacked (and its library implementation executeBackUnbacked) return the actual backed amount: `returns (uint256 backingAmount)`. Bridge integrators must read and reconcile the return value against their own ledger; never assume the full `amount` argument was consumed."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'backUnbacked|executeBackUnbacked'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'backUnbacked|executeBackUnbacked'}, {'function.body_contains_regex': 'unbacked|mintUnbacked|backingAmount'}, {'function.body_not_contains_regex': 'return\\s+backingAmount|return\\s+\\w+\\.backingAmount|returns\\s*\\(\\s*uint256\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — aave-back-unbacked-returns-capped-amount: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
