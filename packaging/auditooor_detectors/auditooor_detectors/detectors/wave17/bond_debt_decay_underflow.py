"""
bond-debt-decay-underflow — generated from reference/patterns.dsl/bond-debt-decay-underflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py bond-debt-decay-underflow.yaml
Source: solodit/C0041
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BondDebtDecayUnderflow(AbstractDetector):
    ARGUMENT = "bond-debt-decay-underflow"
    HELP = "Bond market decays debt via raw subtraction (debt - decay / lastDebt - … / totalDebt -=) with no saturation floor. After a long idle period or an admin parameter change the computed decay can exceed the running debt, panic-reverting the market and permanently bricking bond issuance."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/bond-debt-decay-underflow.yaml"
    WIKI_TITLE = "Bond debt decay can underflow and brick the market"
    WIKI_DESCRIPTION = "A bond market's debt-decay helper (or a caller such as marketPrice / findMarketFor / _currentDebt) subtracts a time-scaled decayAmount from the stored debt without checking that debt >= decayAmount. In Solidity >=0.8 this panic-reverts on underflow. After a prolonged idle period between purchases, or after an admin sets a higher decay interval via setDefaults, the cumulative decay can exceed the r"
    WIKI_EXPLOIT_SCENARIO = "BondBaseSDA tracks market.totalDebt which grows on each purchase and naturally decays with time. The internal helper _currentDebt returns `market.totalDebt - decay` where `decay = totalDebt * secondsSinceLastDecay / decayInterval`. After a quiet weekend the computed decay exceeds totalDebt, so _currentDebt reverts. marketPrice() calls _currentDebt, findMarketFor() calls marketPrice(), purchaseBond"
    WIKI_RECOMMENDATION = "Use a saturating subtraction on the decay write. Either `market.totalDebt = decay > market.totalDebt ? 0 : market.totalDebt - decay;`, or `market.totalDebt -= Math.min(market.totalDebt, decay);`, or gate the decrement behind `if (market.totalDebt >= decay)`. Validate BondBaseSDA.setDefaults inputs s"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'debt|bond|market|decay|debtDecay'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'debtDecay|_currentDebt|_decayDebt|marketPrice|_marketPrice|findMarketFor|_updateDebt|totalDebt'}, {'function.body_contains_regex': {'regex': 'debt\\s*-\\s*decay|lastDebt\\s*-\\s*|totalDebt\\s*-=?\\s*'}}, {'function.body_not_contains_regex': 'unchecked|Math\\.min|\\?\\s*.*-.*:\\s*0|if\\s*\\(.*debt\\s*>=?'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bond-debt-decay-underflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
