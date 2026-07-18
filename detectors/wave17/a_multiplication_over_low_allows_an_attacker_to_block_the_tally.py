"""
a-multiplication-over-low-allows-an-attacker-to-block-the-tally — generated from reference/patterns.dsl/a-multiplication-over-low-allows-an-attacker-to-block-the-tally.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-multiplication-over-low-allows-an-attacker-to-block-the-tally.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMultiplicationOverLowAllowsAnAttackerToBlockTheTally(AbstractDetector):
    ARGUMENT = "a-multiplication-over-low-allows-an-attacker-to-block-the-tally"
    HELP = "Oracle supply-change tally logic reads the pending change but skips the local accrue/refresh helper that should bound the multiplication inputs first."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-multiplication-over-low-allows-an-attacker-to-block-the-tally.yaml"
    WIKI_TITLE = "Oracle supply-change tally skips accrual before multiplication"
    WIKI_DESCRIPTION = "The tally path reads an oracle-controlled supply-change value and performs percentile or tally math before the contract refreshes the local accounting state. If a malicious delegate pushes an extreme supply delta, the stale multiplication inputs can revert and block the tally."
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #16750: a malicious delegate submits an arbitrarily large supply increase, then the tally path multiplies against stale state because it skipped the local accrue step. The multiplication reverts and blocks the daily tally."
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '.*(_accrue|accrue|update|sync|refresh).*'}]
    _MATCH = [{'function.name_matches': '.*(postOracleSupplyChange|tallyOracleSupplyChange).*'}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching_regex': '.*(oracleSupplyChange|supplyChange|percentileChange).*'}, {'function.calls_function_matching': {'regex': '.*(_accrue|accrue|update|sync|validate|check|refresh).*', 'negate': True}}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-multiplication-over-low-allows-an-attacker-to-block-the-tally: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
