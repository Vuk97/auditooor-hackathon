"""
fee-setter-range-check-uses-old-value-not-new — generated from reference/patterns.dsl/fee-setter-range-check-uses-old-value-not-new.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-setter-range-check-uses-old-value-not-new.yaml
Source: auditooor-R75-nethermind-puffer-MEDIUM
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeSetterRangeCheckUsesOldValueNotNew(AbstractDetector):
    ARGUMENT = "fee-setter-range-check-uses-old-value-not-new"
    HELP = "A setter for a fee/rate/threshold reads the parameter as `newValue` but then range-checks `storage.value` (the old value) instead. The guard is effectively never triggered for legitimate updates, so any value can be written. Once an out-of-range value is stored, future updates remain unblocked becau"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-setter-range-check-uses-old-value-not-new.yaml"
    WIKI_TITLE = "Fee/rate setter compares stored old value to max instead of the new input"
    WIKI_DESCRIPTION = "Classic copy-paste bug: `function _setProtocolFeeRate(uint256 newRate) { if ($.protocolFeeRate > MAX) revert; $.protocolFeeRate = newRate; }` — the check gates on the OLD `$.protocolFeeRate`, not `newRate`. An attacker with access to the setter (DAO, multisig, or a bug that permissions them) can set the fee above the documented maximum in one transaction. Worse: once set above max, the guard still"
    WIKI_EXPLOIT_SCENARIO = "PufferProtocol DAO sets `_setProtocolFeeRate(5000)` (50%). Check `if ($.protocolFeeRate > 1000) revert` — stored is 0 (init) or previously 200, so check passes. Storage is written to 5000. DAO now tries to `_setProtocolFeeRate(500)` — check reads $.protocolFeeRate=5000, 5000>1000 reverts. Protocol permanently stuck at 50% fee."
    WIKI_RECOMMENDATION = "Always gate on the NEW parameter: `if (newRate > MAX) revert;`. Consider adding fuzz tests that call setter twice in a row and assert invariants hold between calls. Unit test that setter with valid input after-invalid-input recovery works."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(setFee|setProtocolFee|setRate|setGuardiansFee|setThreshold)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '_?set(Protocol|Guardian|Treasury|Admin|Manager)?Fee(Rate|Bps|Percent)?|set[A-Z][a-zA-Z]*(Rate|Bps|Percent|Fee)'}, {'function.body_contains_regex': 'function\\s+\\w+\\s*\\(\\s*uint(256|128|64)?\\s+(new[A-Z][a-zA-Z]*|_new[A-Z][a-zA-Z]*)'}, {'function.body_contains_regex': 'if\\s*\\(\\s*\\$?\\.?[a-zA-Z_0-9]+(Fee|Rate|protocolFee|guardiansFee)[a-zA-Z_0-9]*\\s*>\\s*[0-9]+\\s*\\)'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*new[A-Z][a-zA-Z]*\\s*>\\s*[0-9]+|if\\s*\\(\\s*_new[A-Z][a-zA-Z]*\\s*>\\s*[0-9]+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-setter-range-check-uses-old-value-not-new: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
