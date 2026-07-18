"""
fee-uncapped-in-constructor — generated from reference/patterns.dsl/fee-uncapped-in-constructor.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fee-uncapped-in-constructor.yaml
Source: solodit-novel/slice_aa-fee-constructor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FeeUncappedInConstructor(AbstractDetector):
    ARGUMENT = "fee-uncapped-in-constructor"
    HELP = "Constructor assigns a fee from a caller-supplied argument without enforcing the same MAX_FEE cap the setter function enforces. Deployment can initialise with an unbounded fee."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fee-uncapped-in-constructor.yaml"
    WIKI_TITLE = "Fee uncapped in constructor (setter enforces cap)"
    WIKI_DESCRIPTION = "A contract defines `MAX_FEE` and a setter `setFee` with `require(newFee <= MAX_FEE)`, but the constructor accepts `_fee` and assigns it directly. The cap is only enforced on updates, not on initial deployment — allowing the deployer to initialise with `fee > MAX_FEE`."
    WIKI_EXPLOIT_SCENARIO = "Protocol deployer (possibly a malicious multisig member) deploys with `fee = 50_00` while `MAX_FEE = 10_00`. Users are subsequently charged 50% of every trade with no way to reduce below 10% unless someone calls the setter (which would revert because `existingFee > MAX_FEE` in some implementations)."
    WIKI_RECOMMENDATION = "Apply the same `require(fee <= MAX_FEE)` in the constructor (or initializer) that setFee uses. Better: factor into a shared `_setFee` internal that both call."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_declaration_matching': 'MAX_\\w*FEE|MAX_FEE_BPS|FEE_CAP'}, {'contract.has_function_body_matching': 'require\\s*\\(\\s*\\w*[fF]ee\\s*<=?\\s*MAX_\\w*FEE'}]
    _MATCH = [{'function.is_constructor': True}, {'function.has_param_of_type': 'uint256'}, {'function.body_contains_regex': '\\w*[fF]ee\\s*='}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*\\w*[fF]ee\\s*<=?\\s*MAX_\\w*FEE|require\\s*\\(\\s*_\\w*fee\\s*<=?\\s*MAX'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fee-uncapped-in-constructor: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
