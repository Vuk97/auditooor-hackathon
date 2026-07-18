"""
r74-input-propose-missing-parameter-checks — generated from reference/patterns.dsl/r74-input-propose-missing-parameter-checks.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-input-propose-missing-parameter-checks.yaml
Source: r74b-cross-firm-cs+tob+oz
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74InputProposeMissingParameterChecks(AbstractDetector):
    ARGUMENT = "r74-input-propose-missing-parameter-checks"
    HELP = "Governance propose() does not verify the length-equality of (targets, values, calldatas, signatures) arrays; mismatched proposals grief the queue or revert post-vote."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-input-propose-missing-parameter-checks.yaml"
    WIKI_TITLE = "Governance propose() missing parallel-array length check"
    WIKI_DESCRIPTION = "OpenZeppelin's Governor and derived governance contracts accept proposals as parallel arrays: targets[i] is called with calldatas[i] carrying values[i]. When propose() does not require these arrays have equal length, a malformed proposal can be registered. The resulting proposal either wastes the governance voting cycle (reverts at execute time after quorum) or occupies a unique proposal ID perman"
    WIKI_EXPLOIT_SCENARIO = "An attacker submits a proposal with targets = [A, B, C], values = [1 wei, 2 wei], calldatas = [call1, call2, call3]. propose() does not check lengths. The proposal is registered, passes quorum because governance tokens vote yes, and on execute() reverts due to the length mismatch. The governance cycle (14 days) is wasted — the community cannot queue the real proposal they wanted during that window"
    WIKI_RECOMMENDATION = "First lines of propose() should be: `require(targets.length == values.length, 'len');  require(targets.length == calldatas.length, 'len');` and (for signatures variant) `require(targets.length == signatures.length, 'len');`. Also reject empty proposals: `require(targets.length > 0, 'empty');`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(propose|proposeWithDescription|proposalThreshold|governor|Governor)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(propose|_propose|submitProposal|createProposal)$'}, {'function.body_contains_regex': '\\btargets\\b|\\bcalldatas\\b|\\bsignatures\\b'}, {'function.body_not_contains_regex': 'targets\\.length\\s*==\\s*values\\.length|values\\.length\\s*==\\s*calldatas\\.length|length\\s*==\\s*\\w+\\.length|require\\s*\\([^)]*\\.length\\s*==\\s*[^)]*\\.length'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-input-propose-missing-parameter-checks: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
