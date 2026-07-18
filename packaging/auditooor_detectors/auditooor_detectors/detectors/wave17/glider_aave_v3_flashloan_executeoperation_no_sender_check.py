"""
glider-aave-v3-flashloan-executeoperation-no-sender-check — generated from reference/patterns.dsl/glider-aave-v3-flashloan-executeoperation-no-sender-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-aave-v3-flashloan-executeoperation-no-sender-check.yaml
Source: hexens-glider/aave-v3-flashloan-callback-execute-operation-lacks
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderAaveV3FlashloanExecuteoperationNoSenderCheck(AbstractDetector):
    ARGUMENT = "glider-aave-v3-flashloan-executeoperation-no-sender-check"
    HELP = "Aave V3 flashloan receiver `executeOperation` does not verify `msg.sender == POOL` and does not bind the `initiator` parameter to a trusted caller. Anyone can call the receiver directly and trigger any post-loan logic without actually borrowing."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-aave-v3-flashloan-executeoperation-no-sender-check.yaml"
    WIKI_TITLE = "Aave V3 flashloan executeOperation missing pool / initiator validation"
    WIKI_DESCRIPTION = "Aave V3 flashloan receivers implement `executeOperation(address[] assets, uint256[] amounts, uint256[] premiums, address initiator, bytes params)`. The contract MUST verify two things before acting: (1) `msg.sender` is the canonical Aave pool (otherwise any EOA can fake a callback), and (2) the `initiator` is an address the receiver itself triggered (otherwise arbitrary parties can steer the recei"
    WIKI_EXPLOIT_SCENARIO = "Receiver spends `amounts[0]` into a DEX swap and transfers proceeds to `initiator`. Attacker calls `executeOperation` directly, passes `initiator=attacker`, no tokens ever flowed in, but post-flash logic still executes and transfers residual contract balance to the attacker."
    WIKI_RECOMMENDATION = "Add `require(msg.sender == address(POOL), \"caller not pool\")` at the top of the callback AND `require(initiator == address(this), \"initiator not self\")` if only self-initiated flashloans are expected."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'executeOperation\\s*\\('}]
    _MATCH = [{'function.name_matches': '^executeOperation$'}, {'function.kind': 'external_or_public'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(address\\()?\\s*(POOL|pool|_pool|addressesProvider|ADDRESSES_PROVIDER|LENDING_POOL|lendingPool)|initiator\\s*==|require\\s*\\(\\s*initiator'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — glider-aave-v3-flashloan-executeoperation-no-sender-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
