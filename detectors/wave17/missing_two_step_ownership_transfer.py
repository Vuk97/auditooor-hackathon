"""
missing-two-step-ownership-transfer — generated from reference/patterns.dsl/missing-two-step-ownership-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py missing-two-step-ownership-transfer.yaml
Source: kiln-v1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MissingTwoStepOwnershipTransfer(AbstractDetector):
    ARGUMENT = "missing-two-step-ownership-transfer"
    HELP = "A contract uses single-step transferOwnership that immediately changes ownership, risking permanent lockout if the new owner is a wrong address. Use Ownable2Step (propose → accept) pattern instead."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/missing-two-step-ownership-transfer.yaml"
    WIKI_TITLE = "Missing two-step ownership transfer"
    WIKI_DESCRIPTION = "The contract inherits from Ownable but not Ownable2Step, and has a transferOwnership function that directly sets _owner = newOwner without a two-step (propose → accept) pattern. This can cause permanent lockout if ownership is transferred to a wrong address."
    WIKI_EXPLOIT_SCENARIO = "Owner calls transferOwnership to a mistyped address. Since the transfer is immediate, the owner loses access to all owner-only functions permanently. The funds/permissions locked in the contract can never be recovered."
    WIKI_RECOMMENDATION = "Inherit from Ownable2Step instead of Ownable and use the two-step pattern: transferOwnership (proposes new owner) → acceptOwnership (accepts). This allows the original owner to cancel a pending transfer if a mistake is noticed."

    _PRECONDITIONS = [{'function.contract.source_matches_regex': 'Ownable'}, {'function.contract.not_source_matches_regex': 'Ownable2Step'}]
    _MATCH = [{'function.name_matches': 'transferOwnership'}, {'function.body_contains_regex': '_owner\\s*=\\s*newOwner'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — missing-two-step-ownership-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
