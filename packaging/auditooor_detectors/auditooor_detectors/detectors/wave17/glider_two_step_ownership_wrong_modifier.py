"""
glider-two-step-ownership-wrong-modifier — generated from reference/patterns.dsl/glider-two-step-ownership-wrong-modifier.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-two-step-ownership-wrong-modifier.yaml
Source: hexens-glider/two-step-ownership-transfer-with-incorrect-modifier
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderTwoStepOwnershipWrongModifier(AbstractDetector):
    ARGUMENT = "glider-two-step-ownership-wrong-modifier"
    HELP = "`acceptOwnership` (or similar) uses `onlyOwner`/`onlyAdmin` as its gate. The accept-side of a two-step transfer must gate on `msg.sender == pendingOwner` — otherwise the current owner can self-complete a transfer they staged, making the second step a no-op and defeating the whole purpose of two-step"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-two-step-ownership-wrong-modifier.yaml"
    WIKI_TITLE = "Two-step ownership transfer: accept gated on current owner rather than pending owner"
    WIKI_DESCRIPTION = "Two-step ownership transfer exists so that a typo in `transferOwnership(newOwner)` cannot brick the contract — the new address must explicitly call `acceptOwnership` to prove it controls that key. If the accept side is gated on `onlyOwner` / `onlyAdmin`, the current owner can complete the transfer themselves (to any address), which (a) re-introduces the single-step risk and (b) sidesteps the hands"
    WIKI_EXPLOIT_SCENARIO = "Current owner calls `transferOwnership(alice)` — pendingOwner = alice. Because `acceptOwnership` is `onlyOwner`, the current owner can now call `acceptOwnership()` themselves and the internal `_transferOwnership(pendingOwner)` fires, setting `owner = alice` without alice's consent or participation. If `pendingOwner` was set by mistake to a dead address, the current owner can still complete the tra"
    WIKI_RECOMMENDATION = "Gate `accept*` on `require(msg.sender == pendingOwner, \"not pending\")`. Do not use an `onlyOwner` modifier on accept-side endpoints. Clear `pendingOwner = address(0)` after a successful accept to prevent re-use."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'pending|proposed|nominated|newOwner|newAdmin|candidate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(acceptOwnership|acceptAdmin|acceptBeneficiary|acceptGovernance|acceptRole|claimOwnership|confirmOwnership|takeOwnership|becomeOwner|finalizeOwnership)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyGovernance', 'onlyRole']}}, {'function.writes_storage_matching': '^(_?owner|_?admin|_?pendingOwner|_?pendingAdmin|_?governance|_?beneficiary)$'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*(?:pending|proposed|nominated|newOwner)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-two-step-ownership-wrong-modifier: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
