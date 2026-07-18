"""
glider-permissionless-setfee-no-cap — generated from reference/patterns.dsl/glider-permissionless-setfee-no-cap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-permissionless-setfee-no-cap.yaml
Source: glider/exploitable-set-fee-no-access-control
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPermissionlessSetfeeNoCap(AbstractDetector):
    ARGUMENT = "glider-permissionless-setfee-no-cap"
    HELP = "setFee / setRate / setPerformanceFee setter has no access control AND no upper-bound check. Anyone can push fees to extreme values, bricking swaps or capturing user assets."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-permissionless-setfee-no-cap.yaml"
    WIKI_TITLE = "Permissionless setFee with no upper-bound cap"
    WIKI_DESCRIPTION = "Fee-setter functions must be both role-gated and have a cap (`require(newFee <= MAX_FEE_BPS)`). When a setter has neither, any caller can crank the fee to 100%, denying user exits or capturing their value on each interaction."
    WIKI_EXPLOIT_SCENARIO = "Contract exposes `setPerformanceFee(uint256 newFee)` without `onlyOwner` and with no cap. Attacker calls `setPerformanceFee(type(uint256).max)`. Next harvest or withdraw applies the unbounded fee, transferring the entire vault balance to the fee recipient."
    WIKI_RECOMMENDATION = "Add `onlyOwner` / `onlyRole(ADMIN_ROLE)` and a compile-time upper bound: `require(newFee <= MAX_FEE_BPS, 'cap'); fee = newFee;`. Emit an event for off-chain monitoring."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(fee|Fee|rate|Rate)\\s*[+=]|feeBps|FEE_BPS|protocolFee|performanceFee'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^set\\w*Fee\\w*'}, {'function.body_contains_regex': '\\w*[Ff]ee\\w*\\s*=\\s*\\w+'}, {'function.body_not_contains_regex': 'onlyOwner|onlyRole|hasRole|_checkRole|onlyGovernor|onlyAdmin|msg\\.sender\\s*==\\s*(owner|admin|governor)|require\\s*\\(\\s*\\w*[Ff]ee\\w*\\s*<=\\s*\\d'}, {'function.has_modifier': {'includes': []}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-permissionless-setfee-no-cap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
