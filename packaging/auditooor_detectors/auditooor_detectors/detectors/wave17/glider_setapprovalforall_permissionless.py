"""
glider-setapprovalforall-permissionless — generated from reference/patterns.dsl/glider-setapprovalforall-permissionless.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-setapprovalforall-permissionless.yaml
Source: hexens-glider/set-approval-for-all-can-be-called-by-anyone
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderSetapprovalforallPermissionless(AbstractDetector):
    ARGUMENT = "glider-setapprovalforall-permissionless"
    HELP = "Public function calls internal `_setApprovalForAll(owner, operator, true)` with user-controlled `owner` and no validation that `owner == msg.sender`. Any attacker becomes operator over any NFT holder and drains their tokens."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-setapprovalforall-permissionless.yaml"
    WIKI_TITLE = "Permissionless _setApprovalForAll — anyone can become operator"
    WIKI_DESCRIPTION = "`_setApprovalForAll` is the raw internal hook behind `setApprovalForAll(operator, approved)`. The standard wrapper hardcodes `owner = msg.sender`. Any wrapper that passes a user-supplied `owner` without checking `msg.sender == owner` is an approval-hijack primitive — the attacker sets themselves as an operator on any target address and then calls `transferFrom` to drain."
    WIKI_EXPLOIT_SCENARIO = "Custom gated approval function: `grantMarketAccess(address owner, address operator) external { _setApprovalForAll(owner, operator, true); }`. No modifier. Attacker calls `grantMarketAccess(victim, attacker)`. Attacker now operator over every NFT owned by victim → `transferFrom(victim, attacker, tokenId)` for every token."
    WIKI_RECOMMENDATION = "Either derive owner from msg.sender (`_setApprovalForAll(msg.sender, operator, approved)`) or require `msg.sender == owner || approved-operator(msg.sender, owner)`. Never accept unauthenticated `owner`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '_setApprovalForAll|ERC721|ERC1155'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '_setApprovalForAll\\s*\\('}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyRole', 'onlyAdmin', 'onlyApprovedOperator'], 'negate': True}}, {'function.body_not_contains_regex': 'msg\\.sender\\s*==\\s*\\w*owner|require\\s*\\(\\s*\\w+\\s*==\\s*msg\\.sender|_isApprovedOrOwner\\s*\\(\\s*msg\\.sender|ownerOf\\s*\\(\\s*\\w+\\s*\\)\\s*==\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-setapprovalforall-permissionless: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
