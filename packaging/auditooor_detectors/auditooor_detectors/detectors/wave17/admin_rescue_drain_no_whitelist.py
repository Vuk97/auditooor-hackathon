"""
admin-rescue-drain-no-whitelist — generated from reference/patterns.dsl/admin-rescue-drain-no-whitelist.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py admin-rescue-drain-no-whitelist.yaml
Source: auditooor-cross-cluster
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AdminRescueDrainNoWhitelist(AbstractDetector):
    ARGUMENT = "admin-rescue-drain-no-whitelist"
    HELP = "Admin-gated rescue/sweep function can transfer an arbitrary ERC20 out of the contract. Without a blacklist of the protocol's user-asset tokens (collateral / underlying / stakingToken / shares), a compromised owner can drain user deposits under the pretense of rescuing stuck tokens."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/admin-rescue-drain-no-whitelist.yaml"
    WIKI_TITLE = "Admin rescue/sweep drains user funds (no user-asset blacklist)"
    WIKI_DESCRIPTION = "The contract exposes an onlyOwner / onlyAdmin rescueTokens(address token, …) / emergencyWithdraw / sweep / recoverERC20 entry-point whose body transfers the named token's balance out of the contract. The fix idiom — require(token != asset) / require(token != address(collateral)) / an explicit allow-list of airdropped junk — is missing, so the admin can choose the protocol's primary deposit token a"
    WIKI_EXPLOIT_SCENARIO = "A yield vault holds 10M USDC of user deposits in its `asset` (== USDC) slot. The contract has `function rescueTokens(address token, uint256 amount) external onlyOwner { IERC20(token).transfer(owner, amount); }` with no blacklist. An attacker who compromises the owner key calls rescueTokens(USDC, 10_000_000e6). The entire depositor principal is transferred to the attacker. Users' share tokens still"
    WIKI_RECOMMENDATION = "Blacklist the user-asset tokens in every rescue path: `require(token != asset && token != address(collateral) && token != stakingToken && token != shareToken, 'cannot rescue user asset')`. Better: turn the rescue function into an allow-list of recognised airdrop tokens that explicitly cannot overlap"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'collateral|asset|underlying|depositToken|stakingToken|mainAsset'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'rescue|emergencyRescue|rescueTokens|sweep|_sweep|withdrawStuck|adminWithdraw|recoverERC20'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance'], 'negate': False}}, {'function.has_param_of_type': 'address'}, {'function.body_not_contains_regex': 'require\\s*\\(.*token\\s*!=\\s*(asset|collateral|underlying|stakingToken)|token\\s*!=\\s*address\\s*\\(\\s*collateral|token\\s*!=\\s*address\\s*\\(\\s*asset'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — admin-rescue-drain-no-whitelist: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
