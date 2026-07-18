"""
stake-token-replace-breaks-existing-stakes — generated from reference/patterns.dsl/stake-token-replace-breaks-existing-stakes.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stake-token-replace-breaks-existing-stakes.yaml
Source: solodit/C0377
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakeTokenReplaceBreaksExistingStakes(AbstractDetector):
    ARGUMENT = "stake-token-replace-breaks-existing-stakes"
    HELP = "Admin setter replaces the stake-token / underlying / asset pointer without requiring totalStaked == 0 or running a migration routine; existing user balances (denominated in the OLD token) become unrecoverable or can be double-counted against the NEW token."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stake-token-replace-breaks-existing-stakes.yaml"
    WIKI_TITLE = "Stake-token replacement breaks existing staker balances"
    WIKI_DESCRIPTION = "Staking and vault contracts track user balances as a single uint per address, implicitly denominated in the contract's current stakeToken / underlying / asset. When an admin function re-points that address to a different ERC20 without first draining or explicitly migrating existing deposits, the previously-deposited tokens are stranded in the contract under the old address while user-visible balan"
    WIKI_EXPLOIT_SCENARIO = "Admin calls setStakeToken(newToken) while totalStaked > 0. The function overwrites stakeToken without checking for in-flight deposits. A new user deposits 1000 newToken; their balance[new] = 1000. An old user who had previously deposited 1000 oldToken sees their balance[old] = 1000 still stored. Both users can now call withdraw() which transfers from stakeToken (now newToken). The first withdrawer"
    WIKI_RECOMMENDATION = "Any admin setter that changes the identity of the principal/stake/asset token MUST (a) require(totalStaked == 0) so no prior balances exist, OR (b) execute a bounded migration routine (_migrateStakes / migrationComplete) that converts or refunds every outstanding balance atomically before the pointe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'stakeToken|asset|underlying|principalToken'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(setStakeToken|changeUnderlying|updateAsset|setAsset|migrateToken|replaceToken)$'}, {'function.has_modifier': {'includes': ['onlyOwner', 'onlyAdmin', 'onlyRoles', 'onlyGovernance', 'onlyRole', 'onlyOperator', 'onlyDAO'], 'negate': False}}, {'function.body_not_contains_regex': 'totalStaked\\s*==\\s*0|require\\s*\\(.*totalStaked\\s*==\\s*0|totalSupply\\s*==\\s*0|require\\s*\\(.*totalSupply\\s*==\\s*0|migrationComplete|_migrateStakes|migrateStakes'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — stake-token-replace-breaks-existing-stakes: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
