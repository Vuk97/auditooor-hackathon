"""
burn-does-not-update-totalsupply — generated from reference/patterns.dsl/burn-does-not-update-totalsupply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py burn-does-not-update-totalsupply.yaml
Source: solodit/C0107
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BurnDoesNotUpdateTotalsupply(AbstractDetector):
    ARGUMENT = "burn-does-not-update-totalsupply"
    HELP = "Custom burn path decrements balance but never decrements totalSupply — maxSupply caps can be re-minted and pro-rata reward / share math is wrong."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/burn-does-not-update-totalsupply.yaml"
    WIKI_TITLE = "Burn path does not update totalSupply"
    WIKI_DESCRIPTION = "A custom burn / _burn implementation reduces the user's balance field but omits the matching `totalSupply -= amount` write. Downstream logic that caps mints at maxSupply, divides rewards by totalSupply, or uses totalSupply for vault share pricing silently diverges from the true circulating amount."
    WIKI_EXPLOIT_SCENARIO = "Protocol caps supply at 1M. User mints 100k, then burns 100k — balance goes to 0 but totalSupply is still 100k. User mints another 900k without issue; subsequent users find mints blocked because totalSupply + amount > cap while the true circulating supply is only 900k. Worse: a reward pool dividing by a stale totalSupply underpays honest holders."
    WIKI_RECOMMENDATION = "Every burn path that decrements balance MUST mirror with `totalSupply -= amount`. In ERC1155Enumerable also remove the token id from the enumeration array. Add an invariant test: sum(balances) == totalSupply."

    _PRECONDITIONS = [{'contract.has_state_var_matching': '(?i)(totalSupply|_totalSupply|supply|totalLocked|totalShares)'}, {'contract.has_function_matching': '(?i)(burn|_burn)'}, {'contract.source_matches_regex': '(?i)(ERC20|ERC1155|ERC4626|Token|Share|Vault|Pool|mint|burn|totalSupply)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(burn|_burn|burnFrom|_burnFrom|burnFor|burnShares|burnFromShares|burnInternal)$'}, {'function.writes_storage_matching': '(?i)(balance|_balances|shares|locked)'}, {'function.body_not_contains_regex': '(?i)(totalSupply|_totalSupply|supply|totalShares|totalLocked)\\s*(-=|=.*-|\\-\\-)'}, {'function.not_source_matches_regex': '(super\\._burn\\s*\\(|ERC20\\._burn|ERC20Upgradeable\\._burn|_update\\s*\\(\\s*\\w+\\s*,\\s*address\\s*\\(\\s*0\\s*\\)|_beforeTokenTransfer\\s*\\(\\s*\\w+\\s*,\\s*address\\s*\\(\\s*0\\s*\\)|ERC1155\\._burn)'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — burn-does-not-update-totalsupply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
