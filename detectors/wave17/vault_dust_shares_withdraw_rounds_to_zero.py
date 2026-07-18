"""
vault-dust-shares-withdraw-rounds-to-zero — generated from reference/patterns.dsl/vault-dust-shares-withdraw-rounds-to-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-dust-shares-withdraw-rounds-to-zero.yaml
Source: solodit/vault-dust-redeem-round-down-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultDustSharesWithdrawRoundsToZero(AbstractDetector):
    ARGUMENT = "vault-dust-shares-withdraw-rounds-to-zero"
    HELP = "Share-based vault redeem/withdraw computes assets = shares * totalAssets / totalSupply without ceil-rounding or a require(assets > 0) guard; a user redeeming a tiny number of shares burns them for zero assets."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-dust-shares-withdraw-rounds-to-zero.yaml"
    WIKI_TITLE = "Vault dust-shares redeem/withdraw rounds assets to zero"
    WIKI_DESCRIPTION = "The vault converts shares to assets using floor division: `assets = shares * totalAssets / totalSupply`. When `shares * totalAssets < totalSupply`, the integer result is zero and the redeem path still burns the caller's shares while transferring zero assets. The caller loses the shares with nothing in exchange; the rest of the pool silently inherits the redeemed value via a slightly higher price-p"
    WIKI_EXPLOIT_SCENARIO = "A user holds 1 share of a vault where totalSupply = 1e18 and totalAssets = 9e17 (< totalSupply). They call `redeem(1)`. The vault computes assets = 1 * 9e17 / 1e18 = 0 (floor). The vault burns the 1 share, transfers 0 assets, emits a successful event. The user's share is destroyed for nothing; the remaining holders' price-per-share rises infinitesimally. At scale (e.g. accidental dust balances lef"
    WIKI_RECOMMENDATION = "Either (a) round UP when converting shares to assets in redeem/withdraw paths (use `ceilDiv` / `Math.ceilDiv` / `mulDivRoundingUp`), so the last caller absorbs the rounding cost rather than the redeemer, or (b) revert with `require(assets > 0, \"ZeroAssets\")` so a dust redeem fails loudly instead o"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'totalAssets|totalSupply|shares'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(redeem|withdraw|_withdraw|unstake|cashOut)$'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(shares\\s*\\*\\s*totalAssets\\s*\\/|_convertToAssets\\s*\\(\\s*shares|shares\\s*\\*\\s*_totalSupply)'}, {'function.body_not_contains_regex': '(ceilDiv|Math\\.ceilDiv|mulDivRoundingUp|require\\s*\\(.*assets\\s*>\\s*0|require\\s*\\(.*_assets\\s*!=\\s*0)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — vault-dust-shares-withdraw-rounds-to-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
