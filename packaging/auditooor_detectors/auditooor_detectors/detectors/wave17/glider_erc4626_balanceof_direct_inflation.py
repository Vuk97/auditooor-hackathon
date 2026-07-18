"""
glider-erc4626-balanceof-direct-inflation — generated from reference/patterns.dsl/glider-erc4626-balanceof-direct-inflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-erc4626-balanceof-direct-inflation.yaml
Source: hexens-glider/erc-4626-share-inflation-attack
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderErc4626BalanceofDirectInflation(AbstractDetector):
    ARGUMENT = "glider-erc4626-balanceof-direct-inflation"
    HELP = "ERC-4626 vault computes assets from raw `asset.balanceOf(address(this))`. Attacker front-runs the first real depositor with a direct donation + 1-wei deposit to inflate the share price and steal subsequent deposits."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-erc4626-balanceof-direct-inflation.yaml"
    WIKI_TITLE = "ERC-4626 donation / inflation attack via direct balanceOf"
    WIKI_DESCRIPTION = "The share-inflation attack (a.k.a. first-depositor attack) exploits `totalAssets = asset.balanceOf(address(this))` in an empty vault. Attacker deposits 1 wei (gets 1 share), donates 1e18 tokens directly to the vault (skipping deposit). Now 1 share = 1e18+1 assets. Next depositor sending <1e18 gets 0 shares due to truncation, assets absorbed into the attacker's single share."
    WIKI_EXPLOIT_SCENARIO = "Empty vault. Attacker: `vault.deposit(1)` — receives 1 share, vault holds 1 token. Attacker: `asset.transfer(address(vault), 1e18)` — vault now shows totalAssets=1e18+1 but totalSupply=1. Victim: `vault.deposit(5e17)` — `shares = 5e17 * 1 / (1e18+1) = 0`. Victim's deposit is pooled into the attacker's single share."
    WIKI_RECOMMENDATION = "Track assets via an internal accumulator instead of raw balanceOf, OR use the OZ 4.9 virtual-shares / decimals-offset mitigation, OR seed the vault with a one-time dead share at deployment."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'function\\s+(deposit|mint|withdraw|redeem|totalAssets|convertToShares|convertToAssets)\\s*\\('}]
    _MATCH = [{'function.name_matches': '^(totalAssets|convertToShares|convertToAssets|previewDeposit|previewMint|previewWithdraw|previewRedeem)$'}, {'function.kind': 'external_or_public'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|balanceOf\\s*\\(\\s*self\\s*\\)'}, {'function.body_not_contains_regex': 'virtualShares|OFFSET|_storedAssets|storedTotalAssets|10\\s*\\*\\*\\s*_decimalsOffset'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — glider-erc4626-balanceof-direct-inflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
