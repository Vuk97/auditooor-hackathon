"""
yield-protocol-balance-of-self-used-instead-of-cached — generated from reference/patterns.dsl/yield-protocol-balance-of-self-used-instead-of-cached.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py yield-protocol-balance-of-self-used-instead-of-cached.yaml
Source: auditooor-R76-immunefi-yield-$95k
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class YieldProtocolBalanceOfSelfUsedInsteadOfCached(AbstractDetector):
    ARGUMENT = "yield-protocol-balance-of-self-used-instead-of-cached"
    HELP = "burn/withdraw uses live `pool.balanceOf(address(this))` to compute output. Attacker donates tokens to inflate balance, mints shares, burns to extract donation + portion of other users' assets."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/yield-protocol-balance-of-self-used-instead-of-cached.yaml"
    WIKI_TITLE = "Burn/withdraw uses live balanceOf(this) — donation inflates output"
    WIKI_DESCRIPTION = "Strategy/vault withdrawal paths that compute `output = pool.balanceOf(address(this)) * shareBurn / totalSupply` are donation-attackable: any transfer directly into the strategy address inflates balanceOf without changing totalSupply. The attacker mints a few shares, transfers a large amount to inflate balanceOf, then burns shares to extract proportionally. Even simpler: the attacker transfers-then"
    WIKI_EXPLOIT_SCENARIO = "Yield Protocol's strategy `burn(address to)` computed `poolTokensObtained = pool.balanceOf(address(this)) * burnt / totalSupply_`. Attacker: (1) transfer X pool tokens to strategy, (2) mint strategy shares (proportional), (3) burn → withdraw (balance inflated by donation). Repeat across Arbitrum and mainnet. ~$950k at risk; $95k bounty. Fix: use `poolCached_` (last-snapshotted balance) instead."
    WIKI_RECOMMENDATION = "Vaults must track an internal `_totalAssets` or `poolCached` variable updated on every mint/burn/rewardCollection — never trust live `balanceOf(this)`. For ERC-4626 vaults, use virtual shares + virtual assets (OZ ERC4626 defenses). Before any output calculation, call `_sync()` to reconcile the cache"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.is_yield_strategy_or_vault': True}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^burn$|^withdraw$|^redeem$|^exit\\w*'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': '(?i)pool\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|IERC20\\(\\w+\\)\\.balanceOf\\s*\\(\\s*address\\(this\\)|asset\\.balanceOf\\s*\\(\\s*address\\(this\\)\\s*\\)'}, {'function.body_not_contains_regex': '(?i)poolCached|cachedBalance|_totalAssets\\s*=|_snapshot\\(\\)|skim\\(|sync\\(\\)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — yield-protocol-balance-of-self-used-instead-of-cached: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
