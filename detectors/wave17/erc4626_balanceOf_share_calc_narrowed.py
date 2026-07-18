"""
erc4626-balanceOf-share-calc-narrowed — generated from reference/patterns.dsl/erc4626-balanceOf-share-calc-narrowed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py erc4626-balanceOf-share-calc-narrowed.yaml
Source: auditooor/RG-N4-narrowing-2026-05-08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Erc4626BalanceofShareCalcNarrowed(AbstractDetector):
    ARGUMENT = "erc4626-balanceOf-share-calc-narrowed"
    HELP = "ERC-4626-style vault function reads `balanceOf(address(this))` co-located with share-mint or share-redeem arithmetic. Rebasing / fee-on-transfer / donation manipulation can silently move the share-price denominator; refined from a wider type-mentions scanner to require both an actual balanceOf call "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/erc4626-balanceOf-share-calc-narrowed.yaml"
    WIKI_TITLE = "ERC-4626 share-price uses balanceOf(this) in mint/redeem path (narrowed)"
    WIKI_DESCRIPTION = "An ERC-4626-shaped vault computes share quantities using `balanceOf(address(this))` rather than a tracked/checkpointed total-asset variable. When the underlying token is rebasing (stETH/AMPL), fee-on-transfer, or accepts donations, the share-price denominator drifts silently. An attacker deposits before a favourable rebase / donation and withdraws after, siphoning value from honest stakers. This n"
    WIKI_EXPLOIT_SCENARIO = "(1) Vault holds a rebasing token (stETH). preview/_convertToShares does `assets * totalSupply / balanceOf(address(this))`. Attacker deposits $X, waits for stETH rebase (positive yield), redeems shares back at the new (inflated) numerator. Honest stakers' share price did not move proportionally — attacker pockets the rebase delta. (2) Donation variant: attacker transfers underlying directly to the "
    WIKI_RECOMMENDATION = "Track total assets in an explicit storage variable (`totalAssets`, `storedBalance`, `principalTracked`, `checkpointedAssets`) and update it in deposit/withdraw paths via the actual transferred amount (not balanceOf). Reconcile the storage variable on demand in a permissioned `sync()`. Never use `bal"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(totalShares|totalSupply|_totalSupply|share|sharesOf)'}, {'contract.has_function_body_matching': '(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|balanceOf\\s*\\(\\s*this\\s*\\))'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(deposit|mint|withdraw|redeem|preview(Deposit|Mint|Withdraw|Redeem)|_convertToShares|_convertToAssets|totalAssets|_deposit|_withdraw)'}, {'function.body_contains_regex': '(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|IERC20\\s*\\(\\s*asset\\s*\\(\\s*\\)\\s*\\)\\.balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\))'}, {'function.body_contains_regex': '(\\*\\s*(totalShares|totalSupply|_totalSupply)\\s*\\/|\\/\\s*(totalShares|totalSupply|_totalSupply)\\s*\\*|_mint\\s*\\(|_burn\\s*\\()'}, {'function.body_not_contains_regex': '(import\\s|^\\s*using\\s|immutable\\s+\\w+\\s*=|constructor\\s*\\()'}, {'function.is_mutating': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — erc4626-balanceOf-share-calc-narrowed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
