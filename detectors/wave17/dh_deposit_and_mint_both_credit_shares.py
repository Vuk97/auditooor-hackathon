"""
dh-deposit-and-mint-both-credit-shares — generated from reference/patterns.dsl/dh-deposit-and-mint-both-credit-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py dh-deposit-and-mint-both-credit-shares.yaml
Source: defihacklabs-2025-06/MetaPool
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DhDepositAndMintBothCreditShares(AbstractDetector):
    ARGUMENT = "dh-deposit-and-mint-both-credit-shares"
    HELP = "ERC4626-ish vault exposes a `mint(shares, receiver)` entrypoint that credits shares without pulling any underlying asset. When combined with a `deposit` that already mints, the same payment can be credited twice."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/dh-deposit-and-mint-both-credit-shares.yaml"
    WIKI_TITLE = "ERC4626 mint() credits shares without collecting underlying"
    WIKI_DESCRIPTION = "A liquid-staking / vault contract exposes both `deposit(..)` (which takes assets in and mints shares) and `mint(shares, receiver)` (which is expected to mint shares in exchange for assets pulled via transferFrom / msg.value). The `mint` entrypoint only updates the share bookkeeping — it does not pull any underlying in. If the user already holds a share receipt from an earlier deposit call in the s"
    WIKI_EXPLOIT_SCENARIO = "Meta Pool mpETH (Jun 2025, ~$27M): attacker flash-loans ETH, calls `depositETH{value: 107 ether}(me)` which mints ~97 mpETH and RETURNS 97. Attacker then calls `mint(97 ether, me)` — which simply does `_balances[me] += 97 ether` without pulling anything. Attacker now holds ~194 mpETH for 107 ETH of deposit. Redeems via the mpETH/ETH pool, repays flash loan, pockets the difference."
    WIKI_RECOMMENDATION = "Either (a) remove the standalone `mint(shares, receiver)` entrypoint and keep only `deposit(assets, receiver)`, or (b) implement `mint` as the EIP-4626 spec prescribes: compute `assets = _convertToAssets(shares)` and `safeTransferFrom(msg.sender, address(this), assets)` BEFORE the `_mint(receiver, s"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\bmint\\s*\\(|\\bdepositETH\\s*\\(|\\bdeposit\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^mint$'}, {'function.has_param_name_matching': 'shares|amount|receiver'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\[|_mint\\s*\\(|totalSupply\\s*[+\\-]\\s*=|_balances\\s*\\['}, {'function.body_not_contains_regex': 'transferFrom\\s*\\(|\\.call\\{\\s*value|safeTransferFrom|convertToAssets|_deposit\\s*\\('}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — dh-deposit-and-mint-both-credit-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
