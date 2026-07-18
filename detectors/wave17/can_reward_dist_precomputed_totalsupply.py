"""
can-reward-dist-precomputed-totalsupply — generated from reference/patterns.dsl/can-reward-dist-precomputed-totalsupply.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-reward-dist-precomputed-totalsupply.yaml
Source: cantina/2024-2025-competitions-reward-staleness-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanRewardDistPrecomputedTotalsupply(AbstractDetector):
    ARGUMENT = "can-reward-dist-precomputed-totalsupply"
    HELP = "Reward / fee distribution divides by a totalSupply snapshot taken BEFORE the same tx's mint or burn — new depositor dilutes existing, or exiting user gets share of their own distribution."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-reward-dist-precomputed-totalsupply.yaml"
    WIKI_TITLE = "Reward distribution uses pre-mutation totalSupply snapshot"
    WIKI_DESCRIPTION = "A function that both mutates shares (mint/burn) and distributes a reward must divide the reward by the share total AT THE DISTRIBUTION MOMENT, not at function entry. Snapshotting totalSupply into a local, calling _mint, then `reward / snapshotTotal` splits the reward using the pre-mint denominator — the newly-minted shares receive their pro-rata portion against a denominator that excludes them, so"
    WIKI_EXPLOIT_SCENARIO = "A yield vault's `deposit(amount)` computes `fee = (amount * feeBps) / 10000`, caches `uint256 tsBefore = totalSupply()`, mints shares to the depositor, then credits `fee * 1e18 / tsBefore` to the reward index. The new depositor's freshly-minted shares now claim against that same index — in effect collecting a share of the fee they just paid. Multiple consecutive deposits amplify the leak."
    WIKI_RECOMMENDATION = "Compute the reward-per-share divisor AFTER all mint/burn state mutations, or explicitly pass the post-mutation total into the distribution math. Prefer the OZ ERC4626 pattern where `_deposit` emits `Transfer` for accounting but defers reward accrual to a checkpoint hook that reads live totals. Unit-"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'totalSupply|totalShares|totalStaked|totalAssets'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|mint|stake|withdraw|redeem|burn|distribute|notifyRewardAmount|harvest|accrue|updateIndex)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '(uint256|uint128|uint)\\s+(_?total|_?supply|_?cached|prev\\w*)\\s*=\\s*(totalSupply|totalShares|totalStaked|totalAssets)\\s*\\('}, {'function.body_contains_regex': '(_mint|_burn|mint\\s*\\(|burn\\s*\\()'}, {'function.body_contains_regex': '/\\s*(_?total|_?supply|_?cached|prev\\w*)'}, {'function.body_not_contains_regex': 'totalSupply\\s*\\(\\s*\\)\\s*-\\s*|\\+\\s*amount|post\\w*Supply|newTotal'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-reward-dist-precomputed-totalsupply: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
