"""
stake-old-depositor-steals-new-pre-initial-stake — generated from reference/patterns.dsl/stake-old-depositor-steals-new-pre-initial-stake.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stake-old-depositor-steals-new-pre-initial-stake.yaml
Source: solodit/H-18-staking-funds-vault
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakeOldDepositorStealsNewPreInitialStake(AbstractDetector):
    ARGUMENT = "stake-old-depositor-steals-new-pre-initial-stake"
    HELP = "Staking-vault deposit computes shares as `amount * totalSupply / totalStaked` with no seed/first-depositor guard. The classic ERC-4626 inflation attack: the first depositor donates an enormous underlying balance directly to the vault, then deposits 1 wei to capture the totalStaked, causing subsequen"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stake-old-depositor-steals-new-pre-initial-stake.yaml"
    WIKI_TITLE = "Stake/deposit vault has no first-depositor seed — share inflation attack"
    WIKI_DESCRIPTION = "Any staking / vault flow that converts `amount` to `shares` via `shares = amount * totalSupply / totalStaked` is vulnerable to share-price manipulation if the first depositor can establish an arbitrary ratio. The canonical attack: attacker deposits 1 wei (receives 1 share), direct-transfers 10_000 underlying to the vault (no supply change), then any honest user depositing 9_999 underlying receives"
    WIKI_EXPLOIT_SCENARIO = "Attacker calls `stake(1)` → receives 1 share, `totalSupply = 1`, `totalStaked = 1`. Attacker transfers `10e18` of the underlying directly to the vault (bypassing `stake`). `totalStaked` in storage remains 1, but the **actual** underlying balance is `10e18 + 1`. Honest user Alice calls `stake(5e18)`, computing `shares = 5e18 * 1 / 1 == 5e18` if the code uses `totalStaked` storage, OR `shares = 5e18"
    WIKI_RECOMMENDATION = "On first deposit, either (a) mint a minimum-liquidity dead share to `address(0)` / `address(1)` (UniswapV2 pattern), (b) require the first depositor be the protocol and hard-code a sensible initial ratio, or (c) use virtual-offset accounting: `shares = amount * (totalSupply + VIRTUAL_SHARES) / (tota"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(Vault|Staking|ERC4626|shares|Shares|totalSupply|totalStaked|totalShares)'}, {'contract.has_state_var_matching': 'totalSupply|totalStaked|totalShares|_totalStaked'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(stake|deposit|depositStake|_deposit|depositFunds|depositFor|depositETH)$'}, {'function.not_source_matches_regex': '(MINIMUM_LIQUIDITY|firstDeposit|_mint\\s*\\(\\s*address\\s*\\(\\s*0\\s*\\)|VIRTUAL_SHARES|VIRTUAL_ASSETS|address\\s*\\(\\s*1\\s*\\)|deadShares)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '\\*\\s*totalSupply\\s*/|\\*\\s*totalShares\\s*/|\\*\\s*_totalStaked\\s*/|\\*\\s*totalStaked\\s*/'}, {'function.body_not_contains_regex': 'MINIMUM_LIQUIDITY|firstDeposit|_mint\\s*\\(\\s*address\\s*\\(\\s*0\\s*\\)|dead\\s*=\\s*|address\\s*\\(\\s*1\\s*\\)|totalSupply\\s*==\\s*0\\s*\\?\\s*amount'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — stake-old-depositor-steals-new-pre-initial-stake: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
