"""
first-depositor-share-front-run-via-empty-vault — generated from reference/patterns.dsl/first-depositor-share-front-run-via-empty-vault.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py first-depositor-share-front-run-via-empty-vault.yaml
Source: solodit-cluster/C0169
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FirstDepositorShareFrontRunViaEmptyVault(AbstractDetector):
    ARGUMENT = "first-depositor-share-front-run-via-empty-vault"
    HELP = "Deposit/mint/stake uses `shares = amount` when `totalSupply == 0` with no dead-share burn; attacker front-runs genuine first depositor, deposits 1 wei, donates reserves to inflate share price and steal the victim's stake."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/first-depositor-share-front-run-via-empty-vault.yaml"
    WIKI_TITLE = "First-depositor share front-run via empty-vault 1:1 fallback"
    WIKI_DESCRIPTION = "A vault's deposit / mint / stake path special-cases the empty-vault state by minting shares 1:1 with the deposited amount (`if (totalSupply == 0) shares = amount;`) and does not permanently burn a MINIMUM_LIQUIDITY / DEAD_SHARES seed on that first mint. An attacker front-runs the genuine first depositor, deposits 1 wei to mint 1 share, then transfers underlying directly into the vault contract. Th"
    WIKI_EXPLOIT_SCENARIO = "ZeroLend-style: Alice is about to deposit 10,000 USDC as the first depositor to a new pool. Mallory front-runs Alice's tx, calling `deposit(1)` to mint 1 share (the `totalSupply == 0` branch assigns `shares = 1`). Mallory then transfers 10,000 USDC directly to the pool (bypassing deposit). When Alice's tx lands, the pool now has `totalSupply = 1` and `totalAssets = 10,001`. Alice's `shares = 10,00"
    WIKI_RECOMMENDATION = "On the first deposit, permanently burn a MINIMUM_LIQUIDITY / DEAD_SHARES amount to address(0) or DEAD_ADDRESS (Uniswap V2 style): `shares = amount - DEAD_SHARES; _mint(DEAD_ADDRESS, DEAD_SHARES);`. Alternatively, seed the vault in the constructor/initializer with a protocol-owned dust deposit so `to"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'totalSupply|totalAssets|shares'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.not_slither_synthetic': True}, {'function.is_mutating': True}, {'function.name_matches': 'deposit|_deposit|mint|stake'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalSupply\\s*==\\s*0|_totalSupply\\s*==\\s*0|totalShares\\s*==\\s*0'}, {'function.body_not_contains_regex': 'DEAD_SHARES|BURN_ADDRESS|_initialize\\s*\\(.*\\d|_burn\\s*\\(.*MIN_SHARES|virtualShares|MINIMUM_LIQUIDITY'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — first-depositor-share-front-run-via-empty-vault: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
