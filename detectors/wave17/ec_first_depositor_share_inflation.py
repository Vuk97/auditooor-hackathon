"""
ec-first-depositor-share-inflation — generated from reference/patterns.dsl/ec-first-depositor-share-inflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-first-depositor-share-inflation.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcFirstDepositorShareInflation(AbstractDetector):
    ARGUMENT = "ec-first-depositor-share-inflation"
    HELP = "Deposit function has a totalSupply==0 branch that mints 1:1 shares with no dead-share burn or virtual offset; first depositor can donate to inflate and grief subsequent depositors."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-first-depositor-share-inflation.yaml"
    WIKI_TITLE = "First-depositor share inflation — no dead-share burn or virtual offset"
    WIKI_DESCRIPTION = "When totalSupply equals zero, the deposit function mints shares at a 1:1 ratio to the deposited amount without burning any dead shares or applying a virtual offset. An attacker can be the first depositor with 1 wei, receive 1 share, then donate a large amount of tokens directly to the vault address. The inflated totalAssets makes the second depositor's shares round to 0 (dust amounts) or receive f"
    WIKI_EXPLOIT_SCENARIO = "Vault empty: totalSupply=0, totalAssets=0. Attacker deposits 1 wei, gets 1 share. Attacker donates 1e18 tokens to vault address directly. totalAssets=1e18+1, totalSupply=1. Victim deposits 1e18 tokens: shares = 1e18 * 1 / (1e18+1) = 0 (rounds down). Victim loses 1e18 tokens. Attacker redeems 1 share for 2e18 tokens."
    WIKI_RECOMMENDATION = "On first deposit (totalSupply == 0): burn a minimum number of shares to a dead address (e.g., 1000 dead shares) or add a virtual offset to totalAssets and totalSupply in the share price formula. OpenZeppelin's ERC-4626 implementation adds a 10**_decimalsOffset() virtual offset as the standard mitiga"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'totalAssets|totalSupply|convertToShares|_mint'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|mint|_deposit|_mint)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'totalSupply\\s*==\\s*0|totalAssets\\s*==\\s*0|_totalSupply\\s*==\\s*0|supply\\s*==\\s*0'}, {'function.body_contains_regex': '_mint\\s*\\(|shares\\s*=.*amount'}, {'function.body_not_contains_regex': 'DEAD_SHARES|deadShares|_DEAD|1000.*burn|virtualOffset|VIRTUAL|offset'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-first-depositor-share-inflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
