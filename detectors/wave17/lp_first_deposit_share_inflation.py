"""
lp-first-deposit-share-inflation — generated from reference/patterns.dsl/lp-first-deposit-share-inflation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lp-first-deposit-share-inflation.yaml
Source: solodit-cluster/C0237
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LpFirstDepositShareInflation(AbstractDetector):
    ARGUMENT = "lp-first-deposit-share-inflation"
    HELP = "LP deposit uses amount * totalSupply / reserve share math with no first-deposit mitigation; first depositor can inflate share price and zero out future users."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lp-first-deposit-share-inflation.yaml"
    WIKI_TITLE = "LP first-deposit share-price inflation"
    WIKI_DESCRIPTION = "An addLiquidity / deposit / mint entrypoint computes shares as `amount * totalSupply / reserve` without any minimum-shares lock, virtual-shares offset, or burned-initial-liquidity guard. The first depositor can mint 1 wei of shares, then transfer a huge underlying balance directly to the contract, making the share price enormous and forcing all subsequent (smaller) deposits to round down to zero s"
    WIKI_EXPLOIT_SCENARIO = "Attacker is first to call addLiquidity, minting 1 wei worth of LP shares. They then send 10,000 underlying tokens directly to the pool (bypassing the mint path) so totalSupply=1 but reserve=10000e18. Alice later deposits 5,000 tokens expecting ~half the pool; the contract computes shares = 5000e18 * 1 / 10000e18 = 0 and her deposit is absorbed. Attacker then redeems their 1 wei of shares for the f"
    WIKI_RECOMMENDATION = "Mitigate first-depositor inflation using one or more of: (1) mint and permanently burn a MINIMUM_LIQUIDITY amount of shares on the first deposit (Uniswap V2 style); (2) initialize with virtualShares / virtualReserves offsets (Balancer / ERC-4626 style); (3) require the first depositor to be a truste"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'totalSupply|shares|lpToken|reserve|liquidity'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'addLiquidity|deposit|mint|provide|supplyLiquidity'}, {'function.body_contains_regex': {'regex': '\\*\\s*totalSupply\\s*\\/|\\*\\s*_totalShares\\s*\\/|\\*\\s*totalShares\\s*\\/|shares\\s*=\\s*.*totalSupply'}}, {'function.body_not_contains_regex': 'MIN_SHARES|MINIMUM_LIQUIDITY|_mintMinimum|virtualShares|deadShares|firstDeposit|initialDeposit|BURN_ADDRESS'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lp-first-deposit-share-inflation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
