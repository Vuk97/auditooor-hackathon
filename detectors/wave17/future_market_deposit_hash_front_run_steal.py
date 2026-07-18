"""
future-market-deposit-hash-front-run-steal — generated from reference/patterns.dsl/future-market-deposit-hash-front-run-steal.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py future-market-deposit-hash-front-run-steal.yaml
Source: auditooor-R75-nethermind-ccdm-CRITICAL
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FutureMarketDepositHashFrontRunSteal(AbstractDetector):
    ARGUMENT = "future-market-deposit-hash-front-run-steal"
    HELP = "Depositing into a market keyed by marketHash without validating that the market exists lets an attacker front-run market-creation, depositing into a not-yet-existent marketHash. Solmate's SafeTransferLib does not check code existence, so transferFrom against address(0) silently succeeds; internal ac"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/future-market-deposit-hash-front-run-steal.yaml"
    WIKI_TITLE = "Deposit into non-existent market-hash allows front-running steal once market is created"
    WIKI_DESCRIPTION = "Protocols that let users deposit into markets/campaigns identified by a bytes32 hash (often keccak of token pair + params) and look up the market's input token by hash can be tricked if the hash does not yet have a registered market. Solmate's SafeTransferLib performs inline-assembly calls and doesn't verify code existence at the target, so a call to safeTransferFrom against address(0) (or any EOA"
    WIKI_EXPLOIT_SCENARIO = "A Royco/CCDM-style locker lets anyone deposit into marketHash H. Attacker monitors mempool for a createMarket(H) transaction (or a future Uni V2 pair creation). Before H is registered, attacker calls deposit() with a Weiroll wallet pointing to marketHash=H. The input-token lookup returns address(0); Solmate's safeTransferFrom returns without reverting; internal depositor balance for H is credited "
    WIKI_RECOMMENDATION = "Before accepting a deposit, verify the market exists (e.g. require(marketHashToWeirollMarket[targetMarketHash].owner != address(0))) and verify the resolved token address has code (e.g. require(address(marketInputToken).code.length > 0)). Alternatively use OpenZeppelin's SafeERC20 which performs an "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(marketHash|campaignHash|poolHash|marketId).*(deposit|enter)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(deposit|enter|join|fill)(Into|)'}, {'function.body_contains_regex': 'marketHash.*(token|asset|input)|(token|asset|input).*marketHash'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.has_high_level_call_named': 'safeTransferFrom|safeTransfer'}, {'function.body_contains_regex': '(Solmate|SafeTransferLib|safeTransferFrom)'}, {'function.body_not_contains_regex': '(codesize|code\\.length\\s*>\\s*0|isContract|_assertMarketExists)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — future-market-deposit-hash-front-run-steal: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
