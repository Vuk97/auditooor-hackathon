"""
withdrawal-snapshot-stale-against-appreciating-shares — generated from reference/patterns.dsl/withdrawal-snapshot-stale-against-appreciating-shares.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py withdrawal-snapshot-stale-against-appreciating-shares.yaml
Source: solodit/sherlock/rio-network-H6-30901
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawalSnapshotStaleAgainstAppreciatingShares(AbstractDetector):
    ARGUMENT = "withdrawal-snapshot-stale-against-appreciating-shares"
    HELP = "Withdrawal epoch snapshots sharesOwed at request time; settlement requires exact share match. Share-price appreciation plus fresh idle underlying means shares-held falls below sharesOwed, bricking the whole epoch."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdrawal-snapshot-stale-against-appreciating-shares.yaml"
    WIKI_TITLE = "Withdrawal settlement asserts share-count equality, stalls when share price rises"
    WIKI_DESCRIPTION = "An LRT / vault-of-vaults records `sharesOwed = convertToShares(amountAtRequest)` when a user queues a withdrawal. Settlement later asserts `strategyShares[asset] == sharesOwed`. If new deposits sit idle in the pool between request and settlement AND the inner strategy (e.g., EigenLayer-cbETH) appreciates in share-price, the new underlying doesn't produce the same shares-per-underlying ratio, so cu"
    WIKI_EXPLOIT_SCENARIO = "Alice queues withdrawal for 100 cbETH (sharesOwed = 100 EigenLayer-cbETH at the 1:1 rate). Days pass. EigenLayer-cbETH appreciates 10% (1 share = 1.1 cbETH). Bob deposits 100 cbETH idle in the deposit pool. At settle, protocol has 5 shares committed + 100 cbETH idle; converting idle to shares at the new rate gives only ~90.9 shares. Total ~95.9 shares. Assert `95.9 == 100` fails; revert. Alice, Bo"
    WIKI_RECOMMENDATION = "Commit withdrawals in underlying terms (amount of cbETH), not shares. At settlement compare `underlyingHeld >= underlyingOwed`, then burn exactly enough shares to cover and return the rest. If shares must be tracked, allow over-queueing: settle when `shares >= sharesOwed` and refund the excess. Crit"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(sharesOwed|sharesCommitted|epochShares|withdrawalShares)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(settleEpoch|settleWithdrawal|processWithdrawal|finalizeEpoch|unwindEpoch)'}, {'function.body_contains_regex': 'require\\s*\\(\\s*\\w*Shares\\w*\\s*==\\s*\\w*sharesOwed|if\\s*\\(\\s*\\w*Shares\\w*\\s*!=\\s*\\w*sharesOwed\\s*\\)\\s*revert|INCORRECT_NUMBER_OF_SHARES'}, {'function.body_not_contains_regex': 'convertFromSharesToAsset|idleBalance\\s*>=|underlyingHeld\\s*>=|valueOwed\\s*=='}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — withdrawal-snapshot-stale-against-appreciating-shares: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
