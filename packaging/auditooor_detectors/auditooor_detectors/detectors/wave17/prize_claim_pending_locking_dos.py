"""
prize-claim-pending-locking-dos — generated from reference/patterns.dsl/prize-claim-pending-locking-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py prize-claim-pending-locking-dos.yaml
Source: solodit-C0063
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PrizeClaimPendingLockingDos(AbstractDetector):
    ARGUMENT = "prize-claim-pending-locking-dos"
    HELP = "Batch claimPrizes/batchClaim iterates winners and disburses in a single loop with no try/catch or skip-on-fail. One reverting winner (malicious hook, bad receive(), already-claimed prize) DoSes the entire batch."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/prize-claim-pending-locking-dos.yaml"
    WIKI_TITLE = "Batch prize claim DoSable by single reverting winner — no per-iteration error containment"
    WIKI_DESCRIPTION = "Prize-pool contracts typically expose a batch entrypoint (claimPrizes, batchClaim, distributePrizes, multiClaim) that iterates an array of winners and, per iteration, transfers a prize or notifies the winner via a callback hook. When the per-iteration disbursement is not wrapped in try/catch and there is no skip-on-fail guard, a single failing iteration reverts the whole transaction. This can be e"
    WIKI_EXPLOIT_SCENARIO = "A PoolTogether-style PrizePool exposes `claimPrizes(address[] winners, uint256[] tiers)` that transfers each winner's prize in a loop. A griefer wins a small prize with a contract that reverts on receipt. Every subsequent batch call reverts at the griefer's iteration, blocking all other winners from being paid. The griefer pays ~0 for sustained DoS. Variant: the hook callback `IPrizeReceiver(winne"
    WIKI_RECOMMENDATION = "Wrap the per-winner disbursement in try/catch (or an explicit low-level-call with checked-but-ignored success) so a single reverting winner cannot block the batch. Emit a ClaimFailed(winner, reason) event on failure and let the winner retry individually. If the contract invokes a user-supplied hook,"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'prize|prizePool|winners|claimable'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'claimPrizes|batchClaim|claimRewards|distributePrizes|_claimPrizes|multiClaim'}, {'function.body_contains_regex': 'for\\s*\\([^)]*length|while\\s*\\([^)]*length'}, {'function.body_not_contains_regex': 'try\\s+|catch\\s*\\{|if\\s*\\(\\s*!\\s*success\\s*\\)\\s*continue|if\\s*\\(\\s*!\\s*ok\\s*\\)\\s*continue'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — prize-claim-pending-locking-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
