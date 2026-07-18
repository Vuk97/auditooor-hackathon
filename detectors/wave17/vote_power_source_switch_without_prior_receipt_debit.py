"""
vote-power-source-switch-without-prior-receipt-debit - generated from reference/patterns.dsl/vote-power-source-switch-without-prior-receipt-debit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vote-power-source-switch-without-prior-receipt-debit.yaml
Source: detector-lift-fire5-worker-va-vote-double-count
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VotePowerSourceSwitchWithoutPriorReceiptDebit(AbstractDetector):
    ARGUMENT = "vote-power-source-switch-without-prior-receipt-debit"
    HELP = "Vote weight mixes a direct balance source with a delegated or checkpointed source before a per-proposal receipt is written."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vote-power-source-switch-without-prior-receipt-debit.yaml"
    WIKI_TITLE = "Vote power source mix can double count without a prior receipt"
    WIKI_DESCRIPTION = "Governance vote paths should use one canonical voting-power source per proposal. If the path adds a voter's direct balance to delegated or checkpointed power and no vote receipt is written before the add, self-delegation or a stale delegate source can make the same units count twice."
    WIKI_EXPLOIT_SCENARIO = "A voter delegates to themselves or retains a delegated checkpoint, then votes on a proposal. The vote path adds the direct balance and the delegated source together, and no per-proposal receipt prevents the same source from being counted through both routes."
    WIKI_RECOMMENDATION = "Use one snapshotted voting-power source per proposal. Reject self-delegation or normalize it to zero extra delegated power, and write a per-proposal vote receipt before adding weight."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?is)(vote|voting|proposal|ballot|delegate|checkpoint)'}, {'contract.source_matches_regex': '(?is)(balanceOf|_balances|balances|votingBalance|baseVotes|delegatedTo|delegateVotes|delegatedPower|voteCheckpoints|checkpoints|delegates|delegateOf|representativeOf)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(cast.*vote|cast.*ballot|submit.*vote|submit.*ballot|record.*vote|vote|ballot|tally)'}, {'function.body_contains_regex': '(?is)(?:balanceOf|_balances|balances|votingBalance|baseVotes)\\s*\\[\\s*(?:msg\\.sender|voter|account)\\s*\\]\\s*\\+\\s*(?:(?:delegatedTo|delegateVotes|delegatedPower)\\s*\\[\\s*(?:msg\\.sender|voter|account)\\s*\\]|(?:voteCheckpoints|checkpoints|delegateVotes|delegatedPower)\\s*\\[\\s*(?:delegates|delegateOf|representativeOf)\\s*\\[\\s*(?:msg\\.sender|voter|account)\\s*\\]\\s*\\]\\s*\\[)'}, {'function.body_not_contains_regex': '(?is)(hasVoted|receipt\\s*\\.\\s*hasVoted|already\\s+voted|votedByProposal|proposalVoter|voteReceipts|receiptOf|_writeVoteReceipt|_markVoted)'}, {'function.contract.not_source_matches_regex': '(?is)(?:delegatee|newDelegate|representative)\\s*!=\\s*(?:msg\\.sender|voter|account)'}, {'function.not_in_skip_list': True}, {'function.not_slither_synthetic': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - vote-power-source-switch-without-prior-receipt-debit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
