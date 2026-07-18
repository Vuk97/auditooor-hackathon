"""
governor-execute-missing-succeeded-guard — generated from reference/patterns.dsl/governor-execute-missing-succeeded-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py governor-execute-missing-succeeded-guard.yaml
Source: code4arena/slice_ac-Blackhole-L2Governor
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GovernorExecuteMissingSucceededGuard(AbstractDetector):
    ARGUMENT = "governor-execute-missing-succeeded-guard"
    HELP = "Governor.execute() does not check proposal state == Succeeded (or Queued in timelock governors); Expired, Defeated, or Cancelled proposals can be executed."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/governor-execute-missing-succeeded-guard.yaml"
    WIKI_TITLE = "Governor execute() missing state == Succeeded guard"
    WIKI_DESCRIPTION = "OZ Governor specifies that execute() must only run proposals whose state is `Succeeded` (or `Queued` in a timelocked variant). Overrides or custom subclasses that skip this check allow already-expired or already-defeated proposals to be executed, which collapses governance safety: a proposal that narrowly lost can be re-run by the proposer until the timing window trick lands."
    WIKI_EXPLOIT_SCENARIO = "BlackGovernor.execute() calls through to the target calls without checking the proposal state. A proposal that was defeated by 1 vote in the `ForVotes < AgainstVotes` branch can still be executed, pushing through a hostile fee-schedule change, or a reward-nudge that freezes tail emissions."
    WIKI_RECOMMENDATION = "Before executing any call, `require(state(id) == ProposalState.Succeeded)` (or Queued for TimelockController-based flows). Avoid unbounded overrides that skip parent checks."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Governor|Governance|proposal|Proposal'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(execute|executeProposal|_execute)$'}, {'function.body_contains_regex': '\\.call\\s*\\(|executeProposalOp|executeBatch|_executeTransaction'}, {'function.body_not_contains_regex': 'ProposalState\\.Succeeded|ProposalState\\.Queued|state\\s*\\(\\s*\\w+\\s*\\)\\s*==\\s*ProposalState|require\\s*\\(\\s*proposalState\\s*==\\s*(Succeeded|Queued)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — governor-execute-missing-succeeded-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
