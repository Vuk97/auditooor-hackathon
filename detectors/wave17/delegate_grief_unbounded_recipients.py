"""
delegate-grief-unbounded-recipients — generated from reference/patterns.dsl/delegate-grief-unbounded-recipients.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py delegate-grief-unbounded-recipients.yaml
Source: solodit/C0335
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DelegateGriefUnboundedRecipients(AbstractDetector):
    ARGUMENT = "delegate-grief-unbounded-recipients"
    HELP = "delegate / stake / transfer path iterates over a per-delegatee list without a small cap — attacker can pad the list (1024 dust positions) to make the target's future calls revert on gas."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/delegate-grief-unbounded-recipients.yaml"
    WIKI_TITLE = "Vote delegation grief: unbounded delegate list causes OOG DoS"
    WIKI_DESCRIPTION = "Voting-escrow and delegation systems maintain an array of (delegator → delegatee) relationships. If the per-delegatee list is iterated on delegate/transfer/stake without a hard small cap, any attacker can fill the list with dust delegations to a target so that the target's legitimate delegate / transfer / vote calls run out of gas."
    WIKI_EXPLOIT_SCENARIO = "MAX_DELEGATES=1024. Attacker creates 1024 sybil addresses and delegates 1 wei each to Victim. Victim now attempts delegate() to move their own tokens — the loop over 1024 entries costs ~30M gas and the transaction reverts. Victim is griefed for the duration of the escrow lock."
    WIKI_RECOMMENDATION = "Set MAX_DELEGATES to a small value (e.g. 8 or 16) OR replace the per-delegatee array with a Merkle-root / checkpointed structure that does not iterate. Reject delegate() when recipient.delegateCount >= MAX; do not let the attacker append."

    _PRECONDITIONS = [{'contract.has_function_matching': '(?i)(delegate|_delegate|setDelegate)'}, {'contract.source_matches_regex': '(?i)(MAX_DELEGATES|maxDelegates|delegates\\s*\\[|_delegatees|_delegators)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(delegate|delegateTo|delegateBySig|redelegate|transfer|transferFrom|increaseAmount|increaseUnlockTime|setDelegate|stake|stakeFor|lock|lockFor|_delegate|_transfer)$'}, {'function.body_contains_regex': '(?i)(for\\s*\\(|while\\s*\\().{0,40}(delegates|delegators|_delegatees|delegatee)'}, {'function.body_not_contains_regex': '(?i)(require|if).{0,80}(delegates|length|count)\\s*<=?\\s*[0-9]{1,3}\\s*[,)]'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — delegate-grief-unbounded-recipients: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
