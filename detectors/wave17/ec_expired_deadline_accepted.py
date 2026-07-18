"""
ec-expired-deadline-accepted — generated from reference/patterns.dsl/ec-expired-deadline-accepted.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-expired-deadline-accepted.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcExpiredDeadlineAccepted(AbstractDetector):
    ARGUMENT = "ec-expired-deadline-accepted"
    HELP = "Swap function accepts deadline parameter but does not enforce require(deadline >= block.timestamp); stale transactions execute at unfavorable prices."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-expired-deadline-accepted.yaml"
    WIKI_TITLE = "Swap deadline not enforced — expired transactions can be replayed"
    WIKI_DESCRIPTION = "The function accepts a deadline argument representing the latest block timestamp at which the transaction is valid, but does not include a require(block.timestamp <= deadline) check before executing the swap. Validators or searchers can hold the transaction in the mempool and include it when the price has moved maximally against the user, within a window defined by the expiry value (or forever if "
    WIKI_EXPLOIT_SCENARIO = "User submits swap with deadline = block.timestamp + 3600. Gas too low, tx stays in mempool. 1 hour later, market has moved 5% against user. Validator includes tx just before deadline. User receives 5% less than expected with no recourse."
    WIKI_RECOMMENDATION = "Add `require(block.timestamp <= deadline, 'expired')` as the first check in any time-sensitive function. For permit-followed-by-swap patterns, check both the permit deadline and the swap deadline. Recommend users set deadline to block.timestamp + small constant (300 seconds max) rather than large va"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'deadline|Deadline|expiry|Expiry'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_param_name_matching': 'deadline|expiry|expiration|_deadline'}, {'function.body_contains_regex': 'swap|transfer|exactInput|exactOutput|safeTransfer'}, {'function.body_not_contains_regex': 'require\\s*\\(.*deadline|require\\s*\\(.*expir|block\\.timestamp\\s*<=?\\s*deadline|deadline\\s*>=?\\s*block\\.timestamp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-expired-deadline-accepted: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
