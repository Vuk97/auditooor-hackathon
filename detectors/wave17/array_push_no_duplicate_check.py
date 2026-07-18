"""
array-push-no-duplicate-check — generated from reference/patterns.dsl/array-push-no-duplicate-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py array-push-no-duplicate-check.yaml
Source: solodit/C0151
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ArrayPushNoDuplicateCheck(AbstractDetector):
    ARGUMENT = "array-push-no-duplicate-check"
    HELP = "Adder/enroller appends to a storage array without checking for duplicates — same address/id can be inserted twice, causing double rewards, double vesting, or iteration gas grief."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/array-push-no-duplicate-check.yaml"
    WIKI_TITLE = "Array push without duplicate check: double entry on rewards/vesting recipients"
    WIKI_DESCRIPTION = "Functions that append a caller-controlled address or id to a storage list (recipients, whitelist, vesting targets) without first checking membership allow the same entry to appear multiple times. Any downstream code that iterates the list (reward distribution, vesting release) will process the duplicate entry multiple times, producing double payouts or enabling a gas DoS."
    WIKI_EXPLOIT_SCENARIO = "Admin calls addVestingRecipient(alice, 100). Operator misfires / malicious admin calls it again. alice is now in the recipients array twice; when release() iterates and pays each entry, alice receives 2x her allocation at the expense of other recipients."
    WIKI_RECOMMENDATION = "Before `push`, check membership via a parallel `mapping(address => bool) added` or `mapping(id => uint256) indexPlusOne`, or scan the array when small. Reject duplicates with a named error. For high-throughput lists, use an EnumerableSet."

    _PRECONDITIONS = [{'contract.has_function_body_matching': '(?i)(\\.push\\s*\\()'}, {'contract.source_matches_regex': '(?i)(recipient|whitelist|allowlist|enrolled|registered|stakeholder|beneficiar|vesting|participant|holders)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(add|register|enroll|whitelist|addRecipient|addRecipients|addAllowed|addAddress|addAddresses|addParticipant|addStakeholder|addHolder|addBeneficiary)[A-Za-z0-9_]*$'}, {'function.body_contains_regex': '\\.push\\s*\\('}, {'function.body_not_contains_regex': '(?i)(require|revert|if)\\s*\\(.{0,200}(!\\s*(isRegistered|exists|contains|_seen|alreadyAdded|added)\\s*\\[|\\[\\s*\\w+\\s*\\]\\s*==\\s*address\\s*\\(\\s*0\\s*\\)|\\.length\\s*==\\s*0)'}, {'function.not_source_matches_regex': '(EnumerableSet\\.add|EnumerableSet\\.AddressSet|indexPlusOne\\s*\\[|\\balreadyAdded\\s*\\[|\\b_seen\\s*\\[|for\\s*\\([^)]+\\)\\s*\\{[^}]{0,200}==\\s*\\w+\\s*\\)\\s*(revert|return))'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — array-push-no-duplicate-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
