"""
a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1- — generated from reference/patterns.dsl/a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousUserCouldDosAVestingScheduleBySendingOnly1(AbstractDetector):
    ARGUMENT = "a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-"
    HELP = "A malicious user could DOS a vesting schedule by sending only 1 wei of TLC to the vesting escrow address"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-.yaml"
    WIKI_TITLE = "A malicious user could DOS a vesting schedule by sending only 1 wei of TLC to the vesting escrow address"
    WIKI_DESCRIPTION = "## Severity: Critical Risk\n\n## Context:\n- `ERC20VestableVotesUpgradeable.1.sol#L132-L134`\n- `ERC20VestableVotesUpgradeable.1.sol#L137-L139`\n- `ERC20VestableVotesUpgradeable.1.sol#L86-L97`\n- `ERC20VestableVotesUpgradeable.1.sol#L353`\n\n## Description:\nAn external user who owns some TLC tokens could DO"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #7003: ## Severity: Critical Risk\n\n## Context:\n- `ERC20VestableVotesUpgradeable.1.sol#L132-L134`\n- `ERC20VestableVotesUpgradeable.1.sol#L137-L139`\n- `ERC20VestableVotesUpgradeable.1.sol#L86-L97`\n- `ERC20Vest"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(computeVestingReleasableAmount|balanceOf).*'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.reads_state_var_matching': '.*(balanceOf|computeVestingReleasableAmount).*'}, {'function.does_not_call_matching': '.*(accrue|update|sync|validate|check|refresh).*'}]

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
                info = [f, f" — a-malicious-user-could-dos-a-vesting-schedule-by-sending-only-1-: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
