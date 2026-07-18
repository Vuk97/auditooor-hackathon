"""
w68-reentrancy-during-pause-hook — generated from reference/patterns.dsl/w68-reentrancy-during-pause-hook.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-reentrancy-during-pause-hook.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68ReentrancyDuringPauseHook(AbstractDetector):
    ARGUMENT = "w68-reentrancy-during-pause-hook"
    HELP = "Reentrancy triggered during paused state via external hook callback before state update"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-reentrancy-during-pause-hook.yaml"
    WIKI_TITLE = "Reentrancy triggered during paused state via hook"
    WIKI_DESCRIPTION = "An external hook callback fires before the balance state is decremented, so a malicious hook can reenter and drain funds even while the contract is paused."
    WIKI_EXPLOIT_SCENARIO = "Reentrancy triggered during paused state via external hook callback before state update"
    WIKI_RECOMMENDATION = "Apply checks-effects-interactions: update state before the external hook call."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(withdraw|claim|redeem).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)\\.call\\s*\\([^;]*;[\\s\\S]*?(balance|amount)\\s*\\[[^\\]]+\\]\\s*-='}]

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
                info = [f, f" — w68-reentrancy-during-pause-hook: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
