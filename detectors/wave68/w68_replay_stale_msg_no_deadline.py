"""
w68-replay-stale-msg-no-deadline — generated from reference/patterns.dsl/w68-replay-stale-msg-no-deadline.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py w68-replay-stale-msg-no-deadline.yaml
Source: W6-8 zero-coverage detector batch (auditooor capability lift)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class W68ReplayStaleMsgNoDeadline(AbstractDetector):
    ARGUMENT = "w68-replay-stale-msg-no-deadline"
    HELP = "Stale or old message replayed to execute outdated action - no deadline or consumed-message guard"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/w68-replay-stale-msg-no-deadline.yaml"
    WIKI_TITLE = "Stale or old message replayed to execute outdated action"
    WIKI_DESCRIPTION = "The message-execution path has no deadline check and no consumed-message bookkeeping, so an old message can be replayed indefinitely."
    WIKI_EXPLOIT_SCENARIO = "Stale or old message replayed to execute outdated action - no deadline or consumed-message guard"
    WIKI_RECOMMENDATION = "Include a deadline and a unique consumed-once message id."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(executeMessage|processMessage|relay).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(credited|balance)\\s*\\[[^\\]]+\\]\\s*\\+='}, {'function.body_not_contains_regex': '(?i)(deadline|expiry|consumed\\s*\\[)'}]

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
                info = [f, f" — w68-replay-stale-msg-no-deadline: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
