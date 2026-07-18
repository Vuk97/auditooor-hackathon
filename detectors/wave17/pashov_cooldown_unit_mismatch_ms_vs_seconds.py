"""
pashov-cooldown-unit-mismatch-ms-vs-seconds — generated from reference/patterns.dsl/pashov-cooldown-unit-mismatch-ms-vs-seconds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py pashov-cooldown-unit-mismatch-ms-vs-seconds.yaml
Source: auditooor-R75-pashov-Elixir-sdeUSD-H01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PashovCooldownUnitMismatchMsVsSeconds(AbstractDetector):
    ARGUMENT = "pashov-cooldown-unit-mismatch-ms-vs-seconds"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: flags a narrow Solidity cooldown gate that stores the deadline in seconds but compares it against a millisecond timestamp."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/pashov-cooldown-unit-mismatch-ms-vs-seconds.yaml"
    WIKI_TITLE = "Cooldown check compares milliseconds against seconds (or vice versa)"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this detector is intentionally narrow for Solidity and looks for a cooldown or unlock flow that writes its deadline from `block.timestamp` in seconds and later compares that deadline against a `block.timestamp * 1000` millisecond value inside the user-facing release path."
    WIKI_EXPLOIT_SCENARIO = "A staking contract records `cooldownEnd = block.timestamp + cooldownDuration;`. The unstake path later computes `currentTime = block.timestamp * 1000;` and requires `currentTime >= cooldownEnd`. Because the left side is milliseconds while the right side is seconds, the check passes immediately and the cooldown never meaningfully applies."
    WIKI_RECOMMENDATION = "Use one time unit throughout the module and convert at the edges only. If the stored deadline is in seconds, compare it to raw `block.timestamp`; if the code truly needs milliseconds, multiply the stored deadline once when it is written. Keep submission_posture NOT_SUBMIT_READY until broader corpus validation exists."

    _PRECONDITIONS = [
        {'contract.source_matches_regex': '(?is)cooldownEnd\\s*=\\s*block\\.timestamp\\s*\\+|block\\.timestamp\\s*\\*\\s*1000'}
    ]
    _MATCH = [
        {'function.kind': 'external_or_public'},
        {'function.name_matches': 'unstake|withdraw|claim|redeem|release|unlock'},
        {'function.body_contains_regex': '(?is)(currentTime|current_time|nowMs|timestampMs|timeMs)\\s*=\\s*block\\.timestamp\\s*\\*\\s*1000'},
        {'function.body_contains_regex': '(?is)(require|assert)\\s*\\([^;]*(currentTime|current_time|nowMs|timestampMs|timeMs)\\s*(>=|>)\\s*(cooldownEnd|cooldown_end|unlockAt|unlockTime|releaseAt|releaseTime|vestingEnd)'},
        {'function.body_not_contains_regex': '(?is)(cooldownEnd|cooldown_end|unlockAt|unlockTime|releaseAt|releaseTime|vestingEnd)\\s*\\*\\s*1000|/\\s*1000|/\\s*1_000|toMilliseconds|secondsToMs'},
        {'function.not_in_skip_list': True},
        {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'},
    ]

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
                info = [f, f" — pashov-cooldown-unit-mismatch-ms-vs-seconds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
