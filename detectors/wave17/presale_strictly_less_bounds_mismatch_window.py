"""
presale-strictly-less-bounds-mismatch-window - generated from reference/patterns.dsl/presale-strictly-less-bounds-mismatch-window.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py presale-strictly-less-bounds-mismatch-window.yaml
Source: auditooor-R75-code4rena-2024-01-curves-872
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PresaleStrictlyLessBoundsMismatchWindow(AbstractDetector):
    ARGUMENT = "presale-strictly-less-bounds-mismatch-window"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: an externally callable presale buy path uses `startTime <= block.timestamp` in a revert guard, making the path callable before startTime and blocked once the presale should be live."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/presale-strictly-less-bounds-mismatch-window.yaml"
    WIKI_TITLE = "Presale start-time guard is inverted"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row flags the owned presale-buy shape where an external/public buy entrypoint reverts when `startTime <= block.timestamp`. That inversion lets callers buy before the presale starts, then blocks them once `block.timestamp` reaches `startTime`. Keep this row NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "Motivating Curves-shaped scenario: a whitelist buy path checks `if (presalesMeta[subject].startTime == 0 || presalesMeta[subject].startTime <= block.timestamp) revert PresaleUnavailable();`. At `startTime - 1` a whitelisted buyer can execute; at `startTime` and later every legitimate presale buy reverts. This row does not claim broader corpus-backed exploit evidence beyond the owned fixture proof."
    WIKI_RECOMMENDATION = "Flip the bound so pre-start calls revert and in-window calls can proceed, for example `require(startTime != 0 && block.timestamp >= startTime && block.timestamp < presaleEndTime)`. Add end-of-window tests. Do not promote from fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)presale|whitelist|startTime'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)buyPresale|buyWhitelisted|claimDuring\\w*|joinPresale'}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': '(?i)(presale\\w*\\.startTime|presalesMeta(?:\\[[^\\]]+\\])?\\.startTime|startTime\\w*|presaleStart)'}, {'function.body_contains_regex': '(?i)((presale\\w*\\.startTime|presalesMeta(?:\\[[^\\]]+\\])?\\.startTime|startTime\\w*|presaleStart)\\s*<=\\s*(block\\.timestamp|_now|now)|(block\\.timestamp|_now|now)\\s*>=\\s*(presale\\w*\\.startTime|presalesMeta(?:\\[[^\\]]+\\])?\\.startTime|startTime\\w*|presaleStart))'}, {'function.body_contains_regex': '(?i)revert\\s+\\w*Presale\\w*Unavailable|revert\\s+NotActive'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - presale-strictly-less-bounds-mismatch-window: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
