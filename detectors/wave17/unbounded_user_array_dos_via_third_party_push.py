"""
unbounded-user-array-dos-via-third-party-push — generated from reference/patterns.dsl/unbounded-user-array-dos-via-third-party-push.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py unbounded-user-array-dos-via-third-party-push.yaml
Source: auditooor-R75-code4rena-2024-01-curves-1068
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UnboundedUserArrayDosViaThirdPartyPush(AbstractDetector):
    ARGUMENT = "unbounded-user-array-dos-via-third-party-push"
    HELP = "Per-user ownedSubjects array only grows, never pops when balance is zero — any third-party transfer can bloat the array and DoS ops that iterate it."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/unbounded-user-array-dos-via-third-party-push.yaml"
    WIKI_TITLE = "Per-user ownership tracker is append-only; third-parties can bloat it to DoS victim"
    WIKI_DESCRIPTION = "`_addOwnedCurvesTokenSubject(owner, subject)` is called on every buy, and also on every `_transfer` (recipient side). Entries are never removed when user's balance drops to zero. An attacker can create a junk curveTokenSubject, mint massive supply, and spam-transfer 1 token to a victim's address. The victim's `ownedCurvesTokenSubjects[]` array grows unbounded. Functions that iterate the array in a"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys a throwaway subject, mints 10_000 tokens, and executes `transferAllCurvesTokens(victim)` looping across 10_000 entries. Each _transfer call appends to victim's array. Victim tries to join a presale — the _addOwnedCurvesTokenSubject loop iterates 10_000 entries from storage → OOG. Victim cannot participate in any presale."
    WIKI_RECOMMENDATION = "On zero-balance sell/transfer, pop the subject from the owner's array. Use an EnumerableSet keyed by address, not a push-only vector. Alternatively, gate `_addOwnedCurvesTokenSubject` with a min-balance guard (must come from an actual buy, not a dust transfer)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'internal'}, {'function.name_matches': '(?i)_addOwned\\w*|_trackAsset|_pushAsset|_addSubject|_addHolding'}, {'function.body_contains_regex': '(?i)\\.push\\s*\\(|\\[owner\\]\\.push|\\[to\\]\\.push'}, {'function.body_contains_regex': '(?i)for\\s*\\(\\s*uint\\w*\\s+i\\s*=\\s*0\\s*;\\s*i\\s*<\\s*\\w+\\.length'}, {'function.body_not_contains_regex': '(?i)balance\\s*>\\s*0|if\\s*\\(\\s*\\w+Balance\\s*\\[[^\\]]*\\]\\s*\\[[^\\]]*\\]\\s*==\\s*0\\s*\\)|_removeOwned|\\.pop\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — unbounded-user-array-dos-via-third-party-push: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
