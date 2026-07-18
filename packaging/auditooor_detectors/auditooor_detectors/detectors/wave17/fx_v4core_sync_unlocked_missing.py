"""
fx-v4core-sync-unlocked-missing — generated from reference/patterns.dsl/fx-v4core-sync-unlocked-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-v4core-sync-unlocked-missing.yaml
Source: github:Uniswap/v4-core@4dc48bb
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxV4coreSyncUnlockedMissing(AbstractDetector):
    ARGUMENT = "fx-v4core-sync-unlocked-missing"
    HELP = "sync() is callable without an active unlock session. An attacker can call sync() between another caller's unlock/settle to overwrite the synced currency reserve, causing settle() to compute an incorrect (larger) paid amount and enabling token theft."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-v4core-sync-unlocked-missing.yaml"
    WIKI_TITLE = "sync() missing onlyWhenUnlocked modifier — stale reserve manipulation during active session"
    WIKI_DESCRIPTION = "In pool managers that use a sync-then-settle payment pattern, sync() checkpoints the current token balance as the before-state for delta accounting. If sync() lacks an onlyWhenUnlocked guard, it can be called externally to overwrite an in-progress session's reserved balance, making settle() compute a larger paid value than was actually transferred in."
    WIKI_EXPLOIT_SCENARIO = "Uniswap v4 ToB L01 (2024): during an active unlock session where Alice has synced currency X at balance B0, Bob calls sync(X) at balance B1 > B0. Alice then calls settle(), crediting her with B1 - B0 extra tokens she never transferred."
    WIKI_RECOMMENDATION = "Apply onlyWhenUnlocked (or equivalent) modifier to sync(). Alternatively, use transient storage that is automatically scoped to the unlock call frame."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^sync$'}, {'contract.has_function_matching': '^settle$|^unlock$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^sync$'}, {'function.body_contains_regex': 'reserve|balance|tstore|Currency'}, {'function.body_not_contains_regex': 'onlyWhenUnlocked|isUnlocked|require.*lock|Lock\\.'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-v4core-sync-unlocked-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
