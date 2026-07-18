"""
islong-flag-not-cleared-on-liquidation — generated from reference/patterns.dsl/islong-flag-not-cleared-on-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py islong-flag-not-cleared-on-liquidation.yaml
Source: solodit-novel/slice_ae-GTE-Perps
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class IslongFlagNotClearedOnLiquidation(AbstractDetector):
    ARGUMENT = "islong-flag-not-cleared-on-liquidation"
    HELP = "Liquidation zeros position amount but does not reset isLong/direction flag. Stale flag blocks user from opening opposite-side positions later."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/islong-flag-not-cleared-on-liquidation.yaml"
    WIKI_TITLE = "Liquidation leaves isLong/direction flag stale"
    WIKI_DESCRIPTION = "Perp liquidation must fully reset the position record. Clearing only the `amount`/`size` field leaves metadata (isLong, direction, entry price) dangling. If a future open-position flow reads the flag to gate direction change, the user is stuck with the dead direction flag and cannot open a fresh opposite-side position until the metadata is cleared — which they may have no way to do."
    WIKI_EXPLOIT_SCENARIO = "GTE Perps slot: user opens long, gets liquidated. `liquidate(user)` does `positions[user].amount = 0`. User tries to open a short: `open()` reads `positions[user].isLong == true` and reverts with 'direction locked'. User cannot open until admin manually cleans up. Effectively griefs the user or bricks the slot."
    WIKI_RECOMMENDATION = "Use `delete positions[user]` to zero the entire struct on liquidation. Alternatively, explicitly reset every field: `isLong = false; amount = 0; entryPrice = 0; leverage = 0`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'isLong|direction|long|short|Position|perp|perps'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'liquidat|forceClose|closePosition|seize|unwind'}, {'function.body_contains_regex': 'position\\.amount|size\\s*=\\s*0|\\.amount\\s*=\\s*0|positions\\s*\\[[^\\]]+\\]\\.amount'}, {'function.body_not_contains_regex': 'isLong\\s*=\\s*false|delete\\s+positions\\s*\\[|\\.direction\\s*=|\\.isLong\\s*=\\s*false'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — islong-flag-not-cleared-on-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
