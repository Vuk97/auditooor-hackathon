"""
transfer-to-plot-does-not-update-pointer — generated from reference/patterns.dsl/transfer-to-plot-does-not-update-pointer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py transfer-to-plot-does-not-update-pointer.yaml
Source: auditooor-R75-code4rena-2024-07-munchables-198
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TransferToPlotDoesNotUpdatePointer(AbstractDetector):
    ARGUMENT = "transfer-to-plot-does-not-update-pointer"
    HELP = "transferToPlot updates old-plot (free) and new-plot (occupied) but never writes `toilerState[tokenId].plotId = plotId` — the per-token pointer stays stale, enabling double-occupancy."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/transfer-to-plot-does-not-update-pointer.yaml"
    WIKI_TITLE = "transferToUnoccupiedPlot forgets to update per-token plotId pointer, enabling double-occupancy"
    WIKI_DESCRIPTION = "The function clears `plotOccupied[landlord][oldPlotId]` and sets `plotOccupied[landlord][newPlotId]`, but leaves `toilerState[tokenId].plotId` pointing to oldPlotId. Consequences: (a) accounting loops that read `toilerState.plotId` use the wrong plot for tax/reward math; (b) if the landlord later reduces their plot count such that newPlotId is out of range, the dirty-flag check reads oldPlotId (st"
    WIKI_EXPLOIT_SCENARIO = "Alice's token is at plotId 1. She calls transferToUnoccupiedPlot(tokenId, 3). State: plotOccupied[landlord][1] = free, plotOccupied[landlord][3] = Alice, toilerState[tokenId].plotId = 1 (stale). Landlord unstakes weight so numPlots shrinks to 2. _farmPlots checks `_getNumPlots(landlord) < toiler.plotId` → 2 < 1 is false → dirty is not set — Alice keeps accruing rewards on a plot that no longer exi"
    WIKI_RECOMMENDATION = "Immediately write `toilerState[tokenId].plotId = plotId` inside the move. Add an invariant test: for every staked tokenId, `plotOccupied[toilerState[tokenId].landlord][toilerState[tokenId].plotId].tokenId == tokenId`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)transferTo\\w*|moveTo\\w*|migrateTo\\w*|relocate\\w*'}, {'function.body_contains_regex': '(?i)\\w+Occupied\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*plotId\\s*\\]\\s*='}, {'function.body_contains_regex': '(?i)\\w+Occupied\\s*\\[\\s*\\w+\\s*\\]\\s*\\[\\s*oldPlotId\\s*\\]\\s*=\\s*\\w*Plot\\s*\\('}, {'function.body_not_contains_regex': '(?i)toilerState\\s*\\[\\s*tokenId\\s*\\]\\s*\\.plotId\\s*=\\s*plotId|\\.slot\\s*=\\s*newSlot'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — transfer-to-plot-does-not-update-pointer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
