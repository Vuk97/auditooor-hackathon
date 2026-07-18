"""
perp-remove-collateral-updates-storage-without-onchain-transfer — generated from reference/patterns.dsl/perp-remove-collateral-updates-storage-without-onchain-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py perp-remove-collateral-updates-storage-without-onchain-transfer.yaml
Source: auditooor-R75-c4-2023-03-polynomial-H189
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PerpRemoveCollateralUpdatesStorageWithoutOnchainTransfer(AbstractDetector):
    ARGUMENT = "perp-remove-collateral-updates-storage-without-onchain-transfer"
    HELP = "`removeCollateral` decrements the internal `totalCollateral`/`usedFunds` storage variable but omits the external call that actually pulls the asset out of the downstream exchange / clearinghouse. Fixture-smoke/source-shape proof only; NOT_SUBMIT_READY."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/perp-remove-collateral-updates-storage-without-onchain-transfer.yaml"
    WIKI_TITLE = "removeCollateral mutates storage without invoking the exchange-level removal — collateral orphaned"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. Derivative vault wrappers (Polynomial KangarooVault, Ribbon DOV, GMX-aggregator vaults) hold a position on an underlying exchange. The wrapper exposes admin-only `addCollateral` and `removeCollateral` methods that mirror the exchange calls. A common bug: `addCollateral` does `EXCHANGE.addCollateral(pos, x); totalCollateral += x`, but its counterpart `removeCo"
    WIKI_EXPLOIT_SCENARIO = "(1) KangarooVault has positionId X with collateral = 10_000 USDC on-exchange and `positionData.totalCollateral = 10_000`. (2) Admin calls `removeCollateral(3_000)`. Function does `usedFunds -= 3_000; positionData.totalCollateral -= 3_000;`. No exchange call. (3) On-exchange: still 10_000 USDC collateral backing position X. Internal: thinks 7_000. (4) Admin later calls `closePosition`. `tradeParams"
    WIKI_RECOMMENDATION = "`removeCollateral` must call the downstream exchange: `EXCHANGE.removeCollateral(positionId, amount)` BEFORE decrementing the internal accounting. Add a post-condition: `require(token.balanceOf(address(this)) == preBalance + amount, 'collateral-not-pulled')`. Invariant test: internal `totalCollatera"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(removeCollateral|withdrawCollateral|decreaseCollateral|KangarooVault|CoveredCall|perpVault)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(removeCollateral|_removeCollateral|withdrawCollateral|decreaseCollateral|reduceCollateral)'}, {'function.body_contains_regex': '(usedFunds|totalCollateral|positionData\\.totalCollateral|collateralAmount)\\s*-='}, {'function.body_not_contains_regex': '(EXCHANGE\\.removeCollateral|pool\\.withdraw|IExchange|CLEARING|perpsMarket\\.|safeTransfer|_safeTransfer)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — perp-remove-collateral-updates-storage-without-onchain-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
