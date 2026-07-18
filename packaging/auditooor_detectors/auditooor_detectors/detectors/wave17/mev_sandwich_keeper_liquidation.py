"""
mev-sandwich-keeper-liquidation — generated from reference/patterns.dsl/mev-sandwich-keeper-liquidation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py mev-sandwich-keeper-liquidation.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MevSandwichKeeperLiquidation(AbstractDetector):
    ARGUMENT = "mev-sandwich-keeper-liquidation"
    HELP = "Keeper / harvest / liquidation entry point reads the oracle price inline (Chainlink latestAnswer, Uniswap slot0) and acts on it in the same tx, with no TWAP or commit-reveal guard. MEV bots can sandwich the call at a manipulated price."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/mev-sandwich-keeper-liquidation.yaml"
    WIKI_TITLE = "MEV-sandwichable keeper: inline oracle read in liquidation / harvest path"
    WIKI_DESCRIPTION = "A permissionless or lightly-gated keeper function (`liquidate`, `harvest`, `keep`, `rebalance`, `forceLiquidate`, ...) derives the execution price from a single-tx oracle read — Chainlink `latestAnswer` / `latestRoundData` or a Uniswap-V3 `pool.slot0` spot — and acts on that price in the same transaction. Because the price source can be perturbed within the same block (e.g. a large swap in the ora"
    WIKI_EXPLOIT_SCENARIO = "A lending protocol's `liquidatePosition` reads the collateral price from `uniswapPool.slot0()` and closes the borrower's position at the returned spot. A searcher spots a barely-healthy position, front-runs with a large swap that depresses the spot price, invokes `liquidatePosition` at the artificial low (maximising the seizure discount) and back-runs with the reverse swap. The borrower loses coll"
    WIKI_RECOMMENDATION = "Replace the inline spot read with a time-weighted price: Uniswap-V3 `pool.observe([... windowSeconds, 0])` with a window large enough to make sandwiching unprofitable, or a Chainlink reading with a `stalenessThreshold` and a deviation-from-recent-median guard. For harvests, move the price fix into a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': 'liquidate|harvest|keep'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'liquidate|harvest|keep|_liquidate|_harvest|rebalance|forceLiquidate'}, {'function.body_contains_regex': {'regex': 'getPrice\\s*\\(|latestAnswer|latestRoundData|pool\\.slot0|sqrtPriceX96'}}, {'function.body_not_contains_regex': 'TWAP|\\.observe\\s*\\(|commitment|commitPrice|lastPriceUpdate|stalenessThreshold'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — mev-sandwich-keeper-liquidation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
