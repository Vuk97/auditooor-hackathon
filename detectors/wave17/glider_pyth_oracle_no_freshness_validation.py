"""
glider-pyth-oracle-no-freshness-validation — generated from reference/patterns.dsl/glider-pyth-oracle-no-freshness-validation.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-pyth-oracle-no-freshness-validation.yaml
Source: hexens-glider/pyth-oracle-prices-are-not-validated-for-freshness
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPythOracleNoFreshnessValidation(AbstractDetector):
    ARGUMENT = "glider-pyth-oracle-no-freshness-validation"
    HELP = "Consumer reads a Pyth oracle price via `getPrice` / `getPriceUnsafe` without asserting `publishTime` is recent. Pyth is pull-based — the on-chain price can be arbitrarily stale — so any price-dependent action (borrow/liquidate/swap) can be arbitraged using an old update until someone pushes a fresh "
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-pyth-oracle-no-freshness-validation.yaml"
    WIKI_TITLE = "Pyth price consumed without freshness / publishTime check"
    WIKI_DESCRIPTION = "Pyth oracles are pull-based: the on-chain price updates only when a user explicitly pushes a signed update. Reading via `IPyth.getPrice(id)` or `getPriceUnsafe(id)` returns whatever was last pushed, potentially hours old. Price-dependent logic that does not assert `block.timestamp - price.publishTime <= maxAge` can be pinned at a stale favourable price, enabling under-priced liquidations, over-col"
    WIKI_EXPLOIT_SCENARIO = "Lending pool reads collateral price via `pyth.getPriceUnsafe(ethId)`. Last on-chain update was 40 minutes ago at $2_500 — current market is $3_300. Attacker (a) deposits ETH priced at $2_500 (overstated — actually $3_300), (b) borrows against this over-collateralised position up to the $2_500 × LTV cap. Then pushes a fresh Pyth update to $3_300 and immediately withdraws the extra collateral, leavi"
    WIKI_RECOMMENDATION = "Use `pyth.getPriceNoOlderThan(priceId, maxAge)` with `maxAge` tuned to the asset's volatility (60s for majors, ~30s for small caps, longer for stables). If you must use `getPrice` / `getPriceUnsafe`, wrap it: `require(block.timestamp - price.publishTime <= MAX_AGE, \"stale\")`. Monitor the tail of t"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IPyth|pyth|PythStructs|getPriceUnsafe|getPriceNoOlderThan|getPrice'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': 'pyth\\.getPrice|IPyth\\(.+\\)\\.getPrice|getPriceUnsafe|getPrice\\s*\\(.+id\\s*\\)'}, {'function.body_not_contains_regex': 'getPriceNoOlderThan|publishTime\\s*>=|publishTime\\s*<\\s*block\\.timestamp|block\\.timestamp\\s*-\\s*publishTime|MAX_PRICE_AGE|require\\s*\\(.*price\\.publishTime'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-pyth-oracle-no-freshness-validation: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
