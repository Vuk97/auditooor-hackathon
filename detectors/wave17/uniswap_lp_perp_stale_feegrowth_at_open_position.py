"""
uniswap-lp-perp-stale-feegrowth-at-open-position — generated from reference/patterns.dsl/uniswap-lp-perp-stale-feegrowth-at-open-position.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-lp-perp-stale-feegrowth-at-open-position.yaml
Source: auditooor-R75-c4-2023-12-particle-H28
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapLpPerpStaleFeegrowthAtOpenPosition(AbstractDetector):
    ARGUMENT = "uniswap-lp-perp-stale-feegrowth-at-open-position"
    HELP = "openPosition snapshots feeGrowthInside from the Uniswap v3 `positions` mapping (stale since the last `collect/burn`) instead of from the pool's live tick state. Later `closePosition` compares live state to stale → borrower owes LP fees accrued BEFORE they borrowed."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-lp-perp-stale-feegrowth-at-open-position.yaml"
    WIKI_TITLE = "LP-perp opens with stale feeGrowthInside read from Uniswap positions, not from pool ticks"
    WIKI_DESCRIPTION = "Particle, Gamma Vaults, Panoptic, and similar LP-leverage protocols borrow a Uniswap v3 position from a lender, give the borrower the exposure, and track owed fees via feeGrowth differentials. At open, the protocol must snapshot the CURRENT feeGrowthInside for the position's tick range — the number at open determines the baseline for 'fees earned during the borrow'. The Uniswap NFT's `positions` m"
    WIKI_EXPLOIT_SCENARIO = "(1) LP opened a Uniswap v3 position 1 month ago, hasn't called `collect` since. `positions(tokenId).feeGrowthInside0LastX128 = F0`. Pool's current live feeGrowthInside is F0 + ΔF_LP (fees earned over the month). (2) Borrower opens a Particle lien against the position. `openPosition` snapshots cache.feeGrowthInside0LastX128 = F0 (from positions mapping, stale). (3) Borrower holds the position for 1"
    WIKI_RECOMMENDATION = "Read the pool's live feeGrowthInside at open via `IUniswapV3Pool.ticks(tickLower/Upper)` + current global feeGrowth (or use the Uniswap `PositionValue` library's live calculation, not the NFT-stored one). Concretely, call `Base.getFeeGrowthInside(token0, token1, fee, tickLower, tickUpper)` which com"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(openPosition|openLien|borrowLp|ParticlePositionManager|leverageLP|LpLoan)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(openPosition|_openPosition|openLien|borrowLp|_prepareLeverage|beginLeverage)'}, {'function.body_contains_regex': '(feeGrowthInside0LastX128|feeGrowthInside1LastX128)'}, {'function.body_contains_regex': 'positionManager\\.positions|INonfungiblePositionManager|npm\\.positions'}, {'function.body_not_contains_regex': '(getFeeGrowthInside|pool\\.ticks|IUniswapV3Pool\\([^)]*\\)\\.ticks|observeFeeGrowth)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-lp-perp-stale-feegrowth-at-open-position: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
