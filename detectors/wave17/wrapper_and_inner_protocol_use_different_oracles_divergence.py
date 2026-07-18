"""
wrapper-and-inner-protocol-use-different-oracles-divergence — generated from reference/patterns.dsl/wrapper-and-inner-protocol-use-different-oracles-divergence.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py wrapper-and-inner-protocol-use-different-oracles-divergence.yaml
Source: auditooor-R110-morpho-PreLiquidation
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WrapperAndInnerProtocolUseDifferentOraclesDivergence(AbstractDetector):
    ARGUMENT = "wrapper-and-inner-protocol-use-different-oracles-divergence"
    HELP = "A wrapper / hook contract over a base lending protocol carries its own pricing oracle (`PRE_LIQUIDATION_ORACLE`, `wrapperOracle`, `hookOracle`, `softOracle`) and uses it for the wrapper's eligibility / threshold / incentive math, but the actual state-mutating call into the base protocol (`Morpho.rep"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/wrapper-and-inner-protocol-use-different-oracles-divergence.yaml"
    WIKI_TITLE = "Wrapper / pre-liquidation contract uses one oracle while inner protocol uses another — divergence-band DoS"
    WIKI_DESCRIPTION = "Morpho's `PreLiquidation.sol` (and Aave-v3 health-extension contracts, Compound-v3 vault wrappers, generic 'soft liquidation' hooks) carries its own `PRE_LIQUIDATION_ORACLE` immutable, set at deploy time independently of the underlying market's `marketParams.oracle`. The wrapper computes the borrower's `collateralQuoted` via `IOracle(PRE_LIQUIDATION_ORACLE).price()` and decides eligibility / preLI"
    WIKI_EXPLOIT_SCENARIO = "A curator deploys `PreLiquidation` for a wstETH/USDC market on Morpho Blue with `PRE_LIQUIDATION_ORACLE = pythBackedOracle` (TWAP-cached from a Pyth feed) and the underlying Morpho market uses `marketParams.oracle = chainlinkOracle` (live Chainlink). During a brief wstETH/USD depeg, Pyth shows wstETH at $1.05k and Chainlink shows wstETH at $0.95k. Borrower B has 1 wstETH collateral and $0.99k debt"
    WIKI_RECOMMENDATION = "Force oracle agreement at deploy time OR pass the wrapper's oracle through into the inner call. Option A (constraint): in the constructor, `require(PRE_LIQUIDATION_ORACLE == _marketParams.oracle, OracleMismatch())` — eliminates the divergence class entirely (but loses the wrapper's flexibility to us"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'PreLiquidation|Liquidator|Hook|Extension|Wrapper|Adapter|Strategy|HealthChecker'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?preLiquidate|_?softLiquidate|_?liquidate|_?triggerLiquidation|_?checkHealth|_?evaluatePosition)$'}, {'function.body_contains_regex': 'PRE_LIQUIDATION_ORACLE|wrapperOracle|hookOracle|secondaryOracle|softOracle|preOracle\\b|altOracle\\b'}, {'function.body_contains_regex': '\\.\\s*(repay|withdrawCollateral|liquidate|borrow|withdraw|forceDeallocate)\\s*\\(|MORPHO\\.\\w+\\s*\\(|baseProtocol\\.\\w+\\s*\\('}, {'function.body_not_contains_regex': '_isHealthy\\s*\\([^)]*PRE_LIQUIDATION_ORACLE|_isHealthy\\s*\\([^)]*wrapperOracle|setMarketOracle\\s*\\(\\s*PRE_LIQUIDATION_ORACLE|require\\s*\\(\\s*\\w*ORACLE\\b\\s*==\\s*marketParams\\.oracle'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — wrapper-and-inner-protocol-use-different-oracles-divergence: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
