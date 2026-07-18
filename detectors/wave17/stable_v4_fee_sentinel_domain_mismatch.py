"""
stable-v4-fee-sentinel-domain-mismatch — generated from reference/patterns.dsl/stable-v4-fee-sentinel-domain-mismatch.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py stable-v4-fee-sentinel-domain-mismatch.yaml
Source: revert-stableswap-hooks/recall-2026-05-02
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StableV4FeeSentinelDomainMismatch(AbstractDetector):
    ARGUMENT = "stable-v4-fee-sentinel-domain-mismatch"
    HELP = "Uniswap v4 PoolKey fee accepts a hook fee value that is later used as percentage arithmetic without excluding dynamic-fee sentinels."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/stable-v4-fee-sentinel-domain-mismatch.yaml"
    WIKI_TITLE = "Uniswap v4 fee sentinel reused as StableSwap arithmetic fee"
    WIKI_DESCRIPTION = "Uniswap v4 reserves sentinel fee encodings such as the dynamic-fee flag for PoolKey semantics. Hook implementations that store the same value as an LP fee percentage must reject those sentinels before fee math."
    WIKI_EXPLOIT_SCENARIO = "A factory deploys a hook with LPFeeLibrary.DYNAMIC_FEE_FLAG. PoolKey initialization accepts it as dynamic-fee configuration, but hook fee calculation treats the sentinel as an oversized percentage and normal swaps revert or charge impossible fees."
    WIKI_RECOMMENDATION = "Reject dynamic-fee sentinel values and require the fee to be within the same maximum domain used by arithmetic fee calculation before building PoolKey or storing the value."

    _PRECONDITIONS = []
    _MATCH = []

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
                info = [f, f" — stable-v4-fee-sentinel-domain-mismatch: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
