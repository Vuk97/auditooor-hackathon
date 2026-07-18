"""
twap-window-too-short — generated from reference/patterns.dsl/twap-window-too-short.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py twap-window-too-short.yaml
Source: solodit-cluster-C0303
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TwapWindowTooShort(AbstractDetector):
    ARGUMENT = "twap-window-too-short"
    HELP = "TWAP oracle window is hardcoded to a short interval (<= 10 minutes). Attackers can manipulate the pool with a flashloan and move the TWAP enough to mis-price collateral or mint obligations. Safe windows are >= 30 minutes (1800s)."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/twap-window-too-short.yaml"
    WIKI_TITLE = "TWAP observation window too short (< 30 minutes)"
    WIKI_DESCRIPTION = "Contracts that consume a Uniswap V2/V3 TWAP with a short observation window (10s / 30s / 60s / 300s / 600s) remain vulnerable to the exact manipulation TWAPs were meant to prevent. A ~$100k flashloan can move the spot price for one block, and a 10-minute window smooths that perturbation across only a handful of blocks; the TWAP output still diverges materially from the honest price. Consumers use "
    WIKI_EXPLOIT_SCENARIO = "The attacker flashloans ~$100k, swaps into the observed Uniswap pool to push the spot price 5-15%, waits the few blocks covered by the 60-second TWAP window, reads the manipulated TWAP through the protocol's oracle wrapper to mint undercollateralized debt or liquidate honest positions at a stale valuation, then swaps back and repays the flashloan — pocketing the margin."
    WIKI_RECOMMENDATION = "Use a TWAP observation window of at least 30 minutes (1800 seconds). On Uniswap V3 prefer 30-60 minute cardinality; on V2 use a period of at least 1800s combined with deviation sanity checks against a secondary oracle (Chainlink). Never hardcode a sub-10-minute window on a market that can be moved w"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': 'observe\\s*\\(\\s*(\\[0,\\s*(10|30|60|300|600)\\]|1_?0|3_?0|6_?0)|TWAP_PERIOD\\s*=\\s*(10|30|60|300|600)\\s*;|twapWindow\\s*=\\s*(10|30|60|300|600)\\s*;|consult\\s*\\(.*?,\\s*(10|30|60|300|600)\\s*\\)'}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — twap-window-too-short: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
