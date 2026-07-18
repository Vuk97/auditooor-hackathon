"""
nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers — generated from reference/patterns.dsl/nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers.yaml
Source: r106-centrifuge-v3-NAVManager.netAssetValue
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class NavAggregatorClampsNegativeDiffToZeroSkewsMultipoolReaders(AbstractDetector):
    ARGUMENT = "nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers"
    HELP = "NAV-style summing aggregator iterates multiple `(isPositive, value)` components, accumulates into `totalPositive`/`totalNegative`, and returns `totalPositive - totalNegative` clamped to zero. The clamp hides genuine underflow; downstream multi-pool readers that average per-pool NAVs are biased upwar"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers.yaml"
    WIKI_TITLE = "NAV / equity aggregator clamps negative-net to zero — skews multi-pool index"
    WIKI_DESCRIPTION = "An accounting NAV reader sums equity, gain, loss, and liability per pool by branching on each account's `isPositive` flag. A clamp `if (totalNegative >= totalPositive) return 0;` is added to avoid uint underflow. Per-pool consumers can tolerate the clamp because they treat zero as 'no value'. Multi-pool consumers (a master price feeder that averages or weighs sub-pool NAVs into a single pool-share"
    WIKI_EXPLOIT_SCENARIO = "Pool A holds `equity=100, gain=0, loss=0, liability=0` → NAV = 100. Pool B holds `equity=10, gain=0, loss=0, liability=200` → real NAV = -190 but clamped to 0. SimplePriceManager averages: `(100 + 0) / 2 = 50` vs the real `-90 / 2 = -45`. Share price across the master fund is therefore 95 wei higher per share than reality. An attacker redeems shares against the master fund and walks away with asse"
    WIKI_RECOMMENDATION = "Return a signed value (`int128`) so consumers see the true sign, then clamp at the consumer boundary if they cannot tolerate negatives. Or expose two separate views: `(uint128 surplus, uint128 deficit)` and require the consumer to handle deficit explicitly. If clamping is essential, additionally emi"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(nav|equity|aggregat|networth|tvl|valuat)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(nav|netAssetValue|equity|aggregateValue|tvlOf|networth|portfolioValue|portfolioNAV)'}, {'function.body_contains_regex': 'if\\s*\\(\\s*\\w*[Nn]egative\\w*\\s*>=?\\s*\\w*[Pp]ositive\\w*\\s*\\)\\s*\\{?\\s*return\\s+(?:0|uint128\\s*\\(\\s*0\\s*\\))'}, {'function.body_contains_regex': '\\w*[Pp]ositive\\w*\\s*\\+=\\s*\\w+|\\w*[Nn]egative\\w*\\s*\\+=\\s*\\w+'}, {'function.body_not_contains_regex': '\\b(int128|int256)\\s+\\w*[Nn]et\\w*|signed\\w*\\s*=|return\\s*\\(\\s*int'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — nav-aggregator-clamps-negative-diff-to-zero-skews-multipool-readers: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
