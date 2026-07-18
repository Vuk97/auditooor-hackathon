"""
glider-api3-oracle-no-staleness-check — generated from reference/patterns.dsl/glider-api3-oracle-no-staleness-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-api3-oracle-no-staleness-check.yaml
Source: hexens-glider/api3-oracle-price-data-is-not-validated-for-stalen
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderApi3OracleNoStalenessCheck(AbstractDetector):
    ARGUMENT = "glider-api3-oracle-no-staleness-check"
    HELP = "Consumer reads an API3 `IProxy.read()` feed (returns `int224 value, uint32 timestamp`) without asserting the timestamp is within a staleness window or value > 0."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-api3-oracle-no-staleness-check.yaml"
    WIKI_TITLE = "API3 price consumed without timestamp / value validation"
    WIKI_DESCRIPTION = "API3 proxies expose `read() returns (int224 value, uint32 timestamp)`. The int224 type is distinctive to API3 and should be a reliable contract-level signal. Per API3 docs, both value and timestamp MUST be validated: `require(value > 0)` and `require(block.timestamp - timestamp <= maxStale)`. Skipping either allows stale prices to drive borrow/liquidate/swap logic."
    WIKI_EXPLOIT_SCENARIO = "Collateral oracle returns `value=0` during a brief feed outage. Contract uses `value` directly in `collateralValue = amount * value / 1e18` — collateral evaluates to 0, position shows insolvent, attacker triggers liquidation at the floor."
    WIKI_RECOMMENDATION = "Always pair the read: `(int224 value, uint32 timestamp) = proxy.read(); require(value > 0, \"invalid\"); require(block.timestamp - timestamp <= MAX_STALE, \"stale\");`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'IProxy|IApi3Proxy|int224|api3|Api3ReaderProxy'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '\\.read\\s*\\(\\s*\\)|int224\\s+\\w+|int224\\s*\\)'}, {'function.body_not_contains_regex': 'block\\.timestamp\\s*-\\s*\\w*[Tt]imestamp|timestamp\\s*>=\\s*block\\.timestamp|MAX_STALENESS|STALE_AFTER|require\\s*\\(\\s*\\w+Timestamp|require\\s*\\(\\s*block\\.timestamp\\s*-\\s*\\w*[Tt]imestamp'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — glider-api3-oracle-no-staleness-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
