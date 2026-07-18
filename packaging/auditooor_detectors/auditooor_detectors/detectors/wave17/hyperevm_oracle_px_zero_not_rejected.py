"""
hyperevm-oracle-px-zero-not-rejected — generated from reference/patterns.dsl/hyperevm-oracle-px-zero-not-rejected.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py hyperevm-oracle-px-zero-not-rejected.yaml
Source: monetrix-c4-2026-04-precompile-reader
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class HyperevmOraclePxZeroNotRejected(AbstractDetector):
    ARGUMENT = "hyperevm-oracle-px-zero-not-rejected"
    HELP = "HyperCore ORACLE_PX (0x807) / SPOT_PX (0x808) returns 0 to signal a feed outage — not a real price. Reading either precompile and using the value without `require(price > 0)` turns an outage into a zero-priced notional (under-reports backing, instant liquidation, broken invariants)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/hyperevm-oracle-px-zero-not-rejected.yaml"
    WIKI_TITLE = "HyperCore oraclePx / spotPx zero return treated as valid price"
    WIKI_DESCRIPTION = "Hyperliquid's HyperEVM oracle precompiles (0x807 perp/spot oracle price, 0x808 HL spot pair price) return a uint64. A zero return is an OUTAGE SENTINEL — the documented contract is `0` means 'feed not initialized, asset suspended, or transient outage', NOT that the asset is worth zero. A protocol that decodes the result and feeds it directly into mark-to-market or notional math turns every outage "
    WIKI_EXPLOIT_SCENARIO = "Hedge fund vault on HyperEVM uses `oraclePx(BTC_PERP_INDEX)` to value its 10 BTC spot hedge. Code: `uint64 px = abi.decode(staticcallReturn, (uint64));` followed by `notional = balance * px / scalar;` — no zero guard. L1 BTC oracle goes silent for 90 seconds during a chain incident. During the window: (1) every backing read sees notional = 0 for the hedge leg; (2) `totalBacking()` drops by the hed"
    WIKI_RECOMMENDATION = "Every consumer of the HyperCore oracle precompiles MUST `require(price > 0, \"oracle outage\")` immediately after decoding. Centralize the read in a `PrecompileReader.oraclePx` / `.spotPx` wrapper that bakes the check in; do not allow business-logic contracts to call the precompile directly. Add a c"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'oraclePx|spotPx|PRECOMPILE_ORACLE_PX|PRECOMPILE_SPOT_PX|0x0000000000000000000000000000000000000807|0x0000000000000000000000000000000000000808'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '0x0000000000000000000000000000000000000807|0x0000000000000000000000000000000000000808|PRECOMPILE_ORACLE_PX|PRECOMPILE_SPOT_PX'}, {'function.body_contains_regex': '\\.staticcall\\s*\\('}, {'function.body_contains_regex': 'abi\\.decode\\s*\\(\\s*[a-zA-Z_]+\\s*,\\s*\\(\\s*uint64\\s*\\)\\s*\\)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(?:price|px|rawPx|rawPerpOraclePx|rawSpotPx|p)\\s*>\\s*0|price\\s*==\\s*0\\s*\\)\\s*\\{|if\\s*\\(\\s*(?:price|px)\\s*==\\s*0\\s*\\)\\s*revert|revert\\s+OraclePxZero|revert\\s+ZeroPrice|"oracle px zero"|"px zero"|"spot px zero"'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — hyperevm-oracle-px-zero-not-rejected: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
