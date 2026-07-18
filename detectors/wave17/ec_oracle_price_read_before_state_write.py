"""
ec-oracle-price-read-before-state-write — generated from reference/patterns.dsl/ec-oracle-price-read-before-state-write.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-oracle-price-read-before-state-write.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcOraclePriceReadBeforeStateWrite(AbstractDetector):
    ARGUMENT = "ec-oracle-price-read-before-state-write"
    HELP = "Function reads oracle price before updating protocol state; a manipulated price feeds into the state-change math without post-update verification."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-oracle-price-read-before-state-write.yaml"
    WIKI_TITLE = "Oracle price read before state write (sequencing bug)"
    WIKI_DESCRIPTION = "The function fetches an external price before completing its own state mutations. If the price source is a pool or oracle that the attacker can move (via flashloan, donation, or AMM trade), they can front-run the price read and then let the state write execute against the manipulated value."
    WIKI_EXPLOIT_SCENARIO = "Lending protocol reads collateral price via getPrice(), then updates user.collateral += donatedAmount. Attacker donates tokens to inflate collateral value, triggering healthy-looking health factor before the accounting reflects the real state."
    WIKI_RECOMMENDATION = "Apply the checks-effects-interactions pattern: complete all state mutations before reading any external oracle. If the oracle price must be read early, snapshot it and re-verify after the state write. Use time-weighted prices (TWAP) to reduce single-block manipulation risk."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestAnswer|latestRoundData|getPrice|currentPrice|getReserves|slot0'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.latestAnswer\\(\\)|\\.latestRoundData\\(\\)|\\.getPrice\\(|\\.currentPrice\\(|getReserves\\(\\)|\\.slot0\\(\\)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': 'balances\\[|shares\\[|debt\\[|collateral\\[|totalSupply\\s*[+\\-]?='}, {'function.body_not_contains_regex': 'require\\s*\\(.*price|assert\\s*\\(.*price|minPrice|maxPrice|staleness|updatedAt'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-oracle-price-read-before-state-write: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
