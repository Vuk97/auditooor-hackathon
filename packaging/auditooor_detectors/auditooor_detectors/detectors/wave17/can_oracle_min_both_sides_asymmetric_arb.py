"""
can-oracle-min-both-sides-asymmetric-arb — generated from reference/patterns.dsl/can-oracle-min-both-sides-asymmetric-arb.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py can-oracle-min-both-sides-asymmetric-arb.yaml
Source: cantina/2024-2025-ebisu-seneca-lending-min-price-class
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CanOracleMinBothSidesAsymmetricArb(AbstractDetector):
    ARGUMENT = "can-oracle-min-both-sides-asymmetric-arb"
    HELP = "Health-factor / borrow path uses `min(oracle1, oracle2)` for BOTH collateral and debt valuation — this is not conservative; attacker arbitrages the oracle spread by opening at low, closing at low."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/can-oracle-min-both-sides-asymmetric-arb.yaml"
    WIKI_TITLE = "Symmetric min() oracle used for both collateral and debt sides"
    WIKI_DESCRIPTION = "Protocols that read two oracles (primary + fallback, spot + TWAP, Chainlink + Pyth) often apply `min()` on both sides of the health equation thinking it is the safer choice. It is not. The correct asymmetric rule is: underestimate what borrowers supply (use min for collateral) AND overestimate what they owe (use max for debt). Applying min to both sides lets an attacker open a position when price "
    WIKI_EXPLOIT_SCENARIO = "Ebisu / Seneca / lending-fork class: primary Chainlink prints WETH at $3,000, secondary TWAP at $2,900. The protocol uses `min()` → $2,900 collateral value. User supplies 10 WETH (accounted $29k), borrows $29k stablecoin. Oracles converge next block to $3,000 / $3,000 = $30k collateral value, BUT since debt valuation also used `min()` at open and the debt stablecoin is also min-valued, the user's "
    WIKI_RECOMMENDATION = "Implement the strict asymmetric rule: `collateralValue = size * min(priceA, priceB)` AND `debtValue = amount * max(priceA, priceB)` at EVERY health-factor / borrow / withdraw call site. Alternatively, use a single chosen oracle with a deviation tripwire (revert if the two sources disagree by more th"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'collateral|debt|borrow|oracle|priceFeed'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(borrow|withdraw|liquidate|computeHealth|_healthFactor|previewBorrow|getAccountValue|checkCollateralization)'}, {'function.body_contains_regex': '(Math\\.min|_min\\s*\\(|\\bmin\\s*\\(|<\\s*\\w*[Pp]rice\\s*\\?\\s*\\w+[Pp]rice\\s*:)'}, {'function.body_not_contains_regex': '(Math\\.max|_max\\s*\\(|\\bmax\\s*\\().*debt|debtPrice\\s*=\\s*[^;]*max|collateralPrice\\s*=\\s*[^;]*min[\\s\\S]*debtPrice\\s*=\\s*[^;]*max'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — can-oracle-min-both-sides-asymmetric-arb: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
