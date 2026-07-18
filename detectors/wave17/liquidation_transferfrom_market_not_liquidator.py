"""
liquidation-transferfrom-market-not-liquidator — generated from reference/patterns.dsl/liquidation-transferfrom-market-not-liquidator.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py liquidation-transferfrom-market-not-liquidator.yaml
Source: auditooor-R75-c4-yield-2024-05-predy-27
"""

# NOT_SUBMIT_READY: fixture-smoke/source-shape proof only for this row.

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LiquidationTransferfromMarketNotLiquidator(AbstractDetector):
    ARGUMENT = "liquidation-transferfrom-market-not-liquidator"
    HELP = "Negative-margin compensation transferFrom targets market / vault instead of msg.sender — liquidation of unhealthy positions always reverts."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/liquidation-transferfrom-market-not-liquidator.yaml"
    WIKI_TITLE = "Bad-debt transferFrom pulls from market contract, not liquidator, DoSing every underwater liquidation"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row matches a liquidation-shaped function where a negative `remainingMargin` branch charges the shortfall via `safeTransferFrom(..., address(this), address(this), uint256(-remainingMargin))` or another market/vault/pool self-source. It does not yet prove the full protocol semantics around insolvency handling, so the row remains NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "Predy LiquidationLogic.executeLiquidate: once remainingMargin < 0, the function calls `ERC20.safeTransferFrom(pairStatus.quotePool.token, address(this), address(this), uint256(-remainingMargin))` — `from` is the market itself. No allowance exists; every underwater liquidation reverts. Protocol cannot deleverage bad positions."
    WIKI_RECOMMENDATION = "Pass `msg.sender` as the `from` argument so the liquidator actually covers the shortfall. Do not promote from this fixture smoke alone; add protocol-specific tests that prove the liquidation branch is genuinely charging the liquidator and not the market contract."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(liquidat|remainingMargin|safeTransferFrom)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(liquidate|executeLiquidate|settleBadDebt)'}, {'function.body_contains_regex': '(?i)remainingMargin\\s*<\\s*0'}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\('}, {'function.body_contains_regex': 'safeTransferFrom\\s*\\(\\s*[^,]+\\s*,\\s*(?:address\\s*\\(\\s*this\\s*\\)|market|vault|pool|pairStatus\\.[A-Za-z0-9_\\.]+)\\s*,\\s*address\\s*\\(\\s*this\\s*\\)\\s*,\\s*uint256\\s*\\(\\s*-\\s*remainingMargin\\s*\\)'}, {'function.body_not_contains_regex': 'safeTransferFrom\\s*\\(\\s*[^,]+\\s*,\\s*msg\\.sender\\s*,\\s*address\\s*\\(\\s*this\\s*\\)\\s*,\\s*uint256\\s*\\(\\s*-\\s*remainingMargin\\s*\\)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — liquidation-transferfrom-market-not-liquidator: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
