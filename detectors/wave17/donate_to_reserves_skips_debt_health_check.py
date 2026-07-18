"""
donate-to-reserves-skips-debt-health-check — generated from reference/patterns.dsl/donate-to-reserves-skips-debt-health-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py donate-to-reserves-skips-debt-health-check.yaml
Source: auditooor-R76-rekt-euler-2023
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DonateToReservesSkipsDebtHealthCheck(AbstractDetector):
    ARGUMENT = "donate-to-reserves-skips-debt-health-check"
    HELP = "A function that lets a user remove their own collateral (donate / burn / send to reserves) runs no post-state solvency check, letting attackers manufacture an underwater position to then self-liquidate at a discount."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/donate-to-reserves-skips-debt-health-check.yaml"
    WIKI_TITLE = "Collateral-reducing function is not gated by a post-state solvency / health check"
    WIKI_DESCRIPTION = "In CDP-style lending protocols, EVERY entrypoint that reduces a borrower's collateral-side balance MUST trigger an account-health check after the mutation. If a protocol exposes an auxiliary 'donate to reserves' or 'burn-to-contribute' path that does not call `checkLiquidity` on the donor, an attacker can lever up 30x, donate the tiny collateral leg, then self-liquidate from a sister contract to h"
    WIKI_EXPLOIT_SCENARIO = "Attacker flash-loans 30M DAI, deposits as collateral, borrows 200M DAI worth of dToken against eToken (leverage). Balance: ~200M eDAI, 200M dDAI. Attacker calls `donateToReserves(eDAI, 100M)` — eDAI balance drops to 100M, dDAI stays 200M. Position is 2x underwater but no health check fired. Attacker then liquidates their own position from Contract B; the liquidator receives discounted eDAI collate"
    WIKI_RECOMMENDATION = "Wrap every collateral-reducing entry-point with `checkLiquidity(msg.sender)` (or your lending protocol's equivalent post-state solvency check). Consider using a post-call hook / modifier that rejects the transaction if the account's health factor falls below 1.0 after the mutation. A general rule: t"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)lend|borrow|collateral|reserve|liquidat|health|accountliquidity'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^donateToReserves$|^donateToReserve$|^contributeToReserve$|^reduceCollateral$|^burnFromAccount$|^transferCollateralAway$'}, {'function.body_contains_regex': '(?i)\\b(?:reserve|reserves|protocolReserve)\\b'}, {'function.body_contains_regex': '(?i)\\b(?:_balances|balanceOf|collateral)\\w*'}, {'function.body_contains_regex': '(?i)-='}, {'function.body_not_contains_regex': '(?i)checkLiquidity|checkAccountLiquidity|checkHealthFactor|requireAccountStatusCheck|_isHealthy|healthFactor\\s*>=|collateralValue\\s*>=\\s*debt'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — donate-to-reserves-skips-debt-health-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
