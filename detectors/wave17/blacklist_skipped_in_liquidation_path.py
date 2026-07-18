"""
blacklist-skipped-in-liquidation-path — generated from reference/patterns.dsl/blacklist-skipped-in-liquidation-path.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py blacklist-skipped-in-liquidation-path.yaml
Source: solodit-novel/slice_ah-d3-doma
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BlacklistSkippedInLiquidationPath(AbstractDetector):
    ARGUMENT = "blacklist-skipped-in-liquidation-path"
    HELP = "Protocol blacklist enforced in repay/borrow paths but not in liquidation. Liquidator can force-seize collateral of a blacklisted borrower, bypassing the sanction."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/blacklist-skipped-in-liquidation-path.yaml"
    WIKI_TITLE = "Liquidation path skips blacklist enforcement"
    WIKI_DESCRIPTION = "Blacklist / deny-list checks applied to user-initiated operations must also apply to permissionless force-operations like liquidation. Otherwise an adversarial liquidator can coerce state transitions on blacklisted borrowers, nullifying the sanction effect."
    WIKI_EXPLOIT_SCENARIO = "Protocol blacklists address X (e.g., OFAC-listed). `repayBorrow(X)` reverts due to blacklist check. `liquidate(X)` has no blacklist check; anyone calls it, seizes X's collateral, and mints X's healthy position off the books. Blacklist effectively bypassed."
    WIKI_RECOMMENDATION = "Apply the blacklist check to every function that mutates a user's position, including liquidation paths: `require(!isBlacklisted(borrower) && !isBlacklisted(liquidator))`. If liquidation of blacklisted accounts is intentionally needed, gate it behind governance."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'blacklist|isBlacklisted|denyList|sanction'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'liquidate|seize|forceRepay|closePosition|liquidation'}, {'function.body_not_contains_regex': 'isBlacklisted|blacklisted\\s*\\[|denyList|sanctioned|blocklist'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — blacklist-skipped-in-liquidation-path: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
