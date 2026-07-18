"""
vault-admin-action-uses-mark-price — generated from reference/patterns.dsl/vault-admin-action-uses-mark-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py vault-admin-action-uses-mark-price.yaml
Source: phase-33-novel-surfacer-triangle-price-vault-mark
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class VaultAdminActionUsesMarkPrice(AbstractDetector):
    ARGUMENT = "vault-admin-action-uses-mark-price"
    HELP = "vault-admin-action-uses-mark-price"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/vault-admin-action-uses-mark-price.yaml"
    WIKI_TITLE = "vault-admin-action-uses-mark-price"
    WIKI_DESCRIPTION = "vault-admin-action-uses-mark-price"
    WIKI_EXPLOIT_SCENARIO = "vault-admin-action-uses-mark-price"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(vault|strategy|manager|treasury|perp|clearingHouse)'}, {'function.kind': 'external_or_public'}, {'function.has_modifier': '(?i)(onlyAdmin|onlyOwner|onlyGovernance|onlyKeeper|onlyManager|onlyRole)'}, {'function.body_matches_regex': '(?i)(mark_price|markPrice|getMarkPrice|_mark\\b|indexToMark|pnl\\s*=|realizedPnl|unrealizedPnl)'}, {'function.not_body_matches_regex': '(?i)(TWAP|twap|timeWeighted|oracle\\.|heartbeat|staleAfter|updatedAt|getRoundData|chainlink)'}, {'function.not_source_matches_regex': '(?i)(mock|test|fixture|t\\.sol$)'}]
    _MATCH = [{'function.body_contains_regex': '(?i)(setFee|setRake|rebalance|sweep|skim|withdrawFees|takeFees|harvest|collect|setRatio|setAllocation)'}, {'function.body_contains_regex': '(?i)(\\*\\s*markPrice|markPrice\\s*\\*|getMarkPrice\\(|pnl\\s*\\*|mulDiv\\([^)]*mark)'}]

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
                info = [f, f" — vault-admin-action-uses-mark-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
