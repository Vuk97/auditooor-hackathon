"""
restricted-token-action-missing-registry-check - generated from reference/patterns.dsl/restricted-token-action-missing-registry-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py restricted-token-action-missing-registry-check.yaml
Source: auditooor capability lift 2026-06-02 sibling generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RestrictedTokenActionMissingRegistryCheck(AbstractDetector):
    ARGUMENT = "restricted-token-action-missing-registry-check"
    HELP = "Token holder action mutates balances, allowances, shares, or burn state while omitting the freeze, blocklist, veto, or restriction registry check."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/restricted-token-action-missing-registry-check.yaml"
    WIKI_TITLE = "Restricted token action missing registry check"
    WIKI_DESCRIPTION = "The contract maintains a holder restriction registry, but a public token movement, approval, burn, exit, join, redeem, or ragequit path mutates holder rights without consulting that registry."
    WIKI_EXPLOIT_SCENARIO = "Token holder action mutates balances, allowances, shares, or burn state while omitting the freeze, blocklist, veto, or restriction registry check."
    WIKI_RECOMMENDATION = "Route every holder action through the same restriction helper and test transfer, transferFrom, approve, burn, exit, join, and ragequit variants against frozen and blocked accounts."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(frozen|blocked|vetoed|blacklist|blocklist|restricted)'}, {'contract.has_state_var_matching': '(?i)(frozen|blocked|vetoed|blacklist|blocklist|restricted|balanceOf|balances|allowance|shares)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i).*(transfer|send|move|burn|approve|setApprovalForAll|ragequit|exit|leave|redeem|join|execute).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(balanceOf\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|_balances\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|(?:allowance|_allowances)\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\]\\s*=|shares\\s*\\[[^\\]]+\\]\\s*(-=|\\+=)|_burn\\s*\\(|_approve\\s*\\(|transferFrom\\s*\\()'}, {'function.body_not_contains_regex': '(?i)(frozen|blocked|vetoed|blacklist|blocklist|restricted|notFrozen|canTransfer|beforeTokenTransfer)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - restricted-token-action-missing-registry-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
