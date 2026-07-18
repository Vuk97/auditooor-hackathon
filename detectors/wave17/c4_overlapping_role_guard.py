"""
c4-overlapping-role-guard — generated from reference/patterns.dsl/c4-overlapping-role-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-overlapping-role-guard.yaml
Source: code4arena/slice_ab-Ethena-UStb
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4OverlappingRoleGuard(AbstractDetector):
    ARGUMENT = "c4-overlapping-role-guard"
    HELP = "Sensitive action checks whitelist membership but forgets to also reject blacklisted addresses. An account that is BOTH whitelisted and blacklisted slips through."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-overlapping-role-guard.yaml"
    WIKI_TITLE = "Whitelist check without complementary blacklist gate"
    WIKI_DESCRIPTION = "Protocols that enforce both a whitelist (allowed to act) and blacklist (explicitly banned) must check both. Relying solely on the whitelist lets mistakenly-dual-listed addresses bypass the ban."
    WIKI_EXPLOIT_SCENARIO = "USD token enforces `whitelist[user] == true` for burns. Attacker adds to whitelist in a permissionless epoch, gets blacklisted for fraud — but burn still passes the whitelist-only check. Attacker burns to redeem collateral before being removed from whitelist."
    WIKI_RECOMMENDATION = "Add `require(!isBlacklisted(msg.sender))` alongside every whitelist check. Prefer a single `require(canAct(msg.sender))` internal that checks both."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'whitelist|blacklist|isWhitelisted|isBlacklisted'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(burn|mint|redeem|transfer|transferFrom|redistribute)'}, {'function.body_contains_regex': 'isWhitelisted\\s*\\(|whitelist\\s*\\[\\s*\\w+\\s*\\]|require\\s*\\(\\s*\\w*whitelist'}, {'function.body_not_contains_regex': 'isBlacklisted\\s*\\(|blacklist\\s*\\[|require\\s*\\(\\s*!\\s*\\w*blacklist|require\\s*\\(\\s*!\\s*isBlacklisted'}, {'function.contract_has_source_matching': 'blacklist|isBlacklisted'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-overlapping-role-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
