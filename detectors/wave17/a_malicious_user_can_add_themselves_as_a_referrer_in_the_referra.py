"""
a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra — generated from reference/patterns.dsl/a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AMaliciousUserCanAddThemselvesAsAReferrerInTheReferra(AbstractDetector):
    ARGUMENT = "a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra"
    HELP = "A malicious user can add themselves as a referrer in the Referral contract to aid phishing attacks"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra.yaml"
    WIKI_TITLE = "A malicious user can add themselves as a referrer in the Referral contract to aid phishing attacks"
    WIKI_DESCRIPTION = "**Severity**: Medium\n\n**Status**: Resolved\n\n**Description**\n\nThe Referral contract is responsible for the referral program which allows users to refer others to earn rewards for introducing users to the protocol. The issue lies within the registerReferral function where a malicious user can add them"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #45620: **Severity**: Medium\n\n**Status**: Resolved\n\n**Description**\n\nThe Referral contract is responsible for the referral program which allows users to refer others to earn rewards for introducing users to t"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(referr|referral)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(registerReferral|setReferrer|bindReferral|refer)'}, {'function.reads_msg_sender': True}, {'function.body_contains_regex': '(?i)(referrer|referral)'}, {'function.body_contains_regex': '\\[\\s*msg\\s*\\.\\s*sender\\s*\\]\\s*=\\s*(msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\))'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*[^;{}]*(referrer|referral)[^;{}]*!=\\s*(msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\))|require\\s*\\(\\s*(msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\))[^;{}]*!=[^;{}]*(referrer|referral)'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — a-malicious-user-can-add-themselves-as-a-referrer-in-the-referra: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
