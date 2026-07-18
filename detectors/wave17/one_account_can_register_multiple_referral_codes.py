"""
one-account-can-register-multiple-referral-codes — generated from reference/patterns.dsl/one-account-can-register-multiple-referral-codes.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py one-account-can-register-multiple-referral-codes.yaml
Source: zellic audit Avantis - Zellic Audit Report
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OneAccountCanRegisterMultipleReferralCodes(AbstractDetector):
    ARGUMENT = "one-account-can-register-multiple-referral-codes"
    HELP = "registerCode assigns codeOwners[_code] = msg.sender without a visible per-account existing-code guard."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/one-account-can-register-multiple-referral-codes.yaml"
    WIKI_TITLE = "One account can register multiple referral codes"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only for a registerCode path that checks codeOwners[_code] == address(0) and then assigns codeOwners[_code] = msg.sender without a visible accountCode[msg.sender] / hasCode[msg.sender] uniqueness guard. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "registerCode assigns codeOwners[_code] = msg.sender without a visible per-account existing-code guard."
    WIKI_RECOMMENDATION = "Track code ownership per account and reject a second registration from the same caller. Do not promote from this fixture smoke alone."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(referral|referrer|registerCode|codeOwners)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^registerCode$'}, {'function.body_contains_regex': '(?i)\\bcodeOwners\\s*\\[[^\\]]+\\]\\s*==\\s*address\\s*\\(\\s*0\\s*\\)'}, {'function.body_contains_regex': '(?i)\\bcodeOwners\\s*\\[[^\\]]+\\]\\s*=\\s*(msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\))'}, {'function.body_not_contains_regex': '(?is)(?:require|assert)\\s*\\([^;{}]*(?:accountCode|userCode|codeByAccount|codeOf|codeForAccount|hasCode|hasRegisteredCode|registeredCode|codeRegistered|ownsCode)\\s*\\[\\s*(?:msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\))\\s*\\][^;{}]*(?:==|!=)\\s*(?:0|false|bytes32\\s*\\(\\s*0\\s*\\)|address\\s*\\(\\s*0\\s*\\))|(?:require|assert)\\s*\\([^;{}]*!\\s*(?:hasCode|hasRegisteredCode|registeredCode|ownsCode)\\s*\\[\\s*(?:msg\\s*\\.\\s*sender|_msgSender\\s*\\(\\s*\\))\\s*\\]'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" — one-account-can-register-multiple-referral-codes: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
