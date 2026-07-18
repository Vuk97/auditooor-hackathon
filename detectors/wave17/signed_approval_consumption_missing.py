"""
signed-approval-consumption-missing - generated from reference/patterns.dsl/signed-approval-consumption-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py signed-approval-consumption-missing.yaml
Source: auditooor capability lift 2026-06-02 sibling generalizer
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SignedApprovalConsumptionMissing(AbstractDetector):
    ARGUMENT = "signed-approval-consumption-missing"
    HELP = "Signed approval or delegation writes permission state after signature recovery without binding and consuming a nonce, deadline, domain, salt, or used marker."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/signed-approval-consumption-missing.yaml"
    WIKI_TITLE = "Signed approval consumption missing"
    WIKI_DESCRIPTION = "A signed permit, approval, preapproval, authorization, or delegation updates permission state after signature recovery, but the digest omits replay controls or the path never consumes them, so the same authorization can be replayed."
    WIKI_EXPLOIT_SCENARIO = "Signed approval or delegation writes permission state after signature recovery without binding and consuming a nonce, deadline, domain, salt, or used marker."
    WIKI_RECOMMENDATION = "Bind signed approvals to owner-scoped nonces, deadlines, chain and verifying contract domain, salt or purpose, target and amount, and consume the authorization atomically before or during the state write."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(permit|approv|delegat|authori|sign|recover|ecrecover|isValidSignature)'}, {'contract.has_function_matching': '(?i)(permit|approv|delegat|authori|sign)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i).*(permit|approv|delegat|authori|preapprov).*'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.body_contains_regex': '(?i)(ecrecover|_recover|recover\\s*\\(|isValidSignature)'}, {'function.body_contains_regex': '(?i)keccak256\\s*\\(\\s*abi\\.encode'}, {'function.writes_state_var_matching_regex': '(?i)(allowance|approval|preapprov|delegat|auth|permission|grant)'}, {'function.body_not_contains_regex': '(?i)(nonce|nonces|deadline|expiry|expires|domainSeparator|DOMAIN_SEPARATOR|chainid|verifyingContract|salt|used|consum(?:e|ed|ption)|nullifier)'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - signed-approval-consumption-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
