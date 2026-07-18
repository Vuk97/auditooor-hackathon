"""
glider-permit-grief-dos — generated from reference/patterns.dsl/glider-permit-grief-dos.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-permit-grief-dos.yaml
Source: hexens-glider/grief-dos-calls-utilizing-permit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderPermitGriefDos(AbstractDetector):
    ARGUMENT = "glider-permit-grief-dos"
    HELP = "Function forwards user-supplied permit signature to token.permit() without try/catch or prior allowance check. Front-runner can call permit() with the same signature first; the victim's call then reverts on nonce mismatch, DoS'ing the deposit/swap."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-permit-grief-dos.yaml"
    WIKI_TITLE = "Permit front-run grief — unwrapped permit call"
    WIKI_DESCRIPTION = "ERC-2612 permit consumes a one-shot nonce. If a contract wraps deposit/swap around permit() without try/catch or an allowance fallback, any observer can mine a permit tx first — the victim's combined tx then reverts, stranding gas and blocking the intended action. The spender still gains the allowance (attacker goal is grief, not theft)."
    WIKI_EXPLOIT_SCENARIO = "Victim broadcasts depositWithPermit(sig). MEV bot extracts permit args, calls token.permit(sig), then the victim's tx reverts on 'INVALID_SIGNATURE' (nonce consumed). Victim pays gas, no deposit occurs. Repeat to permanently block the victim's entry."
    WIKI_RECOMMENDATION = "Wrap permit() in try/catch and fall through to allowance check on failure. Or check allowance >= amount first and skip permit if already approved."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.permit\\s*\\('}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '\\.permit\\s*\\('}, {'function.body_not_contains_regex': 'try\\s+.*\\.permit|allowance\\s*\\(|\\.allowance|catch'}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-permit-grief-dos: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
