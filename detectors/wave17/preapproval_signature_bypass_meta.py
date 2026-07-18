"""
preapproval-signature-bypass-meta - generated from reference/patterns.dsl/preapproval-signature-bypass-meta.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py preapproval-signature-bypass-meta.yaml
Source: polymarket-v2-meta-class-r41
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PreapprovalSignatureBypassMeta(AbstractDetector):
    ARGUMENT = "preapproval-signature-bypass-meta"
    HELP = "Order verification accepts signature.length == 0 when a preapproval flag is set, with no expiry/deadline check — operator-flipped flag authorizes a signature-less fill."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/preapproval-signature-bypass-meta.yaml"
    WIKI_TITLE = "Preapproval bypasses signature when no expiry bound"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: the owned fixture pair models an order verifier that accepts signature.length == 0 when preapproved[orderHash] is set and has no same-function expiry/deadline/timestamp bound. NOT_SUBMIT_READY until corpus-backed impact evidence exists."
    WIKI_EXPLOIT_SCENARIO = "Operator preapproves order H for a legitimate purpose. Operator is later compromised (or operator-role key leaks). Attacker replays the signature-less fill path using H indefinitely, against any market state, because nothing in the preapproval digest binds to a deadline."
    WIKI_RECOMMENDATION = "Either bind preapproval to a deadline stored alongside the boolean flag and revert once block.timestamp exceeds it, or automatically invalidate preapproval on any order status update. Keep this row NOT_SUBMIT_READY until evidence expands beyond the owned fixture pair."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'preapproved'}, {'contract.has_function_body_matching': 'preapproved\\['}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'signature\\.length\\s*==\\s*0|signature\\.length == 0'}, {'function.body_contains_regex': 'preapproved\\['}, {'function.body_not_contains_regex': 'deadline|expiry|expires|timestamp\\s*[<>=]'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" - preapproval-signature-bypass-meta: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
