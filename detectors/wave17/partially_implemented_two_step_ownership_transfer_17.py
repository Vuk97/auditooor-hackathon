"""
partially-implemented-two-step-ownership-transfer-17 — generated from reference/patterns.dsl/partially-implemented-two-step-ownership-transfer-17.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py partially-implemented-two-step-ownership-transfer-17.yaml
Source: auditooor-row-local-fixture-repair
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PartiallyImplementedTwoStepOwnershipTransfer17(AbstractDetector):
    ARGUMENT = "partially-implemented-two-step-ownership-transfer-17"
    HELP = "Accept-side two-step ownership/admin endpoint finalizes from a pending nominee slot without proving that `msg.sender` is that nominee."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/partially-implemented-two-step-ownership-transfer-17.yaml"
    WIKI_TITLE = "Partially implemented two-step ownership transfer"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row proves a contract that appears to implement a staged ownership/admin handoff via `pendingOwner`-style storage, but its accept-side endpoint still writes the live owner/admin slot from that pending slot without a visible nominee-authentication check. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "The current owner stages `pendingOwner = alice`, then calls an accept-side endpoint that finalizes from `pendingOwner` without requiring Alice to call from her own address. The two-step flow exists syntactically but the second step no longer proves nominee control."
    WIKI_RECOMMENDATION = "Require `msg.sender == pendingOwner` (or the equivalent nominee slot) on the accept-side endpoint, clear the pending slot after acceptance, and keep this row NOT_SUBMIT_READY until a real corpus target demonstrates impact."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(accept|claim|confirm|take|finalize|complete|become)(Ownership|Owner|Admin|Governance|Role)$'}, {'function.body_contains_regex': '(?i)(owner|admin|governance)\\s*=\\s*(pending|proposed|nominated|candidate|newOwner)|_transferOwnership\\s*\\(\\s*(pending|proposed|nominated|candidate|newOwner)'}, {'function.body_not_contains_regex': 'msg\\.sender\\s*(==|!=)\\s*(pending|proposed|nominated|candidate|newOwner)|(pending|proposed|nominated|candidate|newOwner)\\s*(==|!=)\\s*msg\\.sender'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — partially-implemented-two-step-ownership-transfer-17: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
