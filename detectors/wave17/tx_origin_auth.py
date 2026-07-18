"""
tx-origin-auth — generated from reference/patterns.dsl/tx-origin-auth.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py tx-origin-auth.yaml
Source: auditooor-seed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class TxOriginAuth(AbstractDetector):
    ARGUMENT = "tx-origin-auth"
    HELP = "tx.origin used for authorization — phishable via arbitrary intermediate contract."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/tx-origin-auth.yaml"
    WIKI_TITLE = "tx.origin authentication (SWC-115)"
    WIKI_DESCRIPTION = "Using tx.origin for authorization allows phishing: if user signs a tx to a malicious contract, that contract calls the protocol as msg.sender != tx.origin == user and bypasses the check."
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys contract X. Victim calls any X method. X calls target.protectedFn() — tx.origin is victim, check passes, attacker acts as victim."
    WIKI_RECOMMENDATION = "Use msg.sender. Only use tx.origin for 'only EOA' checks via `require(tx.origin == msg.sender)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.body_contains_regex': 'tx\\.origin\\s*=='}, {'function.kind': 'external_or_public'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}]

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
                info = [f, f" — tx-origin-auth: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
