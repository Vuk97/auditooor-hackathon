"""
glider-create3-salt-hijack-leads-to-deterministic-address — generated from reference/patterns.dsl/glider-create3-salt-hijack-leads-to-deterministic-address.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-create3-salt-hijack-leads-to-deterministic-address.yaml
Source: hexens-glider/create3-salt-hijack-leads-to-deterministic-address
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderCreate3SaltHijackLeadsToDeterministicAddress(AbstractDetector):
    ARGUMENT = "glider-create3-salt-hijack-leads-to-deterministic-address"
    HELP = "CREATE3 salt hijack in open ProxyFactory (deterministic address DoS/ownership)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-create3-salt-hijack-leads-to-deterministic-address.yaml"
    WIKI_TITLE = "CREATE3 salt hijack in open ProxyFactory (deterministic address DoS/ownership)"
    WIKI_DESCRIPTION = "Flags factory contracts that expose public/external deployment functions using CREATE3 with caller-supplied salts, without access control or commit-then-reveal. The deployed address depends only on (factory, salt, bytecode) - constructor arguments do not affect the address, enabling frontrunning attacks. Based on Immunefi #38066 vulnerability."
    WIKI_EXPLOIT_SCENARIO = "Transpiled from Hexens Glider query create3-salt-hijack-leads-to-deterministic-address. Tags: factory, create3, salt, deploy, frontrun, dos, address-hijack."
    WIKI_RECOMMENDATION = "Apply the check implied by the original Glider query — see hexens-glider source for context."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(CREATE3|create3|deployDeterministic|computeAddress|ProxyFactory|SaltFactory)'}, {'function.kind': 'external_or_public'}, {'function.kind': 'external'}, {'function.is_mutating': True}, {'function.is_constructor': False}, {'function.name_matches': '(?i)^(deploy|deployProxy|deployClone|create|createProxy|createDeterministic|create3)$'}]
    _MATCH = [{'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.body_contains_regex': '(CREATE3|create3|\\.deploy\\s*\\(\\s*salt|keccak256\\s*\\([^\\)]*salt)'}, {'function.not_source_matches_regex': '(onlyOwner|onlyRole|onlyAdmin|onlyAuthorized|AccessControl|commitHash|revealSalt|saltCommit|saltOf\\s*\\[)'}]

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
                info = [f, f" — glider-create3-salt-hijack-leads-to-deterministic-address: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
