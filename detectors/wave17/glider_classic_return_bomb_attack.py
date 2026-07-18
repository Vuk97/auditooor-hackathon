"""
glider-classic-return-bomb-attack — generated from reference/patterns.dsl/glider-classic-return-bomb-attack.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-classic-return-bomb-attack.yaml
Source: glider-query-db/classic-return-bomb-attack
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderClassicReturnBombAttack(AbstractDetector):
    ARGUMENT = "glider-classic-return-bomb-attack"
    HELP = "External call returns value consumed by abi.decode or copied into memory without bounding returndatasize. Malicious callee can return 4GB to exhaust caller's gas."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-classic-return-bomb-attack.yaml"
    WIKI_TITLE = "Return-bomb attack via unbounded returndata copy"
    WIKI_DESCRIPTION = "Solidity's default low-level `.call` copies the full returndata into memory. A hostile callee can return gigabytes of data, consuming all caller gas as a DoS."
    WIKI_EXPLOIT_SCENARIO = "Router forwards swap to user-supplied token; token contract returns `bytes(4GB)`; caller runs out of gas decoding return, user's tx reverts permanently."
    WIKI_RECOMMENDATION = "Use assembly to call with explicit `returndatasize` bound, or compare `returndatasize()` to expected length before copying."

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.call\\s*[\\({]|\\.staticcall|\\.delegatecall'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.has_low_level_call': True}, {'function.body_contains_regex': '\\.(call|staticcall|delegatecall)\\s*[\\({][^;]*;\\s*(\\w+\\s*=\\s*abi\\.decode|require\\s*\\(\\s*success)?'}, {'function.body_not_contains_regex': 'assembly\\s*\\{[^}]*returndatasize|gaslimit|0x20|mload\\s*\\(\\s*ret|limit\\s*:'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-classic-return-bomb-attack: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
