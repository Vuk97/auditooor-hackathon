"""
r94-loop-compact-sig-variant-allows-replay — generated from reference/patterns.dsl/r94-loop-compact-sig-variant-allows-replay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-compact-sig-variant-allows-replay.yaml
Source: loop-cycle-54-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopCompactSigVariantAllowsReplay(AbstractDetector):
    ARGUMENT = "r94-loop-compact-sig-variant-allows-replay"
    HELP = "r94-loop-compact-sig-variant-allows-replay"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-compact-sig-variant-allows-replay.yaml"
    WIKI_TITLE = "r94-loop-compact-sig-variant-allows-replay"
    WIKI_DESCRIPTION = "r94-loop-compact-sig-variant-allows-replay"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-compact-sig-variant-allows-replay"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(ECDSA|recover|tryRecover)'}]
    _MATCH = [{'function.kind': 'internal_or_private'}, {'function.name_matches': '(?i)(recover|tryRecover|verifySig|validateSig|checkSig)'}, {'function.source_matches_regex': '(signature\\.length\\s*==\\s*64|sig\\.len\\s*\\(\\s*\\)\\s*==\\s*64|EIP-?2098|compact)'}, {'function.not_source_matches_regex': '(only65|rejectCompact|canonicalizeSignature|signature\\.length\\s*!=\\s*65)'}]

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
                info = [f, f" — r94-loop-compact-sig-variant-allows-replay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
